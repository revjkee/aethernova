# cybersecurity-core/cybersecurity/adversary_emulation/tooling/sigma_pack.py
# Industrial-grade Sigma packer:
# - Load & validate Sigma YAML rules from files/directories
# - Deduplicate by rule id or structural fingerprint
# - Filter by product/service (logsource), tags include/exclude, min level
# - Normalize to JSON, build indices (tags, mitre techniques), compute sha256/size
# - Emit manifest.json and packaged bundle (.zip or .tar.gz)
# - Optional compilation to backends via sigma-cli/sigmac if available
# - Structured JSON logging and CLI
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import io
import json
import logging
import os
import pathlib
import re
import sys
import tarfile
import tempfile
import textwrap
import time
import zipfile
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

# -------- Optional deps checks --------
try:
    import yaml  # PyYAML
except Exception as e:
    raise SystemExit("Missing dependency: pyyaml. Install with: pip install pyyaml") from e

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:
    raise SystemExit("Missing dependency: pydantic. Install with: pip install pydantic") from e

import subprocess


# -------- JSON logging --------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # allow extra dict via record.extra
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.handlers = [h]


log = logging.getLogger("sigma.pack")


# -------- Models --------
SIGMA_LEVELS = ("low", "medium", "high", "critical", "informational")


class SigmaLogsource(BaseModel):
    product: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None


class SigmaRuleModel(BaseModel):
    # minimal Sigma schema subset + common fields
    id: Optional[str] = Field(None, regex=r"^[a-fA-F0-9\-]{4,64}$")
    title: str
    status: Optional[str] = None
    description: Optional[str] = None
    references: Optional[List[str]] = None
    tags: List[str] = Field(default_factory=list)
    logsource: Optional[SigmaLogsource] = None
    detection: Dict[str, Any]
    falsepositives: Optional[List[str]] = None
    level: Optional[str] = Field(None)

    @validator("level")
    def check_level(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        lv = str(v).lower()
        if lv not in SIGMA_LEVELS:
            raise ValueError(f"Unsupported level: {v}")
        return lv

    @validator("tags", pre=True)
    def normalize_tags(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v.strip()]
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if str(x).strip()]
        return []

    @validator("title")
    def title_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("title must be non-empty")
        return v.strip()

    @validator("detection")
    def detection_nonempty(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not v or not isinstance(v, dict):
            raise ValueError("detection must be a non-empty mapping")
        return v


@dataclass(frozen=True)
class SigmaRule:
    raw: Dict[str, Any]
    model: SigmaRuleModel
    path: pathlib.Path
    sha256: str
    fingerprint: str  # stable identity for deduplication
    mitre_techniques: List[str]


@dataclass
class BundleItem:
    rule: SigmaRule
    normalized_json: Dict[str, Any]
    bytes_size: int
    content_sha256: str


@dataclass
class BuildResult:
    items: List[BundleItem]
    filtered_out: int
    deduplicated: int
    manifest: Dict[str, Any]
    out_path: pathlib.Path


# -------- Utilities --------
MITRE_TAG_RE = re.compile(r"(attack\.)?(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def read_yaml(path: pathlib.Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def detect_sigma_cli() -> Optional[str]:
    # Prefer sigma-cli (new) then sigmac (legacy)
    for cmd in ("sigma-cli", "sigmac"):
        try:
            out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=5)
            if out.returncode == 0:
                return cmd
        except Exception:
            continue
    return None


def list_paths(inputs: List[pathlib.Path], patterns: Tuple[str, ...] = ("*.yml", "*.yaml")) -> List[pathlib.Path]:
    files: List[pathlib.Path] = []
    for inp in inputs:
        if inp.is_file() and any(fnmatch.fnmatch(inp.name.lower(), pat) for pat in patterns):
            files.append(inp)
        elif inp.is_dir():
            for root, _, names in os.walk(inp):
                for n in names:
                    if any(fnmatch.fnmatch(n.lower(), pat) for pat in patterns):
                        files.append(pathlib.Path(root) / n)
    return sorted(set(files))


def rule_fingerprint(model: SigmaRuleModel, raw: Dict[str, Any]) -> str:
    # Prefer explicit id; else structural fingerprint of title + keys of detection
    if model.id:
        return f"id:{model.id}"
    det = raw.get("detection", {})
    # stable order of keys; avoid values to reduce noise
    keys = sorted(det.keys())
    src = json.dumps(
        {"title": model.title.strip().lower(), "keys": keys, "product": (model.logsource or SigmaLogsource()).product,
         "service": (model.logsource or SigmaLogsource()).service},
        sort_keys=True, ensure_ascii=False
    )
    return "fp:" + sha256_bytes(src.encode("utf-8"))[:24]


def extract_mitre(tags: List[str]) -> List[str]:
    techniques: Set[str] = set()
    for t in tags:
        m = MITRE_TAG_RE.search(t)
        if m:
            techniques.add("T" + m.group(2).upper()[1:])  # normalize to Txxxx(.xxx)
    return sorted(techniques)


def ensure_dir(p: pathlib.Path) -> pathlib.Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


# -------- Loading & validation --------
def load_rules(paths: List[pathlib.Path]) -> List[SigmaRule]:
    rules: List[SigmaRule] = []
    for p in list_paths(paths):
        try:
            raw = read_yaml(p)
            if not isinstance(raw, dict):
                log.warning("Skip non-mapping YAML", extra={"extra": {"path": str(p)}})
                continue
            model = SigmaRuleModel.parse_obj(raw)
            sh = sha256_file(p)
            fp = rule_fingerprint(model, raw)
            mitre = extract_mitre(model.tags)
            rules.append(SigmaRule(raw=raw, model=model, path=p, sha256=sh, fingerprint=fp, mitre_techniques=mitre))
        except Exception as e:
            log.error("Invalid Sigma rule", extra={"extra": {"path": str(p), "error": str(e)}})
    return rules


# -------- Filtering & dedup --------
def filter_rules(
    rules: List[SigmaRule],
    product: Optional[str],
    service: Optional[str],
    include_tags: Set[str],
    exclude_tags: Set[str],
    min_level: Optional[str],
) -> Tuple[List[SigmaRule], int, int]:
    # dedup by fingerprint; prefer with explicit id
    kept: Dict[str, SigmaRule] = {}
    for r in rules:
        cur = kept.get(r.fingerprint)
        if cur is None:
            kept[r.fingerprint] = r
            continue
        # Prefer rule that has explicit id / higher level
        cur_level = (cur.model.level or "").lower()
        new_level = (r.model.level or "").lower()
        prefer = (bool(r.model.id) and not bool(cur.model.id)) or (new_level, r.path.name) > (cur_level, cur.path.name)
        if prefer:
            kept[r.fingerprint] = r

    deduplicated = len(rules) - len(kept)

    def level_rank(lv: Optional[str]) -> int:
        if lv is None:
            return -1
        try:
            return SIGMA_LEVELS.index(lv)
        except ValueError:
            return -1

    min_rank = level_rank(min_level) if min_level else None

    def accept(r: SigmaRule) -> bool:
        ls = r.model.logsource or SigmaLogsource()
        if product and (ls.product or "").lower() != product.lower():
            return False
        if service and (ls.service or "").lower() != service.lower():
            return False
        if include_tags and not include_tags.intersection({t.lower() for t in r.model.tags}):
            return False
        if exclude_tags and exclude_tags.intersection({t.lower() for t in r.model.tags}):
            return False
        if min_rank is not None and level_rank(r.model.level) < min_rank:
            return False
        return True

    filtered = [r for r in kept.values() if accept(r)]
    filtered_out = len(kept) - len(filtered)
    return sorted(filtered, key=lambda x: (x.model.title.lower(), x.path.name)), filtered_out, deduplicated


# -------- Normalization & indices --------
def normalize_rule(rule: SigmaRule) -> Dict[str, Any]:
    # Retain original YAML fields, plus derived metadata
    base = dict(rule.raw)  # shallow copy
    meta = {
        "_meta": {
            "source_path": str(rule.path),
            "source_sha256": rule.sha256,
            "fingerprint": rule.fingerprint,
            "mitre_techniques": rule.mitre_techniques,
            "normalized_at": dt.datetime.utcnow().isoformat() + "Z",
        }
    }
    base.update(meta)
    return base


def build_indices(items: List[BundleItem]) -> Dict[str, Any]:
    by_tag: Dict[str, List[str]] = {}
    by_tech: Dict[str, List[str]] = {}
    for it in items:
        tags = it.normalized_json.get("tags") or []
        for t in tags:
            tl = str(t).lower()
            by_tag.setdefault(tl, []).append(it.normalized_json.get("id") or it.rule.fingerprint)
        for tech in it.rule.mitre_techniques:
            by_tech.setdefault(tech, []).append(it.normalized_json.get("id") or it.rule.fingerprint)

    # sort and unique
    for d in (by_tag, by_tech):
        for k in list(d.keys()):
            d[k] = sorted(sorted(set(d[k])))
    return {"by_tag": by_tag, "by_mitre": by_tech}


# -------- Optional compilation via sigma-cli/sigmac --------
def compile_rule_text(rule_path: pathlib.Path, backend: str, cli: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (compiled_query, error_text)
    """
    try:
        if "sigma-cli" in cli:
            # sigma-cli generate --target <backend> -r <rule>
            cmd = [cli, "generate", "--target", backend, "-r", str(rule_path)]
        else:
            # legacy sigmac -t <backend> <rule>
            cmd = [cli, "-t", backend, str(rule_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            out = proc.stdout.strip()
            return (out if out else None, None)
        else:
            return (None, proc.stderr.strip() or "Compilation failed")
    except Exception as e:
        return (None, f"Compilation error: {e}")


def compile_bundle(
    items: List[BundleItem],
    tmp_dir: pathlib.Path,
    backends: List[str],
    cli: str,
) -> Dict[str, Dict[str, Union[str, None]]]:
    """
    For each rule file written to tmp_dir/rules/<name>.yml compile to backends.
    Returns mapping: backend -> rule_id -> compiled_query (or None if error).
    """
    compiled: Dict[str, Dict[str, Union[str, None]]] = {}
    for b in backends:
        compiled[b] = {}
    for it in items:
        rule_id = it.normalized_json.get("id") or it.rule.fingerprint
        # we wrote normalized JSON; compile from original YAML content
        yaml_path = tmp_dir / "rules_yaml" / f"{rule_id}.yml"
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        yaml_text = yaml.safe_dump(it.rule.raw, sort_keys=False, allow_unicode=True)
        yaml_path.write_text(yaml_text, encoding="utf-8")
        for b in backends:
            query, err = compile_rule_text(yaml_path, b, cli)
            compiled[b][rule_id] = query if err is None else None
    return compiled


# -------- Packaging --------
def write_bundle(
    items: List[BundleItem],
    out_dir: pathlib.Path,
    bundle_name: str,
    fmt: str,
    manifest: Dict[str, Any],
    compiled: Optional[Dict[str, Dict[str, Union[str, None]]]] = None,
) -> pathlib.Path:
    ensure_dir(out_dir)
    out_path = out_dir / f"{bundle_name}.{('zip' if fmt == 'zip' else 'tar.gz')}"
    # Build staging dir
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        rules_dir = td_path / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        for it in items:
            rule_id = it.normalized_json.get("id") or it.rule.fingerprint
            p = rules_dir / f"{rule_id}.json"
            p.write_text(json.dumps(it.normalized_json, ensure_ascii=False, indent=2), encoding="utf-8")
        # compiled queries
        if compiled:
            comp_dir = td_path / "compiled"
            for backend, m in compiled.items():
                bdir = comp_dir / backend
                bdir.mkdir(parents=True, exist_ok=True)
                for rid, query in m.items():
                    qfile = bdir / f"{rid}.txt"
                    qfile.write_text("" if query is None else str(query), encoding="utf-8")
        # manifest
        (td_path / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        if fmt == "zip":
            with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(td_path):
                    for f in files:
                        full = pathlib.Path(root) / f
                        rel = full.relative_to(td_path)
                        zf.write(full, arcname=str(rel))
        else:
            with tarfile.open(out_path, "w:gz") as tf:
                tf.add(td_path, arcname=".")

    return out_path


# -------- Builder --------
def build_pack(
    sources: List[pathlib.Path],
    out_dir: pathlib.Path,
    name: str,
    product: Optional[str] = None,
    service: Optional[str] = None,
    include_tags: Optional[List[str]] = None,
    exclude_tags: Optional[List[str]] = None,
    min_level: Optional[str] = None,
    fmt: str = "zip",
    compile_backends: Optional[List[str]] = None,
) -> BuildResult:
    start = time.time()
    rules = load_rules(sources)
    filtered, filtered_out, deduped = filter_rules(
        rules,
        product=product,
        service=service,
        include_tags={t.lower() for t in (include_tags or [])},
        exclude_tags={t.lower() for t in (exclude_tags or [])},
        min_level=min_level.lower() if min_level else None,
    )

    items: List[BundleItem] = []
    for r in filtered:
        norm = normalize_rule(r)
        blob = json.dumps(norm, ensure_ascii=False, sort_keys=True).encode("utf-8")
        items.append(
            BundleItem(
                rule=r,
                normalized_json=norm,
                bytes_size=len(blob),
                content_sha256=sha256_bytes(blob),
            )
        )

    indices = build_indices(items)
    manifest = {
        "name": name,
        "created_at": dt.datetime.utcnow().isoformat() + "Z",
        "source_count": len(rules),
        "included_count": len(items),
        "filtered_out": filtered_out,
        "deduplicated": deduped,
        "product": product,
        "service": service,
        "min_level": min_level,
        "include_tags": sorted(include_tags or []),
        "exclude_tags": sorted(exclude_tags or []),
        "indices": {k: {kk: len(v) for kk, v in v.items()} for k, v in indices.items()},
        "hashes": {
            "rules_total_bytes": sum(i.bytes_size for i in items),
            "rules_sha256_agg": sha256_bytes("".join(i.content_sha256 for i in items).encode("utf-8")),
        },
        "tool": {"name": "sigma_pack", "version": "1.0.0"},
    }

    compiled: Optional[Dict[str, Dict[str, Union[str, None]]]] = None
    if compile_backends:
        cli = detect_sigma_cli()
        if cli is None:
            log.warning("sigma-cli/sigmac not found; skip compilation")
        else:
            with tempfile.TemporaryDirectory() as td:
                # reuse normalization but write original YAML to compile
                tmpdir = pathlib.Path(td)
                compiled = compile_bundle(items, tmpdir, compile_backends, cli)

    # Attach indices into manifest for quick introspection
    manifest["indices_examples"] = {k: {kk: v[:5] for kk, v in vv.items()} for k, vv in indices.items()}

    out_path = write_bundle(items, out_dir, name, fmt=fmt, manifest=manifest, compiled=compiled)

    duration_ms = int((time.time() - start) * 1000)
    manifest["duration_ms"] = duration_ms

    log.info(
        "Pack built",
        extra={
            "extra": {
                "name": name,
                "out_path": str(out_path),
                "duration_ms": duration_ms,
                "included": len(items),
                "source": len(rules),
                "filtered_out": filtered_out,
                "deduplicated": deduped,
            }
        },
    )

    return BuildResult(items=items, filtered_out=filtered_out, deduplicated=deduped, manifest=manifest, out_path=out_path)


# -------- CLI --------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sigma pack builder: load YAML rules, filter, deduplicate, normalize and package into bundle."
    )
    p.add_argument(
        "-i",
        "--input",
        dest="inputs",
        required=True,
        nargs="+",
        type=pathlib.Path,
        help="Paths to rule files or directories (YAML).",
    )
    p.add_argument(
        "-o",
        "--out-dir",
        dest="out_dir",
        required=True,
        type=pathlib.Path,
        help="Output directory for the bundle.",
    )
    p.add_argument("-n", "--name", dest="name", required=True, help="Bundle name (base filename without extension).")
    p.add_argument("--product", type=str, default=None, help="Filter by logsource.product")
    p.add_argument("--service", type=str, default=None, help="Filter by logsource.service")
    p.add_argument("--include-tags", type=str, default=None, help="Comma-separated tags to include (OR).")
    p.add_argument("--exclude-tags", type=str, default=None, help="Comma-separated tags to exclude.")
    p.add_argument("--min-level", type=str, default=None, choices=list(SIGMA_LEVELS), help="Minimal rule level.")
    p.add_argument("--format", dest="fmt", type=str, default="zip", choices=["zip", "tgz"], help="Bundle format.")
    p.add_argument(
        "--compile",
        dest="compile_backends",
        type=str,
        default=None,
        help="Comma-separated backends to compile with sigma-cli/sigmac (e.g. splunk,es-qs,stix).",
    )
    p.add_argument("--log-level", type=str, default="INFO")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    configure_logging(args.log_level)

    inputs = [p.resolve() for p in args.inputs]
    out_dir = args.out_dir.resolve()
    include_tags = [t.strip() for t in (args.include_tags or "").split(",") if t.strip()]
    exclude_tags = [t.strip() for t in (args.exclude_tags or "").split(",") if t.strip()]
    compile_backends = [t.strip() for t in (args.compile_backends or "").split(",") if t.strip()]
    fmt = "zip" if args.fmt == "zip" else "tgz"

    res = build_pack(
        sources=inputs,
        out_dir=out_dir,
        name=args.name,
        product=args.product,
        service=args.service,
        include_tags=include_tags or None,
        exclude_tags=exclude_tags or None,
        min_level=args.min_level,
        fmt=("zip" if fmt == "zip" else "tar.gz"),
        compile_backends=compile_backends or None,
    )
    # Write final manifest alongside bundle
    manifest_path = out_dir / f"{args.name}.manifest.json"
    manifest_path.write_text(json.dumps(res.manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"bundle": str(res.out_path), "manifest": str(manifest_path)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
