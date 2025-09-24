#!/usr/bin/env python3
# policy-core/cli/tools/validate_bundle.py
# Industrial-grade validator for policy bundles (JSON/YAML/ZIP/dir).
# Python 3.11+

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
import re
import sys
import textwrap
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# Optional deps (best-effort)
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:
    import jsonschema  # type: ignore
except Exception:
    jsonschema = None  # type: ignore


# --------------------------- Constants / Schema ---------------------------

ALGORITHMS = {"deny-overrides", "permit-overrides", "first-applicable"}
EFFECTS = {"Permit", "Deny"}
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}$")
POLICY_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.:/]{1,254}$")
RULE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.:/]{0,127}$")
WHEN_CHARS_RE = re.compile(r"^[\w\s\.\(\)\[\]\{\}<>=!&|':\"+\-/*%,]+$")

# Minimal JSON Schema (used if jsonschema installed). We keep it permissive; lints enforce stricter domain rules.
BUNDLE_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Policy Bundle",
    "type": "object",
    "required": ["policies"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "integer"},
        "tenant_id": {"type": ["string", "null"]},
        "metadata": {"type": "object"},
        "policies": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["policy_id", "name", "algorithm", "rules"],
                "additionalProperties": False,
                "properties": {
                    "policy_id": {"type": "string", "minLength": 2, "maxLength": 255},
                    "name": {"type": "string", "minLength": 1, "maxLength": 255},
                    "algorithm": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "version": {"type": "integer"},
                    "status": {"type": "string"},
                    "doc": {"type": "object"},
                    "rules": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["id", "effect"],
                            "additionalProperties": False,
                            "properties": {
                                "id": {"type": "string", "minLength": 1, "maxLength": 128},
                                "name": {"type": "string"},
                                "effect": {"type": "string"},
                                "when": {"type": ["string", "array"]},
                                "obligations": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name"],
                                        "additionalProperties": True,
                                        "properties": {
                                            "name": {"type": "string"},
                                            "params": {"type": "object"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "$include": {"type": ["string", "array"]},
    },
}


# --------------------------- Data structures ---------------------------

class Severity:
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass(slots=True)
class Issue:
    severity: str
    code: str
    message: str
    path: List[Union[str, int]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class PolicyDigest:
    policy_id: str
    name: str
    algorithm: str
    rule_count: int
    tags: List[str]
    etag: str


@dataclass(slots=True)
class Report:
    ok: bool
    issues: List[Issue] = field(default_factory=list)
    policies: List[PolicyDigest] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "ok": self.ok,
                "issues": [x.to_dict() for x in self.issues],
                "policies": [dataclasses.asdict(p) for p in self.policies],
                "stats": self.stats,
            },
            ensure_ascii=False,
            indent=2,
        )


# --------------------------- Loading / Includes ---------------------------

def _read_text(fp: Path | str) -> str:
    return Path(fp).read_text(encoding="utf-8")


def _load_json(data: str) -> Any:
    return json.loads(data)


def _load_yaml(data: str) -> Any:
    if yaml is None:
        raise RuntimeError("YAML support not available. Install PyYAML to read .yaml files.")
    return yaml.safe_load(data)


def _load_any_from_bytes(name: str, content: bytes) -> Any:
    suffix = name.lower()
    text = content.decode("utf-8")
    if suffix.endswith(".json"):
        return _load_json(text)
    if suffix.endswith((".yml", ".yaml")):
        return _load_yaml(text)
    raise ValueError(f"Unsupported file type: {name}")


def _load_any(path: Path) -> Any:
    if path.suffix.lower() == ".json":
        return _load_json(_read_text(path))
    if path.suffix.lower() in (".yml", ".yaml"):
        return _load_yaml(_read_text(path))
    raise ValueError(f"Unsupported file type: {path}")


def _discover_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() in (".json", ".yml", ".yaml"):
            files.append(p)
    return files


def _bundle_from_single(obj: Any) -> Dict[str, Any]:
    # Accept either bundle or single policy.
    if isinstance(obj, Mapping) and "policies" in obj:
        # Ensure shape
        b = dict(obj)
        b.setdefault("metadata", {})
        b.setdefault("version", 1)
        return b
    if isinstance(obj, Mapping) and {"policy_id", "name", "algorithm", "rules"} <= set(obj.keys()):
        return {"version": 1, "metadata": {}, "policies": [dict(obj)]}
    raise ValueError("Input file is neither a bundle nor a single policy object.")


def _read_bundle_from_zip(zip_path: Path) -> Dict[str, Any]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        # Prefer bundle.* if present
        names = zf.namelist()
        bundle_name = next((n for n in names if Path(n).name.lower().startswith("bundle.") and Path(n).suffix.lower() in (".json", ".yml", ".yaml")), None)
        items: List[Dict[str, Any]] = []
        if bundle_name:
            obj = _load_any_from_bytes(bundle_name, zf.read(bundle_name))
            return _bundle_from_single(obj)  # if it's bundle already — return
        # Else, aggregate policies/*
        for n in names:
            p = Path(n)
            if p.suffix.lower() not in (".json", ".yml", ".yaml"):
                continue
            try:
                obj = _load_any_from_bytes(n, zf.read(n))
                b = _bundle_from_single(obj)
                items.extend(b["policies"])
            except Exception:
                continue
        if not items:
            raise ValueError("ZIP archive contains no readable .json/.yaml policy files.")
        return {"version": 1, "metadata": {"source": zip_path.name}, "policies": items}


def _read_bundle(path: Path) -> Dict[str, Any]:
    if path.is_file() and path.suffix.lower() == ".zip":
        return _read_bundle_from_zip(path)
    if path.is_file():
        return _bundle_from_single(_load_any(path))
    if path.is_dir():
        items: List[Dict[str, Any]] = []
        for f in _discover_files(path):
            try:
                b = _bundle_from_single(_load_any(f))
                items.extend(b["policies"])
            except Exception:
                # Skip non-policy files silently
                continue
        if not items:
            raise ValueError(f"No policy files found under {path}")
        return {"version": 1, "metadata": {"source": str(path)}, "policies": items}
    raise ValueError(f"Unsupported path: {path}")


def _resolve_includes(obj: Any, base_dir: Optional[Path]) -> Any:
    """
    Expand shallow $include references (string or list of strings).
    Included files are merged as bundles; later items override earlier on simple keys.
    """
    if not isinstance(obj, Mapping):
        return obj
    out = dict(obj)
    includes = out.get("$include")
    if not includes:
        return out
    paths = includes if isinstance(includes, list) else [includes]
    merged: Dict[str, Any] = {"version": out.get("version", 1), "metadata": out.get("metadata", {}), "policies": []}
    for p in paths:
        if not base_dir:
            raise ValueError("$include used without base directory context")
        file_path = (base_dir / p).resolve()
        sub = _read_bundle(file_path) if file_path.is_dir() or file_path.suffix.lower() == ".zip" else _bundle_from_single(_load_any(file_path))
        merged["policies"].extend(sub["policies"])
    # Local policies appended after includes
    if "policies" in out:
        merged["policies"].extend(out["policies"])
    # Remove include directive
    return merged


# --------------------------- Validation / Lints ---------------------------

def _norm(obj: Any) -> Any:
    """Normalize to a deterministic JSON form (sorted keys, trimmed strings)."""
    if isinstance(obj, Mapping):
        return {k: _norm(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, list):
        return [_norm(v) for v in obj]
    if isinstance(obj, str):
        return obj.strip()
    return obj


def _sha256(obj: Any) -> str:
    canon = json.dumps(_norm(obj), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def validate_schema(bundle: Mapping[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    if jsonschema is None:
        # Soft: without jsonschema we do minimal shape checks
        if not isinstance(bundle, Mapping) or "policies" not in bundle or not isinstance(bundle["policies"], list):
            issues.append(Issue(Severity.ERROR, "SCHEMA", "Bundle must be an object with 'policies' array", ["$"]))
            return issues
        # check policies presence
        for i, pol in enumerate(bundle["policies"]):
            if not isinstance(pol, Mapping):
                issues.append(Issue(Severity.ERROR, "SCHEMA", "Policy must be an object", ["policies", i]))
                continue
            for k in ("policy_id", "name", "algorithm", "rules"):
                if k not in pol:
                    issues.append(Issue(Severity.ERROR, "SCHEMA", f"Missing '{k}'", ["policies", i, k]))
            if not isinstance(pol.get("rules"), list) or not pol.get("rules"):
                issues.append(Issue(Severity.ERROR, "SCHEMA", "rules must be non-empty array", ["policies", i, "rules"]))
        return issues
    # Full jsonschema validation
    try:
        jsonschema.validate(instance=bundle, schema=BUNDLE_SCHEMA)  # type: ignore
    except Exception as e:
        issues.append(Issue(Severity.ERROR, "SCHEMA", f"{e}", ["$"]))
    return issues


def lint_bundle(bundle: Mapping[str, Any], *, strict_unknown_fields: bool, require_tags: bool,
                max_rules: Optional[int], forbid_wildcard_subject: bool) -> Tuple[List[Issue], List[PolicyDigest]]:
    issues: List[Issue] = []
    digests: List[PolicyDigest] = []

    # Unknown top-level fields
    allowed_top = {"version", "tenant_id", "metadata", "policies"}
    top_unknown = set(bundle.keys()) - allowed_top
    if strict_unknown_fields and top_unknown:
        issues.append(Issue(Severity.ERROR, "UNKNOWN_TOPLEVEL", f"Unknown top-level fields: {sorted(top_unknown)}", ["$"]))
    elif top_unknown:
        issues.append(Issue(Severity.WARNING, "UNKNOWN_TOPLEVEL", f"Unknown top-level fields: {sorted(top_unknown)}", ["$"]))

    # Duplicate policy_id
    seen_pids: Dict[str, int] = {}
    for i, pol in enumerate(bundle.get("policies", [])):
        path = ["policies", i]
        pid = str(pol.get("policy_id", "")).strip()
        name = str(pol.get("name", "")).strip()
        algo = str(pol.get("algorithm", "")).strip()
        tags = list(pol.get("tags") or [])

        # policy_id rules
        if not POLICY_ID_RE.match(pid or ""):
            issues.append(Issue(Severity.ERROR, "POLICY_ID", f"Invalid policy_id '{pid}'", path + ["policy_id"]))
        if pid in seen_pids:
            issues.append(Issue(Severity.ERROR, "DUP_POLICY_ID", f"Duplicate policy_id '{pid}' (first at index {seen_pids[pid]})", path))
        else:
            seen_pids[pid] = i

        # name length
        if not (1 <= len(name) <= 255):
            issues.append(Issue(Severity.ERROR, "NAME", "name must be 1..255 chars", path + ["name"]))

        # algorithm
        if algo not in ALGORITHMS:
            issues.append(Issue(Severity.ERROR, "ALGORITHM", f"algorithm must be one of {sorted(ALGORITHMS)}", path + ["algorithm"]))

        # tags
        if require_tags and not tags:
            issues.append(Issue(Severity.ERROR, "TAGS", "tags required (empty)", path + ["tags"]))
        for j, t in enumerate(tags):
            if not isinstance(t, str) or not TAG_RE.match(t):
                issues.append(Issue(Severity.ERROR, "TAG", f"invalid tag '{t}'", path + ["tags", j]))

        # rules
        rules = pol.get("rules") or []
        if max_rules is not None and len(rules) > max_rules:
            issues.append(Issue(Severity.ERROR, "RULES_LIMIT", f"too many rules ({len(rules)} > {max_rules})", path + ["rules"]))

        seen_rids: Dict[str, int] = {}
        for k, rule in enumerate(rules):
            rpath = path + ["rules", k]
            rid = str(rule.get("id", "")).strip()
            eff = str(rule.get("effect", "")).strip()
            when = rule.get("when", None)

            if not RULE_ID_RE.match(rid or ""):
                issues.append(Issue(Severity.ERROR, "RULE_ID", f"Invalid rule id '{rid}'", rpath + ["id"]))
            if rid in seen_rids:
                issues.append(Issue(Severity.ERROR, "DUP_RULE_ID", f"Duplicate rule id '{rid}' (first at index {seen_rids[rid]})", rpath))
            else:
                seen_rids[rid] = k

            if eff not in EFFECTS:
                issues.append(Issue(Severity.ERROR, "EFFECT", f"effect must be one of {sorted(EFFECTS)}", rpath + ["effect"]))

            # when: string or array of strings
            if when is not None:
                if isinstance(when, str):
                    if not WHEN_CHARS_RE.match(when):
                        issues.append(Issue(Severity.ERROR, "WHEN", "when contains forbidden characters", rpath + ["when"]))
                elif isinstance(when, list):
                    for wi, w in enumerate(when):
                        if not isinstance(w, str) or not WHEN_CHARS_RE.match(w):
                            issues.append(Issue(Severity.ERROR, "WHEN", "when item invalid", rpath + ["when", wi]))
                else:
                    issues.append(Issue(Severity.ERROR, "WHEN", "when must be string or array of strings", rpath + ["when"]))

            # forbid wildcard subject if requested (heuristic)
            if forbid_wildcard_subject and isinstance(when, str) and "subject." not in when and "resource." not in when:
                issues.append(Issue(Severity.WARNING, "WILDCARD", "rule condition does not reference subject/resource (possible wildcard)", rpath + ["when"]))

            # obligations shape
            if "obligations" in rule:
                obs = rule.get("obligations") or []
                if not isinstance(obs, list):
                    issues.append(Issue(Severity.ERROR, "OBLIGATIONS", "obligations must be array", rpath + ["obligations"]))
                else:
                    for oi, ob in enumerate(obs):
                        if not isinstance(ob, Mapping) or "name" not in ob:
                            issues.append(Issue(Severity.ERROR, "OBLIGATION", "each obligation must be object with 'name'", rpath + ["obligations", oi]))

        # digest
        etag = _sha256({"policy_id": pid, "name": name, "algorithm": algo, "rules": rules, "tags": tags})
        digests.append(PolicyDigest(policy_id=pid, name=name, algorithm=algo, rule_count=len(rules), tags=tags, etag=etag))

    return issues, digests


# --------------------------- Reporting ---------------------------

def _fmt_path(path: List[Union[str, int]]) -> str:
    if not path:
        return "$"
    s = "$"
    for p in path:
        if isinstance(p, int):
            s += f"[{p}]"
        else:
            s += f".{p}"
    return s


def print_text_report(rep: Report, *, stream: io.TextIOBase = sys.stdout) -> None:
    sev_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for i in rep.issues:
        sev_counts[i.severity] = sev_counts.get(i.severity, 0) + 1

    print("Validation Report", file=stream)
    print("  ok:", rep.ok, file=stream)
    print("  issues:", sum(sev_counts.values()), f"(errors={sev_counts['ERROR']}, warnings={sev_counts['WARNING']}, info={sev_counts['INFO']})", file=stream)
    print("", file=stream)

    if rep.policies:
        print("Policies:", file=stream)
        for p in rep.policies:
            print(f"  - {p.policy_id} | {p.name} | {p.algorithm} | rules={p.rule_count} | etag={p.etag[:12]} | tags={p.tags}", file=stream)
        print("", file=stream)

    if rep.issues:
        print("Issues:", file=stream)
        for it in rep.issues:
            print(f"  [{it.severity}] {it.code} at {_fmt_path(it.path)}: {it.message}", file=stream)
        print("", file=stream)

    if rep.stats:
        print("Stats:", file=stream)
        for k, v in rep.stats.items():
            print(f"  {k}: {v}", file=stream)


# --------------------------- CLI ---------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="policy-validate",
        description="Validate policy bundle (JSON/YAML/ZIP/dir) with schema and lint rules.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("paths", nargs="+", help="Files, directories, or ZIP archives to validate")
    p.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    p.add_argument("--fail-on", choices=["errors", "warnings", "never"], default="errors", help="Failure threshold for exit code")
    p.add_argument("--require-tags", action="store_true", help="Require non-empty tags for each policy")
    p.add_argument("--max-rules-per-policy", type=int, default=None, help="Maximum number of rules allowed per policy")
    p.add_argument("--forbid-unknown-fields", action="store_true", help="Fail on unknown top-level fields")
    p.add_argument("--forbid-wildcard-subject", action="store_true", help="Warn if rule condition does not reference subject/resource")
    p.add_argument("--print-etags", action="store_true", help="Print only etags for each policy and exit 0")
    return p


def validate_paths(
    paths: Sequence[str],
    *,
    strict_unknown_fields: bool,
    require_tags: bool,
    max_rules: Optional[int],
    forbid_wildcard_subject: bool,
) -> Report:
    t0 = time.perf_counter()
    issues: List[Issue] = []
    digests: List[PolicyDigest] = []
    total_policies = 0
    total_rules = 0

    for raw in paths:
        path = Path(raw)
        if not path.exists():
            issues.append(Issue(Severity.ERROR, "INPUT", f"Path not found: {path}", ["$"]))
            continue

        try:
            base_dir = path if path.is_dir() else path.parent
            bundle = _read_bundle(path)
            bundle = _resolve_includes(bundle, base_dir)
        except Exception as e:
            issues.append(Issue(Severity.ERROR, "LOAD", f"{e}", [str(path)]))
            continue

        # Schema
        issues.extend(validate_schema(bundle))

        # Lints
        l_issues, l_digests = lint_bundle(
            bundle,
            strict_unknown_fields=strict_unknown_fields,
            require_tags=require_tags,
            max_rules=max_rules,
            forbid_wildcard_subject=forbid_wildcard_subject,
        )
        issues.extend(l_issues)
        digests.extend(l_digests)
        total_policies += len(l_digests)
        total_rules += sum(d.rule_count for d in l_digests)

    # Severity rollup
    error_count = sum(1 for i in issues if i.severity == Severity.ERROR)
    warn_count = sum(1 for i in issues if i.severity == Severity.WARNING)

    ok = error_count == 0 and not (warn_count and False)  # ok can be true even with warnings
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    stats = {
        "inputs": len(paths),
        "policies": total_policies,
        "rules": total_rules,
        "errors": error_count,
        "warnings": warn_count,
        "elapsed_ms": elapsed_ms,
        "jsonschema_enabled": bool(jsonschema),
        "yaml_enabled": bool(yaml),
    }
    return Report(ok=ok, issues=issues, policies=digests, stats=stats)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    rep = validate_paths(
        args.paths,
        strict_unknown_fields=args.forbid_unknown_fields,
        require_tags=args.require_tags,
        max_rules=args.max_rules_per_policy,
        forbid_wildcard_subject=args.forbid_wildcard_subject,
    )

    # Print-only ETags mode
    if args.print_etags:
        for p in rep.policies:
            print(f"{p.policy_id}\t{p.etag}")
        return 0

    # Output
    if args.format == "json":
        print(rep.to_json())
    else:
        print_text_report(rep)

    # Exit code policy
    errors = sum(1 for i in rep.issues if i.severity == Severity.ERROR)
    warnings = sum(1 for i in rep.issues if i.severity == Severity.WARNING)

    if args.strict:
        errors += warnings  # treat warnings as errors

    if args.fail_on == "never":
        return 0
    if args.fail_on == "warnings":
        return 1 if (errors + warnings) > 0 else 0
    # default: errors
    return 1 if errors > 0 else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
