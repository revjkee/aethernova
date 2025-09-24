from __future__ import annotations

"""
cybersecurity-core/cybersecurity/adversary_emulation/tooling/yara_pack.py

Industrial-grade YARA bundle packer/validator.

Features:
- Recursively discovers .yar/.yara files in provided inputs.
- Safe include expansion (controlled search paths; prevents directory traversal).
- Duplicate rule name detection across bundle.
- SHA-256 and size metadata for all files; deterministic ordering.
- JSON manifest (schema id + stats) with conflicts/duplicates.
- Optional compile check if 'yara' (yara-python) is available; otherwise skips.
- ZIP bundle writer with embedded manifest.
- CLI: pack, validate, list.

Safety:
- Pure Python stdlib (optional import of 'yara' if available).
- Path normalization + traversal guard for include expansion.
- File size caps; text decoding with 'utf-8' and 'replace'.

Python: 3.11+
"""

import argparse
import dataclasses
import fnmatch
import io
import json
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Optional yara-python
try:
    import yara  # type: ignore
    _HAVE_YARA = True
except Exception:
    _HAVE_YARA = False


# ------------------------ Utilities ------------------------

def _sha256_bytes(b: bytes) -> str:
    h = sha256()
    h.update(b)
    return h.hexdigest()


def _sha256_file(p: Path) -> str:
    h = sha256()
    with p.open("rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_ext(name: str) -> str:
    return name.lower()


def _is_yara_file(p: Path) -> bool:
    return _norm_ext(p.suffix) in {".yar", ".yara"}


def _safe_resolve(base: Path, target: Path) -> Path:
    """Resolve target against base and ensure it stays within base."""
    base = base.resolve()
    target = (base / target).resolve() if not target.is_absolute() else target.resolve()
    try:
        target.relative_to(base)
    except Exception as ex:
        raise ValueError(f"Unsafe include path outside allowed root: {target}") from ex
    return target


def _strip_comments_yara(src: str) -> str:
    """
    Remove // and /* */ comments outside of strings.
    Conservative state machine; not a full parser, but robust enough for index tasks.
    """
    out = []
    i = 0
    n = len(src)
    in_str = False
    in_line = False
    in_block = False
    esc = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if in_line:
            if ch == "\n":
                in_line = False
                out.append(ch)
            i += 1
            continue

        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue

        # not in string/comment
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue

        out.append(ch)
        i += 1
    return "".join(out)


_RULE_RE = re.compile(r"(?m)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_INCLUDE_RE = re.compile(r'(?m)^\s*include\s+"([^"]+)"\s*')
_IMPORT_RE = re.compile(r'(?m)^\s*import\s+"([^"]+)"\s*')


@dataclass(frozen=True)
class RuleIndex:
    path: str
    rules: List[str]
    imports: List[str]
    includes: List[str]
    sha256: str
    size: int


def _index_yara_text(text: str, path: Path) -> RuleIndex:
    stripped = _strip_comments_yara(text)
    rules = _RULE_RE.findall(stripped)
    imports = _IMPORT_RE.findall(stripped)
    includes = _INCLUDE_RE.findall(stripped)
    raw = text.encode("utf-8", errors="replace")
    return RuleIndex(
        path=str(path),
        rules=rules,
        imports=imports,
        includes=includes,
        sha256=_sha256_bytes(raw),
        size=len(raw),
    )


def _read_text(p: Path, max_bytes: int) -> str:
    data = p.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"File too large: {p} ({len(data)} bytes > cap {max_bytes})")
    return data.decode("utf-8", errors="replace")


# ------------------------ Include expansion ------------------------

class IncludeExpander:
    """
    Safely expands 'include "..."' directives by inlining content.
    Enforces traversal within allowed roots and prevents cycles.
    """

    def __init__(self, allowed_roots: List[Path], max_bytes: int = 2_000_000) -> None:
        self.roots = [r.resolve() for r in allowed_roots]
        self.max_bytes = max_bytes

    def _resolve_include(self, anchor_file: Path, inc: str) -> Optional[Path]:
        # Relative to anchor first
        candidates: List[Path] = []
        if not Path(inc).is_absolute():
            candidates.append((anchor_file.parent / inc))
        # Then search across roots
        for root in self.roots:
            candidates.append(root / inc)

        for cand in candidates:
            cand = cand.resolve()
            # Ensure cand is under one of the roots
            if any(self._is_within(root, cand) for root in self.roots) and cand.exists() and cand.is_file():
                return cand
        return None

    @staticmethod
    def _is_within(root: Path, target: Path) -> bool:
        try:
            target.relative_to(root)
            return True
        except Exception:
            return False

    def expand(self, file_path: Path, visited: Optional[Set[Path]] = None) -> str:
        visited = set() if visited is None else set(visited)
        file_path = file_path.resolve()
        if file_path in visited:
            raise ValueError(f"Include cycle detected at {file_path}")
        visited.add(file_path)

        text = _read_text(file_path, self.max_bytes)
        stripped = _strip_comments_yara(text)
        includes = _INCLUDE_RE.findall(stripped)

        if not includes:
            return text

        # Inline in order: replace each include directive with actual content
        buf = io.StringIO()
        last_pos = 0
        for m in _INCLUDE_RE.finditer(stripped):
            # write text up to include (from original text for fidelity)
            segment = text[last_pos:m.start()]
            buf.write(segment)
            inc_name = m.group(1)
            resolved = self._resolve_include(file_path, inc_name)
            if resolved is None:
                raise FileNotFoundError(f"Include not found or out of roots: {inc_name} (from {file_path})")
            inlined = self.expand(resolved, visited)
            buf.write(f"\n// --- begin include: {inc_name} ({resolved}) ---\n")
            buf.write(inlined)
            buf.write(f"\n// --- end include: {inc_name} ---\n")
            last_pos = m.end()

        buf.write(text[last_pos:])
        return buf.getvalue()


# ------------------------ Discovery ------------------------

def discover_inputs(paths: Iterable[Path]) -> List[Path]:
    files: Set[Path] = set()
    for p in paths:
        if p.is_file() and _is_yara_file(p):
            files.add(p.resolve())
        elif p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file() and _is_yara_file(sub):
                    files.add(sub.resolve())
    return sorted(files)


# ------------------------ Bundle model ------------------------

@dataclass
class BundleFile:
    relpath: str
    sha256: str
    size: int
    rules: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)


@dataclass
class BundleManifest:
    schema: str
    created_at: str
    root: str
    files: List[BundleFile]
    duplicates: Dict[str, List[str]]  # rule_name -> [paths...]
    stats: Dict[str, int]
    compile_check: Dict[str, str] | None  # {"status": "ok"|"skipped"|"error", "error"?: str}


# ------------------------ Packing ------------------------

class YaraPacker:
    """
    Build a deterministic YARA bundle:
      - expand includes safely
      - index rule names/imports
      - detect duplicates
      - write manifest
      - optional compile validation (yara-python)
    """

    def __init__(
        self,
        inputs: List[Path],
        bundle_root: Path,
        allowed_roots: Optional[List[Path]] = None,
        max_bytes: int = 2_000_000,
    ) -> None:
        self.inputs = inputs
        self.bundle_root = bundle_root.resolve()
        self.allowed_roots = [p.resolve() for p in (allowed_roots or list({p.parent for p in inputs}))]
        self.expander = IncludeExpander(self.allowed_roots, max_bytes=max_bytes)
        self.max_bytes = max_bytes

    def build(self) -> Tuple[BundleManifest, Dict[str, bytes]]:
        """
        Returns manifest and a dict of files {relpath: content_bytes} ready to be zipped.
        """
        rel_to_bytes: Dict[str, bytes] = {}
        bundle_files: List[BundleFile] = []
        rule_to_paths: Dict[str, List[str]] = {}

        # Deterministic order
        for src in sorted(self.inputs):
            rel = self._relativize(src)
            expanded = self.expander.expand(src)
            content_bytes = expanded.encode("utf-8", errors="replace")
            if len(content_bytes) > self.max_bytes:
                raise ValueError(f"Expanded file too large: {src} ({len(content_bytes)} bytes)")

            idx = _index_yara_text(expanded, src)
            bf = BundleFile(
                relpath=rel.as_posix(),
                sha256=_sha256_bytes(content_bytes),
                size=len(content_bytes),
                rules=sorted(set(idx.rules)),
                imports=sorted(set(idx.imports)),
                includes=sorted(set(idx.includes)),
            )
            bundle_files.append(bf)
            rel_to_bytes[bf.relpath] = content_bytes

            for r in bf.rules:
                rule_to_paths.setdefault(r, []).append(bf.relpath)

        duplicates = {r: paths for r, paths in rule_to_paths.items() if len(paths) > 1}

        compile_check = self._compile_check(rel_to_bytes)

        manifest = BundleManifest(
            schema="aethernova.yara.bundle/1.0",
            created_at=_utc_now_iso(),
            root=str(self.bundle_root),
            files=sorted(bundle_files, key=lambda x: x.relpath),
            duplicates=duplicates,
            stats={
                "files": len(bundle_files),
                "rules": sum(len(b.rules) for b in bundle_files),
                "imports": len({imp for b in bundle_files for imp in b.imports}),
                "includes": sum(len(b.includes) for b in bundle_files),
                "duplicates": len(duplicates),
            },
            compile_check=compile_check,
        )
        return manifest, rel_to_bytes

    def _relativize(self, p: Path) -> Path:
        # try to make paths relative to first allowed root containing p
        for root in self.allowed_roots:
            try:
                return p.resolve().relative_to(root)
            except Exception:
                continue
        # fallback to name
        return Path(p.name)

    def _compile_check(self, rel_to_bytes: Dict[str, bytes]) -> Dict[str, str] | None:
        # Optional: compile using yara-python if available by concatenating sources into one namespace
        if not _HAVE_YARA:
            return {"status": "skipped", "reason": "yara-python not installed"}
        try:
            # Build single combined source (already expanded includes)
            combined = "\n\n".join(
                f"// file: {rel}\n" + rel_to_bytes[rel].decode("utf-8", errors="replace")
                for rel in sorted(rel_to_bytes.keys())
            )
            # If there are duplicate rule names, compilation may fail — that's expected and useful.
            yara.compile(source=combined)  # type: ignore
            return {"status": "ok"}
        except Exception as ex:
            return {"status": "error", "error": f"{ex.__class__.__name__}: {ex}"}


# ------------------------ ZIP writer ------------------------

def write_zip_bundle(
    out_zip: Path,
    manifest: BundleManifest,
    rel_to_bytes: Dict[str, bytes],
    manifest_path: str = "_manifest.json",
) -> None:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        # deterministic order
        for rel in sorted(rel_to_bytes.keys()):
            z.writestr(rel, rel_to_bytes[rel])
        z.writestr(manifest_path, json.dumps(dataclasses.asdict(manifest), ensure_ascii=False, indent=2))


# ------------------------ CLI ------------------------

def _cmd_pack(args: argparse.Namespace) -> int:
    inputs = []
    for pattern in args.input:
        p = Path(pattern)
        if p.exists():
            inputs.append(p)
        else:
            # globbing support (shell-independent)
            base = Path(".")
            for m in base.rglob("*"):
                if m.is_file() and fnmatch.fnmatch(str(m), pattern):
                    inputs.append(m)
    files = discover_inputs(inputs)
    if not files:
        print("No YARA files discovered.", file=sys.stderr)
        return 2

    allowed_roots = [Path(p) for p in (args.allow_root or [])]
    if not allowed_roots:
        # Use parents of inputs as allowed roots by default
        allowed_roots = sorted({f.parent for f in files})

    packer = YaraPacker(files, Path(args.output), allowed_roots=allowed_roots, max_bytes=args.max_bytes)
    manifest, rel_to_bytes = packer.build()

    if args.manifest:
        Path(args.manifest).parent.mkdir(parents=True, exist_ok=True)
        Path(args.manifest).write_text(json.dumps(dataclasses.asdict(manifest), ensure_ascii=False, indent=2), encoding="utf-8")
    if args.zip:
        write_zip_bundle(Path(args.zip), manifest, rel_to_bytes)
    if not args.manifest and not args.zip:
        # default to zip beside output path if nothing specified
        default_zip = Path(str(args.output) if args.output.suffix.lower() == ".zip" else f"{args.output}.zip")
        write_zip_bundle(default_zip, manifest, rel_to_bytes)

    # Print short summary
    print(json.dumps({
        "status": "ok",
        "stats": manifest.stats,
        "duplicates": manifest.duplicates,
        "compile_check": manifest.compile_check,
        "files": [bf.relpath for bf in manifest.files],
    }, ensure_ascii=False, indent=2))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    # Validate an existing ZIP bundle or loose files
    if args.zip:
        with zipfile.ZipFile(args.zip, "r") as z:
            names = sorted(n for n in z.namelist() if _is_yara_file(Path(n)))
            if not names:
                print("ZIP contains no YARA files.", file=sys.stderr)
                return 2
            tmp_map: Dict[str, bytes] = {}
            for n in names:
                tmp_map[n] = z.read(n)

            # Reindex and optionally compile
            files: List[BundleFile] = []
            rule_to_paths: Dict[str, List[str]] = {}
            for rel in sorted(tmp_map.keys()):
                text = tmp_map[rel].decode("utf-8", errors="replace")
                idx = _index_yara_text(text, Path(rel))
                bf = BundleFile(
                    relpath=rel,
                    sha256=_sha256_bytes(tmp_map[rel]),
                    size=len(tmp_map[rel]),
                    rules=sorted(set(idx.rules)),
                    imports=sorted(set(idx.imports)),
                    includes=sorted(set(idx.includes)),
                )
                files.append(bf)
                for r in bf.rules:
                    rule_to_paths.setdefault(r, []).append(rel)
            duplicates = {r: v for r, v in rule_to_paths.items() if len(v) > 1}

            combined = "\n\n".join(f"// {rel}\n{text.decode('utf-8', 'replace')}" for rel, text in sorted(tmp_map.items()))
            compile_res = {"status": "skipped", "reason": "yara-python not installed"}
            if _HAVE_YARA:
                try:
                    yara.compile(source=combined)  # type: ignore
                    compile_res = {"status": "ok"}
                except Exception as ex:
                    compile_res = {"status": "error", "error": f"{ex.__class__.__name__}: {ex}"}

            report = {
                "files": [dataclasses.asdict(bf) for bf in files],
                "duplicates": duplicates,
                "compile_check": compile_res,
                "stats": {
                    "files": len(files),
                    "rules": sum(len(b.rules) for b in files),
                    "duplicates": len(duplicates),
                },
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
    else:
        # Validate loose inputs by building in-memory (no zip)
        inputs = [Path(p) for p in args.input]
        files = discover_inputs(inputs)
        if not files:
            print("No YARA files discovered.", file=sys.stderr)
            return 2
        packer = YaraPacker(files, Path("."), allowed_roots=[f.parent for f in files], max_bytes=args.max_bytes)
        manifest, _ = packer.build()
        print(json.dumps({
            "duplicates": manifest.duplicates,
            "stats": manifest.stats,
            "compile_check": manifest.compile_check,
        }, ensure_ascii=False, indent=2))
        return 0


def _cmd_list(args: argparse.Namespace) -> int:
    if args.zip:
        with zipfile.ZipFile(args.zip, "r") as z:
            names = sorted(n for n in z.namelist() if _is_yara_file(Path(n)))
            print(json.dumps({"files": names}, ensure_ascii=False, indent=2))
            return 0
    else:
        inputs = [Path(p) for p in args.input]
        files = [str(p) for p in discover_inputs(inputs)]
        print(json.dumps({"files": files}, ensure_ascii=False, indent=2))
        return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yara-pack",
        description="Deterministic, safe YARA bundle packer/validator."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # pack
    sp = sub.add_parser("pack", help="Build bundle from inputs")
    sp.add_argument("-i", "--input", action="append", required=True, help="File/dir or glob; can repeat")
    sp.add_argument("-o", "--output", type=Path, default=Path("./yara_bundle"), help="Output base name (zip path if --zip omitted)")
    sp.add_argument("--zip", type=Path, help="Explicit ZIP path to write")
    sp.add_argument("--manifest", type=Path, help="Write manifest JSON to path")
    sp.add_argument("--allow-root", action="append", help="Allowed include root; can repeat")
    sp.add_argument("--max-bytes", type=int, default=2_000_000, help="Max bytes per file (after expansion)")
    sp.set_defaults(func=_cmd_pack)

    # validate
    sv = sub.add_parser("validate", help="Validate existing bundle or loose files")
    sv.add_argument("-i", "--input", action="append", help="File/dir or glob; used if --zip not provided")
    sv.add_argument("--zip", type=Path, help="Existing bundle zip to validate")
    sv.add_argument("--max-bytes", type=int, default=2_000_000, help="Max bytes per file")
    sv.set_defaults(func=_cmd_validate)

    # list
    sl = sub.add_parser("list", help="List YARA files")
    sl.add_argument("-i", "--input", action="append", help="File/dir or glob; used if --zip not provided")
    sl.add_argument("--zip", type=Path, help="Existing bundle zip to list")
    sl.set_defaults(func=_cmd_list)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    t0 = time.time()
    try:
        rc = args.func(args)
        return rc
    finally:
        t1 = time.time()
        # stderr timing for CI logs
        print(f"[yara-pack] elapsed_ms={int((t1 - t0) * 1000)}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
