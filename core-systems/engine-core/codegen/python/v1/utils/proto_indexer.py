#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Industrial-grade .proto indexer:
- Recursively discover .proto files with include/exclude globs
- Parse imports/options/packages efficiently (parallel I/O)
- Build dependency graph, detect cycles, topologically sort
- Incremental cache (content hash + mtime) to skip unchanged
- Export JSON (compilation order, graph) and DOT (GraphViz)
- Usable as library or CLI
- Zero external deps; Python 3.9+
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import fnmatch
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ----------------------------- Logging ------------------------------------- #

LOG_LEVEL = os.getenv("PROTO_INDEXER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
LOGGER = logging.getLogger("proto_indexer")

# ----------------------------- Constants ----------------------------------- #

DEFAULT_INCLUDE_PATTERNS = ("**/*.proto",)
DEFAULT_EXCLUDE_PATTERNS = ("**/build/**", "**/.venv/**", "**/.tox/**", "**/node_modules/**", "**/dist/**")

CACHE_DIR_NAME = ".proto_index"
CACHE_FILE_NAME = "cache.json"

# Regex patterns kept simple but robust for proto syntax (imports, package, option go_package/java_package)
RE_IMPORT = re.compile(r'^\s*import\s+(?:public\s+)?(?P<q>"[^"]+"|\'[^\']+\')\s*;\s*$', re.MULTILINE)
RE_PACKAGE = re.compile(r'^\s*package\s+(?P<pkg>[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*;\s*$', re.MULTILINE)
RE_OPTION = re.compile(r'^\s*option\s+(?P<key>(?:go_package|java_package))\s*=\s*(?P<q>"[^"]+"|\'[^\']+\')\s*;\s*$', re.MULTILINE)

# ----------------------------- Data models --------------------------------- #

@dataclass(frozen=True)
class FileId:
    """Canonical identity for a proto file (path relative to workspace root)."""
    relpath: str

    def __str__(self) -> str:
        return self.relpath


@dataclass
class ProtoFileMeta:
    file_id: FileId
    abspath: str
    mtime: float
    size: int
    sha256: str
    package: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    options: Dict[str, str] = field(default_factory=dict)


@dataclass
class IndexResult:
    root: str
    files: Dict[str, ProtoFileMeta]  # keyed by relpath
    graph: Dict[str, Set[str]]       # edges: file -> set(dependencies)
    reverse_graph: Dict[str, Set[str]]
    topo_order: List[str] = field(default_factory=list)
    cyclic_scc: List[Set[str]] = field(default_factory=list)
    changed_files: Set[str] = field(default_factory=set)

    def to_json(self) -> Dict:
        return {
            "root": self.root,
            "files": {k: _meta_to_json(v) for k, v in self.files.items()},
            "graph": {k: sorted(list(v)) for k, v in self.graph.items()},
            "reverse_graph": {k: sorted(list(v)) for k, v in self.reverse_graph.items()},
            "topo_order": self.topo_order,
            "cyclic_components": [sorted(list(s)) for s in self.cyclic_scc],
            "changed_files": sorted(list(self.changed_files)),
        }


def _meta_to_json(m: ProtoFileMeta) -> Dict:
    return {
        "file_id": str(m.file_id),
        "abspath": m.abspath,
        "mtime": m.mtime,
        "size": m.size,
        "sha256": m.sha256,
        "package": m.package,
        "imports": m.imports,
        "options": m.options,
    }


# ----------------------------- Exceptions ---------------------------------- #

class ProtoIndexerError(Exception):
    pass


class CycleError(ProtoIndexerError):
    def __init__(self, cycles: List[Set[str]]):
        super().__init__("Dependency cycles detected")
        self.cycles = cycles


# ----------------------------- Discovery ----------------------------------- #

def _match_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)


def discover_proto_files(
    root: Path,
    include_patterns: Iterable[str] = DEFAULT_INCLUDE_PATTERNS,
    exclude_patterns: Iterable[str] = DEFAULT_EXCLUDE_PATTERNS,
) -> List[Path]:
    root = root.resolve()
    files: List[Path] = []
    for pat in include_patterns:
        for p in root.glob(pat):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if _match_any(rel, exclude_patterns):
                continue
            files.append(p)
    # De-duplicate while keeping order
    seen: Set[str] = set()
    unique: List[Path] = []
    for p in files:
        key = p.resolve().as_posix()
        if key not in seen:
            seen.add(key)
            unique.append(p)
    LOGGER.info("Discovered %d proto files under %s", len(unique), root)
    return unique


# ----------------------------- Parsing ------------------------------------- #

def _sha256_file(path: Path) -> Tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _parse_proto_text(text: str) -> Tuple[List[str], Optional[str], Dict[str, str]]:
    """Extract imports, package and key options from proto content."""
    imports: List[str] = []
    for m in RE_IMPORT.finditer(text):
        q = m.group("q")
        imports.append(q[1:-1])  # strip quotes

    pkg: Optional[str] = None
    m_pkg = RE_PACKAGE.search(text)
    if m_pkg:
        pkg = m_pkg.group("pkg").strip()

    options: Dict[str, str] = {}
    for m in RE_OPTION.finditer(text):
        key = m.group("key")
        val = m.group("q")[1:-1]
        options[key] = val

    return imports, pkg, options


def _read_and_parse(path: Path, root: Path) -> ProtoFileMeta:
    sha, size = _sha256_file(path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    imports, pkg, options = _parse_proto_text(text)
    rel = path.relative_to(root).as_posix()
    meta = ProtoFileMeta(
        file_id=FileId(rel),
        abspath=str(path.resolve().as_posix()),
        mtime=path.stat().st_mtime,
        size=size,
        sha256=sha,
        package=pkg,
        imports=imports,
        options=options,
    )
    return meta


def parse_all(files: List[Path], root: Path, max_workers: int = os.cpu_count() or 4) -> Dict[str, ProtoFileMeta]:
    metas: Dict[str, ProtoFileMeta] = {}
    t0 = time.time()
    with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_read_and_parse, p, root): p for p in files}
        for fut in futures.as_completed(futs):
            p = futs[fut]
            try:
                meta = fut.result()
                metas[meta.file_id.relpath] = meta
            except Exception as e:
                LOGGER.exception("Failed to parse %s: %s", p, e)
                raise
    LOGGER.info("Parsed %d files in %.3fs", len(metas), time.time() - t0)
    return metas


# ----------------------------- Graph --------------------------------------- #

def build_dependency_graph(metas: Dict[str, ProtoFileMeta]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Builds forward and reverse dependency graphs keyed by relpath.
    Edge A -> B means A imports B (A depends on B)."""
    # Map import string to candidate relpath (heuristic: imports typically use workspace-relative paths)
    # We will try exact match first; if not found, attempt to resolve by basename uniqueness.
    relpaths: Set[str] = set(metas.keys())
    by_basename: Dict[str, str] = {}
    for rp in relpaths:
        base = Path(rp).name
        # Only accept unique basenames to avoid ambiguity
        if base not in by_basename:
            by_basename[base] = rp
        else:
            by_basename[base] = ""  # mark ambiguous

    forward: Dict[str, Set[str]] = {rp: set() for rp in relpaths}
    reverse: Dict[str, Set[str]] = {rp: set() for rp in relpaths}

    def resolve_import(imp: str) -> Optional[str]:
        if imp in metas:
            return imp
        # try strip leading ./ or /
        norm = imp.lstrip("./")
        if norm in metas:
            return norm
        base = Path(imp).name
        candidate = by_basename.get(base, "")
        return candidate or None

    unresolved: List[Tuple[str, str]] = []
    for rp, meta in metas.items():
        for imp in meta.imports:
            tgt = resolve_import(imp)
            if tgt and tgt in relpaths:
                forward[rp].add(tgt)
                reverse[tgt].add(rp)
            else:
                unresolved.append((rp, imp))

    if unresolved:
        # Not fatal: protoc can still resolve with -I include paths.
        # We log them to aid configuration.
        for rp, imp in unresolved[:20]:
            LOGGER.warning("Unresolved import: %s -> %s", rp, imp)
        LOGGER.info("Total unresolved imports: %d", len(unresolved))
    return forward, reverse


def topo_sort(graph: Dict[str, Set[str]]) -> Tuple[List[str], List[Set[str]]]:
    """Kahn's algorithm + cycle extraction (SCC via DFS fallback)."""
    # Compute indegree
    indeg: Dict[str, int] = {n: 0 for n in graph}
    for src, deps in graph.items():
        for d in deps:
            indeg[d] = indeg.get(d, 0) + 1

    # Nodes with zero indegree
    queue: List[str] = [n for n, deg in indeg.items() if deg == 0]
    order: List[str] = []
    indeg_work = dict(indeg)

    while queue:
        n = queue.pop()
        order.append(n)
        for d in graph.get(n, ()):
            indeg_work[d] -= 1
            if indeg_work[d] == 0:
                queue.append(d)

    if len(order) == len(graph):
        return order, []

    # Cycles exist. Extract SCCs (Tarjan).
    sccs = strongly_connected_components(graph)
    cyclic = [s for s in sccs if len(s) > 1 or _self_loop(graph, s)]
    return order, cyclic


def _self_loop(graph: Dict[str, Set[str]], nodes: Set[str]) -> bool:
    for n in nodes:
        if n in graph.get(n, set()):
            return True
    return False


def strongly_connected_components(graph: Dict[str, Set[str]]) -> List[Set[str]]:
    index = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    stack: List[str] = []
    on_stack: Set[str] = set()
    result: List[Set[str]] = []

    sys.setrecursionlimit(max(10000, len(graph) * 2))

    def strongconnect(v: str):
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in graph.get(v, ()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        # If v is a root node, pop the stack and generate an SCC
        if lowlink[v] == indices[v]:
            scc: Set[str] = set()
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.add(w)
                if w == v:
                    break
            result.append(scc)

    for v in graph:
        if v not in indices:
            strongconnect(v)
    return result


# ----------------------------- Cache --------------------------------------- #

@dataclass
class CacheEntry:
    sha256: str
    mtime: float
    size: int
    package: Optional[str]
    imports: List[str]
    options: Dict[str, str]


@dataclass
class CacheModel:
    version: int
    root: str
    entries: Dict[str, CacheEntry]  # relpath -> entry


CACHE_VERSION = 1


def load_cache(root: Path) -> Optional[CacheModel]:
    path = root / CACHE_DIR_NAME / CACHE_FILE_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != CACHE_VERSION:
            LOGGER.info("Cache version mismatch, ignoring")
            return None
        entries = {
            k: CacheEntry(
                sha256=v["sha256"],
                mtime=v["mtime"],
                size=v["size"],
                package=v.get("package"),
                imports=v.get("imports", []),
                options=v.get("options", {}),
            )
            for k, v in data.get("entries", {}).items()
        }
        return CacheModel(version=CACHE_VERSION, root=data["root"], entries=entries)
    except Exception as e:
        LOGGER.warning("Failed to load cache: %s", e)
        return None


def save_cache(root: Path, metas: Dict[str, ProtoFileMeta]) -> None:
    cache_dir = root / CACHE_DIR_NAME
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / CACHE_FILE_NAME
    payload = {
        "version": CACHE_VERSION,
        "root": root.as_posix(),
        "entries": {
            rp: {
                "sha256": m.sha256,
                "mtime": m.mtime,
                "size": m.size,
                "package": m.package,
                "imports": m.imports,
                "options": m.options,
            }
            for rp, m in metas.items()
        },
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def compute_changed_files(metas: Dict[str, ProtoFileMeta], cache: Optional[CacheModel]) -> Set[str]:
    if not cache:
        return set(metas.keys())
    changed: Set[str] = set()
    for rp, m in metas.items():
        e = cache.entries.get(rp)
        if not e:
            changed.add(rp)
            continue
        if e.sha256 != m.sha256 or e.size != m.size or abs(e.mtime - m.mtime) > 1e-6:
            changed.add(rp)
    return changed


# ----------------------------- Exporters ----------------------------------- #

def export_json(index: IndexResult, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(index.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
    LOGGER.info("Wrote JSON index to %s", out_path.as_posix())


def export_dot(index: IndexResult, out_path: Path) -> None:
    """GraphViz DOT export (forward deps)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = ["digraph proto_deps {"]
    lines.append('  rankdir=LR; node [shape=box, fontsize=10];')

    # style cyclic nodes
    cyclic_nodes: Set[str] = set().union(*index.cyclic_scc) if index.cyclic_scc else set()

    for node, deps in index.graph.items():
        nlabel = node.replace('"', '\\"')
        if node in cyclic_nodes:
            lines.append(f'  "{nlabel}" [color=red, style=filled, fillcolor="#ffeeee"];')
        else:
            lines.append(f'  "{nlabel}";')
        for dep in deps:
            dlabel = dep.replace('"', '\\"')
            lines.append(f'  "{nlabel}" -> "{dlabel}";')

    lines.append("}")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    LOGGER.info("Wrote DOT graph to %s", out_path.as_posix())


# ----------------------------- Orchestration -------------------------------- #

def index_workspace(
    root: Path,
    include: Iterable[str] = DEFAULT_INCLUDE_PATTERNS,
    exclude: Iterable[str] = DEFAULT_EXCLUDE_PATTERNS,
    max_workers: int = os.cpu_count() or 4,
    allow_cycles: bool = False,
) -> IndexResult:
    files = discover_proto_files(root, include, exclude)
    metas = parse_all(files, root, max_workers=max_workers)

    cache = load_cache(root)
    changed = compute_changed_files(metas, cache)

    forward, reverse = build_dependency_graph(metas)
    order, cycles = topo_sort(forward)

    index = IndexResult(
        root=root.as_posix(),
        files=metas,
        graph=forward,
        reverse_graph=reverse,
        topo_order=order,
        cyclic_scc=cycles,
        changed_files=changed,
    )

    save_cache(root, metas)

    if cycles and not allow_cycles:
        # Provide detailed error with sample cycle nodes
        sample = sorted(list(next(iter(cycles))))
        LOGGER.error("Dependency cycles detected (sample): %s", sample)
        raise CycleError(cycles)

    return index


# ----------------------------- CLI ----------------------------------------- #

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Index .proto files, build dependency graph and output compilation order.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--root", type=str, default=".", help="Workspace root")
    p.add_argument("--include", type=str, nargs="*", default=list(DEFAULT_INCLUDE_PATTERNS), help="Glob patterns to include")
    p.add_argument("--exclude", type=str, nargs="*", default=list(DEFAULT_EXCLUDE_PATTERNS), help="Glob patterns to exclude")
    p.add_argument("--max-workers", type=int, default=os.cpu_count() or 4, help="Parallel workers for parsing")
    p.add_argument("--json-out", type=str, default="", help="Write JSON index to this path")
    p.add_argument("--dot-out", type=str, default="", help="Write GraphViz DOT to this path")
    p.add_argument("--allow-cycles", action="store_true", help="Do not fail on cycles")
    p.add_argument("--print-order", action="store_true", help="Print topological order to stdout")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(args.root).resolve()
    try:
        index = index_workspace(
            root=root,
            include=args.include,
            exclude=args.exclude,
            max_workers=args.max_workers,
            allow_cycles=args.allow_cycles,
        )
    except CycleError as ce:
        # Still write outputs if requested, for diagnostics
        if args.json_out:
            try:
                export_json(IndexResult(
                    root=str(root),
                    files={}, graph={}, reverse_graph={}, topo_order=[],
                    cyclic_scc=ce.cycles, changed_files=set()
                ), Path(args.json_out))
            except Exception:
                pass
        LOGGER.error("Cycles detected. Re-run with --allow-cycles to inspect full index.")
        return 2
    except Exception as e:
        LOGGER.exception("Indexing failed: %s", e)
        return 1

    if args.json_out:
        export_json(index, Path(args.json_out))
    if args.dot_out:
        export_dot(index, Path(args.dot_out))
    if args.print_order:
        for rp in index.topo_order:
            print(rp)

    # basic stdout summary (no noise if not needed)
    LOGGER.info(
        "Indexed %d files. Changed: %d. Cycles: %d.",
        len(index.files), len(index.changed_files), len(index.cyclic_scc)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
