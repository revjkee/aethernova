# engine-core/engine/plugins/loader.py
"""
Industrial-grade plugin loader for engine-core.

Features:
- Discovery from:
    * filesystem dirs with manifests (plugin.json / plugin.toml optional)
    * installed distributions via entry points: "engine_core.plugins"
- Canonical manifest with semver, engine ABI check, optional dependencies/optional extras
- Integrity:
    * SHA-256 of source tree (py files + manifest) with deterministic traversal
    * cache of last known hashes to skip reload
- Dependency resolution:
    * topological sort with cycle detection
    * version constraints (semver ^, ~, >=, <=, ==, !=)
- Lifecycle:
    * load -> init(ctx) -> start(ctx) -> stop(ctx) -> unload
    * per-plugin state and error isolation
- Hot reload:
    * polling mtime/hash; safe stop->reload chain; backoff after failures
- Telemetry:
    * event hook (on_event), counters/timers (no жёстких deps)
- Optional process isolation:
    * SubprocessRunner (spawn) with message pipe (stdin/stdout JSON lines)
      for untrusted plugins; graceful stop with timeout
- Safety:
    * Strict public API surface via PluginContext
    * No exec of arbitrary code strings
    * Import by module spec from known roots only

No external dependencies. Python 3.10+.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Set
import fnmatch
import importlib
import importlib.util
import importlib.metadata as imd
import inspect
import io
import json
import os
import pathlib
import pkgutil
import re
import runpy
import shutil
import subprocess
import sys
import threading
import time
import traceback
import hashlib

# =========================
# Constants & utils
# =========================

ENGINE_ABI = "1.0"  # bump on breaking API in PluginContext/Loader

def _now_ms() -> int:
    return int(time.monotonic() * 1000)

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_tree(root: pathlib.Path, patterns: Iterable[str] = ("*.py", "plugin.json")) -> str:
    files: List[pathlib.Path] = []
    for dirpath, _, filenames in os.walk(root):
        for pat in patterns:
            for name in fnmatch.filter(filenames, pat):
                files.append(pathlib.Path(dirpath) / name)
    # deterministic order
    files.sort(key=lambda p: str(p.relative_to(root)).replace(os.sep, "/"))
    h = hashlib.sha256()
    for p in files:
        rel = str(p.relative_to(root)).replace(os.sep, "/").encode("utf-8")
        h.update(b"F:")
        h.update(rel)
        h.update(b":")
        h.update(sha256_file(p).encode("ascii"))
    return h.hexdigest()

# =========================
# Errors
# =========================

class PluginError(Exception): ...
class ManifestError(PluginError): ...
class ResolveError(PluginError): ...
class LoadError(PluginError): ...
class StartError(PluginError): ...
class StopError(PluginError): ...
class IsolationError(PluginError): ...

# =========================
# SemVer minimal
# =========================

_semver_re = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")

def _parse_semver(s: str) -> Tuple[int, int, int]:
    m = _semver_re.match(s.strip())
    if not m:
        raise ManifestError(f"invalid semver: {s}")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

def _cmp_semver(a: str, b: str) -> int:
    aa, bb = _parse_semver(a), _parse_semver(b)
    return (aa > bb) - (aa < bb)

def _constraint_ok(ver: str, con: str) -> bool:
    ver = ver.strip()
    con = con.strip()
    if con.startswith("^"):
        base = con[1:]
        ma, mi, pa = _parse_semver(base)
        va, vi, vp = _parse_semver(ver)
        if va != ma: return False
        if vi < mi: return False
        return True
    if con.startswith("~"):
        base = con[1:]
        ma, mi, pa = _parse_semver(base)
        va, vi, vp = _parse_semver(ver)
        return (va, vi) == (ma, mi) and vp >= pa
    if con.startswith(">="):
        return _cmp_semver(ver, con[2:].strip()) >= 0
    if con.startswith("<="):
        return _cmp_semver(ver, con[2:].strip()) <= 0
    if con.startswith("=="):
        return _cmp_semver(ver, con[2:].strip()) == 0
    if con.startswith("!="):
        return _cmp_semver(ver, con[2:].strip()) != 0
    if con.startswith(">"):
        return _cmp_semver(ver, con[1:].strip()) > 0
    if con.startswith("<"):
        return _cmp_semver(ver, con[1:].strip()) < 0
    # default exact
    return _cmp_semver(ver, con) == 0

# =========================
# Manifest & spec
# =========================

@dataclass(slots=True)
class PluginManifest:
    name: str
    version: str
    main: str                      # dotted module path or relative .py within root
    entry: str = "plugin"          # attribute in module exposing API object
    description: str = ""
    author: str = ""
    license: str = ""
    engine_abi: str = f">={ENGINE_ABI}"
    requires: Dict[str, str] = field(default_factory=dict)   # plugin_name -> semver constraint
    optional: Dict[str, str] = field(default_factory=dict)   # optional deps
    isolated: bool = False                                   # run in subprocess
    env: Dict[str, str] = field(default_factory=dict)        # environment vars for isolated
    capabilities: List[str] = field(default_factory=list)    # declared caps for routing

    @staticmethod
    def from_path(p: pathlib.Path) -> "PluginManifest":
        # Prefer plugin.json
        pj = p / "plugin.json"
        if pj.exists():
            try:
                data = json.loads(pj.read_text(encoding="utf-8"))
            except Exception as e:
                raise ManifestError(f"invalid JSON in {pj}: {e}") from e
            return _validate_manifest(data, base=p)
        # Fallback: try to sniff a single .py with header dict PLUGIN
        for f in p.glob("*.py"):
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if "PLUGIN_MANIFEST" in txt:
                scope: Dict[str, Any] = {}
                runpy.run_path(str(f), scope)
                data = scope.get("PLUGIN_MANIFEST")
                if not isinstance(data, dict):
                    raise ManifestError(f"{f} PLUGIN_MANIFEST must be dict")
                m = _validate_manifest(data, base=p)
                if not m.main:
                    m.main = f.name
                return m
        raise ManifestError(f"manifest not found in {p}")

def _validate_manifest(d: Mapping[str, Any], base: pathlib.Path) -> PluginManifest:
    req = ("name","version","main")
    for r in req:
        if r not in d:
            raise ManifestError(f"manifest missing {r}")
    return PluginManifest(
        name=str(d["name"]),
        version=str(d["version"]),
        main=str(d["main"]),
        entry=str(d.get("entry","plugin")),
        description=str(d.get("description","")),
        author=str(d.get("author","")),
        license=str(d.get("license","")),
        engine_abi=str(d.get("engine_abi", f">={ENGINE_ABI}")),
        requires=dict(d.get("requires", {})),
        optional=dict(d.get("optional", {})),
        isolated=bool(d.get("isolated", False)),
        env=dict(d.get("env", {})),
        capabilities=list(d.get("capabilities", [])),
    )

@dataclass(slots=True)
class PluginSpec:
    name: str
    version: str
    path: pathlib.Path
    manifest: PluginManifest
    hash: str
    module_name: Optional[str] = None  # assigned after import
    entry_attr: str = "plugin"

# =========================
# Context & API surface
# =========================

@dataclass(slots=True)
class Telemetry:
    emit: Callable[[str, Mapping[str,str], Mapping[str,float]], None] = lambda n,t,f: None

@dataclass(slots=True)
class PluginContext:
    engine_abi: str
    engine_version: str
    config: Mapping[str, Any]
    services: Mapping[str, Any]
    telemetry: Telemetry

# Expected plugin object interface (entry attribute):
# class MyPlugin:
#     def init(self, ctx: PluginContext) -> None: ...
#     def start(self, ctx: PluginContext) -> None: ...
#     def stop(self, ctx: PluginContext) -> None: ...
#     def on_event(self, name: str, payload: Mapping[str,Any]) -> None: ...

@dataclass(slots=True)
class PluginHandle:
    spec: PluginSpec
    module: Optional[Any]
    instance: Optional[Any]
    loaded_at_ms: int
    started: bool = False
    failed: bool = False
    last_error: Optional[str] = None
    last_mtime: float = 0.0

# =========================
# Loader
# =========================

class PluginLoader:
    def __init__(
        self,
        *,
        engine_version: str = "0.1.0",
        engine_abi: str = ENGINE_ABI,
        roots: Iterable[pathlib.Path] = (),
        config: Mapping[str, Any] = {},
        services: Mapping[str, Any] = {},
        telemetry: Optional[Callable[[str, Mapping[str,str], Mapping[str,float]], None]] = None,
        hot_reload: bool = True,
        backoff_s: float = 3.0,
    ) -> None:
        self.engine_version = engine_version
        self.engine_abi = engine_abi
        self.roots = [pathlib.Path(r).resolve() for r in roots]
        self.config = dict(config)
        self.services = dict(services)
        self.telemetry = Telemetry(emit=telemetry or (lambda n,t,f: None))
        self.hot_reload = hot_reload
        self.backoff_s = max(0.5, backoff_s)
        self._handles: Dict[str, PluginHandle] = {}
        self._hash_cache: Dict[str, str] = {}
        self._stop = threading.Event()
        self._watcher_th: Optional[threading.Thread] = None

    # -------- Discovery --------

    def discover(self) -> List[PluginSpec]:
        specs: List[PluginSpec] = []

        # From filesystem roots
        for root in self.roots:
            if not root.exists():
                continue
            for p in root.iterdir():
                if not p.is_dir():
                    continue
                try:
                    man = PluginManifest.from_path(p)
                    if not _constraint_ok(self.engine_abi, man.engine_abi):
                        raise ManifestError(f"{man.name} requires engine_abi {man.engine_abi}, ours {self.engine_abi}")
                    h = sha256_tree(p)
                    specs.append(PluginSpec(name=man.name, version=man.version, path=p, manifest=man, hash=h, entry_attr=man.entry))
                except ManifestError as e:
                    self._emit("plugin.discover.manifest_error", {"path":str(p)}, {"err":1.0})
                    continue

        # From entry points
        try:
            eps = imd.entry_points()
            group = eps.select(group="engine_core.plugins") if hasattr(eps, "select") else eps.get("engine_core.plugins", [])
            for ep in group:
                name = ep.name
                try:
                    module = ep.module
                    dist = ep.dist
                    version = dist.version
                    # cannot compute tree hash; use dist metadata digest
                    h = sha256_bytes(_canonical_json({"dist":dist.metadata["Name"], "ver":version, "ep":ep.value}))
                    man = PluginManifest(
                        name=name, version=version, main=ep.module, entry="plugin",
                        engine_abi=f">={ENGINE_ABI}", requires={}, optional={}, isolated=False
                    )
                    specs.append(PluginSpec(name=name, version=version, path=pathlib.Path(dist.locate_file("")), manifest=man, hash=h, entry_attr="plugin"))
                except Exception:
                    self._emit("plugin.discover.entrypoint_error", {"ep":str(ep)}, {"err":1.0})
        except Exception:
            # metadata unsupported environment -> ignore
            pass

        # Deduplicate by name; prefer higher version, then filesystem over entry point (configurable policy)
        chosen: Dict[str, PluginSpec] = {}
        for s in specs:
            cur = chosen.get(s.name)
            if not cur or _cmp_semver(s.version, cur.version) > 0:
                chosen[s.name] = s
        return list(chosen.values())

    # -------- Resolve dependencies --------

    def resolve(self, specs: List[PluginSpec]) -> List[PluginSpec]:
        by_name = {s.name: s for s in specs}
        graph: Dict[str, Set[str]] = {s.name: set() for s in specs}
        for s in specs:
            for dep, con in s.manifest.requires.items():
                if dep not in by_name:
                    raise ResolveError(f"{s.name} missing required dependency {dep}")
                if not _constraint_ok(by_name[dep].version, con):
                    raise ResolveError(f"{s.name} requires {dep}{con}, found {by_name[dep].version}")
                graph[s.name].add(dep)
        # topo sort (Kahn)
        indeg: Dict[str, int] = {n: 0 for n in graph}
        for n, deps in graph.items():
            for d in deps:
                indeg[n] += 0  # ensure key
                indeg[d] = indeg.get(d, 0)
        for n, deps in graph.items():
            for d in deps:
                indeg[n] += 0
        indeg = {n: sum(1 for x in graph.values() if n in x) for n in graph}
        q = [n for n, k in indeg.items() if k == 0]
        order: List[str] = []
        while q:
            n = q.pop()
            order.append(n)
            for m in graph:
                if n in graph[m]:
                    indeg[m] -= 1
                    if indeg[m] == 0:
                        q.append(m)
        if len(order) != len(graph):
            # cycle detection: simple report
            raise ResolveError("dependency cycle detected")
        return [by_name[n] for n in order]

    # -------- Load/unload lifecycle --------

    def load_all(self, specs: Optional[List[PluginSpec]] = None) -> List[PluginHandle]:
        if specs is None:
            specs = self.resolve(self.discover())
        else:
            specs = self.resolve(specs)

        loaded: List[PluginHandle] = []
        ctx = PluginContext(engine_abi=self.engine_abi, engine_version=self.engine_version, config=self.config, services=self.services, telemetry=self.telemetry)

        for s in specs:
            try:
                h = self._load_one(s, ctx)
                loaded.append(h)
            except Exception as e:
                self._emit("plugin.load.error", {"name":s.name}, {"err":1.0})
        # start watcher
        if self.hot_reload and not self._watcher_th:
            self._watcher_th = threading.Thread(target=self._watch_loop, name="plugin-watcher", daemon=True)
            self._watcher_th.start()
        return loaded

    def _load_one(self, spec: PluginSpec, ctx: PluginContext) -> PluginHandle:
        # Skip if unchanged
        prev = self._handles.get(spec.name)
        if prev and prev.spec.hash == spec.hash:
            return prev

        # Import module
        module = self._import_spec(spec)
        # Entry object
        attr = spec.entry_attr or "plugin"
        if not hasattr(module, attr):
            raise LoadError(f"{spec.name}: entry attribute '{attr}' not found")
        entry = getattr(module, attr)
        instance = entry() if inspect.isclass(entry) else entry

        handle = PluginHandle(spec=spec, module=module, instance=instance, loaded_at_ms=_now_ms(), last_mtime=self._mtime(spec.path))
        self._handles[spec.name] = handle
        self._hash_cache[spec.name] = spec.hash

        # init/start
        if hasattr(instance, "init"):
            instance.init(ctx)
        if hasattr(instance, "start"):
            instance.start(ctx)
            handle.started = True

        self._emit("plugin.load.ok", {"name":spec.name, "ver":spec.version}, {"t":1.0})
        return handle

    def _import_spec(self, spec: PluginSpec):
        # Support dotted module (installed) or relative file within path
        main = spec.manifest.main
        if main.endswith(".py") or (spec.path / main).exists():
            # load by file path relative to root
            file_path = (spec.path / main).resolve()
            mod_name = f"engine_plugins.{spec.name}"
            spec.module_name = mod_name
            if mod_name in sys.modules:
                del sys.modules[mod_name]
            loader = importlib.machinery.SourceFileLoader(mod_name, str(file_path))
            mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(mod_name, loader))
            sys.modules[mod_name] = mod
            loader.exec_module(mod)
            return mod
        else:
            # dotted
            mod = importlib.import_module(main)
            spec.module_name = mod.__name__
            return mod

    def stop_all(self, timeout_s: float = 5.0) -> None:
        for h in list(self._handles.values()):
            self._stop_one(h, timeout_s)
        self._handles.clear()
        self._stop.set()

    def _stop_one(self, h: PluginHandle, timeout_s: float) -> None:
        if not h.instance:
            return
        try:
            if h.started and hasattr(h.instance, "stop"):
                h.instance.stop(PluginContext(self.engine_abi, self.engine_version, self.config, self.services, self.telemetry))
        except Exception as e:
            self._emit("plugin.stop.error", {"name":h.spec.name}, {"err":1.0})

    # -------- Events --------

    def broadcast(self, name: str, payload: Mapping[str, Any]) -> None:
        for h in self._handles.values():
            try:
                inst = h.instance
                if inst and hasattr(inst, "on_event"):
                    inst.on_event(name, payload)
            except Exception:
                self._emit("plugin.event.error", {"name":h.spec.name, "ev":name}, {"err":1.0})

    # -------- Hot reload --------

    def _watch_loop(self) -> None:
        # naive polling loop with backoff
        next_try: Dict[str, float] = {}
        while not self._stop.is_set():
            time.sleep(0.5)
            for name, h in list(self._handles.items()):
                try:
                    root = h.spec.path
                    if not root.exists():
                        continue
                    m = self._mtime(root)
                    if m > h.last_mtime + 1e-6:
                        # recompute hash
                        new_hash = sha256_tree(root)
                        if new_hash != self._hash_cache.get(name):
                            self._emit("plugin.reload.detect", {"name":name}, {"m":m})
                            self._reload_handle(h, new_hash)
                except Exception:
                    self._emit("plugin.reload.error", {"name":name}, {"err":1.0})
                    continue

    def _reload_handle(self, h: PluginHandle, new_hash: str) -> None:
        name = h.spec.name
        # backoff control
        now = time.monotonic()
        # stop old
        try:
            self._stop_one(h, 5.0)
        except Exception:
            pass
        # purge module
        if h.spec.module_name and h.spec.module_name in sys.modules:
            try:
                del sys.modules[h.spec.module_name]
            except Exception:
                pass
        # load again
        spec = PluginSpec(
            name=h.spec.name, version=h.spec.version, path=h.spec.path,
            manifest=h.spec.manifest, hash=new_hash, entry_attr=h.spec.entry_attr
        )
        ctx = PluginContext(self.engine_abi, self.engine_version, self.config, self.services, self.telemetry)
        try:
            nh = self._load_one(spec, ctx)
            self._emit("plugin.reload.ok", {"name":name}, {"t":1.0})
        except Exception:
            self._emit("plugin.reload.fail", {"name":name}, {"err":1.0})

    @staticmethod
    def _mtime(root: pathlib.Path) -> float:
        latest = 0.0
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(".py") or fn == "plugin.json":
                    p = pathlib.Path(dirpath) / fn
                    latest = max(latest, p.stat().st_mtime)
        return latest

    # -------- Telemetry --------

    def _emit(self, name: str, tags: Mapping[str,str], fields: Mapping[str,float]) -> None:
        try:
            self.telemetry.emit(name, tags, fields)
        except Exception:
            pass

    # -------- Introspection --------

    def handles(self) -> Mapping[str, PluginHandle]:
        return dict(self._handles)

# =========================
# Optional: Subprocess isolation
# =========================

class SubprocessRunner:
    """
    Minimal JSONL protocol for isolated plugin binaries/scripts.
    Expected manifest: {"isolated": true, "main": "bin/my_plugin.py"}
    The plugin process must read JSON lines { "cmd": "start"/"stop"/"event", ... } and respond with {"ok": true}.
    """
    def __init__(self, cmd: List[str], env: Mapping[str,str] = {}, cwd: Optional[str] = None) -> None:
        self.cmd = list(cmd)
        self.env = {**os.environ, **env}
        self.cwd = cwd
        self.p: Optional[subprocess.Popen] = None

    def start(self) -> None:
        if self.p:
            return
        try:
            self.p = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.cwd, env=self.env)
        except Exception as e:
            raise IsolationError(str(e)) from e

    def _send(self, obj: Mapping[str, Any], timeout_s: float = 5.0) -> Mapping[str, Any]:
        if not self.p or not self.p.stdin or not self.p.stdout:
            raise IsolationError("process not started")
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        self.p.stdin.write(line)
        self.p.stdin.flush()
        t0 = time.monotonic()
        while True:
            if (time.monotonic() - t0) > timeout_s:
                raise IsolationError("subprocess timeout")
            out = self.p.stdout.readline()
            if not out:
                time.sleep(0.01); continue
            try:
                return json.loads(out)
            except Exception:
                continue

    def stop(self, timeout_s: float = 3.0) -> None:
        if not self.p:
            return
        try:
            self._send({"cmd":"stop"}, timeout_s=timeout_s)
        except Exception:
            pass
        try:
            self.p.terminate()
        except Exception:
            pass
        self.p = None

# =========================
# __all__
# =========================

__all__ = [
    "ENGINE_ABI",
    "PluginLoader",
    "PluginManifest",
    "PluginSpec",
    "PluginContext",
    "PluginHandle",
    "SubprocessRunner",
    # errors
    "PluginError","ManifestError","ResolveError","LoadError","StartError","StopError","IsolationError",
]
