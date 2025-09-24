# security-core/security/self_inhibitor/runtime_hooks.py
# Industrial self-inhibition runtime guards for Python using Audit Hooks (PEP 578)
# and resilient fallbacks. Stdlib-only.
#
# Features:
#  - System-wide audit hook with blocking ("block") or observation ("log") policy
#  - Guards for: network egress, subprocess, filesystem writes, dynamic code (eval/exec/compile), imports
#  - Allowlists for destinations, binaries, paths, modules
#  - Thread-safe counters, ring buffer of recent events, structured logs
#  - Per-thread/with-context temporary allowances
#  - Environment-based bootstrap: install_from_env()
#  - Health snapshot for /health endpoints
#
# IMPORTANT:
#  - sys.addaudithook is irreversible; this class supports "disabled" soft-flag to noop afterwards.
#  - Install as early as possible in process lifetime.

from __future__ import annotations

import functools
import ipaddress
import logging
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# -----------------------------
# Policy model
# -----------------------------

@dataclass(frozen=True)
class NetAllow:
    hosts: Set[str] = field(default_factory=set)           # exact hostnames (lowercase)
    nets: Set[ipaddress._BaseNetwork] = field(default_factory=set)  # ip_network objects
    ports: Set[int] = field(default_factory=set)           # allowed ports; empty = any
    allow_loopback: bool = True
    allow_unix: bool = True

@dataclass(frozen=True)
class FsAllow:
    write_dirs: Set[str] = field(default_factory=set)      # normalized absolute prefixes

@dataclass(frozen=True)
class SubprocAllow:
    exec_prefixes: Set[str] = field(default_factory=set)   # normalized abs prefixes
    allow_shell: bool = False
    require_abs_path: bool = True

@dataclass(frozen=True)
class ImportPolicy:
    blocked_modules: Set[str] = field(default_factory=set)
    allowed_modules: Optional[Set[str]] = None             # None = any except blocked

@dataclass(frozen=True)
class DynCodePolicy:
    block_eval_exec: bool = True
    block_compile: bool = False

@dataclass(frozen=True)
class Policy:
    mode: str = "block"  # "block" or "log"
    block_network: bool = True
    net_allow: NetAllow = NetAllow()
    block_subprocess: bool = True
    subproc_allow: SubprocAllow = SubprocAllow()
    block_fs_writes: bool = True
    fs_allow: FsAllow = FsAllow()
    block_imports: bool = False
    import_policy: ImportPolicy = ImportPolicy()
    dyn_code: DynCodePolicy = DynCodePolicy()
    hard_kill: bool = False  # if True, os._exit(180) on critical violations

# -----------------------------
# Utilities
# -----------------------------

def _norm_path(p: str) -> str:
    try:
        return os.path.realpath(os.path.abspath(p))
    except Exception:
        return os.path.abspath(p)

def _path_in_allowed(path: str, prefixes: Set[str]) -> bool:
    path = _norm_path(path)
    for pref in prefixes:
        if path.startswith(pref):
            return True
    return False

def _host_port_from_sockaddr(sa: Tuple[Any, ...]) -> Tuple[str, Optional[int]]:
    # sockaddr differs by family
    if not isinstance(sa, tuple):
        return ("", None)
    if len(sa) >= 2:
        return (str(sa[0]).lower(), int(sa[1]))
    return (str(sa[0]).lower(), None)

def _is_ip_in_nets(ip: str, nets: Set[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in nets)
    except Exception:
        return False

def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def _int_env(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v.strip())
    except Exception:
        return default

def _split_csv_env(name: str) -> List[str]:
    v = os.getenv(name)
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]

# -----------------------------
# SelfInhibitor
# -----------------------------

class SelfInhibitor:
    """
    Install an audit hook and defensive patches to block/observe risky operations.
    """

    _installed_once = False
    _instance: Optional["SelfInhibitor"] = None

    def __init__(self, policy: Policy, logger: Optional[logging.Logger] = None) -> None:
        self.policy = policy
        self.logger = logger or logging.getLogger("security.self_inhibitor")
        self.disabled = False

        # Stats
        self._lock = threading.RLock()
        self._counters: Dict[str, int] = {}
        self._recent: List[Tuple[float, str, Dict[str, Any]]] = []
        self._recent_limit = 256

        # Thread-local temporary allowances
        self._tls = threading.local()
        self._tls.net_allow: List[Tuple[str, Optional[int]]] = []
        self._tls.fs_allow: List[str] = []
        self._tls.subproc_allow: List[str] = []

        # Patches bookkeeping
        self._patched = False
        self._orig_open = None
        self._orig_popen = None
        self._orig_system = None
        self._orig_socket_connect = None

    # ---------- Public API ----------

    @classmethod
    def install_global(cls, policy: Policy, logger: Optional[logging.Logger] = None) -> "SelfInhibitor":
        """
        Install global singleton. Idempotent. Must be called early.
        """
        if cls._installed_once:
            return cls._instance  # type: ignore[return-value]
        inst = cls(policy, logger)
        inst._install_audit_hook()
        inst._install_patches()
        cls._installed_once = True
        cls._instance = inst
        return inst

    def disable(self) -> None:
        """
        Soft-disable checks (audit hook remains but returns fast).
        Useful for maintenance windows.
        """
        with self._lock:
            self.disabled = True

    def enable(self) -> None:
        with self._lock:
            self.disabled = False

    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "policy_mode": self.policy.mode,
                "disabled": self.disabled,
                "counters": dict(self._counters),
                "recent": list(self._recent),
            }

    # ---------- Context allowances ----------

    def allow_network(self, host: str, port: Optional[int] = None):
        """
        Temporarily allow network connect to (host, port) within the context.
        """
        class _Ctx:
            def __init__(ctx, outer: "SelfInhibitor"):
                ctx.outer = outer
            def __enter__(ctx):
                lst = getattr(ctx.outer._tls, "net_allow", [])
                lst.append((host.lower(), port))
                ctx.outer._tls.net_allow = lst
            def __exit__(ctx, exc_type, exc, tb):
                lst = ctx.outer._tls.net_allow
                lst.pop()
        return _Ctx(self)

    def allow_fs_write(self, path_prefix: str):
        class _Ctx:
            def __init__(ctx, outer: "SelfInhibitor"):
                ctx.outer = outer
                ctx.pref = _norm_path(path_prefix)
            def __enter__(ctx):
                lst = getattr(ctx.outer._tls, "fs_allow", [])
                lst.append(ctx.pref)
                ctx.outer._tls.fs_allow = lst
            def __exit__(ctx, exc_type, exc, tb):
                lst = ctx.outer._tls.fs_allow
                lst.pop()
        return _Ctx(self)

    def allow_subprocess(self, exec_prefix: str):
        class _Ctx:
            def __init__(ctx, outer: "SelfInhibitor"):
                ctx.outer = outer
                ctx.pref = _norm_path(exec_prefix)
            def __enter__(ctx):
                lst = getattr(ctx.outer._tls, "subproc_allow", [])
                lst.append(ctx.pref)
                ctx.outer._tls.subproc_allow = lst
            def __exit__(ctx, exc_type, exc, tb):
                lst = ctx.outer._tls.subproc_allow
                lst.pop()
        return _Ctx(self)

    # ---------- Internals: install ----------

    def _install_audit_hook(self) -> None:
        def hook(event: str, args: Tuple[Any, ...]) -> None:
            if self.disabled:
                return
            try:
                self._audit_dispatch(event, args)
            except PermissionError as e:
                self._record(event, {"blocked": True, "reason": str(e)})
                self._log_denied(event, str(e))
                if self.policy.hard_kill:
                    os._exit(180)
                raise
            except Exception as e:
                # Never break the process on hook error
                self._record(event, {"error": repr(e)})
                self.logger.exception("self_inhibitor_hook_error", exc_info=e)

        sys.addaudithook(hook)

    def _install_patches(self) -> None:
        if self._patched:
            return
        # builtins.open (write intents)
        import builtins, subprocess
        self._orig_open = builtins.open
        self._orig_popen = subprocess.Popen
        self._orig_system = os.system
        self._orig_socket_connect = socket.socket.connect

        @functools.wraps(self._orig_open)
        def guarded_open(file, mode="r", *a, **kw):
            # Allow read-only; inspect write flags
            if self._should_block_open(file, mode):
                self._deny("open", f"write denied: {file} mode={mode}")
            return self._orig_open(file, mode, *a, **kw)

        @functools.wraps(self._orig_popen)
        def guarded_popen(*p_args, **p_kw):
            if self._should_block_subprocess(p_args, p_kw):
                self._deny("subprocess.Popen", f"spawn denied: args={p_args[0]!r}")
            return self._orig_popen(*p_args, **p_kw)

        @functools.wraps(self._orig_system)
        def guarded_system(cmd):
            if self._should_block_system(cmd):
                self._deny("os.system", f"system denied: {cmd!r}")
            return self._orig_system(cmd)

        @functools.wraps(self._orig_socket_connect)
        def guarded_connect(sock: socket.socket, address):
            if self._should_block_connect(sock, address):
                self._deny("socket.connect", f"egress denied: {address!r}")
            return self._orig_socket_connect(sock, address)

        import builtins as _b
        _b.open = guarded_open
        import subprocess as _sp
        _sp.Popen = guarded_popen
        os.system = guarded_system
        socket.socket.connect = guarded_connect

        self._patched = True

    # ---------- Internals: audit handling ----------

    def _audit_dispatch(self, event: str, args: Tuple[Any, ...]) -> None:
        # Increment counters for observed events of interest
        if event in ("open", "subprocess.Popen", "os.system", "socket.connect",
                     "compile", "exec", "import", "ctypes.dlopen"):
            self._bump(event)

        # Enforce per type
        if event == "open":
            path, mode, _ = args[0], (args[1] if len(args) > 1 else "r"), None
            if self._should_block_open(path, mode):
                self._deny(event, f"write denied: {path} mode={mode}")
        elif event == "subprocess.Popen":
            if self._should_block_subprocess(args, {}):
                self._deny(event, f"spawn denied: args={args!r}")
        elif event == "os.system":
            cmd = args[0] if args else ""
            if self._should_block_system(cmd):
                self._deny(event, f"system denied: {cmd!r}")
        elif event == "socket.connect":
            sock, address = args[0], args[1]
            if self._should_block_connect(sock, address):
                self._deny(event, f"egress denied: {address!r}")
        elif event == "compile" and self.policy.dyn_code.block_compile:
            self._deny(event, "dynamic compile denied")
        elif event == "exec" and self.policy.dyn_code.block_eval_exec:
            self._deny(event, "dynamic exec/eval denied")
        elif event == "import" and self.policy.block_imports:
            modname = str(args[0]).split(".")[0].lower() if args else ""
            if not self._is_import_allowed(modname):
                self._deny(event, f"import denied: {modname}")
        # other events only logged by counters / recent ring

    def _bump(self, event: str) -> None:
        with self._lock:
            self._counters[event] = self._counters.get(event, 0) + 1

    def _record(self, event: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._recent.append((time.time(), event, payload))
            if len(self._recent) > self._recent_limit:
                self._recent = self._recent[-self._recent_limit:]

    def _log_denied(self, event: str, reason: str) -> None:
        self.logger.warning("self_inhibitor_denied", extra={"event": event, "reason": reason})

    def _deny(self, event: str, reason: str) -> None:
        self._record(event, {"blocked": True, "reason": reason})
        if self.policy.mode == "log":
            self._log_denied(event, reason)
            return
        raise PermissionError(reason)

    # ---------- Checkers ----------

    def _should_block_open(self, path: Any, mode: Any) -> bool:
        if not self.policy.block_fs_writes:
            return False
        try:
            path_s = str(path)
        except Exception:
            return True
        m = str(mode or "r")
        write_intent = any(ch in m for ch in ("w", "a", "+", "x"))
        if not write_intent:
            return False
        # thread-local allowance
        for pref in getattr(self._tls, "fs_allow", []):
            if _path_in_allowed(path_s, {pref}):
                return False
        allowed = set(self.policy.fs_allow.write_dirs)
        # Always allow typical ephemeral dirs if explicitly whitelisted by policy
        return not _path_in_allowed(path_s, allowed)

    def _should_block_subprocess(self, p_args: Tuple[Any, ...], p_kw: Dict[str, Any]) -> bool:
        if not self.policy.block_subprocess:
            return False
        # Extract executable path
        try:
            argv = p_args[0]
        except Exception:
            return True
        shell = bool(p_kw.get("shell", False))
        if shell and not self.policy.subproc_allow.allow_shell:
            return True
        if isinstance(argv, (list, tuple)) and argv:
            exe = str(argv[0])
        else:
            exe = str(argv)
        if self.policy.subproc_allow.require_abs_path and not os.path.isabs(exe):
            return True
        exe_n = _norm_path(exe)
        # thread-local allowance
        for pref in getattr(self._tls, "subproc_allow", []):
            if exe_n.startswith(pref):
                return False
        # policy allow
        for pref in self.policy.subproc_allow.exec_prefixes:
            if exe_n.startswith(pref):
                return False
        return True

    def _should_block_system(self, cmd: str) -> bool:
        if not self.policy.block_subprocess:
            return False
        # os.system is shell=True by definition
        if not self.policy.subproc_allow.allow_shell:
            return True
        return False

    def _should_block_connect(self, sock: socket.socket, address: Any) -> bool:
        if not self.policy.block_network:
            return False
        try:
            fam = sock.family
        except Exception:
            fam = socket.AF_INET
        # UNIX sockets
        if fam == socket.AF_UNIX:
            return not self.policy.net_allow.allow_unix
        # (host, port)
        host, port = _host_port_from_sockaddr(address)
        # thread-local allowance
        for h, p in getattr(self._tls, "net_allow", []):
            if (not h or h == host) and (p is None or p == port):
                return False
        # loopback
        if self.policy.net_allow.allow_loopback:
            try:
                ip = socket.gethostbyname(host)
                if ip.startswith("127.") or ip == "::1":
                    return False
            except Exception:
                pass
        # allowed hosts
        if host in self.policy.net_allow.hosts:
            if not self.policy.net_allow.ports or (port in self.policy.net_allow.ports):
                return False
        # allowed nets
        if _is_ip_in_nets(host, self.policy.net_allow.nets):
            if not self.policy.net_allow.ports or (port in self.policy.net_allow.ports):
                return False
        return True

    def _is_import_allowed(self, modname: str) -> bool:
        ipol = self.policy.import_policy
        if modname in ipol.blocked_modules:
            return False
        if ipol.allowed_modules is not None and modname not in ipol.allowed_modules:
            return False
        return True

# -----------------------------
# Env bootstrap
# -----------------------------

def _parse_net_allow() -> NetAllow:
    hosts = {h.lower() for h in _split_csv_env("SELF_INHIBITOR_ALLOW_NET_HOSTS")}
    nets_s = _split_csv_env("SELF_INHIBITOR_ALLOW_NET_NETS")
    nets: Set[ipaddress._BaseNetwork] = set()
    for n in nets_s:
        try:
            nets.add(ipaddress.ip_network(n, strict=False))
        except Exception:
            continue
    ports: Set[int] = set()
    for p in _split_csv_env("SELF_INHIBITOR_ALLOW_NET_PORTS"):
        try:
            ports.add(int(p))
        except Exception:
            pass
    return NetAllow(
        hosts=hosts,
        nets=nets,
        ports=ports,
        allow_loopback=_bool_env("SELF_INHIBITOR_ALLOW_LOOPBACK", True),
        allow_unix=_bool_env("SELF_INHIBITOR_ALLOW_UNIX", True),
    )

def _parse_fs_allow() -> FsAllow:
    dirs = {_norm_path(p) for p in _split_csv_env("SELF_INHIBITOR_ALLOW_WRITE_DIRS")}
    return FsAllow(write_dirs=dirs)

def _parse_subproc_allow() -> SubprocAllow:
    prefs = {_norm_path(p) for p in _split_csv_env("SELF_INHIBITOR_ALLOW_EXEC_PREFIXES")}
    return SubprocAllow(
        exec_prefixes=prefs,
        allow_shell=_bool_env("SELF_INHIBITOR_ALLOW_SHELL", False),
        require_abs_path=_bool_env("SELF_INHIBITOR_REQUIRE_ABS_EXEC", True),
    )

def _parse_import_policy() -> ImportPolicy:
    blocked = {m.strip().lower() for m in _split_csv_env("SELF_INHIBITOR_BLOCKED_MODULES")}
    allowed_env = _split_csv_env("SELF_INHIBITOR_ALLOWED_MODULES")
    allowed = {m.strip().lower() for m in allowed_env} if allowed_env else None
    return ImportPolicy(blocked_modules=blocked, allowed_modules=allowed)

def policy_from_env() -> Policy:
    return Policy(
        mode=os.getenv("SELF_INHIBITOR_MODE", "block").lower(),
        block_network=_bool_env("SELF_INHIBITOR_BLOCK_NET", True),
        net_allow=_parse_net_allow(),
        block_subprocess=_bool_env("SELF_INHIBITOR_BLOCK_SUBPROC", True),
        subproc_allow=_parse_subproc_allow(),
        block_fs_writes=_bool_env("SELF_INHIBITOR_BLOCK_FS", True),
        fs_allow=_parse_fs_allow(),
        block_imports=_bool_env("SELF_INHIBITOR_BLOCK_IMPORTS", False),
        import_policy=_parse_import_policy(),
        dyn_code=DynCodePolicy(
            block_eval_exec=_bool_env("SELF_INHIBITOR_BLOCK_DYNCODE", True),
            block_compile=_bool_env("SELF_INHIBITOR_BLOCK_COMPILE", False),
        ),
        hard_kill=_bool_env("SELF_INHIBITOR_HARD_KILL", False),
    )

def install_from_env(logger: Optional[logging.Logger] = None) -> SelfInhibitor:
    """
    Parse environment and install global inhibitor if SELF_INHIBITOR=1 (default yes).
    """
    enabled = _bool_env("SELF_INHIBITOR", True)
    policy = policy_from_env()
    logger = logger or logging.getLogger("security.self_inhibitor")
    if not enabled:
        inst = SelfInhibitor(policy, logger)
        inst.disable()
        return inst
    return SelfInhibitor.install_global(policy, logger)

# -----------------------------
# Example default policy builder
# -----------------------------

def default_tight_policy(app_data_dir: Optional[str] = None) -> Policy:
    """
    Secure-by-default policy:
      - Block egress except loopback/UNIX
      - Block subprocess entirely
      - Block FS writes except app_data_dir and /tmp
      - Block dynamic exec/eval
      - No import blocking by default
    """
    allow_dirs = set()
    if app_data_dir:
        allow_dirs.add(_norm_path(app_data_dir))
    # Allow tmp by default for ephemeral files
    for p in ("/tmp", os.getenv("TMPDIR", "/tmp")):
        if p:
            allow_dirs.add(_norm_path(p))
    return Policy(
        mode="block",
        block_network=True,
        net_allow=NetAllow(hosts=set(), nets=set(), ports=set(), allow_loopback=True, allow_unix=True),
        block_subprocess=True,
        subproc_allow=SubprocAllow(exec_prefixes=set(), allow_shell=False, require_abs_path=True),
        block_fs_writes=True,
        fs_allow=FsAllow(write_dirs=allow_dirs),
        block_imports=False,
        import_policy=ImportPolicy(),
        dyn_code=DynCodePolicy(block_eval_exec=True, block_compile=False),
        hard_kill=False,
    )

# -----------------------------
# Module init helper (optional)
# -----------------------------

# If you want automatic install based on env at import time, uncomment:
# _AUTO = os.getenv("SELF_INHIBITOR_AUTO", "0")
# if _AUTO in ("1", "true", "yes", "on"):
#     install_from_env()

# -----------------------------
# Minimal self-test (optional)
# -----------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pol = default_tight_policy()
    inh = SelfInhibitor.install_global(pol)

    # FS write denied outside /tmp
    try:
        open("/etc/secret", "w").write("x")  # noqa: P201
    except PermissionError as e:
        print("FS OK:", e)

    # Net connect denied (except loopback)
    try:
        s = socket.socket()
        s.connect(("example.com", 443))
    except PermissionError as e:
        print("NET OK:", e)

    # Subprocess denied
    import subprocess
    try:
        subprocess.Popen(["/bin/true"])
    except PermissionError as e:
        print("SUBPROC OK:", e)

    # Dyn code denied
    try:
        exec("print('x')")  # noqa: S102
    except PermissionError as e:
        print("EXEC OK:", e)

    print("HEALTH:", inh.health())
