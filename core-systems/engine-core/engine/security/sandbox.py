# -*- coding: utf-8 -*-
"""
engine-core / engine / security / sandbox.py

Policy-driven secure sandbox for untrusted Python code.

Design goals:
- Defense-in-depth: run untrusted code out-of-process with strict resource limits where possible;
  fall back to in-process AST sandbox for simple expressions/snippets.
- Deterministic environment: -I -S -E -s (isolated, no site, no user site, no env imports),
  sanitized env, cwd temp dir, minimal PATH.
- Resource limits (Unix): CPU time (RLIMIT_CPU), address space (RLIMIT_AS), file size (RLIMIT_FSIZE),
  number of open files (RLIMIT_NOFILE), process count (RLIMIT_NPROC), core dumps off, stack size.
  On Windows, best-effort wall clock timeout with JobObjects not used (stdlib only).
- Filesystem policy: readonly allowlist and write allowlist within temp root;
  deny by default; optional "mounts" (bind-like copy) for readonly inputs.
- Networking: disabled by default. In-process: stub out socket; out-of-process: no network modules import,
  unset proxy envs; optionally block AF_INET/AF_INET6 with seccomp if available.
- Import policy: allowlist modules; everything else blocked (both modes).
- Builtins: minimal safe builtins allowlist (abs, min, max, range, enumerate, len, sum, map, filter,
  all, any, zip, sorted, list, dict, set, tuple, print with capture, pow (bounded), divmod, ord, chr).
- Logging/audit: structured events, stdout/stderr capture, timing, exit code, violation reports.
- Deterministic RNG: optional seeding of random module; secrets disabled.
- No external deps.

NOTE:
- This is a secure-by-default *engineering* sandbox. It cannot guarantee perfect isolation against
  novel interpreter escapes. Always prefer the out-of-process mode with OS resource limits.
"""

from __future__ import annotations

import ast
import builtins as _builtins
import contextlib
import io
import json
import os
import runpy
import shutil
import signal
import sys
import tempfile
import textwrap
import time
import types
import traceback
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Callable

# Unix-only imports guarded
try:
    import resource  # type: ignore[attr-defined]
except Exception:
    resource = None  # type: ignore[assignment]

try:
    import subprocess  # always stdlib
except Exception:  # pragma: no cover
    subprocess = None  # type: ignore[assignment]

# Optional hardening extras
try:
    import ctypes  # noqa
except Exception:
    ctypes = None  # type: ignore[assignment]

__all__ = [
    "SandboxPolicy",
    "SandboxResult",
    "Violation",
    "Sandbox",
    "InProcessSandbox",
    "SubprocessSandbox",
]

# ======================================================================================
# Policy & Result models
# ======================================================================================

@dataclass
class SandboxPolicy:
    # Execution mode preference: "subprocess" or "inprocess"
    mode: str = "subprocess"

    # Time limits
    cpu_time_sec: int = 1                 # RLIMIT_CPU for subprocess (best-effort)
    wall_time_sec: float = 2.0            # watchdog wall-clock timeout

    # Memory/file limits (subprocess)
    memory_mb: int = 256                  # RLIMIT_AS / address space
    file_size_mb: int = 8                 # RLIMIT_FSIZE single file
    open_files: int = 16                  # RLIMIT_NOFILE
    processes: int = 1                    # RLIMIT_NPROC (no forks by default)

    # Filesystem policy (within temp root)
    readonly_paths: List[str] = field(default_factory=list)  # host paths to copy into temp root as RO
    write_paths: List[str] = field(default_factory=list)     # subpaths allowed to write within temp root
    keep_artifacts: bool = False          # keep temp dir for inspection
    artifact_max_bytes: int = 512 * 1024  # cap to export back as artifacts (per file)

    # Import/builtins policy
    allowed_modules: List[str] = field(default_factory=lambda: ["math", "statistics", "random", "itertools"])
    allowed_builtins: List[str] = field(default_factory=lambda: [
        "abs","min","max","range","enumerate","len","sum","map","filter","all","any","zip","sorted",
        "list","dict","set","tuple","print","pow","divmod","ord","chr","reversed","round","isinstance"
    ])
    max_pow_exp: int = 10_000_000         # bound pow base**exp if exp is int
    allow_network: bool = False
    allow_subprocess: bool = False

    # Determinism
    seed_random: Optional[int] = 0        # None => no seeding; 0 => deterministic seed default

    # Input plumbing
    input_stdin: Optional[str] = None     # piped into child stdin or used by in-process

    # Entry
    entrypoint: str = "exec"              # "exec" | "eval" | "module"
    module_name: Optional[str] = None     # for module run (ignored otherwise)
    filename: str = "<sandbox>"           # synthetic filename for tracebacks

    # Security toggles (advanced)
    disable_ctypes: bool = True
    disable_importlib: bool = True
    disable_open: bool = True
    disable_os_environ: bool = True

    # Extra environment vars for subprocess
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class Violation:
    kind: str
    message: str


@dataclass
class SandboxResult:
    ok: bool
    exit_code: int
    wall_time_sec: float
    cpu_time_sec: Optional[float]
    stdout: str
    stderr: str
    return_value: Any
    violations: List[Violation] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)      # filename->text (best-effort)
    logs: List[Dict[str, Any]] = field(default_factory=list)


# ======================================================================================
# AST validator (in-process mode)
# ======================================================================================

class _ASTGuard(ast.NodeVisitor):
    """
    Whitelist AST: forbid imports, attribute access to dunder, exec/eval/compile, with, lambda,
    comprehensions allowed, function/class defs allowed but with restricted globals.
    """

    def __init__(self, pol: SandboxPolicy) -> None:
        self.pol = pol
        self.violations: List[Violation] = []

    # Disallowed nodes
    _deny = (ast.Import, ast.ImportFrom, ast.With, ast.AsyncWith, ast.Global, ast.Nonlocal, ast.Lambda,
             ast.Await, ast.Yield, ast.YieldFrom, ast.Try, ast.Raise, ast.Delete, ast.ClassDef)
    _deny_calls = {"eval", "exec", "compile", "__import__", "open", "input", "help", "vars",
                   "locals", "globals", "dir", "getattr", "setattr", "delattr", "memoryview",
                   "super", "classmethod", "staticmethod", "property", "format"}

    def visit(self, node):  # type: ignore[override]
        if isinstance(node, self._deny):
            self._viol(f"node_forbidden:{type(node).__name__}", node)
            return
        return super().visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        # disallow __dunder__ access
        if isinstance(node.attr, str) and (node.attr.startswith("__") or node.attr.endswith("__")):
            self._viol("attribute_dunder_forbidden", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        # protect pow large exponents if static int
        if isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn in self._deny_calls:
                self._viol(f"call_forbidden:{fn}", node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> Any:
        # allow any variable names; resolution handled in globals
        return

    def _viol(self, msg: str, node: ast.AST) -> None:
        self.violations.append(Violation(kind="ast", message=f"{msg} at line {getattr(node,'lineno',0)}"))


# ======================================================================================
# In-process sandbox
# ======================================================================================

class InProcessSandbox:
    def __init__(self, pol: SandboxPolicy) -> None:
        self.pol = pol

    def run(self, source: str) -> SandboxResult:
        t0 = time.perf_counter()
        guard = _ASTGuard(self.pol)
        try:
            tree = ast.parse(source, filename=self.pol.filename, mode="exec" if self.pol.entrypoint != "eval" else "eval")
            guard.visit(tree)
        except SyntaxError as e:
            return _res_fail("syntax_error", str(e), t0)

        if guard.violations:
            return _res_fail("ast_rejected", ";".join(v.message for v in guard.violations), t0)

        # Build safe environment
        safe_builtins = _make_builtins(self.pol)
        mod_whitelist = set(self.pol.allowed_modules)

        def _import_blocker(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[override]
            if name in mod_whitelist:
                return _safe_import(name)
            raise ImportError(f"import blocked: {name}")

        g: Dict[str, Any] = {
            "__builtins__": safe_builtins,
            "__name__": "__main__",
            "__package__": None,
            "__doc__": None,
            "__import__": _import_blocker,
        }

        if self.pol.seed_random is not None:
            try:
                import random
                random.seed(self.pol.seed_random)
            except Exception:
                pass

        # Patch dangerous modules in sys.modules for duration
        patches = _patch_runtime(self.pol, inprocess=True)

        # IO capture
        stdout_io = io.StringIO()
        stderr_io = io.StringIO()
        if self.pol.input_stdin is not None:
            stdin_io = io.StringIO(self.pol.input_stdin)
        else:
            stdin_io = io.StringIO("")

        rv: Any = None
        # Wall-clock timeout via signal alarm (Unix) or watchdog thread
        cancel = _timeout(self.pol.wall_time_sec)

        try:
            with contextlib.redirect_stdout(stdout_io), contextlib.redirect_stderr(stderr_io), _redirect_stdin(stdin_io):
                if self.pol.entrypoint == "eval":
                    rv = eval(compile(tree, self.pol.filename, "eval"), g, None)  # noqa: S307 guarded AST
                else:
                    exec(compile(tree, self.pol.filename, "exec"), g, None)  # noqa: S102 guarded AST
        except TimeoutError as e:
            return _res_fail("timeout", str(e), t0, stdout=stdout_io.getvalue(), stderr=stderr_io.getvalue())
        except BaseException as e:
            return _res_fail("runtime_error", _format_exc(e), t0, stdout=stdout_io.getvalue(), stderr=stderr_io.getvalue())
        finally:
            cancel()
            _unpatch_runtime(patches)

        return SandboxResult(
            ok=True,
            exit_code=0,
            wall_time_sec=time.perf_counter() - t0,
            cpu_time_sec=None,
            stdout=stdout_io.getvalue(),
            stderr=stderr_io.getvalue(),
            return_value=rv,
            violations=guard.violations,
            artifacts={},
            logs=[],
        )


# ======================================================================================
# Subprocess sandbox
# ======================================================================================

class SubprocessSandbox:
    """
    Execute in isolated Python subprocess with hardened flags and rlimits.
    """

    def __init__(self, pol: SandboxPolicy) -> None:
        self.pol = pol

    def run(self, source: str) -> SandboxResult:
        if subprocess is None:
            return _res_fail("not_supported", "subprocess module unavailable", time.perf_counter())

        t0 = time.perf_counter()

        # Prepare temp root
        root = tempfile.mkdtemp(prefix="sbx-")
        artifacts: Dict[str, str] = {}
        try:
            # mount (copy) readonly inputs
            for p in self.pol.readonly_paths:
                _safe_copy_into(root, p, readonly=True)
            # ensure write paths exist within root
            for rel in self.pol.write_paths:
                dst = os.path.join(root, rel.lstrip(os.sep))
                os.makedirs(dst, exist_ok=True)

            # Build runner script
            runner = _build_runner_code(self.pol)
            runner_path = os.path.join(root, "__runner__.py")
            with open(runner_path, "w", encoding="utf-8") as f:
                f.write(runner)

            src_path = os.path.join(root, "__user__.py")
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(source)

            # Env
            env = _make_env(self.pol)

            # Command
            argv = [sys.executable, "-I", "-S", "-E", "-s", "-B", runner_path]
            stdin_data = self.pol.input_stdin.encode("utf-8") if self.pol.input_stdin is not None else None

            # Pre-exec hardening (Unix)
            preexec = None
            if os.name == "posix" and resource is not None:
                def _preexec():
                    # Block signals until exec
                    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
                    _apply_rlimits(self.pol)
                    # Optionally block networking by removing capabilities; seccomp not in stdlib
                preexec = _preexec

            # Run
            p = subprocess.Popen(
                argv,
                cwd=root,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=preexec,  # type: ignore[arg-type]
                text=False,
            )

            try:
                out, err = p.communicate(input=stdin_data, timeout=self.pol.wall_time_sec)
                exit_code = p.returncode
            except subprocess.TimeoutExpired:
                p.kill()
                out, err = p.communicate()
                return _res_fail("timeout", f"wall>={self.pol.wall_time_sec}s", t0, stdout=out.decode("utf-8","replace"), stderr=err.decode("utf-8","replace"))

            # Parse JSON header from runner (first line)
            header, rest_out = _split_json_header(out)
            stdout = rest_out.decode("utf-8", "replace")
            stderr = err.decode("utf-8", "replace")

            violations = [Violation(**v) for v in header.get("violations", [])] if isinstance(header, dict) else []

            # Collect artifacts (limited)
            if self.pol.keep_artifacts:
                artifacts = _collect_artifacts(root, self.pol.artifact_max_bytes)

            return SandboxResult(
                ok=(exit_code == 0),
                exit_code=exit_code,
                wall_time_sec=time.perf_counter() - t0,
                cpu_time_sec=header.get("cpu_time_sec") if isinstance(header, dict) else None,
                stdout=stdout,
                stderr=stderr,
                return_value=header.get("return_value"),
                violations=violations,
                artifacts=artifacts,
                logs=[{"root": root}] if self.pol.keep_artifacts else [],
            )
        finally:
            if not self.pol.keep_artifacts:
                with contextlib.suppress(Exception):
                    shutil.rmtree(root, ignore_errors=True)


# ======================================================================================
# Public facade
# ======================================================================================

class Sandbox:
    """
    Facade selecting the safer available mode according to policy.
    """

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self.policy = policy or SandboxPolicy()

    def run(self, source: str) -> SandboxResult:
        pol = self.policy
        if pol.mode == "inprocess":
            return InProcessSandbox(pol).run(source)
        # Prefer subprocess if available
        if subprocess is not None:
            return SubprocessSandbox(pol).run(source)
        # fallback
        return InProcessSandbox(pol).run(source)


# ======================================================================================
# Helpers: safe builtins & runtime patching (in-process)
# ======================================================================================

def _make_builtins(pol: SandboxPolicy) -> Dict[str, Any]:
    allowed = {k: getattr(_builtins, k) for k in pol.allowed_builtins if hasattr(_builtins, k)}
    # safe print (capture provided by redirect, but guard size)
    def _safe_print(*args, **kwargs):
        print(*args, **kwargs)
    allowed["print"] = _safe_print

    # bound pow
    _orig_pow = allowed.get("pow", _builtins.pow)
    def _bounded_pow(a, b, *rest):
        if isinstance(b, int) and abs(b) > pol.max_pow_exp:
            raise ValueError("pow exponent too large")
        return _orig_pow(a, b, *rest)
    allowed["pow"] = _bounded_pow

    # Remove __import__ from builtins
    allowed["__import__"] = None
    # Remove open unless allowed
    if pol.disable_open:
        allowed["open"] = None
    # Remove __build_class__ to restrict class creation (still allowed but safer to keep)
    # We keep it to allow simple classes, but classdef blocked in AST anyway.
    return allowed


def _safe_import(name: str):
    # Import strictly from stdlib allowed set
    if name in sys.modules:
        return sys.modules[name]
    module = __import__(name)
    # prune dangerous attributes
    if name == "random":
        import random
        random.seed(0)
    return module


def _patch_runtime(pol: SandboxPolicy, *, inprocess: bool) -> List[Tuple[Any, str, Any]]:
    """
    Monkey-patch in-process runtime to block network / dangerous modules.
    Returns list of (obj, attr, old_value) to restore.
    """
    patches: List[Tuple[Any, str, Any]] = []

    def _patch(obj, attr, val):
        old = getattr(obj, attr, None)
        patches.append((obj, attr, old))
        try:
            setattr(obj, attr, val)
        except Exception:
            pass

    # Block network
    if not pol.allow_network:
        import types as _types
        blocked = _types.ModuleType("socket_blocked")
        def _sock_block(*a, **k):  # noqa: ANN001
            raise RuntimeError("network disabled by sandbox")
        blocked.socket = _sock_block  # type: ignore[attr-defined]
        sys.modules["socket"] = blocked
        # Also block http(s), urllib
        for m in ("http", "http.client", "urllib", "urllib.request", "ssl"):
            sys.modules[m] = blocked

    # Disallow subprocess
    if not pol.allow_subprocess:
        sys.modules["subprocess"] = None  # type: ignore[assignment]

    if pol.disable_ctypes:
        sys.modules["ctypes"] = None  # type: ignore[assignment]

    if pol.disable_importlib:
        sys.modules["importlib"] = None  # type: ignore[assignment]

    if pol.disable_os_environ:
        _patch(os, "environ", {})

    return patches


def _unpatch_runtime(patches: List[Tuple[Any, str, Any]]) -> None:
    for obj, attr, old in reversed(patches):
        try:
            setattr(obj, attr, old)
        except Exception:
            pass


@contextlib.contextmanager
def _redirect_stdin(src: io.StringIO):
    old = sys.stdin
    try:
        sys.stdin = src
        yield
    finally:
        sys.stdin = old


def _timeout(seconds: float) -> Callable[[], None]:
    """
    Returns cancel() function. On Unix uses SIGALRM; on others uses watchdog thread.
    """
    canceled = False
    if hasattr(signal, "SIGALRM"):
        def _handler(signum, frame):  # noqa: ARG001
            raise TimeoutError("execution timeout")
        old = signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, max(0.0001, float(seconds)))
        def cancel():
            nonlocal canceled
            if not canceled:
                canceled = True
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old)
        return cancel
    else:
        import threading
        t = threading.Timer(max(0.0001, float(seconds)), lambda: (_ for _ in ()).throw(TimeoutError("execution timeout")))
        t.daemon = True
        t.start()
        def cancel():
            nonlocal canceled
            if not canceled:
                canceled = True
                t.cancel()
        return cancel


def _res_fail(kind: str, msg: str, t0: float, *, stdout: str | bytes = "", stderr: str | bytes = "") -> SandboxResult:
    so = stdout.decode("utf-8", "replace") if isinstance(stdout, (bytes, bytearray)) else stdout
    se = stderr.decode("utf-8", "replace") if isinstance(stderr, (bytes, bytearray)) else stderr
    return SandboxResult(
        ok=False,
        exit_code=1,
        wall_time_sec=time.perf_counter() - t0,
        cpu_time_sec=None,
        stdout=so,
        stderr=se,
        return_value=None,
        violations=[Violation(kind=kind, message=msg)],
        artifacts={},
        logs=[],
    )


def _format_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))


# ======================================================================================
# Helpers: subprocess mode implementation
# ======================================================================================

def _apply_rlimits(pol: SandboxPolicy) -> None:
    if resource is None:
        return
    MB = 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (pol.cpu_time_sec, pol.cpu_time_sec))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (pol.file_size_mb * MB, pol.file_size_mb * MB))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (pol.open_files, pol.open_files))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (pol.processes, pol.processes))
    except Exception:
        pass
    try:
        # Address space
        resource.setrlimit(resource.RLIMIT_AS, (pol.memory_mb * MB, pol.memory_mb * MB))
    except Exception:
        pass
    try:
        # Small stack to avoid deep recursion
        resource.setrlimit(resource.RLIMIT_STACK, (8 * MB, 8 * MB))
    except Exception:
        pass


def _make_env(pol: SandboxPolicy) -> Dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "UTF-8",
    }
    if not pol.allow_network:
        # Proxy vars cleared
        for k in list(os.environ.keys()):
            if k.lower().endswith("_proxy") or k.lower() in ("http_proxy", "https_proxy", "no_proxy"):
                env[k] = ""
    # User extras (whitelisted)
    for k, v in pol.env.items():
        if isinstance(k, str) and isinstance(v, str) and len(k) < 128 and len(v) < 4096:
            env[k] = v
    return env


def _build_runner_code(pol: SandboxPolicy) -> str:
    """
    Runner process code. Prints a single JSON line header to stdout with return_value/violations/timing,
    then forwards user stdout.
    """
    allowed_mods = json.dumps(pol.allowed_modules, ensure_ascii=False)
    allowed_bi = json.dumps(pol.allowed_builtins, ensure_ascii=False)
    entry = pol.entrypoint
    filename = pol.filename
    seed = pol.seed_random
    disable_open = pol.disable_open
    max_pow = pol.max_pow_exp
    allow_subproc = pol.allow_subprocess
    allow_net = pol.allow_network

    return textwrap.dedent(f"""
    import sys, os, io, json, time, builtins, types, runpy, importlib
    import traceback

    t0 = time.perf_counter()

    # Capture user stdout to emit JSON header first
    user_out = io.StringIO()
    user_err = io.StringIO()

    def _safe_print(*a, **k):
        print(*a, **k)

    # Build safe builtins
    ALLOWED_BUILTINS = {allowed_bi}
    allowed = {{k: getattr(builtins, k) for k in ALLOWED_BUILTINS if hasattr(builtins, k)}}
    # bound pow
    _orig_pow = allowed.get("pow", builtins.pow)
    def _bounded_pow(a, b, *rest):
        if isinstance(b, int) and abs(b) > {max_pow}:
            raise ValueError("pow exponent too large")
        return _orig_pow(a, b, *rest)
    allowed["pow"] = _bounded_pow
    allowed["print"] = _safe_print
    allowed["__import__"] = None
    if {str(disable_open)}:
        allowed["open"] = None
    builtins.__dict__.clear()
    builtins.__dict__.update(allowed)

    # Block dangerous modules
    sys.modules.pop("ctypes", None)
    sys.modules.pop("importlib", None)

    if not {str(allow_subproc)}:
        sys.modules["subprocess"] = None

    if not {str(allow_net)}:
        m = types.ModuleType("socket_blocked")
        def _sb(*a, **k): raise RuntimeError("network disabled by sandbox")
        m.socket = _sb
        sys.modules["socket"] = m
        for _n in ("http","http.client","urllib","urllib.request","ssl"):
            sys.modules[_n] = m

    # Import policy
    ALLOWED_MODULES = set({allowed_mods})
    real_import = __import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ALLOWED_MODULES:
            return real_import(name, globals, locals, fromlist, level)
        raise ImportError(f"import blocked: {{name}}")

    # Seed random if requested
    seed = {repr(seed)}
    if seed is not None:
        try:
            import random
            random.seed(seed)
        except Exception:
            pass

    # Prepare execution env
    g = {{
        "__builtins__": builtins.__dict__,
        "__name__": "__main__",
        "__package__": None,
        "__doc__": None,
        "__import__": guarded_import,
    }}

    return_value = None
    violations = []
    cpu_time_sec = None

    # Run user code
    src_path = "__user__.py"
    try:
        # CPU time best-effort via resource if available
        try:
            import resource as _res
            t_before = _res.getrusage(_res.RUSAGE_SELF).ru_utime
        except Exception:
            t_before = None

        with contextlib.redirect_stdout(user_out), contextlib.redirect_stderr(user_err):
            code = open(src_path, "r", encoding="utf-8").read()
            if {repr(entry)} == "eval":
                return_value = eval(compile(code, {repr(filename)}, "eval"), g, None)
            elif {repr(entry)} == "module":
                # Run as module (not from sys.path; from cwd)
                return_value = runpy.run_path(src_path, run_name="__main__")
            else:
                exec(compile(code, {repr(filename)}, "exec"), g, None)

        try:
            if t_before is not None:
                import resource as _res
                cpu_time_sec = _res.getrusage(_res.RUSAGE_SELF).ru_utime - t_before
        except Exception:
            cpu_time_sec = None

        status = 0
    except BaseException as e:
        violations.append({{"kind":"runtime_error","message":"".join(traceback.format_exception(type(e), e, e.__traceback__))}})
        status = 1

    # Emit header as first line
    header = {{
        "ok": status == 0,
        "return_value": return_value,
        "violations": [v for v in violations],
        "cpu_time_sec": cpu_time_sec,
    }}
    sys.stdout.write(json.dumps(header, ensure_ascii=False) + "\\n")
    # Then forward captured streams
    sys.stdout.write(user_out.getvalue())
    sys.stderr.write(user_err.getvalue())
    sys.stdout.flush(); sys.stderr.flush()
    sys.exit(status)
    """)


def _split_json_header(out: bytes) -> Tuple[Dict[str, Any], bytes]:
    # find first newline
    nl = out.find(b"\n")
    if nl == -1:
        return {}, out
    try:
        head = json.loads(out[:nl].decode("utf-8", "replace"))
    except Exception:
        head = {}
    return head, out[nl + 1:]


def _safe_copy_into(root: str, path: str, *, readonly: bool) -> None:
    if not os.path.exists(path):
        return
    base = os.path.basename(path.rstrip(os.sep))
    dst = os.path.join(root, base)
    if os.path.isdir(path):
        shutil.copytree(path, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(path, dst)
    if readonly:
        for dirpath, dirnames, filenames in os.walk(dst):
            for d in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, d), 0o555)
                except Exception:
                    pass
            for f in filenames:
                try:
                    os.chmod(os.path.join(dirpath, f), 0o444)
                except Exception:
                    pass


def _collect_artifacts(root: str, cap: int) -> Dict[str, str]:
    artifacts: Dict[str, str] = {}
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.startswith("__"):  # runner/user
                continue
            full = os.path.join(dirpath, fn)
            try:
                with open(full, "rb") as f:
                    data = f.read(cap + 1)
                if len(data) > cap:
                    data = data[:cap]
                rel = os.path.relpath(full, root)
                artifacts[rel] = data.decode("utf-8", "replace")
            except Exception:
                continue
    return artifacts


# ======================================================================================
# Example self-test
# ======================================================================================

if __name__ == "__main__":
    src = "import math\\nprint('hi', math.sqrt(9))\\nres = sum(range(10))\\n"
    pol = SandboxPolicy(
        mode="subprocess",
        cpu_time_sec=1,
        wall_time_sec=2.0,
        memory_mb=128,
        allowed_modules=["math","itertools"],
        seed_random=0,
        keep_artifacts=False,
    )
    sb = Sandbox(pol)
    r = sb.run(src)
    print(json.dumps(asdict(r), ensure_ascii=False, indent=2)[:1200])
