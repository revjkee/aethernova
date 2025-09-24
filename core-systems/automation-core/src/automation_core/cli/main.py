# -*- coding: utf-8 -*-
"""
Industrial CLI entrypoint for automation-core.

Verified facts and references used in this file:
- argparse for building user-friendly CLIs and sub-commands (official docs).  # :contentReference[oaicite:0]{index=0}
- logging with hierarchical loggers (getLogger(__name__)) is idiomatic.       # :contentReference[oaicite:1]{index=1}
- subprocess.run is the recommended way to invoke subprocesses.               # :contentReference[oaicite:2]{index=2}
- importlib.metadata provides version() and entry_points() APIs.              # :contentReference[oaicite:3]{index=3}
- shutil.which discovers executables in PATH.                                 # :contentReference[oaicite:4]{index=4}
- signal.signal allows graceful SIGINT/SIGTERM handling.                      # :contentReference[oaicite:5]{index=5}

Unverified and environment-specific notes:
- Location of scripts/sbom.sh is inferred relative to project layout; if absent,
  the CLI falls back to syft when available. I cannot verify your exact layout.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from importlib import metadata as importlib_metadata  # stdlib importlib.metadata  # :contentReference[oaicite:6]{index=6}
from shutil import which  # stdlib shutil.which  # :contentReference[oaicite:7]{index=7}
from subprocess import CalledProcessError, CompletedProcess, run  # stdlib subprocess.run  # :contentReference[oaicite:8]{index=8}

LOG = logging.getLogger(__name__)

# ------------------------------- constants -------------------------------

APP_PKG_NAME = "automation-core"
DEFAULT_LOG_LEVEL = "INFO"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_EXEC_FAILED = 4
EXIT_INTERRUPTED = 130  # conventional for SIGINT


# ------------------------------- utils -----------------------------------

class JsonFormatter(logging.Formatter):
    """Minimal JSON formatter for logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _setup_logging(level: str, json_mode: bool) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(root.level)
    if json_mode:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)


# Cooperative shutdown flag
class _ShutdownFlag:
    _tripped: bool = False

    @classmethod
    def trip(cls) -> None:
        cls._tripped = True

    @classmethod
    def is_set(cls) -> bool:
        return cls._tripped


def _install_signal_handlers() -> None:
    # SIGINT -> KeyboardInterrupt; we additionally mark a flag for long-running ops.  # :contentReference[oaicite:9]{index=9}
    def _handler(signum, frame):
        LOG.warning("Received signal %s; shutting down gracefully", signum)
        _ShutdownFlag.trip()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handler)


def _package_version() -> str:
    # importlib.metadata.version may raise PackageNotFoundError if not installed.  # :contentReference[oaicite:10]{index=10}
    try:
        return importlib_metadata.version(APP_PKG_NAME)
    except importlib_metadata.PackageNotFoundError:
        # Try module attribute fallback
        try:
            from automation_core import __version__  # type: ignore
            return str(__version__)
        except Exception:
            return "0.0.0+unknown"


def _find_repo_root_from_here() -> Optional[Path]:
    # Attempt to locate project root (folder that may contain /scripts and /src).
    here = Path(__file__).resolve()
    for p in [here] + list(here.parents):
        if (p / "scripts").exists() or (p.parent / "scripts").exists():
            return p if (p / "scripts").exists() else p.parent
    return None


def _find_sbom_script() -> Optional[Path]:
    # 1) ENV hint
    env_hint = os.environ.get("AUTOMATION_CORE_ROOT")
    if env_hint:
        candidate = Path(env_hint) / "scripts" / "sbom.sh"
        if candidate.is_file():
            return candidate

    # 2) relative to repo root guess
    root = _find_repo_root_from_here()
    if root:
        for candidate in [
            root / "scripts" / "sbom.sh",
            root.parent / "scripts" / "sbom.sh",
            root / ".." / "scripts" / "sbom.sh",
        ]:
            c = candidate.resolve()
            if c.is_file():
                return c

    # 3) project layout given by user (automation-core/scripts/sbom.sh)
    # try from two levels up
    guess = Path(__file__).resolve().parents[3] / "scripts" / "sbom.sh"
    if guess.is_file():
        return guess

    return None


def _run(cmd: Sequence[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> CompletedProcess:
    if _ShutdownFlag.is_set():
        raise KeyboardInterrupt()
    LOG.debug("Executing: %s", " ".join(cmd))
    return run(cmd, capture_output=True, text=True, cwd=str(cwd) if cwd else None, env=env, check=False)  # :contentReference[oaicite:11]{index=11}


def _stdout_stderr(cp: CompletedProcess) -> Tuple[str, str]:
    return cp.stdout or "", cp.stderr or ""


# ------------------------------- commands --------------------------------

def cmd_version(args: argparse.Namespace) -> int:
    print(_package_version())
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    # Simple environment self-checks
    checks = {
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
        },
        "tools": {
            "syft": which("syft") is not None,
            "cosign": which("cosign") is not None,
            "jq": which("jq") is not None,
            "docker": which("docker") is not None,
            "git": which("git") is not None,
        },
        "package": {
            "name": APP_PKG_NAME,
            "version": _package_version(),
        },
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2) if args.pretty else json.dumps(checks, ensure_ascii=False))
    return EXIT_OK


def cmd_plugins(args: argparse.Namespace) -> int:
    # Discover entry points under group "automation_core.commands"  # :contentReference[oaicite:12]{index=12}
    plugins_info: List[Dict[str, Any]] = []
    try:
        # importlib.metadata.entry_points API; select by group name (Python 3.10+).  # :contentReference[oaicite:13]{index=13}
        eps = importlib_metadata.entry_points()
        group_eps = eps.select(group="automation_core.commands") if hasattr(eps, "select") else eps.get("automation_core.commands", [])
        for ep in group_eps:
            plugins_info.append({"name": ep.name, "module": ep.module, "value": ep.value})
    except Exception as e:
        LOG.error("Failed to enumerate entry points: %s", e)
        print("[]")
        return EXIT_EXEC_FAILED

    print(json.dumps(plugins_info, ensure_ascii=False, indent=2) if args.pretty else json.dumps(plugins_info, ensure_ascii=False))
    return EXIT_OK


@dataclass
class SbomArgs:
    target: str
    outdir: Path
    formats: str  # csv like "cyclonedx-json,spdx-json"
    name: Optional[str]
    version: Optional[str]
    attest: bool
    extra: Sequence[str]


def _sbom_call_script(a: SbomArgs, sbom_script: Path) -> int:
    cmd = [str(sbom_script), "-t", a.target, "-o", str(a.outdir), "-f", a.formats]
    if a.name:
        cmd += ["--name", a.name]
    if a.version:
        cmd += ["--version", a.version]
    if a.attest:
        cmd += ["--attest"]
    # pass through remaining options verbatim
    cmd += list(a.extra or [])
    cp = _run(cmd)
    out, err = _stdout_stderr(cp)
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return cp.returncode


def _sbom_fallback_syft(a: SbomArgs) -> int:
    # Minimal fallback generating CycloneDX JSON via syft if available.  # syft CLI presence is environment-specific
    if which("syft") is None:
        LOG.error("Neither scripts/sbom.sh nor syft is available")
        return EXIT_NOT_FOUND
    a.outdir.mkdir(parents=True, exist_ok=True)
    safe_base = (a.name or Path(a.target).name).replace("@", "_").replace(":", "_").replace("/", "_")
    out_path = a.outdir / f"{safe_base}.cdx.json"
    src = a.target if ":" in a.target or a.target.startswith(("ghcr.io/", "docker.io/", "registry.", "quay.io/")) else f"dir:{a.target}"
    cmd = ["syft", src, "-o", "cyclonedx-json"]
    cp = _run(cmd)
    out, err = _stdout_stderr(cp)
    if cp.returncode != 0:
        if err:
            sys.stderr.write(err)
        return cp.returncode
    out_path.write_text(out, encoding="utf-8")
    LOG.info("SBOM written to %s", out_path)
    return EXIT_OK


def cmd_sbom(args: argparse.Namespace) -> int:
    sbom_args = SbomArgs(
        target=args.target,
        outdir=Path(args.outdir),
        formats=args.formats,
        name=args.name,
        version=args.app_version,
        attest=args.attest,
        extra=args.pass_through or [],
    )
    script = _find_sbom_script()
    if script and script.is_file() and os.access(script, os.X_OK):
        LOG.debug("Using sbom script at %s", script)
        return _sbom_call_script(sbom_args, script)
    LOG.warning("sbom.sh not found; attempting syft fallback")
    return _sbom_fallback_syft(sbom_args)


# ------------------------------- parser ----------------------------------

def _build_parser(argv: Optional[Sequence[str]] = None) -> argparse.ArgumentParser:
    # argparse supports sub-commands via add_subparsers() (official docs).  # :contentReference[oaicite:14]{index=14}
    parser = argparse.ArgumentParser(
        prog="automation-core",
        description="Automation Core CLI",
    )
    parser.register("type", "bool", lambda v: v.lower() in ("1", "true", "yes", "on"))

    parser.add_argument("--log-level", default=os.environ.get("AUTOMATION_CORE_LOG_LEVEL", DEFAULT_LOG_LEVEL),
                        help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--log-json", action="store_true", default=bool(os.environ.get("AUTOMATION_CORE_LOG_JSON")),
                        help="Emit logs in JSON")
    parser.add_argument("--version", action="store_true", help="Print version and exit")

    subs = parser.add_subparsers(dest="command", metavar="<command>")

    p_ver = subs.add_parser("version", help="Show package version")
    p_ver.set_defaults(func=cmd_version)

    p_doc = subs.add_parser("doctor", help="Environment self-checks")
    p_doc.add_argument("--pretty", action="store_true", help="Pretty JSON")
    p_doc.set_defaults(func=cmd_doctor)

    p_pl = subs.add_parser("plugins", help="List registered CLI plugins (entry points)")
    p_pl.add_argument("--pretty", action="store_true", help="Pretty JSON")
    p_pl.set_defaults(func=cmd_plugins)

    p_sb = subs.add_parser("sbom", help="Generate SBOM via scripts/sbom.sh or syft fallback")
    p_sb.add_argument("-t", "--target", required=True, help="Path or OCI image reference")
    p_sb.add_argument("-o", "--outdir", default=str(Path.cwd() / "sbom"), help="Output directory")
    p_sb.add_argument("-f", "--formats", default="cyclonedx-json", help="Format list for sbom.sh (csv)")
    p_sb.add_argument("--name", help="Application/component name")
    p_sb.add_argument("--app-version", help="Application/component version")
    p_sb.add_argument("--attest", action="store_true", help="Create cosign attestation (sbom.sh only)")
    p_sb.add_argument("--", dest="pass_through", nargs=argparse.REMAINDER,
                      help="Pass-through args for sbom.sh after --")
    p_sb.set_defaults(func=cmd_sbom)

    return parser


# -------------------------------- main -----------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser(argv)
    args = parser.parse_args(argv)

    _setup_logging(args.log_level, args.log_json)
    _install_signal_handlers()

    if args.version and not args.command:
        return cmd_version(args)

    if not args.command:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        return int(args.func(args))  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        LOG.error("Interrupted")
        return EXIT_INTERRUPTED
    except CalledProcessError as e:
        LOG.exception("Subprocess failed: %s", e)
        return EXIT_EXEC_FAILED
    except Exception as e:
        LOG.exception("Unhandled error: %s", e)
        return EXIT_EXEC_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
