# cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/safety/kill_switch.py
"""
Kill Switch for Adversary Emulation / Attack Simulator (Safety-First)

Purpose
-------
Industrial-grade kill-switch to immediately and safely halt emulation activities.
Includes: persisted state with atomic writes, signal handlers, env/file sentinels,
time-limited (TTL) engagement, JSON audit logging, synchronous callbacks, and
developer ergonomics (context manager + decorator + CLI).

Safety & Governance (Normative Guidance)
----------------------------------------
- NIST SP 800-115: technical security testing must be planned/controlled; a hard
  stop (kill switch) is a recommended safety control during assessments.  # Ref: NIST
- NIST SP 800-61r3: incident handling emphasizes rapid containment/eradication;
  a kill-switch enforces immediate containment inside tooling.               # Ref: NIST
- NIST SP 800-53r5 controls (IR, SI): operational safeguards for containment
  and monitoring; this module contributes to those safeguards.               # Ref: NIST
- RFC 2119: "MUST/SHOULD" keywords are used to express normative safety rules.  # Ref: IETF
- Logging follows OWASP guidance: structured, minimal PII, security-relevant.   # Ref: OWASP
- Atomicity: state is persisted via os.replace(...) which performs an atomic
  rename on POSIX; used here for crash-safe updates.                           # Ref: Python docs

References (URLs)
-----------------
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-53r5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- RFC 2119 (requirement levels): https://datatracker.ietf.org/doc/html/rfc2119
- Python os.replace atomic rename (POSIX): https://docs.python.org/3/library/os.html
- Python signal handling: https://docs.python.org/3/library/signal.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

Copyright
---------
(c) 2025 Aethernova / Cybersecurity Core. License: project default.

"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import signal
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

# --------------------------- JSON logging (OWASP-friendly) --------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "@timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S.%fZ"),
            "log.level": record.levelname.lower(),
            "message": record.getMessage(),
            "logger.name": record.name,
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            exc_type, exc_val, _ = record.exc_info
            payload["error.kind"] = getattr(exc_type, "__name__", str(exc_type))
            payload["error.message"] = str(exc_val)
        return json.dumps(payload, ensure_ascii=False)

def _get_logger(name: str = "safety.kill_switch") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False
    return lg

log = _get_logger()

# --------------------------- Data model ---------------------------------------

@dataclass
class KillSwitchState:
    engaged: bool
    reason: str = ""
    issued_by: str = ""
    engaged_at_epoch: float = 0.0
    ttl_seconds: Optional[int] = None  # None => indefinite
    # derived, not persisted explicitly:
    def expires_at_epoch(self) -> Optional[float]:
        if self.ttl_seconds is None:
            return None
        return self.engaged_at_epoch + max(0, int(self.ttl_seconds))

    def is_effective_now(self, now: Optional[float] = None) -> bool:
        if not self.engaged:
            return False
        now = time.time() if now is None else now
        exp = self.expires_at_epoch()
        return True if exp is None else now < exp

# --------------------------- Exceptions ---------------------------------------

class SafetyAbort(RuntimeError):
    """Raised when a guarded operation must stop immediately due to kill-switch."""

# --------------------------- Kill Switch core ---------------------------------

class KillSwitch:
    """
    Thread-safe kill switch with:
    - atomic persistence (os.replace)
    - env override (AETHERNOVA_KILL=1)
    - file sentinel override (<state_dir>/KILL)
    - signal handlers (SIGINT/SIGTERM)
    - TTL support
    - JSON audit log to <state_dir>/safety/safety.jsonl
    """

    ENV_KILL = "AETHERNOVA_KILL"               # "1" engages regardless of state file
    ENV_SAFE = "AETHERNOVA_SAFE_MODE"          # "1" signals tooling MUST run in safe mode
    SENTINEL_NAME = "KILL"

    def __init__(self, state_dir: Path):
        self._state_dir = Path(state_dir)
        self._safety_dir = self._state_dir / "safety"
        self._state_path = self._safety_dir / "kill_switch.json"
        self._log_path = self._safety_dir / "safety.jsonl"
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[KillSwitchState], None]] = []
        self._state = KillSwitchState(engaged=False)
        self._ensure_dirs()
        self._setup_file_logger()

    # ----- setup -----

    def _ensure_dirs(self) -> None:
        self._safety_dir.mkdir(parents=True, exist_ok=True)

    def _setup_file_logger(self) -> None:
        # Duplicate logs into a file (JSONL)
        fh = logging.FileHandler(self._log_path, encoding="utf-8")
        fh.setFormatter(_JsonFormatter())
        log.addHandler(fh)

    # ----- state I/O (atomic) -----

    def _load_state(self) -> KillSwitchState:
        with self._lock:
            if not self._state_path.exists():
                return self._state
            try:
                raw = json.loads(self._state_path.read_text(encoding="utf-8"))
                st = KillSwitchState(**raw)
                # auto-clean expired state
                if st.engaged and not st.is_effective_now():
                    st.engaged = False
                    st.reason = ""
                    st.issued_by = ""
                    st.ttl_seconds = None
                    self._store_state(st)
                self._state = st
            except Exception as e:
                log.error("Failed to load kill switch state", extra={"extra": {"file.path": str(self._state_path)}}, exc_info=True)
            return self._state

    def _store_state(self, st: KillSwitchState) -> None:
        with self._lock:
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(dataclasses.asdict(st), ensure_ascii=False, indent=2), encoding="utf-8")
            # POSIX atomic replace; Windows replace documented behavior used for cross-platform overwrite
            os.replace(tmp, self._state_path)  # atomic on POSIX
            self._state = st
            # audit
            log.info(
                "Kill-switch state persisted",
                extra={"extra": {
                    "event.kind": "state",
                    "event.action": "persist",
                    "file.path": str(self._state_path),
                    "kill.engaged": st.engaged,
                    "kill.reason": st.reason,
                    "kill.issued_by": st.issued_by,
                    "kill.ttl_seconds": st.ttl_seconds,
                }},
            )

    # ----- external overrides -----

    def _env_overridden(self) -> bool:
        return os.getenv(self.ENV_KILL, "").strip() == "1"

    def _sentinel_present(self) -> bool:
        return (self._state_dir / self.SENTINEL_NAME).exists()

    # ----- public API -----

    def register_callback(self, fn: Callable[[KillSwitchState], None]) -> None:
        """Register a synchronous callback invoked on engage/disengage."""
        with self._lock:
            self._callbacks.append(fn)

    def is_engaged(self) -> bool:
        """Check effective kill status (state file + env + sentinel + TTL)."""
        with self._lock:
            st = self._load_state()
            if self._env_overridden() or self._sentinel_present():
                return True
            return st.is_effective_now()

    def engage(self, reason: str, issued_by: str = "", ttl_seconds: Optional[int] = None) -> KillSwitchState:
        """Engage kill switch; future guarded ops MUST abort."""
        with self._lock:
            st = KillSwitchState(
                engaged=True,
                reason=reason,
                issued_by=issued_by,
                engaged_at_epoch=time.time(),
                ttl_seconds=ttl_seconds,
            )
            self._store_state(st)
            for cb in list(self._callbacks):
                try:
                    cb(st)
                except Exception:
                    log.error("Kill-switch callback failed", extra={"extra": {"event.action": "callback"}}, exc_info=True)
            log.info("Kill-switch engaged", extra={"extra": {"event.kind": "state", "event.action": "engage"}})
            return st

    def disengage(self, issued_by: str = "") -> KillSwitchState:
        """Disengage kill switch; guarded ops may resume."""
        with self._lock:
            st = KillSwitchState(engaged=False, reason="", issued_by=issued_by, engaged_at_epoch=time.time(), ttl_seconds=None)
            self._store_state(st)
            for cb in list(self._callbacks):
                try:
                    cb(st)
                except Exception:
                    log.error("Kill-switch callback failed", extra={"extra": {"event.action": "callback"}}, exc_info=True)
            log.info("Kill-switch disengaged", extra={"extra": {"event.kind": "state", "event.action": "disengage"}})
            return st

    # ----- guards -----

    def check_or_abort(self, activity: str = "operation") -> None:
        """Raise SafetyAbort if kill-switch is engaged (env/sentinel/TTL considered)."""
        if self.is_engaged():
            log.warning(
                "Kill-switch abort",
                extra={"extra": {"event.kind": "state", "event.action": "abort", "operation": activity}},
            )
            raise SafetyAbort(f"Aborted '{activity}' due to kill-switch engagement")

    @contextmanager
    def guard(self, activity: str):
        """Guard a critical section; abort immediately if engaged."""
        self.check_or_abort(activity)
        try:
            yield
        finally:
            # optional place for cleanup logs; no-op
            pass

    def guarded(self, activity: str) -> Callable:
        """Decorator to guard functions; checks before invocation."""
        def deco(fn: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                self.check_or_abort(activity)
                return fn(*args, **kwargs)
            return wrapper
        return deco

    # ----- signals -----

    def install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers that engage kill-switch immediately."""
        def _handler(sig_num, _frame):
            try:
                self.engage(reason=f"signal:{sig_num}", issued_by="signal-handler", ttl_seconds=None)
            except Exception:
                log.error("Signal handler failed to engage kill-switch", extra={"extra": {"signal": sig_num}}, exc_info=True)

        # SIGINT always available; SIGTERM may not be on some platforms
        signal.signal(signal.SIGINT, _handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handler)
        log.info("Signal handlers installed", extra={"extra": {"event.kind": "state", "event.action": "signal_handlers"}})

    # ----- utilities -----

    def status(self) -> Dict[str, Any]:
        with self._lock:
            st = self._load_state()
            eff = self.is_engaged()
            return {
                "engaged_effective": eff,
                "state": dataclasses.asdict(st),
                "env_override": self._env_overridden(),
                "file_sentinel": self._sentinel_present(),
                "log_path": str(self._log_path),
                "state_path": str(self._state_path),
                "safe_mode_env": os.getenv(self.ENV_SAFE, "").strip() == "1",
            }

# --------------------------- CLI ------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Kill Switch (safety-first) for adversary emulation / attack simulator")
    p.add_argument("--state-dir", required=True, help="Directory for state/logs (will create <state-dir>/safety).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_engage = sub.add_parser("engage", help="Engage kill switch")
    s_engage.add_argument("--reason", default="manual", help="Reason string")
    s_engage.add_argument("--by", default="operator", help="Issuer (operator id)")
    s_engage.add_argument("--ttl", type=int, default=None, help="TTL in seconds (optional)")

    s_diseng = sub.add_parser("disengage", help="Disengage kill switch")
    s_diseng.add_argument("--by", default="operator", help="Issuer (operator id)")

    sub.add_parser("status", help="Show effective status")
    sub.add_parser("install-signals", help="Install SIGINT/SIGTERM handlers and block (demo)")

    return p

def _cmd_engage(ks: KillSwitch, args: argparse.Namespace) -> int:
    ks.engage(reason=args.reason, issued_by=args.by, ttl_seconds=args.ttl)
    print(json.dumps({"ok": True, "action": "engage", "status": ks.status()}, ensure_ascii=False))
    return 0

def _cmd_disengage(ks: KillSwitch, args: argparse.Namespace) -> int:
    ks.disengage(issued_by=args.by)
    print(json.dumps({"ok": True, "action": "disengage", "status": ks.status()}, ensure_ascii=False))
    return 0

def _cmd_status(ks: KillSwitch, _args: argparse.Namespace) -> int:
    print(json.dumps({"ok": True, "status": ks.status()}, ensure_ascii=False))
    return 0

def _cmd_install_signals(ks: KillSwitch, _args: argparse.Namespace) -> int:
    ks.install_signal_handlers()
    log.info("Press Ctrl+C to engage kill-switch or send SIGTERM", extra={"extra": {"event.action": "await_signal"}})
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        # Already engaged by handler; show status and exit
        print(json.dumps({"ok": True, "status": ks.status()}, ensure_ascii=False))
        return 0

def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = _build_argparser()
    args = ap.parse_args(argv)
    ks = KillSwitch(Path(args.state_dir))

    if args.cmd == "engage":
        return _cmd_engage(ks, args)
    if args.cmd == "disengage":
        return _cmd_disengage(ks, args)
    if args.cmd == "status":
        return _cmd_status(ks, args)
    if args.cmd == "install-signals":
        return _cmd_install_signals(ks, args)

    print(json.dumps({"ok": False, "error": "unknown command"}, ensure_ascii=False))
    return 2

if __name__ == "__main__":
    sys.exit(main())
