# core-systems/genius_core/security/self_inhibitor/examples/quickstart.py
# Industrial quickstart for Self-Inhibitor usage
# Standard library only; Python 3.10+
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, asdict
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

###############################################################################
# Audit logging (structured JSON)
###############################################################################

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            try:
                base.update(record.extra)  # type: ignore[assignment]
            except Exception:
                pass
        return json.dumps(base, ensure_ascii=False)

def build_logger(name: str,
                 log_path: Optional[Path] = None,
                 level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    formatter = JsonFormatter()

    # Console
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    # Rotating file (optional)
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

AUDIT_LOGGER = build_logger(
    "genius_core.self_inhibitor.audit",
    log_path=Path(os.getenv("SELF_INHIBITOR_LOG", "logs/self_inhibitor_audit.log"))
)

###############################################################################
# Errors
###############################################################################

class InhibitionError(RuntimeError):
    """Raised when action is inhibited (fail-closed)."""

class PolicyError(RuntimeError):
    """Raised when policy is invalid or cannot be loaded."""

###############################################################################
# Policy model and defaults
###############################################################################

DEFAULT_POLICY: Dict[str, Any] = {
    "version": "1.0",
    "global": {
        "max_concurrency": 8,
        "rate_limit_per_sec": 5,
        "timeout_sec": 5.0,
        "violation_circuit_threshold": 3,
        "risk_circuit_threshold": 85
    },
    "deny_actions": [
        # Hard denies regardless of risk
        {"action": "shell_command", "reason": "Shell execution disabled"},
        {"action": "network_call", "when_sensitivity_in": ["high"], "reason": "No network on high sensitivity"},
    ],
    "allow_actions": [
        # Explicit allows can override generic rules if risk < allow_max_risk
        {"action": "file_read", "allow_max_risk": 60},
        {"action": "file_write", "allow_max_risk": 40, "when_user_in": ["admin", "system"]},
    ],
    "risk_factors": {
        # Weights sum does not have to be 1.0; score normalized later
        "sensitivity_weight": 0.45,
        "action_weight": 0.30,
        "trust_weight": 0.25,
        "ceil": 100
    },
    "action_base_risk": {
        # Base risk by action
        "file_read": 15,
        "file_write": 45,
        "network_call": 70,
        "shell_command": 95,
        "compute_task": 20
    },
    "sensitivity_risk": {
        # sensitivity ∈ {low, medium, high}
        "low": 5,
        "medium": 25,
        "high": 55
    },
    "trust_bonuses": {
        # user_trust ∈ {low, medium, high}
        "low": -0,
        "medium": -10,
        "high": -25
    }
}

def load_policy(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return DEFAULT_POLICY
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"Policy file not found: {path}")
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise PolicyError(f"Failed to load policy JSON {path}: {e}") from e

###############################################################################
# Rate limiter (token bucket) and concurrency
###############################################################################

class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: Optional[int] = None):
        self.rate = float(rate_per_sec)
        self.capacity = int(capacity if capacity is not None else max(1, int(rate_per_sec)))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated
            refill = elapsed * self.rate
            if refill > 0:
                self.tokens = min(self.capacity, self.tokens + int(refill))
                self.updated = now
            if self.tokens <= 0:
                # wait for next token
                to_wait = 1.0 / max(self.rate, 1e-6)
                await asyncio.sleep(to_wait)
                return await self.acquire()
            self.tokens -= 1

###############################################################################
# Decision and audit data
###############################################################################

@dataclass
class Decision:
    allow: bool
    reason: str
    risk_score: int
    action: str
    context: Dict[str, Any]
    inhibited: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

def audit(event: str, decision: Decision, extra: Optional[Dict[str, Any]] = None) -> None:
    data = {
        "event": event,
        "decision": asdict(decision)
    }
    if extra:
        data["extra"] = extra
    AUDIT_LOGGER.info(event, extra={"extra": data})

###############################################################################
# Self Inhibitor core
###############################################################################

class SelfInhibitor:
    """
    Policy-driven self-inhibitor for guarded execution with:
    - risk scoring
    - policy denies/allows
    - timeout, rate limit, concurrency control
    - circuit breaker (violations/risk)
    - audit logging
    - dry-run (canary) mode
    """

    def __init__(self,
                 policy: Dict[str, Any],
                 *,
                 dry_run: bool = False,
                 logger: Optional[logging.Logger] = None):
        self.policy = policy or DEFAULT_POLICY
        g = self.policy.get("global", {})
        self.timeout_sec = float(g.get("timeout_sec", 5.0))
        self.max_concurrency = int(g.get("max_concurrency", 8))
        self.violation_circuit_threshold = int(g.get("violation_circuit_threshold", 3))
        self.risk_circuit_threshold = int(g.get("risk_circuit_threshold", 85))
        self._violations = 0
        self._dry_run = bool(dry_run)
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._bucket = TokenBucket(rate_per_sec=float(g.get("rate_limit_per_sec", 5)))
        self._logger = logger or AUDIT_LOGGER

    # ------------------------------- Public API -------------------------------

    def guarded(self,
                *,
                action: str,
                context_provider: Optional[Callable[[], Dict[str, Any]]] = None,
                timeout_override: Optional[float] = None) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """
        Decorator to guard any async function.
        """

        def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:

            if not asyncio.iscoroutinefunction(func):
                raise TypeError("@guarded requires async function")

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = context_provider() if context_provider else {}
                return await self.execute(func, action=action, context=context, timeout_override=timeout_override, args=args, kwargs=kwargs)

            return wrapper
        return decorator

    async def execute(self,
                      func: Callable[..., Awaitable[Any]],
                      *,
                      action: str,
                      context: Dict[str, Any],
                      timeout_override: Optional[float] = None,
                      args: Tuple[Any, ...] = (),
                      kwargs: Dict[str, Any] = {}) -> Any:
        """
        Execute guarded function with policy checks, limits and audit.
        Fail-closed unless dry_run is enabled.
        """
        await self._bucket.acquire()
        async with self._sem:
            # Circuit breaker check
            if self._violations >= self.violation_circuit_threshold:
                decision = Decision(
                    allow=False, reason="circuit_breaker_violations",
                    risk_score=100, action=action, context=context, inhibited=True
                )
                audit("inhibit.circuit.violations", decision)
                if self._dry_run:
                    self._logger.warning("Circuit breaker tripped; dry-run continues")
                else:
                    raise InhibitionError("Circuit breaker: too many violations")

            # Risk and policy decision
            risk = self._compute_risk(action, context)
            decision = self._decide(action, context, risk)
            audit("decision", decision)

            # Risk-based circuit breaker
            if risk >= self.risk_circuit_threshold and not decision.allow:
                self._violations += 1
                audit("inhibit.circuit.risk", decision)
                if self._dry_run:
                    self._logger.warning("High risk; dry-run continues")
                else:
                    raise InhibitionError(f"High risk={risk}, action inhibited")

            if not decision.allow:
                self._violations += 1
                audit("inhibit.policy", decision)
                if self._dry_run:
                    self._logger.warning("Policy inhibited; dry-run continues")
                else:
                    raise InhibitionError(f"Action '{action}' inhibited: {decision.reason}")

            # Execute with timeout
            timeout = float(timeout_override or self.timeout_sec)
            try:
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                success = Decision(
                    allow=True, reason="executed",
                    risk_score=risk, action=action, context=context, inhibited=False
                )
                audit("execute.ok", success)
                # reset violations after successful run
                self._violations = 0
                return result
            except asyncio.TimeoutError:
                self._violations += 1
                fail = Decision(
                    allow=False, reason="timeout",
                    risk_score=risk, action=action, context=context, inhibited=True
                )
                audit("execute.timeout", fail)
                if self._dry_run:
                    self._logger.warning("Timeout occurred; dry-run continues")
                    return None
                raise InhibitionError(f"Timeout after {timeout}s")
            except Exception as e:
                self._violations += 1
                fail = Decision(
                    allow=False, reason=f"runtime_error:{type(e).__name__}",
                    risk_score=risk, action=action, context=context, inhibited=True
                )
                audit("execute.error", fail, {"error": str(e)})
                if self._dry_run:
                    self._logger.warning("Runtime error; dry-run continues")
                    return None
                raise

    # --------------------------- Risk & Policy logic --------------------------

    def _compute_risk(self, action: str, context: Dict[str, Any]) -> int:
        rf = self.policy.get("risk_factors", {})
        base = self.policy.get("action_base_risk", {}).get(action, 50)
        sensitivity = str(context.get("sensitivity", "medium")).lower()
        trust = str(context.get("user_trust", "medium")).lower()

        s_risk = self.policy.get("sensitivity_risk", {}).get(sensitivity, 25)
        t_bonus = self.policy.get("trust_bonuses", {}).get(trust, -10)

        s_w = float(rf.get("sensitivity_weight", 0.45))
        a_w = float(rf.get("action_weight", 0.30))
        t_w = float(rf.get("trust_weight", 0.25))
        ceil = int(rf.get("ceil", 100))

        raw = (base * a_w) + (s_risk * s_w) + ((-t_bonus) * t_w)
        risk = int(min(max(raw, 0), ceil))
        return risk

    def _decide(self, action: str, context: Dict[str, Any], risk: int) -> Decision:
        # Hard denies
        for rule in self.policy.get("deny_actions", []):
            if rule.get("action") != action:
                continue
            when_sens = set(map(str.lower, rule.get("when_sensitivity_in", [])))
            if when_sens:
                if str(context.get("sensitivity", "medium")).lower() in when_sens:
                    return Decision(False, rule.get("reason", "denied"), risk, action, context, True)
            else:
                return Decision(False, rule.get("reason", "denied"), risk, action, context, True)

        # Allows with constraints
        for rule in self.policy.get("allow_actions", []):
            if rule.get("action") != action:
                continue
            allow_max_risk = int(rule.get("allow_max_risk", 100))
            when_user = set(map(str.lower, rule.get("when_user_in", [])))
            if when_user and str(context.get("user", "")).lower() not in when_user:
                # Not matching user; try next rule
                continue
            if risk <= allow_max_risk:
                return Decision(True, "allowed_by_rule", risk, action, context, False)

        # Default: allow only if risk is moderate
        if risk < 50:
            return Decision(True, "allowed_by_default_risk", risk, action, context, False)
        return Decision(False, "denied_by_default_risk", risk, action, context, True)

###############################################################################
# Demo guarded functions (async)
###############################################################################

async def simulate_file_read(path: str) -> str:
    await asyncio.sleep(0.05)
    p = Path(path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")[:1024]

async def simulate_file_write(path: str, data: str) -> int:
    await asyncio.sleep(0.05)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        f.write(data)
    return len(data)

async def simulate_compute_task(n: int) -> int:
    # Simple CPU-bound-ish loop kept short; demonstrates guard wrapping
    total = 0
    for i in range(n):
        total += (i * i) % 97
        if i % 1000 == 0:
            await asyncio.sleep(0)  # cooperative
    return total

###############################################################################
# CLI wiring and graceful shutdown
###############################################################################

_SHUTDOWN = asyncio.Event()

def _install_signals() -> None:
    def _handler(signum, frame):
        try:
            _SHUTDOWN.set()
        except Exception:
            pass
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _handler)
        except Exception:
            # Not all platforms allow signal handling in same way
            pass

def _context_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "user": args.user,
        "user_trust": args.user_trust,
        "sensitivity": args.sensitivity,
        "request_id": args.request_id,
    }

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Self-Inhibitor quickstart (industrial)")
    p.add_argument("--policy", type=str, default=os.getenv("SELF_INHIBITOR_POLICY"),
                   help="Path to policy JSON (optional)")
    p.add_argument("--dry-run", action="store_true", help="Canary mode: do not fail hard")
    p.add_argument("--action", required=True, choices=[
        "file_read", "file_write", "compute_task", "network_call", "shell_command"
    ])
    p.add_argument("--user", default="guest")
    p.add_argument("--user-trust", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--sensitivity", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--request-id", default="req-local")
    p.add_argument("--timeout", type=float, default=None, help="Optional per-call timeout override")
    # Action specific
    p.add_argument("--path", type=str, help="Path for file actions")
    p.add_argument("--data", type=str, help="Data for file_write")
    p.add_argument("--n", type=int, default=10000, help="Work size for compute_task")
    return p

###############################################################################
# Main
###############################################################################

async def main(argv: Optional[list[str]] = None) -> int:
    _install_signals()
    args = build_arg_parser().parse_args(argv)
    policy = load_policy(args.policy)

    inhibitor = SelfInhibitor(policy, dry_run=args.dry_run)

    ctx_provider = lambda: _context_from_args(args)

    # Wrap demo functions with inhibitor
    @inhibitor.guarded(action="file_read", context_provider=ctx_provider, timeout_override=args.timeout)
    async def guarded_file_read(path: str) -> str:
        return await simulate_file_read(path)

    @inhibitor.guarded(action="file_write", context_provider=ctx_provider, timeout_override=args.timeout)
    async def guarded_file_write(path: str, data: str) -> int:
        return await simulate_file_write(path, data)

    @inhibitor.guarded(action="compute_task", context_provider=ctx_provider, timeout_override=args.timeout)
    async def guarded_compute(n: int) -> int:
        return await simulate_compute_task(n)

    # Example execution dispatch
    action = args.action
    ctx = _context_from_args(args)
    AUDIT_LOGGER.info("startup", extra={"extra": {"event": "startup", "context": ctx}})

    try:
        if action == "file_read":
            if not args.path:
                raise ValueError("--path is required for file_read")
            result = await guarded_file_read(args.path)
            print(result)

        elif action == "file_write":
            if not args.path or args.data is None:
                raise ValueError("--path and --data are required for file_write")
            written = await guarded_file_write(args.path, args.data)
            print(written)

        elif action == "compute_task":
            result = await guarded_compute(args.n)
            print(result)

        elif action in ("network_call", "shell_command"):
            # These actions are present to show policy inhibition paths.
            # We do not implement actual network/shell. Attempt triggers policy.
            @inhibitor.guarded(action=action, context_provider=ctx_provider, timeout_override=args.timeout)
            async def noop() -> None:
                await asyncio.sleep(0.01)
                return None
            await noop()
            print("ok")

        else:
            raise ValueError(f"Unsupported action: {action}")

        # Wait for graceful shutdown if signal received mid-run
        if _SHUTDOWN.is_set():
            AUDIT_LOGGER.info("shutdown", extra={"extra": {"event": "shutdown", "reason": "signal"}})

        return 0

    except InhibitionError as ie:
        print(f"Inhibited: {ie}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
