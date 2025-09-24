# policy-core/policy_core/pdp/evaluator_cel.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum, auto
from hashlib import sha256
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, Tuple, Union

logger = logging.getLogger(__name__)

__all__ = [
    "Decision",
    "EvaluationResult",
    "EvaluatorConfig",
    "PolicyCompileError",
    "PolicyRuntimeError",
    "PolicyTimeoutError",
    "PolicyBackendUnavailable",
    "CelPolicyEvaluator",
]

# ---------------------------
# Exceptions / Result schema
# ---------------------------

class PolicyBackendUnavailable(RuntimeError):
    """CEL backend is not available. Install optional dependency 'celpy'."""

class PolicyCompileError(RuntimeError):
    """Raised when CEL compilation fails."""

class PolicyRuntimeError(RuntimeError):
    """Raised when CEL evaluation fails."""

class PolicyTimeoutError(TimeoutError):
    """Raised when evaluation exceeds configured timeout."""


class Decision(Enum):
    PERMIT = auto()
    DENY = auto()
    NOT_APPLICABLE = auto()
    INDETERMINATE = auto()


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    value: Optional[Union[bool, int, float, str, dict, list]] = None
    reason: Optional[str] = None
    duration_ms: float = 0.0
    error: Optional[str] = None
    policy_fingerprint: Optional[str] = None


# ---------------------------
# Config / hooks
# ---------------------------

MetricHook = Callable[[str, float, Mapping[str, Any]], None]
AuditHook = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True)
class EvaluatorConfig:
    """
    Industrial configuration for CEL PDP.
    """
    # Max compiled programs to keep in-memory (LRU)
    cache_size: int = 512
    # Async evaluation timeout in seconds (hard stop)
    eval_timeout_s: float = 0.250
    # If True, returns NOT_APPLICABLE instead of raising on non-boolean results
    coerce_non_bool_to_not_applicable: bool = True
    # Optional metric hook: (metric_name, value, tags)
    metric_hook: Optional[MetricHook] = None
    # Optional audit hook: (decision event dict)
    audit_hook: Optional[AuditHook] = None
    # Whether to include policy fingerprint in results/audit
    include_fingerprint: bool = True
    # Whether to log debug info
    debug_logging: bool = False


# ---------------------------
# LRU for compiled programs
# ---------------------------

class _LRU(OrderedDict):
    def __init__(self, maxsize: int):
        super().__init__()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        with self._lock:
            if key in self:
                val = self.pop(key)
                self[key] = val
                return val
        # Create outside lock to avoid holding during compilation
        val = factory()
        with self._lock:
            if key in self:
                # Another thread might have created it
                return self[key]
            self[key] = val
            if len(self) > self._maxsize:
                self.popitem(last=False)
            return val


# ---------------------------
# CEL backend adapter (lazy)
# ---------------------------

class _CelBackend:
    """
    Thin adapter over celpy to isolate imports and provide a small API surface.
    """
    def __init__(self) -> None:
        try:
            # Lazy import to avoid hard dependency at module import time
            import celpy  # type: ignore
            from celpy import Environment  # type: ignore
        except Exception as e:
            raise PolicyBackendUnavailable(
                "CEL backend not available. Install 'celpy' (e.g. pip install celpy)."
            ) from e
        self._celpy = celpy
        self._Environment = Environment

    def compile(self, expression: str):
        try:
            env = self._Environment()
            ast = env.compile(expression)
            program = env.program(ast)
            return env, program
        except Exception as e:
            # celpy raises various exceptions; keep boundary stable
            raise PolicyCompileError(str(e)) from e

    def evaluate(self, program, activation: Mapping[str, Any]) -> Any:
        try:
            # celpy.Activation translates Python dict to CEL activation
            activation_obj = self._celpy.Activation(activation)
            return program.evaluate(activation_obj)
        except Exception as e:
            raise PolicyRuntimeError(str(e)) from e

    def to_python(self, value: Any) -> Any:
        """
        Convert celpy values to native Python.
        For simple cases celpy returns Python primitives already.
        """
        # Known celpy types have `native()` or behave like primitives.
        try:
            if hasattr(value, "native"):
                return value.native()
            return value
        except Exception:
            return value


# ---------------------------
# CelPolicyEvaluator
# ---------------------------

class CelPolicyEvaluator:
    """
    Production-grade CEL Policy Decision Point (PDP) evaluator.

    Features:
      - CEL compilation and LRU-cached programs
      - Async evaluation with hard timeout (wait_for + to_thread)
      - Strict error model (compile/runtime/timeout)
      - Optional audit and metric hooks
      - Deterministic fingerprinting of (expression + schema hint)
    """

    def __init__(
        self,
        config: Optional[EvaluatorConfig] = None,
        *,
        static_activation: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._cfg = config or EvaluatorConfig()
        self._cache = _LRU(maxsize=self._cfg.cache_size)
        self._backend = _CelBackend()
        self._static_activation: Dict[str, Any] = dict(static_activation or {})
        self._compile_lock = threading.Lock()

        if self._cfg.debug_logging:
            logger.setLevel(logging.DEBUG)

    # -----------------------
    # Public API
    # -----------------------

    def fingerprint(self, expression: str, schema_hint: Optional[Mapping[str, Any]] = None) -> str:
        """Deterministic fingerprint of expression and (optional) schema hint."""
        payload = {
            "expr": expression,
            "schema": schema_hint or {},
            "version": "cel-pdp:v1",
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha256(blob).hexdigest()

    def compile(self, expression: str, *, schema_hint: Optional[Mapping[str, Any]] = None):
        """
        Compile and cache a CEL program. Returns internal handle (env, program).
        """
        key = self._cache_key(expression, schema_hint)
        if self._cfg.debug_logging:
            logger.debug("Compile requested", extra={"key": key})

        def _factory():
            with self._compile_lock:
                env, program = self._backend.compile(expression)
                return (env, program)

        return self._cache.get_or_set(key, _factory)

    def evaluate(
        self,
        expression: str,
        activation: Optional[Mapping[str, Any]] = None,
        *,
        schema_hint: Optional[Mapping[str, Any]] = None,
    ) -> EvaluationResult:
        """
        Synchronous evaluation. For CPU-bound CEL evaluation the helper uses the same thread.
        Prefer `evaluate_async` in async code paths.
        """
        start = time.perf_counter()
        fp = self.fingerprint(expression, schema_hint) if self._cfg.include_fingerprint else None
        try:
            env, program = self.compile(expression, schema_hint=schema_hint)
            combined = self._combine_activation(activation)
            raw = self._backend.evaluate(program, combined)
            value = self._backend.to_python(raw)

            decision, reason = self._decide_from_value(value)
            dur_ms = (time.perf_counter() - start) * 1000.0

            self._emit_metrics("policy_eval_ms", dur_ms, {"status": "ok"})
            self._emit_audit(decision, expression, combined, reason, None, dur_ms, fp)

            return EvaluationResult(
                decision=decision,
                value=value if isinstance(value, (bool, int, float, str, list, dict)) else str(value),
                reason=reason,
                duration_ms=dur_ms,
                policy_fingerprint=fp,
            )

        except PolicyCompileError as e:
            dur_ms = (time.perf_counter() - start) * 1000.0
            self._emit_metrics("policy_eval_ms", dur_ms, {"status": "compile_error"})
            self._emit_audit(Decision.INDETERMINATE, expression, activation, "compile_error", str(e), dur_ms, fp)
            raise
        except PolicyRuntimeError as e:
            dur_ms = (time.perf_counter() - start) * 1000.0
            self._emit_metrics("policy_eval_ms", dur_ms, {"status": "runtime_error"})
            self._emit_audit(Decision.INDETERMINATE, expression, activation, "runtime_error", str(e), dur_ms, fp)
            raise

    async def evaluate_async(
        self,
        expression: str,
        activation: Optional[Mapping[str, Any]] = None,
        *,
        schema_hint: Optional[Mapping[str, Any]] = None,
    ) -> EvaluationResult:
        """
        Asynchronous evaluation with a hard timeout.
        Compilation is cached; evaluation runs in a worker via to_thread.
        """
        start = time.perf_counter()
        fp = self.fingerprint(expression, schema_hint) if self._cfg.include_fingerprint else None

        try:
            # Ensure compiled in main thread to reduce contention cost in threadpool
            self.compile(expression, schema_hint=schema_hint)
            combined = self._combine_activation(activation)

            async def _run() -> EvaluationResult:
                # Run sync evaluate() in a worker to isolate CPU-bound work
                return await asyncio.to_thread(self.evaluate, expression, combined, schema_hint=schema_hint)

            res: EvaluationResult = await asyncio.wait_for(
                _run(),
                timeout=self._cfg.eval_timeout_s,
            )
            return res

        except asyncio.TimeoutError as e:
            dur_ms = (time.perf_counter() - start) * 1000.0
            self._emit_metrics("policy_eval_ms", dur_ms, {"status": "timeout"})
            self._emit_audit(Decision.INDETERMINATE, expression, activation, "timeout", "evaluation timed out", dur_ms, fp)
            raise PolicyTimeoutError(f"CEL evaluation exceeded {self._cfg.eval_timeout_s:.3f}s") from e

    # -----------------------
    # Helpers
    # -----------------------

    def _combine_activation(self, activation: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Merge static and request activations. Static wins only if keys do not collide.
        Request-level activation overrides static to support dynamic attributes.
        """
        combined: Dict[str, Any] = dict(self._static_activation)
        if activation:
            for k, v in activation.items():
                combined[k] = self._sanitize_value(v)
        if self._cfg.debug_logging:
            logger.debug("Activation combined", extra={"keys": list(combined.keys())})
        return combined

    def _sanitize_value(self, v: Any) -> Any:
        """
        Best-effort JSON-serializable coercion for activation safety/logging.
        """
        try:
            if isinstance(v, (str, int, float, bool)) or v is None:
                return v
            if isinstance(v, (list, tuple)):
                return [self._sanitize_value(x) for x in v]
            if isinstance(v, dict):
                return {str(k): self._sanitize_value(val) for k, val in v.items()}
            # Fallback to string representation for complex objects
            return json.loads(json.dumps(v, default=str))
        except Exception:
            return str(v)

    def _decide_from_value(self, value: Any) -> Tuple[Decision, str]:
        """
        Map CEL result to policy decision. By convention, boolean True => PERMIT, False => DENY.
        Non-boolean results:
          - If config.coerce_non_bool_to_not_applicable: NOT_APPLICABLE
          - Else: INDETERMINATE
        """
        if isinstance(value, bool):
            return (Decision.PERMIT if value else Decision.DENY, "boolean")
        if self._cfg.coerce_non_bool_to_not_applicable:
            return (Decision.NOT_APPLICABLE, f"non_boolean:{type(value).__name__}")
        return (Decision.INDETERMINATE, f"non_boolean:{type(value).__name__}")

    def _cache_key(self, expression: str, schema_hint: Optional[Mapping[str, Any]]) -> str:
        payload = {
            "expr": expression,
            "schema": schema_hint or {},
            "version": "cel-pdp:v1",
        }
        return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def _emit_metrics(self, name: string, value: float, tags: Mapping[str, Any]) -> None:  # type: ignore[name-defined]
        # typing: 'string' is not defined in Python; correct to 'str' with safety
        try:
            if self._cfg.metric_hook:
                self._cfg.metric_hook(str(name), float(value), dict(tags))
        except Exception:  # never break execution on metrics path
            if self._cfg.debug_logging:
                logger.exception("Metric hook failed")

    def _emit_audit(
        self,
        decision: Decision,
        expression: Optional[str],
        activation: Optional[Mapping[str, Any]],
        reason: Optional[str],
        error: Optional[str],
        duration_ms: float,
        fingerprint: Optional[str],
    ) -> None:
        try:
            if self._cfg.audit_hook:
                event = {
                    "component": "policy_core.pdp.cel",
                    "decision": decision.name,
                    "reason": reason,
                    "error": error,
                    "duration_ms": round(duration_ms, 3),
                    "fingerprint": fingerprint,
                }
                # For privacy, store only keys of activation by default; comment-in payload if needed
                if activation is not None:
                    try:
                        event["activation_keys"] = sorted(list(activation.keys()))
                    except Exception:
                        event["activation_keys"] = []
                # Do not include full expression by default; add fingerprint instead.
                # Uncomment if you need complete traceability (beware of PII leakage):
                # event["expression"] = expression
                self._cfg.audit_hook(event)
        except Exception:
            if self._cfg.debug_logging:
                logger.exception("Audit hook failed")


# ---------------------------
# Backward-compat shorthand
# ---------------------------

def build_default_evaluator(
    *,
    cache_size: int = 512,
    timeout_s: float = 0.25,
    metric_hook: Optional[MetricHook] = None,
    audit_hook: Optional[AuditHook] = None,
    debug: bool = False,
    static_activation: Optional[Mapping[str, Any]] = None,
) -> CelPolicyEvaluator:
    """
    Convenience constructor with sane defaults.
    """
    cfg = EvaluatorConfig(
        cache_size=cache_size,
        eval_timeout_s=timeout_s,
        metric_hook=metric_hook,
        audit_hook=audit_hook,
        include_fingerprint=True,
        debug_logging=debug,
    )
    return CelPolicyEvaluator(cfg, static_activation=static_activation)
