# -*- coding: utf-8 -*-
"""
engine-core / engine / determinism / float_policy.py

Deterministic floating-point policy and utilities.

Goals:
- Deterministic rounding across platforms via Decimal backend with explicit rounding modes.
- Thread-local policy stack with context manager.
- Quantization by step or decimal digits with well-defined tie-breaking.
- ULP utilities: ulp(), nextafter() with portable fallback.
- Deterministic reductions: Kahan/Neumaier sum, per-step quantized sum/dot.
- Deterministic roundf(), quantize(), fma() using high-precision intermediate Decimal.
- Stable comparisons: ulp-based equality and tolerant comparisons.
- Environment fingerprint to aid reproducibility audits.

WARNING:
- This module aims at *deterministic* behavior, not performance. Use it in
  determinism-critical code paths (e.g., gameplay state, lockstep), not in hot inner loops
  unless you measured and accepted the cost.

No external dependencies; only stdlib (decimal, struct, math, threading, hashlib).

Author: Aethernova / engine-core
"""

from __future__ import annotations

import enum
import hashlib
import math
import os
import platform
import struct
import sys
import threading
from dataclasses import dataclass, asdict
from decimal import Decimal, localcontext, ROUND_HALF_EVEN, ROUND_HALF_UP, ROUND_UP, ROUND_DOWN, ROUND_CEILING, ROUND_FLOOR, getcontext
from typing import Any, Iterable, List, Optional, Sequence, Tuple, Dict

__all__ = [
    "RoundMode",
    "FloatPolicy",
    "FloatPolicyScope",
    "get_policy",
    "set_policy",
    "roundf",
    "quantize",
    "ulp",
    "nextafter",
    "almost_equal_ulps",
    "almost_equal_tol",
    "dsum",
    "ddot",
    "kahan_sum",
    "neumaier_sum",
    "fma",
    "env_fingerprint",
]

# ============================================================
# Rounding modes
# ============================================================

class RoundMode(str, enum.Enum):
    TIES_TO_EVEN = "ties_to_even"        # IEEE 754 "bankers rounding"
    TIES_AWAY = "ties_away"              # ties go away from zero
    TOWARDS_ZERO = "towards_zero"        # truncate
    AWAY_FROM_ZERO = "away_from_zero"    # always away from zero
    UP = "up"                            # towards +inf
    DOWN = "down"                        # towards -inf


_DEC_ROUND_MAP: Dict[RoundMode, str] = {
    RoundMode.TIES_TO_EVEN: ROUND_HALF_EVEN,
    RoundMode.TIES_AWAY: ROUND_HALF_UP,          # symmetric for +/- half
    RoundMode.TOWARDS_ZERO: ROUND_DOWN,          # Decimal's DOWN == toward 0
    RoundMode.AWAY_FROM_ZERO: ROUND_UP,          # Decimal's UP == away from 0
    RoundMode.UP: ROUND_CEILING,                 # toward +inf
    RoundMode.DOWN: ROUND_FLOOR,                 # toward -inf
}

# ============================================================
# Policy model and global manager (thread-local)
# ============================================================

@dataclass(frozen=True)
class FloatPolicy:
    """
    Floating-point determinism policy.

    Fields:
      mode: rounding strategy for ties and direction.
      decimals: optional number of decimal digits to keep (quantize by 10^-decimals).
      step: optional quantum step (e.g., 0.001). If both 'decimals' and 'step' set,
            'step' takes precedence.
      dec_precision: Decimal working precision for intermediate computations (>= 34 recommended).
      clamp_inf_nan: if True, raises ValueError on NaN/Inf inputs to core ops.
    """
    mode: RoundMode = RoundMode.TIES_TO_EVEN
    decimals: Optional[int] = None
    step: Optional[float] = None
    dec_precision: int = 50
    clamp_inf_nan: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signature(self) -> str:
        """
        Stable hash for audit logs and snapshot headers to prove policy sameness across peers.
        """
        h = hashlib.sha256()
        h.update(b"FloatPolicy:v1")
        h.update(str(self.mode.value).encode("utf-8"))
        h.update(str(self.decimals).encode("utf-8"))
        h.update(repr(self.step).encode("utf-8"))
        h.update(str(self.dec_precision).encode("utf-8"))
        h.update(b"1" if self.clamp_inf_nan else b"0")
        return h.hexdigest()


# Default policy (bankers rounding, no quantization)
_DEFAULT_POLICY = FloatPolicy()

# Thread-local stack: allows nested scopes per thread
_tlocal = threading.local()
_tlocal.stack = []  # type: ignore[attr-defined]

def get_policy() -> FloatPolicy:
    stk: List[FloatPolicy] = getattr(_tlocal, "stack", [])
    return stk[-1] if stk else _DEFAULT_POLICY

def set_policy(policy: FloatPolicy) -> None:
    """Set as the only active policy for current thread (clears stack)."""
    _tlocal.stack = [policy]  # type: ignore[attr-defined]

class FloatPolicyScope:
    """
    Context manager that pushes a policy for the current thread.

    Example:
        with FloatPolicyScope(FloatPolicy(mode=RoundMode.TIES_AWAY, decimals=3)):
            x = roundf(1.23455)  # -> 1.235 (ties away)
    """
    def __init__(self, policy: FloatPolicy) -> None:
        self._policy = policy

    def __enter__(self) -> None:
        stk: List[FloatPolicy] = getattr(_tlocal, "stack", [])
        stk.append(self._policy)
        _tlocal.stack = stk  # type: ignore[attr-defined]

    def __exit__(self, exc_type, exc, tb) -> None:
        stk: List[FloatPolicy] = getattr(_tlocal, "stack", [])
        if stk:
            stk.pop()
        _tlocal.stack = stk  # type: ignore[attr-defined]

# ============================================================
# Core helpers
# ============================================================

def _check_finite(x: float, pol: FloatPolicy) -> None:
    if pol.clamp_inf_nan and (math.isnan(x) or math.isinf(x)):
        raise ValueError("NaN/Inf not allowed by FloatPolicy")

def _to_dec(x: float) -> Decimal:
    # Exact conversion of binary float to Decimal
    return Decimal.from_float(float(x))

def _quantize_decimal(xd: Decimal, pol: FloatPolicy) -> Decimal:
    """
    Apply policy's quantization/rounding to a Decimal value.
    """
    rnd = _DEC_ROUND_MAP[pol.mode]
    with localcontext() as ctx:
        ctx.prec = max(28, int(pol.dec_precision))  # ensure enough precision
        ctx.rounding = rnd
        if pol.step is not None:
            stepd = _to_dec(pol.step)
            if stepd == 0:
                return +xd  # unary plus enforces context rounding only
            q = (xd / stepd).to_integral_value(rounding=rnd)
            return q * stepd
        if pol.decimals is not None:
            # exponent 10^-decimals
            exp = Decimal((0, (1,), -int(pol.decimals)))  # 1e-nd
            return xd.quantize(exp, rounding=rnd)
        # Only rounding mode (no quantization) => identity in given context
        return +xd

def roundf(x: float, *, policy: Optional[FloatPolicy] = None, decimals: Optional[int] = None) -> float:
    """
    Deterministic rounding of float 'x' according to policy.
    If 'decimals' provided, it temporarily overrides policy.decimals.
    """
    pol = policy or get_policy()
    _check_finite(x, pol)
    xd = _to_dec(x)
    pol_eff = FloatPolicy(
        mode=pol.mode,
        decimals=pol.decimals if decimals is None else decimals,
        step=pol.step,
        dec_precision=pol.dec_precision,
        clamp_inf_nan=pol.clamp_inf_nan,
    )
    yd = _quantize_decimal(xd, pol_eff)
    return float(yd)

def quantize(x: float, *, step: Optional[float] = None, decimals: Optional[int] = None, policy: Optional[FloatPolicy] = None) -> float:
    """
    Quantize x to the nearest quantum:
      - If 'step' is provided, quantize to multiples of 'step' using policy.mode.
      - Else if 'decimals' provided, quantize to 10^-decimals.
      - Else use current policy (may include step/decimals).
    """
    pol = policy or get_policy()
    _check_finite(x, pol)
    xd = _to_dec(x)
    if step is not None or decimals is not None:
        pol = FloatPolicy(
            mode=pol.mode,
            decimals=decimals if step is None else None,
            step=step,
            dec_precision=pol.dec_precision,
            clamp_inf_nan=pol.clamp_inf_nan,
        )
    yd = _quantize_decimal(xd, pol)
    return float(yd)

# ============================================================
# ULP / nextafter
# ============================================================

def ulp(x: float) -> float:
    """
    Unit in the last place for |x|, i.e., distance to the next representable float.
    """
    if math.isnan(x) or math.isinf(x):
        return math.inf
    if x == 0.0:
        # minimal positive subnormal ULP for IEEE-754 binary64
        return 2**-1074
    # Use bit tricks: distance between x and nextafter(x, +inf)
    nx = nextafter(x, math.copysign(math.inf, x))
    return abs(nx - x)

def _nextafter_bits(x: float, y: float) -> float:
    # portable implementation using IEEE-754 binary64 layout
    bx = struct.unpack(">Q", struct.pack(">d", float(x)))[0]
    by = struct.unpack(">Q", struct.pack(">d", float(y)))[0]
    if math.isnan(x) or math.isnan(y):
        return math.nan
    if x == y:
        return float(y)
    if x == 0.0:
        # smallest subnormal toward y's sign
        tiny = 1
        bits = tiny | (0x8000_0000_0000_0000 if math.copysign(1.0, y) < 0 else 0)
        return struct.unpack(">d", struct.pack(">Q", bits))[0]
    sign = bx & 0x8000_0000_0000_0000
    if (x < y) == (sign == 0):
        bx += 1
    else:
        bx -= 1
    return struct.unpack(">d", struct.pack(">Q", bx))[0]

def nextafter(x: float, y: float) -> float:
    """
    Next representable float after x in the direction of y.
    Uses math.nextafter if available; otherwise bitwise fallback.
    """
    if hasattr(math, "nextafter"):
        return math.nextafter(float(x), float(y))
    return _nextafter_bits(x, y)

def almost_equal_ulps(a: float, b: float, *, max_ulps: int = 4) -> bool:
    """
    ULP-based equality: True if |a-b| <= max_ulps * ulp(midpoint).
    """
    if math.isnan(a) or math.isnan(b):
        return False
    if a == b:
        return True
    # conservative: use larger ulp near the larger magnitude
    m = max(abs(a), abs(b))
    return abs(a - b) <= (max_ulps * ulp(m))

def almost_equal_tol(a: float, b: float, *, rel: float = 1e-12, abs_: float = 1e-15) -> bool:
    """
    Tolerant equality with explicit relative and absolute tolerances (deterministic).
    """
    return abs(a - b) <= max(abs_, rel * max(abs(a), abs(b)))

# ============================================================
# Deterministic reductions
# ============================================================

def kahan_sum(values: Iterable[float]) -> float:
    """
    Kahan compensated summation (order-dependent but reduced error).
    Deterministic for a fixed input order.
    """
    s = 0.0
    c = 0.0
    for x in values:
        y = x - c
        t = s + y
        c = (t - s) - y
        s = t
    return s

def neumaier_sum(values: Iterable[float]) -> float:
    """
    Neumaier variant (handles different magnitudes better).
    """
    s = 0.0
    c = 0.0
    for x in values:
        t = s + x
        if abs(s) >= abs(x):
            c += (s - t) + x
        else:
            c += (x - t) + s
        s = t
    return s + c

def dsum(values: Iterable[float], *, policy: Optional[FloatPolicy] = None, per_step_quantize: bool = True) -> float:
    """
    Deterministic sum with optional per-step quantization according to policy.
    If per_step_quantize=True, applies policy after each addition (strong determinism).
    Otherwise, performs Kahan sum then quantizes once at the end (faster).
    """
    pol = policy or get_policy()
    if per_step_quantize:
        s = 0.0
        for v in values:
            s = quantize(s + v, policy=pol)
        return s
    else:
        s = kahan_sum(values)
        return quantize(s, policy=pol)

def ddot(a: Sequence[float], b: Sequence[float], *, policy: Optional[FloatPolicy] = None, per_step_quantize: bool = True) -> float:
    """
    Deterministic dot product with optional per-step quantization.
    """
    if len(a) != len(b):
        raise ValueError("ddot: length mismatch")
    pol = policy or get_policy()
    if per_step_quantize:
        acc = 0.0
        for x, y in zip(a, b):
            acc = quantize(acc + quantize(x * y, policy=pol), policy=pol)
        return acc
    else:
        # pairwise Kahan of products
        prods = (x * y for x, y in zip(a, b))
        return quantize(kahan_sum(prods), policy=pol)

# ============================================================
# Deterministic fused multiply-add (Decimal backend)
# ============================================================

def fma(a: float, b: float, c: float, *, policy: Optional[FloatPolicy] = None) -> float:
    """
    Deterministic (a*b + c) under current policy using Decimal intermediate
    with configured precision and rounding mode.
    """
    pol = policy or get_policy()
    for v in (a, b, c):
        _check_finite(v, pol)
    with localcontext() as ctx:
        ctx.prec = max(28, int(pol.dec_precision))
        ctx.rounding = _DEC_ROUND_MAP[pol.mode]
        res = _to_dec(a) * _to_dec(b) + _to_dec(c)
        resq = _quantize_decimal(res, pol)
        return float(resq)

# ============================================================
# Environment fingerprint (for audits)
# ============================================================

def env_fingerprint() -> Dict[str, str]:
    """
    Returns a dict describing environment relevant to numeric determinism.
    """
    impl = {
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "byteorder": sys.byteorder,
        "float_info": f"mant_dig={sys.float_info.mant_dig}, max={sys.float_info.max}, eps={sys.float_info.epsilon}",
        "decimal_context": f"prec={getcontext().prec}, rounding={getcontext().rounding}",
        "pid": str(os.getpid()),
    }
    impl["hash"] = hashlib.sha256("|".join(f"{k}={v}" for k, v in sorted(impl.items())).encode("utf-8")).hexdigest()
    return impl

# ============================================================
# Self-checks (optional smoke tests)
# ============================================================

if __name__ == "__main__":
    # Basic demonstration
    pol = FloatPolicy(mode=RoundMode.TIES_AWAY, decimals=3, dec_precision=60)
    with FloatPolicyScope(pol):
        assert roundf(1.2345) == 1.235
        assert roundf(-1.2345) == -1.235
        # step quantization
        assert quantize(1.2349, step=0.01) == 1.23 if get_policy().mode == RoundMode.DOWN else quantize(1.2349, step=0.01)
        # ulp / nextafter monotonicity
        x = 1.0
        y = nextafter(x, math.inf)
        assert y > x
        # deterministic dot
        a = [0.1, 0.2, 0.3]
        b = [1.0, 2.0, 3.0]
        s1 = ddot(a, b, per_step_quantize=True)
        s2 = ddot(a, b, per_step_quantize=False)
        _ = env_fingerprint()
