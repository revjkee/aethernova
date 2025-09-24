# -*- coding: utf-8 -*-
"""
zero_trust.utils.time
Industrial-grade time utilities for Zero-Trust systems.

Design goals:
- Monotonic-first for intervals/deadlines; wall-clock (UTC) for audit/interop.
- Anti-regression: never return a time earlier than previously observed.
- RFC3339 parsing/formatting with strict UTC handling.
- Drift detection between wall-clock and monotonic anchor.
- Trusted time windows and deadline helpers.
- Secure sleep implemented via monotonic.
- Cryptographic (HMAC) time attestation tokens for replay-safe time proofs.
- ULID generator (Crockford Base32) for traceable, time-ordered IDs.
- Test-friendly: optional time freezing via context manager/env var.
No external dependencies. Python 3.10+.

Copyright:
  (c) 2025 NeuroCity / TeslaAI Genesis. All rights reserved.
License:
  Internal proprietary. Do not distribute.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Callable, Optional, Protocol, Tuple, Union, Iterable, Dict

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

__all__ = [
    "ClockType",
    "TimeError",
    "SecureTimestamp",
    "MonotonicConverter",
    "now_utc",
    "now_utc_strict",
    "ensure_utc",
    "parse_rfc3339",
    "format_rfc3339",
    "monotonic_ns",
    "time_ns_utc",
    "Deadline",
    "TrustedTimeWindow",
    "secure_sleep",
    "add_jitter",
    "DriftSample",
    "DriftDetector",
    "generate_ulid",
    "TimeMac",
    "FrozenTime",
]

# -----------------------------------------------------------------------------
# Exceptions and Types
# -----------------------------------------------------------------------------

class TimeError(RuntimeError):
    """Generic error for time utility failures."""


class ClockType(Enum):
    MONOTONIC = auto()
    WALL_UTC = auto()


@dataclass(frozen=True)
class SecureTimestamp:
    """
    Immutable pair of wall-clock UTC and monotonic nanoseconds.

    - wall_utc: timezone-aware UTC datetime.
    - mono_ns: monotonic nanoseconds reading captured at the same instant.
    """
    wall_utc: datetime
    mono_ns: int

    def to_tuple(self) -> Tuple[datetime, int]:
        return (self.wall_utc, self.mono_ns)


# -----------------------------------------------------------------------------
# Core time helpers
# -----------------------------------------------------------------------------

_UTC = timezone.utc
_LOG = logging.getLogger(__name__)

# Anti-regression guard for wall-clock time served by now_utc_strict()
# This is process-local and thread-safe via GIL (atomic reference swap).
_last_wall_utc_ns: int = 0

# Optional process-wide frozen time for tests (RFC3339 string)
_FREEZE_ENV_KEY = "NEUROCITY_FAKE_TIME_RFC3339"


def monotonic_ns() -> int:
    """High-resolution monotonic time in nanoseconds."""
    return time.monotonic_ns()


def now_utc() -> datetime:
    """
    Return current wall-clock time in UTC, timezone-aware.
    Honors test freeze if environment variable is set.
    """
    frozen = os.getenv(_FREEZE_ENV_KEY)
    if frozen:
        # If freeze is set but invalid, raise early to fail loud.
        return parse_rfc3339(frozen)
    return datetime.now(tz=_UTC)


def time_ns_utc() -> int:
    """Return POSIX UTC timestamp in nanoseconds (derived from now_utc())."""
    return int(now_utc().timestamp() * 1_000_000_000)


def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure a datetime is timezone-aware UTC.
    Naive datetimes are assumed to be in UTC by policy (strict Zero-Trust).
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_UTC)
    return dt.astimezone(_UTC)


def parse_rfc3339(value: str) -> datetime:
    """
    Parse RFC3339/ISO8601 timestamp into a timezone-aware UTC datetime.
    Accepts 'Z' and offsets like '+02:00'. Raises TimeError on failure.
    """
    try:
        # Remove whitespace and normalize
        s = value.strip()
        # Python 3.11+ datetime.fromisoformat handles most RFC3339 forms.
        # Support 'Z' suffix by replacing with +00:00 if needed.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return ensure_utc(dt)
    except Exception as exc:
        raise TimeError(f"Invalid RFC3339 timestamp: {value!r}") from exc


def format_rfc3339(
    dt: datetime,
    *,
    timespec: str = "milliseconds",
    use_z: bool = True
) -> str:
    """
    Format a datetime as RFC3339 string.
    timespec: 'hours','minutes','seconds','milliseconds','microseconds'.
    use_z: 'Z' for UTC instead of '+00:00'.
    """
    dt_utc = ensure_utc(dt)
    s = dt_utc.isoformat(timespec=timespec)
    if use_z:
        # Replace trailing +00:00 with Z
        if s.endswith("+00:00"):
            s = s[:-6] + "Z"
    return s


# -----------------------------------------------------------------------------
# Monotonic <-> Wall converter with anti-regression
# -----------------------------------------------------------------------------

class MonotonicConverter:
    """
    Anchors wall-clock UTC to monotonic_ns so that any future derived wall time
    cannot regress even if system clock jumps backwards.

    Usage:
      conv = MonotonicConverter.new_anchor()
      ts = conv.now()  # SecureTimestamp(wall_utc, mono_ns)
      later = conv.derive_wall_from_mono(another_mono_ns)
    """

    __slots__ = (
        "_anchor_wall_utc",
        "_anchor_mono_ns",
        "_last_wall_ns",
        "_regression_budget_ns",
    )

    def __init__(
        self,
        anchor_wall_utc: datetime,
        anchor_mono_ns: int,
        *,
        regression_budget: timedelta = timedelta(milliseconds=5),
    ) -> None:
        """
        regression_budget: small allowance to absorb tiny fluctuations due to
        conversion rounding. Any computed wall time earlier than (last - budget)
        will be clamped.
        """
        if anchor_wall_utc.tzinfo is None:
            raise TimeError("anchor_wall_utc must be timezone-aware UTC")
        self._anchor_wall_utc = anchor_wall_utc.astimezone(_UTC)
        self._anchor_mono_ns = int(anchor_mono_ns)
        self._last_wall_ns = int(self._anchor_wall_utc.timestamp() * 1_000_000_000)
        self._regression_budget_ns = int(regression_budget.total_seconds() * 1e9)

    @classmethod
    def new_anchor(cls) -> "MonotonicConverter":
        return cls(now_utc(), monotonic_ns())

    def _clamp_non_regressing(self, candidate_ns: int) -> int:
        # Allow minor negative deltas within budget; otherwise clamp to last.
        if candidate_ns + self._regression_budget_ns < self._last_wall_ns:
            # Hard clamp to prevent regression
            cand = self._last_wall_ns
        else:
            cand = max(candidate_ns, self._last_wall_ns)
        self._last_wall_ns = cand
        return cand

    def derive_wall_from_mono(self, mono_ns: int) -> datetime:
        """
        Convert a monotonic reading into a wall-clock UTC using the anchor,
        preventing time regression.
        """
        delta_ns = int(mono_ns) - self._anchor_mono_ns
        candidate_ns = int(self._anchor_wall_utc.timestamp() * 1_000_000_000) + delta_ns
        clamped_ns = self._clamp_non_regressing(candidate_ns)
        return datetime.fromtimestamp(clamped_ns / 1_000_000_000, tz=_UTC)

    def now(self) -> SecureTimestamp:
        """Return SecureTimestamp derived from current monotonic and anchor."""
        m = monotonic_ns()
        w = self.derive_wall_from_mono(m)
        return SecureTimestamp(wall_utc=w, mono_ns=m)


def now_utc_strict() -> datetime:
    """
    Process-wide anti-regressing wall-clock UTC.
    Ensures returned timestamps never decrease across calls.
    Honors FrozenTime if set.
    """
    global _last_wall_utc_ns
    w = now_utc()
    ns = int(w.timestamp() * 1_000_000_000)

    # Clamp with tiny budget to avoid micro-regressions
    budget_ns = 5_000_000  # 5ms
    if ns + budget_ns < _last_wall_utc_ns:
        # Force non-regressing return
        ns = _last_wall_utc_ns
        w = datetime.fromtimestamp(ns / 1_000_000_000, tz=_UTC)
    else:
        ns = max(ns, _last_wall_utc_ns)
        w = datetime.fromtimestamp(ns / 1_000_000_000, tz=_UTC)

    _last_wall_utc_ns = ns
    return w


# -----------------------------------------------------------------------------
# Deadlines, windows, secure sleep, jitter
# -----------------------------------------------------------------------------

class Deadline:
    """Monotonic-based deadline helper."""

    __slots__ = ("_deadline_ns",)

    def __init__(self, timeout: Union[float, timedelta]) -> None:
        if isinstance(timeout, timedelta):
            seconds = timeout.total_seconds()
        else:
            seconds = float(timeout)
        if seconds < 0:
            raise TimeError("Deadline timeout must be non-negative")
        self._deadline_ns = monotonic_ns() + int(seconds * 1_000_000_000)

    def remaining(self) -> float:
        """Seconds remaining until deadline (can be negative)."""
        rem_ns = self._deadline_ns - monotonic_ns()
        return rem_ns / 1_000_000_000

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def raise_if_expired(self, msg: str = "Deadline exceeded") -> None:
        if self.expired():
            raise TimeError(msg)


class TrustedTimeWindow:
    """
    Validates wall-clock time falls within [start, end] with allowed skew.
    Intended for policy checks and time-bound credentials.
    """

    __slots__ = ("_start", "_end", "_allowed_skew")

    def __init__(
        self,
        start: datetime,
        end: datetime,
        *,
        allowed_skew: timedelta = timedelta(seconds=5),
    ) -> None:
        self._start = ensure_utc(start)
        self._end = ensure_utc(end)
        if self._end < self._start:
            raise TimeError("Window end must be >= start")
        if allowed_skew < timedelta(0):
            raise TimeError("allowed_skew must be >= 0")
        self._allowed_skew = allowed_skew

    def contains(self, now: Optional[datetime] = None) -> bool:
        n = ensure_utc(now) if now else now_utc_strict()
        return (self._start - self._allowed_skew) <= n <= (self._end + self._allowed_skew)

    def assert_contains(self, now: Optional[datetime] = None, *, reason: str = "") -> None:
        if not self.contains(now):
            n = ensure_utc(now) if now else now_utc_strict()
            raise TimeError(
                f"Time {format_rfc3339(n)} not in window "
                f"[{format_rfc3339(self._start)} .. {format_rfc3339(self._end)}] "
                f"with skew {self._allowed_skew.total_seconds()}s. {reason}"
            )


def secure_sleep(seconds: float, *, check_interrupt: Optional[Callable[[], bool]] = None) -> None:
    """
    Sleep using monotonic clock; optionally abort early if check_interrupt() returns True.
    Resistant to system clock changes.
    """
    if seconds <= 0:
        return
    end_ns = monotonic_ns() + int(seconds * 1_000_000_000)
    while True:
        if check_interrupt and check_interrupt():
            return
        now_ns = monotonic_ns()
        if now_ns >= end_ns:
            return
        # Sleep in short chunks to remain responsive
        remaining = (end_ns - now_ns) / 1_000_000_000
        time.sleep(min(0.1, max(0.0, remaining)))


def add_jitter(duration: Union[float, timedelta], factor: float = 0.1) -> float:
    """
    Add symmetric random jitter to a duration.
    factor=0.1 => +/-10%. Returns seconds (float).
    """
    if isinstance(duration, timedelta):
        base = duration.total_seconds()
    else:
        base = float(duration)
    if base < 0:
        raise TimeError("Duration must be non-negative")
    if not (0.0 <= factor <= 1.0):
        raise TimeError("factor must be in [0,1]")
    # Use cryptographic randomness to avoid predictability
    jitter = (secrets.randbelow(1_000_000) / 1_000_000.0) * 2.0 - 1.0  # [-1,1)
    return base * (1.0 + jitter * factor)


# -----------------------------------------------------------------------------
# Drift detection between wall-clock and monotonic anchor
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class DriftSample:
    observed_wall: datetime
    derived_wall_from_mono: datetime
    drift: timedelta


class DriftDetector:
    """
    Observes drift between system wall-clock and a monotonic-derived wall time.
    Use to flag suspicious clock changes (e.g., NTP jumps).
    """

    __slots__ = ("_conv", "_threshold")

    def __init__(self, threshold: timedelta = timedelta(seconds=0.250)) -> None:
        self._conv = MonotonicConverter.new_anchor()
        self._threshold = threshold

    def sample(self) -> DriftSample:
        now_mono = monotonic_ns()
        derived_wall = self._conv.derive_wall_from_mono(now_mono)
        observed_wall = now_utc_strict()
        drift = observed_wall - derived_wall
        return DriftSample(
            observed_wall=observed_wall,
            derived_wall_from_mono=derived_wall,
            drift=drift,
        )

    def is_suspicious(self) -> bool:
        s = self.sample()
        return abs(s.drift) > self._threshold


# -----------------------------------------------------------------------------
# ULID (Crockford Base32, 48-bit ms timestamp + 80-bit randomness)
# -----------------------------------------------------------------------------

# Crockford Base32 alphabet
_B32_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def _encode_base32(data: bytes) -> str:
    """Encode bytes to Crockford Base32 without padding."""
    # Convert to a big integer, then map to base32
    n = int.from_bytes(data, "big")
    # Determine number of base32 chars: ceil(len(bits)/5)
    bits = len(data) * 8
    out_len = (bits + 4) // 5
    chars = []
    for _ in range(out_len):
        chars.append(_B32_ALPH[n & 0x1F])
        n >>= 5
    return "".join(reversed(chars))

def generate_ulid(ts: Optional[datetime] = None) -> str:
    """
    Generate ULID string. Orders lexicographically by time.
    If ts is None, uses now_utc_strict().
    """
    dt = ensure_utc(ts) if ts else now_utc_strict()
    # ULID time component: milliseconds since Unix epoch, 48 bits
    ms = int(dt.timestamp() * 1000) & ((1 << 48) - 1)
    time_bytes = ms.to_bytes(6, "big")
    rand_bytes = secrets.token_bytes(10)  # 80 bits
    raw = time_bytes + rand_bytes
    return _encode_base32(raw)


# -----------------------------------------------------------------------------
# HMAC-based time attestation (replay-safe time proofs)
# -----------------------------------------------------------------------------

class TimeMac:
    """
    HMAC-SHA256 attested time tokens.

    Token format (JSON compact, UTF-8):
      {"ts":"<RFC3339>", "n":"<hex 16 bytes>", "ctx":"<optional str>"}
    MAC: HMAC-SHA256 over UTF-8 bytes of the JSON with key=secret.
    Final token is  base64url( json || b"." || mac ).

    Use verify() with max_skew and replay cache (caller-provided) to prevent reuse.
    """

    @staticmethod
    def _b64url_encode(b: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        import base64
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    @staticmethod
    def _compact_json(obj: Dict[str, Union[str, int]]) -> bytes:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def issue(
        cls,
        secret: bytes,
        *,
        ts: Optional[datetime] = None,
        ctx: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> str:
        if not secret:
            raise TimeError("Secret is required")
        t = ensure_utc(ts) if ts else now_utc_strict()
        n = nonce or secrets.token_bytes(16)
        payload = {"ts": format_rfc3339(t), "n": n.hex()}
        if ctx is not None:
            payload["ctx"] = ctx
        payload_bytes = cls._compact_json(payload)
        mac = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
        return f"{cls._b64url_encode(payload_bytes)}.{cls._b64url_encode(mac)}"

    @classmethod
    def verify(
        cls,
        secret: bytes,
        token: str,
        *,
        max_skew: timedelta = timedelta(seconds=5),
        now: Optional[datetime] = None,
        replay_seen_nonce: Optional[Callable[[str], bool]] = None,
        expected_ctx: Optional[str] = None,
    ) -> datetime:
        """
        Verify token integrity and freshness.
        replay_seen_nonce: callable that returns True if nonce was already used (forbid replay).
        Returns attested UTC datetime on success.
        """
        try:
            b_payload, b_mac = token.split(".", 1)
        except ValueError as exc:
            raise TimeError("Invalid token format") from exc

        payload = cls._b64url_decode(b_payload)
        mac = cls._b64url_decode(b_mac)

        calc = hmac.new(secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(calc, mac):
            raise TimeError("Invalid MAC")

        try:
            obj = json.loads(payload.decode("utf-8"))
            ts = parse_rfc3339(obj["ts"])
            nonce_hex = str(obj["n"])
            ctx = obj.get("ctx")
        except Exception as exc:
            raise TimeError("Invalid payload") from exc

        if expected_ctx is not None and ctx != expected_ctx:
            raise TimeError("Context mismatch")

        if replay_seen_nonce and replay_seen_nonce(nonce_hex):
            raise TimeError("Replay detected")

        current = ensure_utc(now) if now else now_utc_strict()
        if abs((current - ts)) > max_skew:
            raise TimeError("Clock skew exceeds policy")
        return ts


# -----------------------------------------------------------------------------
# FrozenTime: test-only time override (no global monkey-patching)
# -----------------------------------------------------------------------------

class FrozenTime(contextlib.AbstractContextManager):
    """
    Context manager to freeze now_utc()/now_utc_strict() via environment variable.
    Does not monkey-patch stdlib clocks; only this module honors the override.
    """

    def __init__(self, rfc3339: str) -> None:
        # Validate early
        _ = parse_rfc3339(rfc3339)
        self._val = rfc3339
        self._prev: Optional[str] = None

    def __enter__(self):
        self._prev = os.getenv(_FREEZE_ENV_KEY)
        os.environ[_FREEZE_ENV_KEY] = self._val
        # Reset anti-regression state so first call starts at frozen time
        global _last_wall_utc_ns
        dt = parse_rfc3339(self._val)
        _last_wall_utc_ns = int(dt.timestamp() * 1_000_000_000)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._prev is None:
            os.environ.pop(_FREEZE_ENV_KEY, None)
        else:
            os.environ[_FREEZE_ENV_KEY] = self._prev
        # No special handling of exceptions
        return False
