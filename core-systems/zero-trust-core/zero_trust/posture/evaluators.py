# zero-trust-core/zero_trust/posture/evaluators.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from http import HTTPStatus
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------- Optional deps (safe fallbacks) ----------------
try:
    # Pydantic is optional, only for input validation niceties
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *a, **k: None  # type: ignore
    ValidationError = Exception  # type: ignore

try:
    # Optional CEL engine (python-cel or cel-python). If absent, CEL evaluator will return UNKNOWN.
    import cel  # type: ignore
except Exception:  # pragma: no cover
    cel = None  # type: ignore

try:
    # Optional prometheus metrics
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Histogram = None  # type: ignore

try:
    # Optional semver/pkg version comparator
    from packaging import version as pkg_version  # type: ignore
except Exception:  # pragma: no cover
    pkg_version = None  # type: ignore

# ---------------- Internal error model (re-use HTTP layer if present) ----------------
try:
    from zero_trust_core.api.http.errors import AppError, ErrorCode, redact  # type: ignore
except Exception:  # pragma: no cover
    class ErrorCode(str, Enum):
        INVALID_INPUT = "INVALID_INPUT"
        INTERNAL = "INTERNAL"
        POLICY_VIOLATION = "POLICY_VIOLATION"
        DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"

    class AppError(Exception):
        def __init__(self, code: ErrorCode, detail: str = "", http_status: int = 500, **kw: Any) -> None:
            self.code = code
            self.detail = detail
            self.http_status = http_status
            super().__init__(f"{code}: {detail}")

    def redact(obj: Any, sensitive_keys: Iterable[str] = ("token", "secret", "password", "authorization")) -> Any:
        return obj

# ---------------- Logging ----------------
logger = logging.getLogger("zero_trust.posture.evaluators")


# ---------------- Core enums and dataclasses ----------------
class PostureResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ComplianceState(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"


@dataclass
class EvaluationContext:
    tenant_id: str
    identity_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckSpec:
    key: str
    params: Dict[str, Any] = field(default_factory=dict)
    required: bool = True
    weight: int = 1
    timeout_sec: float = 2.5


@dataclass
class PostureCheck:
    key: str
    result: PostureResult
    score: int
    details: Dict[str, Any] = field(default_factory=dict)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evaluator_version: str = "1.0.0"
    signature: Optional[str] = None
    duration_ms: int = 0


@dataclass
class Summary:
    checks: List[PostureCheck]
    pass_count: int
    fail_count: int
    unknown_count: int
    score_total: int
    score_passed: int
    compliance: ComplianceState
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------- Metrics (optional) ----------------
if Counter is not None and Histogram is not None:  # pragma: no cover
    MET_EVAL_TOTAL = Counter("zt_posture_eval_total", "Total posture evaluations", ["key", "result"])
    MET_EVAL_TIME = Histogram("zt_posture_eval_seconds", "Evaluator runtime seconds", ["key"])
else:  # pragma: no cover
    MET_EVAL_TOTAL = None
    MET_EVAL_TIME = None


def _observe_time(key: str, dur: float) -> None:
    if MET_EVAL_TIME is not None:
        MET_EVAL_TIME.labels(key=key).observe(dur)


def _inc_total(key: str, result: PostureResult) -> None:
    if MET_EVAL_TOTAL is not None:
        MET_EVAL_TOTAL.labels(key=key, result=result.value).inc()


# ---------------- Utilities ----------------
def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _compare_versions(a: str, b: str) -> int:
    """
    Returns: -1 if a<b, 0 if a==b, 1 if a>b
    """
    if pkg_version:
        va = pkg_version.parse(a)
        vb = pkg_version.parse(b)
        if va < vb:
            return -1
        if va > vb:
            return 1
        return 0
    # Fallback naive split
    def parts(x: str) -> List[int]:
        return [int(p) for p in x.split(".") if p.isdigit()]
    pa, pb = parts(a), parts(b)
    for i in range(max(len(pa), len(pb))):
        ai, bi = (pa[i] if i < len(pa) else 0), (pb[i] if i < len(pb) else 0)
        if ai < bi:
            return -1
        if ai > bi:
            return 1
    return 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seconds_left(dt: Optional[str]) -> Optional[int]:
    try:
        if not dt:
            return None
        # Accept ISO 8601
        exp = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        return int((exp - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return None


# ---------------- Signing ----------------
class ResultSigner:
    def __init__(self, key_b64: Optional[str]) -> None:
        self.key = None
        if key_b64:
            try:
                self.key = base64.b64decode(key_b64)
            except Exception:
                logger.warning("invalid signing key (base64)")
                self.key = None

    def sign(self, check: PostureCheck, *, ctx: EvaluationContext, evidence_hash: str) -> Optional[str]:
        if not self.key:
            return None
        msg = _canonical_json({
            "tenant": ctx.tenant_id,
            "device": ctx.device_id,
            "identity": ctx.identity_id,
            "check": asdict(check),
            "evidenceHash": evidence_hash,
        })
        mac = hmac.new(self.key, msg, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("ascii")


# ---------------- Evaluator interface and registry ----------------
class Evaluator:
    key: str = "base"
    version: str = "1.0.0"
    description: str = ""
    default_weight: int = 1

    async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
        raise NotImplementedError


class EvaluatorRegistry:
    def __init__(self) -> None:
        self._by_key: Dict[str, Callable[[], Evaluator]] = {}

    def register(self, key: str, factory: Callable[[], Evaluator]) -> None:
        if key in self._by_key:
            logger.warning("overwriting evaluator registration: %s", key)
        self._by_key[key] = factory

    def create(self, key: str) -> Evaluator:
        if key not in self._by_key:
            raise AppError(ErrorCode.INVALID_INPUT, detail=f"Unknown evaluator key: {key}", http_status=HTTPStatus.UNPROCESSABLE_ENTITY)
        return self._by_key[key]()

    def list(self) -> List[str]:
        return sorted(self._by_key.keys())


_registry = EvaluatorRegistry()


def register_evaluator(key: str) -> Callable[[Callable[[], Evaluator]], Callable[[], Evaluator]]:
    def deco(factory: Callable[[], Evaluator]) -> Callable[[], Evaluator]:
        _registry.register(key, factory)
        return factory
    return deco


# ---------------- Built-in evaluators ----------------
class _BaseSimpleBoolEvaluator(Evaluator):
    field_path: Tuple[str, ...] = ()
    expected: bool = True
    key: str = "simple"
    version: str = "1.0.0"
    description: str = "Boolean field check in evidence"
    default_weight: int = 1

    async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
        t0 = time.perf_counter()
        # Resolve field from nested dict
        cur: Any = evidence
        for p in params.get("path", self.field_path):
            if not isinstance(cur, Mapping) or p not in cur:
                dur = int((time.perf_counter() - t0) * 1000)
                chk = PostureCheck(
                    key=self.key, result=PostureResult.UNKNOWN, score=0,
                    details={"reason": "field_missing", "path": list(params.get("path", self.field_path))},
                    evaluator_version=self.version, duration_ms=dur
                )
                _inc_total(self.key, chk.result)
                _observe_time(self.key, dur / 1000.0)
                return chk
            cur = cur[p]
        val = bool(cur)
        ok = (val is True) if params.get("expected", self.expected) else (val is False)
        res = PostureResult.PASS if ok else PostureResult.FAIL
        score = params.get("weight", self.default_weight) if res is PostureResult.PASS else 0
        dur = int((time.perf_counter() - t0) * 1000)
        chk = PostureCheck(
            key=self.key, result=res, score=score,
            details={"value": val, "expected": params.get("expected", self.expected), "path": list(params.get("path", self.field_path))},
            evaluator_version=self.version, duration_ms=dur
        )
        _inc_total(self.key, chk.result)
        _observe_time(self.key, dur / 1000.0)
        return chk


@register_evaluator("disk_encryption")
def _make_disk_encryption() -> Evaluator:
    class DiskEncryption(_BaseSimpleBoolEvaluator):
        key = "disk_encryption"
        version = "1.1.0"
        description = "Checks that full-disk encryption is enabled"
        field_path = ("device", "diskEncryption", "enabled")
        expected = True
        default_weight = 2
    return DiskEncryption()


@register_evaluator("secure_boot")
def _make_secure_boot() -> Evaluator:
    class SecureBoot(_BaseSimpleBoolEvaluator):
        key = "secure_boot"
        version = "1.1.0"
        description = "Checks that Secure Boot is enabled"
        field_path = ("device", "secureBoot", "enabled")
        expected = True
        default_weight = 2
    return SecureBoot()


@register_evaluator("firewall_enabled")
def _make_firewall() -> Evaluator:
    class Firewall(_BaseSimpleBoolEvaluator):
        key = "firewall_enabled"
        version = "1.0.1"
        description = "Checks that host firewall is enabled"
        field_path = ("device", "firewall", "enabled")
        expected = True
        default_weight = 1
    return Firewall()


@register_evaluator("antivirus_health")
def _make_av() -> Evaluator:
    class AntivirusHealth(Evaluator):
        key = "antivirus_health"
        version = "1.0.2"
        description = "Checks AV status is healthy and signatures are fresh"
        default_weight = 1

        async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
            t0 = time.perf_counter()
            av = (evidence.get("device") or {}).get("antivirus") if isinstance(evidence.get("device"), Mapping) else None
            if not isinstance(av, Mapping):
                dur = int((time.perf_counter() - t0) * 1000)
                chk = PostureCheck(key=self.key, result=PostureResult.UNKNOWN, score=0,
                                   details={"reason": "field_missing", "path": ["device", "antivirus"]},
                                   evaluator_version=self.version, duration_ms=dur)
                _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
                return chk
            status = str(av.get("status", "")).lower()
            sig_age_hours = _safe_int(av.get("signaturesAgeHours"), 9999)
            max_age = _safe_int(params.get("maxSignaturesAgeHours", 72), 72)
            ok = status in ("healthy", "ok") and sig_age_hours <= max_age
            res = PostureResult.PASS if ok else PostureResult.FAIL
            score = params.get("weight", self.default_weight) if res is PostureResult.PASS else 0
            dur = int((time.perf_counter() - t0) * 1000)
            chk = PostureCheck(
                key=self.key, result=res, score=score,
                details={"status": status, "signaturesAgeHours": sig_age_hours, "maxAge": max_age},
                evaluator_version=self.version, duration_ms=dur
            )
            _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
            return chk
    return AntivirusHealth()


@register_evaluator("jailbreak_root")
def _make_jb_root() -> Evaluator:
    class JailbreakRoot(_BaseSimpleBoolEvaluator):
        key = "jailbreak_root"
        version = "1.0.0"
        description = "Checks device is NOT jailbroken/rooted"
        field_path = ("device", "compromise", "jailbrokenOrRooted")
        expected = False
        default_weight = 3
    return JailbreakRoot()


@register_evaluator("os_version_min")
def _make_os_version() -> Evaluator:
    class OSVersionMin(Evaluator):
        key = "os_version_min"
        version = "1.1.0"
        description = "Checks OS version meets minimal requirement per OS family"
        default_weight = 2

        async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
            t0 = time.perf_counter()
            dev = evidence.get("device") if isinstance(evidence, Mapping) else None
            if not isinstance(dev, Mapping):
                dur = int((time.perf_counter() - t0) * 1000)
                chk = PostureCheck(key=self.key, result=PostureResult.UNKNOWN, score=0,
                                   details={"reason": "field_missing", "path": ["device"]},
                                   evaluator_version=self.version, duration_ms=dur)
                _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
                return chk
            os_name = str(dev.get("os", "")).lower()
            os_ver = str(dev.get("osVersion", "")).strip()
            reqs = params.get("minVersions") or {}
            required = str(reqs.get(os_name, params.get("fallbackMin", ""))).strip()
            if not os_name or not os_ver or not required:
                dur = int((time.perf_counter() - t0) * 1000)
                chk = PostureCheck(key=self.key, result=PostureResult.UNKNOWN, score=0,
                                   details={"reason": "insufficient_data", "os": os_name, "osVersion": os_ver, "required": required},
                                   evaluator_version=self.version, duration_ms=dur)
                _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
                return chk
            comp = _compare_versions(os_ver, required)
            ok = comp >= 0
            res = PostureResult.PASS if ok else PostureResult.FAIL
            score = params.get("weight", self.default_weight) if res is PostureResult.PASS else 0
            dur = int((time.perf_counter() - t0) * 1000)
            chk = PostureCheck(
                key=self.key, result=res, score=score,
                details={"os": os_name, "version": os_ver, "requiredMin": required, "cmp": comp},
                evaluator_version=self.version, duration_ms=dur
            )
            _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
            return chk
    return OSVersionMin()


@register_evaluator("tags_required")
def _make_tags() -> Evaluator:
    class TagsRequired(Evaluator):
        key = "tags_required"
        version = "1.0.0"
        description = "Checks required compliance tags are present"
        default_weight = 1

        async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
            t0 = time.perf_counter()
            required = set(params.get("allOf") or [])
            present = set((evidence.get("device") or {}).get("tags") or [])
            missing = sorted(list(required - present))
            ok = len(missing) == 0
            res = PostureResult.PASS if ok else PostureResult.FAIL
            score = params.get("weight", self.default_weight) if res is PostureResult.PASS else 0
            dur = int((time.perf_counter() - t0) * 1000)
            chk = PostureCheck(
                key=self.key, result=res, score=score,
                details={"required": sorted(list(required)), "present": sorted(list(present)), "missing": missing},
                evaluator_version=self.version, duration_ms=dur
            )
            _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
            return chk
    return TagsRequired()


@register_evaluator("attestation_basic")
def _make_attestation() -> Evaluator:
    class AttestationBasic(Evaluator):
        key = "attestation_basic"
        version = "1.1.0"
        description = "Validates basic device attestation envelope (provider, nonce, expiry)"
        default_weight = 3

        async def evaluate(self, ctx: EvaluationContext, evidence: Dict[str, Any], params: Dict[str, Any]) -> PostureCheck:
            t0 = time.perf_counter()
            att = None
            if isinstance(evidence, Mapping):
                dev = evidence.get("device")
                if isinstance(dev, Mapping):
                    att = (dev.get("attestation") or dev.get("attestations"))
            # normalize: either a dict or list of dicts
            envs: List[Dict[str, Any]] = []
            if isinstance(att, Mapping):
                envs = [att]  # type: ignore
            elif isinstance(att, Sequence):
                envs = [x for x in att if isinstance(x, Mapping)]  # type: ignore

            if not envs:
                dur = int((time.perf_counter() - t0) * 1000)
                chk = PostureCheck(key=self.key, result=PostureResult.UNKNOWN, score=0,
                                   details={"reason": "no_attestation"},
                                   evaluator_version=self.version, duration_ms=dur)
                _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
                return chk

            # Policy
            required_providers = set([s.lower() for s in (params.get("providers") or ["tpm", "apple sep", "android keystore"])])
            required_nonce = params.get("nonce")
            min_valid_sec = _safe_int(params.get("minValidSeconds", 30), 30)

            now = datetime.now(timezone.utc)
            ok = False
            found: List[Dict[str, Any]] = []
            for env in envs:
                provider = str(env.get("provider", "")).lower()
                valid_until = env.get("validUntil") or env.get("valid_until")
                nonce = env.get("nonce")
                exp_left = _seconds_left(valid_until)
                if required_providers and provider not in required_providers:
                    continue
                if required_nonce and str(nonce) != str(required_nonce):
                    continue
                if exp_left is None or exp_left < min_valid_sec:
                    continue
                ok = True
                found.append({"provider": provider, "validUntil": valid_until, "nonce": nonce, "timeLeftSec": exp_left})
                break

            res = PostureResult.PASS if ok else PostureResult.FAIL
            score = params.get("weight", self.default_weight) if res is PostureResult.PASS else 0
            dur = int((time.perf_counter() - t0) * 1000)
            chk = PostureCheck(
                key=self.key, result=res, score=score,
                details={"matched": found, "requiredProviders": sorted(list(required_providers)), "nonceRequired": bool(required_nonce), "minValidSeconds": min_valid_sec},
                evaluator_version=self.version, duration_ms=dur
            )
            _inc_total(self.key, chk.result); _observe_time(self.key, dur/1000.0)
            return chk
    return AttestationBasic()


@register_evaluator("cel_rule")
def _make_cel() -> Evaluator:
    class CelRule(Evaluator):
        key = "cel_rule"
        version = "1.0.0"
        description = "Evaluates a CEL expression over evidence"
        default_weight = 1

        async def evaluate(self, ctx: EvaluationConte
