# cybersecurity/zero_trust/continuous_auth.py
# Industrial-grade Continuous Authentication engine for Zero Trust (Aethernova cybersecurity-core)
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple, Union
from collections import deque
from uuid import UUID, uuid4

# Optional cryptographic attestation verification
try:
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


# =========================
# Models & enums
# =========================

class AuthEffect(str, Enum):
    ALLOW = "ALLOW"               # доступ без дополнительных шагов
    ALLOW_STEP_UP = "ALLOW_STEP_UP"  # доступ при обязательном step-up MFA
    DENY = "DENY"                 # отказ в доступе (текущее действие)
    REVOKE = "REVOKE"             # немедленная ревокация сессии/токена


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalType(str, Enum):
    DEVICE_ATTESTATION = "DEVICE_ATTESTATION"
    GEO_LOGIN = "GEO_LOGIN"
    NETWORK_REPUTATION = "NETWORK_REPUTATION"
    BEHAVIOR_SCORE = "BEHAVIOR_SCORE"
    SESSION_EVENT = "SESSION_EVENT"
    TOKEN_HEALTH = "TOKEN_HEALTH"
    ADMIN_ACTION = "ADMIN_ACTION"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"


class DecisionReason(str, Enum):
    BASELINE = "BASELINE"
    DEVICE_POSTURE_FAIL = "DEVICE_POSTURE_FAIL"
    GEO_IMPOSSIBLE_TRAVEL = "GEO_IMPOSSIBLE_TRAVEL"
    GEO_NEW_LOCATION = "GEO_NEW_LOCATION"
    IP_REPUTATION_BAD = "IP_REPUTATION_BAD"
    BEHAVIOR_ABNORMAL = "BEHAVIOR_ABNORMAL"
    TOKEN_COMPROMISED = "TOKEN_COMPROMISED"
    SESSION_TOO_OLD = "SESSION_TOO_OLD"
    PRIVILEGED_HARDENING = "PRIVILEGED_HARDENING"
    MANUAL_RISK_INCREASE = "MANUAL_RISK_INCREASE"
    STEPUP_COOLDOWN = "STEPUP_COOLDOWN"


@dataclass
class Principal:
    sub: str
    org_id: Optional[UUID] = None
    roles: List[str] = field(default_factory=list)
    risk_multiplier: float = 1.0  # можно усиливать риск для привилегированных


@dataclass
class SessionContext:
    session_id: str
    principal: Principal
    device_id: Optional[str]
    ip: str
    user_agent: Optional[str]
    created_at: datetime
    last_seen_at: datetime
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Signal:
    type: SignalType
    observed_at: datetime
    source: str
    confidence: int  # 0..100
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class RiskVector:
    device: float = 0.0
    network: float = 0.0
    geo: float = 0.0
    behavior: float = 0.0
    session: float = 0.0

    def total(self) -> float:
        # Ограничение 0..100
        return float(max(0.0, min(100.0, self.device + self.network + self.geo + self.behavior + self.session)))


@dataclass
class Decision:
    effect: AuthEffect
    risk_score: float
    risk_level: RiskLevel
    reasons: List[DecisionReason]
    evidence: Dict[str, Any]
    step_up_methods: List[str] = field(default_factory=list)
    valid_until: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["effect"] = self.effect.value
        d["risk_level"] = self.risk_level.value
        d["reasons"] = [r.value for r in self.reasons]
        return d


# =========================
# Provider interfaces
# =========================

class IGeoIP(Protocol):
    def geolocate(self, ip: str) -> Optional[Tuple[float, float, str]]:
        """
        Return (lat, lon, country_code) or None.
        """


class IThreatIntel(Protocol):
    def ip_reputation(self, ip: str) -> Optional[str]:
        """
        Return one of: 'malicious', 'suspicious', 'benign', or None if unknown.
        """


class IAttestation(Protocol):
    def verify_device_attestation(self, payload: Mapping[str, Any]) -> Tuple[bool, str]:
        """
        Verify device attestation payload; return (ok, detail).
        """


class IStateStore(Protocol):
    """
    Abstract storage for session signals & decisions (in-memory or external).
    """
    def get_signals(self, session_id: str) -> List[Signal]: ...
    def append_signal(self, session_id: str, signal: Signal, ttl_sec: int) -> None: ...
    def get_last_decision(self, session_id: str) -> Optional[Decision]: ...
    def set_last_decision(self, session_id: str, decision: Decision, ttl_sec: int) -> None: ...
    def get_last_stepup_ts(self, session_id: str) -> Optional[float]: ...
    def set_last_stepup_ts(self, session_id: str, ts: float) -> None: ...


# =========================
# Default in-memory store
# =========================

class _MemStore(IStateStore):
    def __init__(self) -> None:
        self._signals: Dict[str, Deque[Tuple[Signal, float]]] = {}
        self._decision: Dict[str, Tuple[Decision, float]] = {}
        self._last_stepup: Dict[str, float] = {}
        self._lock = threading.RLock()

    def _cleanup(self) -> None:
        now = time.time()
        with self._lock:
            for sid, dq in list(self._signals.items()):
                while dq and dq[0][1] < now:
                    dq.popleft()
                if not dq:
                    self._signals.pop(sid, None)
            for sid, (_, exp) in list(self._decision.items()):
                if exp < now:
                    self._decision.pop(sid, None)

    def get_signals(self, session_id: str) -> List[Signal]:
        self._cleanup()
        with self._lock:
            dq = self._signals.get(session_id, deque())
            return [s for s, _ in list(dq)]

    def append_signal(self, session_id: str, signal: Signal, ttl_sec: int) -> None:
        self._cleanup()
        with self._lock:
            dq = self._signals.setdefault(session_id, deque(maxlen=1024))
            dq.append((signal, time.time() + ttl_sec))

    def get_last_decision(self, session_id: str) -> Optional[Decision]:
        self._cleanup()
        with self._lock:
            rec = self._decision.get(session_id)
            return rec[0] if rec else None

    def set_last_decision(self, session_id: str, decision: Decision, ttl_sec: int) -> None:
        with self._lock:
            self._decision[session_id] = (decision, time.time() + ttl_sec)

    def get_last_stepup_ts(self, session_id: str) -> Optional[float]:
        with self._lock:
            return self._last_stepup.get(session_id)

    def set_last_stepup_ts(self, session_id: str, ts: float) -> None:
        with self._lock:
            self._last_stepup[session_id] = ts


# =========================
# Utils
# =========================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _age_minutes(dt: datetime) -> float:
    return max(0.0, (_now() - dt).total_seconds() / 60.0)

def _risk_level(score: float) -> RiskLevel:
    if score >= 80.0:
        return RiskLevel.CRITICAL
    if score >= 60.0:
        return RiskLevel.HIGH
    if score >= 35.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW

def _km_distance_haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# =========================
# Default providers (safe fallbacks)
# =========================

class NoopGeoIP(IGeoIP):
    def geolocate(self, ip: str) -> Optional[Tuple[float, float, str]]:
        return None

class NoopTI(IThreatIntel):
    def ip_reputation(self, ip: str) -> Optional[str]:
        return None

class SimpleAttestation(IAttestation):
    """
    Optional JWT-like opaque structure:
      {
        "alg": "HMAC-SHA256" | "RSA-SHA256",
        "pub": "<PEM-encoded RSA public key (if RSA)>",
        "sig": "<base64 signature over canonical payload>",
        "payload": { "device_id": "...", "ts": "...", "state": {"secure_boot": true, ...} }
      }
    """
    def __init__(self, shared_secret: Optional[bytes] = None) -> None:
        self.shared_secret = shared_secret

    def verify_device_attestation(self, payload: Mapping[str, Any]) -> Tuple[bool, str]:
        try:
            alg = str(payload.get("alg") or "")
            sig_b64 = str(payload.get("sig") or "")
            body = payload.get("payload")
            if not isinstance(body, dict) or not sig_b64 or not alg:
                return False, "attestation: invalid format"
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            sig = base64.b64decode(sig_b64)

            if alg == "HMAC-SHA256":
                if not self.shared_secret:
                    return False, "attestation: missing shared secret"
                calc = hmac.new(self.shared_secret, canonical, hashlib.sha256).digest()
                ok = hmac.compare_digest(calc, sig)
                return ok, "ok" if ok else "attestation: HMAC mismatch"

            if alg == "RSA-SHA256" and _HAS_CRYPTO:
                pem = (payload.get("pub") or "").encode("utf-8")
                pubkey = load_pem_public_key(pem)  # type: ignore[arg-type]
                pubkey.verify(  # type: ignore[attr-defined]
                    sig, canonical,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                return True, "ok"

            if alg == "RSA-SHA256" and not _HAS_CRYPTO:
                return False, "attestation: cryptography not available"

            return False, "attestation: unknown alg"
        except Exception as e:
            return False, f"attestation: error {e}"


# =========================
# Policy
# =========================

@dataclass
class RiskPolicy:
    allow_below: float = 25.0
    stepup_from: float = 25.0
    deny_from: float = 75.0
    revoke_on_compromise: bool = True
    stepup_cooldown_sec: int = 900  # 15 min
    decision_ttl_sec: int = 300     # cache решения на 5 мин
    signal_ttl_sec: int = 3600      # храним сигналы 1 час
    privileged_roles: Tuple[str, ...] = ("admin", "root", "security-operations")
    privileged_multiplier: float = 1.25  # усиление риска для привилегированных
    max_session_age_hours: int = 12      # мягкий триггер step-up по возрасту


# =========================
# Engine
# =========================

class ContinuousAuthEngine:
    """
    Контейнер Zero Trust continuous authentication:
    - прием сигналов
    - агрегирование риска
    - политика решений
    - охлаждение step-up
    - потокобезопасное in-memory состояние (можно заменить IStateStore)
    """

    def __init__(
        self,
        *,
        geoip: Optional[IGeoIP] = None,
        ti: Optional[IThreatIntel] = None,
        attestation: Optional[IAttestation] = None,
        policy: Optional[RiskPolicy] = None,
        store: Optional[IStateStore] = None,
    ) -> None:
        self.geoip = geoip or NoopGeoIP()
        self.ti = ti or NoopTI()
        self.attestation = attestation or SimpleAttestation()
        self.policy = policy or RiskPolicy()
        self.store = store or _MemStore()
        self._lock = threading.RLock()

        # кеш последней геолокации по сессии: (lat, lon, country, ts)
        self._geo_cache: Dict[str, Tuple[float, float, str, float]] = {}

    # ---- signals ingestion ----

    def ingest_signal(self, session: SessionContext, signal: Signal) -> None:
        """
        Добавить сигнал с TTL в состояние движка.
        """
        self.store.append_signal(session.session_id, signal, ttl_sec=self.policy.signal_ttl_sec)

    # ---- evaluation ----

    def evaluate_session(self, session: SessionContext) -> Decision:
        """
        Рассчитать решение по сессии. Использует кеш решения в пределах decision_ttl_sec.
        """
        with self._lock:
            cached = self.store.get_last_decision(session.session_id)
            if cached and cached.valid_until and cached.valid_until > _now():
                return cached

            signals = self.store.get_signals(session.session_id)
            risk, reasons, evidence = self._compute_risk(session, signals)
            risk *= self._principal_multiplier(session.principal, reasons)

            # Жесткие правила
            if DecisionReason.TOKEN_COMPROMISED in reasons and self.policy.revoke_on_compromise:
                decision = Decision(
                    effect=AuthEffect.REVOKE,
                    risk_score=min(100.0, max(80.0, risk)),
                    risk_level=_risk_level(min(100.0, max(80.0, risk))),
                    reasons=reasons,
                    evidence=evidence,
                    step_up_methods=[],
                    valid_until=_now() + timedelta(seconds=self.policy.decision_ttl_sec),
                )
                self.store.set_last_decision(session.session_id, decision, ttl_sec=self.policy.decision_ttl_sec)
                return decision

            # Пороговая политика
            effect = AuthEffect.ALLOW
            step_up_methods: List[str] = []
            if risk >= self.policy.deny_from:
                effect = AuthEffect.DENY
            elif risk >= self.policy.stepup_from or DecisionReason.SESSION_TOO_OLD in reasons:
                effect = AuthEffect.ALLOW_STEP_UP
                step_up_methods = self._select_stepup_methods(session, reasons)

                # охлаждение step-up
                last_ts = self.store.get_last_stepup_ts(session.session_id)
                now_ts = time.time()
                if last_ts and (now_ts - last_ts) < self.policy.stepup_cooldown_sec:
                    reasons.append(DecisionReason.STEPUP_COOLDOWN)
                else:
                    self.store.set_last_stepup_ts(session.session_id, now_ts)

            decision = Decision(
                effect=effect,
                risk_score=risk,
                risk_level=_risk_level(risk),
                reasons=reasons,
                evidence=evidence,
                step_up_methods=step_up_methods,
                valid_until=_now() + timedelta(seconds=self.policy.decision_ttl_sec),
            )
            self.store.set_last_decision(session.session_id, decision, ttl_sec=self.policy.decision_ttl_sec)
            return decision

    def evaluate_all(self, sessions: Iterable[SessionContext]) -> Dict[str, Decision]:
        """
        Батч-оценка множества сессий.
        """
        out: Dict[str, Decision] = {}
        for s in sessions:
            out[s.session_id] = self.evaluate_session(s)
        return out

    def revoke_session(self, session_id: str) -> None:
        """
        Нарушение политики или ручное действие SOC: помечаем сессию как REVOKE на TTL.
        """
        decision = Decision(
            effect=AuthEffect.REVOKE,
            risk_score=100.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=[DecisionReason.MANUAL_RISK_INCREASE],
            evidence={"manual": True},
            step_up_methods=[],
            valid_until=_now() + timedelta(seconds=self.policy.decision_ttl_sec),
        )
        self.store.set_last_decision(session_id, decision, ttl_sec=self.policy.decision_ttl_sec)

    # ---- risk computation ----

    def _compute_risk(self, session: SessionContext, signals: List[Signal]) -> Tuple[float, List[DecisionReason], Dict[str, Any]]:
        vec = RiskVector()
        reasons: List[DecisionReason] = [DecisionReason.BASELINE]
        evidence: Dict[str, Any] = {
            "session": {
                "session_id": session.session_id,
                "ip": session.ip,
                "created_at": session.created_at.isoformat(),
                "last_seen_at": session.last_seen_at.isoformat(),
                "roles": list(session.principal.roles or []),
            },
            "signals": [s.to_dict() for s in signals],
        }

        # 1) Session age & idle
        age_h = max(0.0, (_now() - session.created_at).total_seconds() / 3600.0)
        if age_h > self.policy.max_session_age_hours:
            vec.session += min(15.0, (age_h - self.policy.max_session_age_hours) * 2.0)
            reasons.append(DecisionReason.SESSION_TOO_OLD)

        # 2) Device posture / attestation
        for s in signals:
            if s.type == SignalType.DEVICE_ATTESTATION:
                ok, detail = self.attestation.verify_device_attestation(s.payload or {})
                evidence.setdefault("attestation", {})["detail"] = detail
                if not ok:
                    vec.device += 45.0 * (s.confidence / 100.0)
                    reasons.append(DecisionReason.DEVICE_POSTURE_FAIL)
                else:
                    vec.device += 0.0  # успех не снижает риск, но и не повышает

        # 3) Network reputation
        try:
            rep = self.ti.ip_reputation(session.ip)
        except Exception:
            rep = None
        if rep == "malicious":
            vec.network += 60.0
            reasons.append(DecisionReason.IP_REPUTATION_BAD)
        elif rep == "suspicious":
            vec.network += 25.0
            reasons.append(DecisionReason.IP_REPUTATION_BAD)

        # 4) Geo anomalies (impossible travel)
        geo_reason = self._geo_risk(session)
        if geo_reason == "impossible":
            vec.geo += 40.0
            reasons.append(DecisionReason.GEO_IMPOSSIBLE_TRAVEL)
        elif geo_reason == "new_location":
            vec.geo += 20.0
            reasons.append(DecisionReason.GEO_NEW_LOCATION)

        # 5) Behavior score 0..100 from analytics
        for s in signals:
            if s.type == SignalType.BEHAVIOR_SCORE:
                # нормализуем: выше 60 считаем повышенным риском
                score = float(s.payload.get("score", 0.0))
                if score >= 60.0:
                    vec.behavior += min(35.0, (score - 60.0) * 0.7)
                    reasons.append(DecisionReason.BEHAVIOR_ABNORMAL)

        # 6) Token health & admin overrides
        for s in signals:
            if s.type == SignalType.TOKEN_HEALTH and s.payload.get("compromised") is True:
                reasons.append(DecisionReason.TOKEN_COMPROMISED)
                vec.session = max(vec.session, 80.0)
            if s.type == SignalType.MANUAL_OVERRIDE:
                # оператор SOC может поднять риск вручную
                inc = float(s.payload.get("risk_increase", 0.0))
                vec.session += max(0.0, min(100.0, inc))
                reasons.append(DecisionReason.MANUAL_RISK_INCREASE)

        total = vec.total()
        evidence["risk_vector"] = asdict(vec)
        evidence["risk_score"] = total
        return total, list(dict.fromkeys(reasons)), evidence  # уникализируем причины, сохраняя порядок

    def _geo_risk(self, session: SessionContext) -> Optional[str]:
        try:
            ipaddress.ip_address(session.ip)
        except ValueError:
            return None

        loc = self.geoip.geolocate(session.ip)
        if not loc:
            return None
        lat, lon, cc = loc
        now = time.time()

        cache = self._geo_cache.get(session.session_id)
        self._geo_cache[session.session_id] = (lat, lon, cc, now)

        # if no previous, treat as baseline
        if not cache:
            return None

        plat, plon, pcc, pts = cache
        dt_h = max(0.001, (now - pts) / 3600.0)
        dist_km = _km_distance_haversine(plat, plon, lat, lon)
        speed_kmh = dist_km / dt_h
        # impossible travel если > 1000 км/ч и разные локации
        if speed_kmh > 1000.0 and (pcc != cc or dist_km > 1500.0):
            return "impossible"
        # новое местоположение (смена страны)
        if pcc != cc:
            return "new_location"
        return None

    def _principal_multiplier(self, principal: Principal, reasons: List[DecisionReason]) -> float:
        mult = 1.0 * principal.risk_multiplier
        if any(r in principal.roles for r in self.policy.privileged_roles):
            reasons.append(DecisionReason.PRIVILEGED_HARDENING)
            mult *= self.policy.privileged_multiplier
        return mult

    def _select_stepup_methods(self, session: SessionContext, reasons: List[DecisionReason]) -> List[str]:
        # Политику подбора методов MFA можно усложнить; базовая реализация:
        methods = ["webauthn", "totp", "push"]
        # Если device posture fail — требуем WebAuthn
        if DecisionReason.DEVICE_POSTURE_FAIL in reasons:
            return ["webauthn"]
        return methods


# =========================
# Convenience builders
# =========================

def new_session(principal: Principal, *, ip: str, user_agent: Optional[str] = None,
                device_id: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None) -> SessionContext:
    now = _now()
    return SessionContext(
        session_id=str(uuid4()),
        principal=principal,
        device_id=device_id,
        ip=ip,
        user_agent=user_agent,
        created_at=now,
        last_seen_at=now,
        attributes=attributes or {},
    )


# =========================
# Minimal self-test (optional)
# =========================

if __name__ == "__main__":  # pragma: no cover
    # Демонстрация базового пайплайна без внешних провайдеров
    p = Principal(sub="alice", roles=["user"])
    s = new_session(p, ip="8.8.8.8", user_agent="demo-UA", device_id="device-1")
    engine = ContinuousAuthEngine()

    # Поведенческий риск
    engine.ingest_signal(s, Signal(
        type=SignalType.BEHAVIOR_SCORE,
        observed_at=_now(),
        source="behavior-ml",
        confidence=90,
        payload={"score": 75},
    ))

    # Флаг компрометации токена → REVOKE
    engine.ingest_signal(s, Signal(
        type=SignalType.TOKEN_HEALTH,
        observed_at=_now(),
        source="casb",
        confidence=95,
        payload={"compromised": True},
    ))

    decision = engine.evaluate_session(s)
    print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
