# security-core/security/threat_detection/detectors.py
# Промышленный модуль детекции угроз (UEBA/поведенческий анализ).
# Зависимости: pydantic (обязательно), prometheus_client (опционально).
from __future__ import annotations

import math
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# --------- Метрики (опционально) ---------
try:
    from prometheus_client import Counter, Histogram
except Exception:  # noqa: BLE001
    Counter = Histogram = None  # type: ignore

if Counter and Histogram:
    _EVT_COUNTER = Counter("td_events_total", "Processed security events", ["tenant", "detector"])
    _FINDINGS_COUNTER = Counter("td_findings_total", "Generated findings", ["tenant", "detector", "severity"])
    _DETECT_LAT = Histogram("td_detector_duration_seconds", "Detector processing duration", ["detector"])
else:
    _EVT_COUNTER = _FINDINGS_COUNTER = _DETECT_LAT = None  # type: ignore


# ==============================
# Вспомогательные утилиты
# ==============================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlmb/2)**2
    return 2 * R * math.asin(math.sqrt(a))

def severity_from_score(score: float) -> str:
    if score >= 90: return "critical"
    if score >= 70: return "high"
    if score >= 50: return "medium"
    if score >= 30: return "low"
    return "info"

def clamp(v: float, low: float, high: float) -> float:
    return max(low, min(high, v))

def _dedupe_key(parts: Sequence[str]) -> str:
    return "|".join(str(p) for p in parts)

# ==============================
# Модели событий и результатов
# ==============================

class NetworkInfo(BaseModel):
    ip: Optional[str] = None
    asn: Optional[str] = None
    vpn: Optional[bool] = None
    proxy: Optional[bool] = None
    country: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None

class AuthInfo(BaseModel):
    method: Optional[str] = None           # password, oauth, saml, oidc, mtls, etc.
    mfa: Optional[bool] = None
    mfa_level: Optional[int] = None        # 0..3
    token_id: Optional[str] = None
    device_id: Optional[str] = None
    new_device: Optional[bool] = None
    risk_score: Optional[float] = None     # 0..100

class ResourceInfo(BaseModel):
    type: Optional[str] = None
    id: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    bytes: Optional[int] = None

class ActorInfo(BaseModel):
    principal_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class SecurityEvent(BaseModel):
    tenant_id: str
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = Field(default_factory=now_utc)
    kind: str = Field(..., description="login, access, iam.change, token, download, etc.")
    action: Optional[str] = None           # e.g., auth.login, auth.failed, iam.role.grant, data.read
    outcome: Optional[str] = None          # success|failure|denied
    actor: ActorInfo = Field(default_factory=ActorInfo)
    target: ResourceInfo = Field(default_factory=ResourceInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    auth: AuthInfo = Field(default_factory=AuthInfo)
    session: Dict[str, Any] = Field(default_factory=dict)
    env: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None

    @validator("tenant_id")
    def _tid(cls, v: str) -> str:
        if not v or len(v) > 128: raise ValueError("invalid tenant_id")
        return v

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    detector: str
    severity: str
    score: float
    title: str
    description: str
    ttp: List[str] = Field(default_factory=list)  # MITRE ATT&CK codes, e.g., TA0006/T1110
    confidence: float = 0.5
    dedupe_key: Optional[str] = None
    occured_at: datetime = Field(default_factory=now_utc)
    expire_at: Optional[datetime] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

# ==============================
# Хранилище состояния (потокобезопасное)
# ==============================

class TTLStore:
    """Потокобезопасное TTL‑key/value с селективной очисткой по префиксу."""
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if not item: return None
            exp, val = item
            if exp and exp < time.time():
                self._data.pop(key, None)
                return None
            return val

    def set(self, key: str, value: Any, ttl_seconds: Optional[int]) -> None:
        with self._lock:
            exp = time.time() + ttl_seconds if ttl_seconds else float("inf")
            self._data[key] = (exp, value)

    def incr(self, key: str, ttl_seconds: Optional[int]) -> int:
        with self._lock:
            exp, val = self._data.get(key, (0.0, 0))
            if exp and exp < time.time():
                val = 0
            val = int(val) + 1
            exp = time.time() + ttl_seconds if ttl_seconds else float("inf")
            self._data[key] = (exp, val)
            return val

    def clear_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in list(self._data.keys()):
                if k.startswith(prefix):
                    self._data.pop(k, None)

class SlidingWindow:
    """Скользящее окно счетчиков: хранит бкеты по секундам."""
    def __init__(self, window_seconds: int = 300) -> None:
        self.window = window_seconds
        self._lock = threading.RLock()
        self._buckets: Dict[str, Dict[int, int]] = {}

    def add(self, key: str, ts: Optional[datetime] = None, count: int = 1) -> None:
        t = int((ts or now_utc()).timestamp())
        bucket = t - (t % 1)  # секунда
        with self._lock:
            m = self._buckets.setdefault(key, {})
            m[bucket] = m.get(bucket, 0) + count
            # очистка старых
            cutoff = int(now_utc().timestamp()) - self.window
            for b in list(m.keys()):
                if b < cutoff:
                    m.pop(b, None)

    def sum(self, key: str, last_seconds: Optional[int] = None) -> int:
        horizon = int(now_utc().timestamp()) - (last_seconds or self.window)
        with self._lock:
            m = self._buckets.get(key, {})
            return sum(v for b, v in m.items() if b >= horizon)

# ==============================
# Базовый интерфейс детектора
# ==============================

class Detector:
    """Базовый класс для детекторов."""
    name: str = "base-detector"

    def __init__(self, state: TTLStore, window: SlidingWindow, config: Mapping[str, Any]) -> None:
        self.state = state
        self.window = window
        self.config = dict(config or {})

    def process(self, event: SecurityEvent) -> List[Finding]:
        return []

# ==============================
# Реестр и движок
# ==============================

@dataclass
class SuppressionRule:
    principal_regex: Optional[str] = None
    action_regex: Optional[str] = None
    resource_regex: Optional[str] = None
    dedupe_regex: Optional[str] = None

    def suppressed(self, ev: SecurityEvent, finding: Finding) -> bool:
        if self.principal_regex and ev.actor.principal_id and re.search(self.principal_regex, ev.actor.principal_id):
            return True
        if self.action_regex and ev.action and re.search(self.action_regex, ev.action):
            return True
        if self.resource_regex and ev.target.id and re.search(self.resource_regex, ev.target.id):
            return True
        if self.dedupe_regex and finding.dedupe_key and re.search(self.dedupe_regex, finding.dedupe_key):
            return True
        return False

@dataclass
class EngineConfig:
    default_ttl_sec: int = 3600
    suppression: List[SuppressionRule] = field(default_factory=list)

class DetectorEngine:
    """
    Движок: хранит реестр детекторов, прогоняет события, применяет suppression и дедуп.
    """
    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        self.state = TTLStore()
        self.window = SlidingWindow(window_seconds=3600)
        self.detectors: List[Detector] = []
        self._dedup = TTLStore()  # для дедупликации алертов

    def register(self, detector_factory: Callable[[TTLStore, SlidingWindow, Mapping[str, Any]], Detector], *, config: Optional[Mapping[str, Any]] = None) -> None:
        d = detector_factory(self.state, self.window, config or {})
        self.detectors.append(d)

    def handle(self, event: SecurityEvent) -> List[Finding]:
        all_findings: List[Finding] = []
        for d in self.detectors:
            t0 = time.time()
            try:
                fs = d.process(event)
            finally:
                if _DETECT_LAT:
                    _DETECT_LAT.labels(detector=d.name).observe(time.time() - t0)
            if _EVT_COUNTER:
                _EVT_COUNTER.labels(tenant=event.tenant_id, detector=d.name).inc()
            for f in fs:
                if self._suppressed(event, f):
                    continue
                if self._deduped(f):
                    continue
                all_findings.append(f)
                if _FINDINGS_COUNTER:
                    _FINDINGS_COUNTER.labels(tenant=f.tenant_id, detector=d.name, severity=f.severity).inc()
        return all_findings

    def _suppressed(self, ev: SecurityEvent, f: Finding) -> bool:
        for rule in self.config.suppression:
            if rule.suppressed(ev, f):
                return True
        return False

    def _deduped(self, f: Finding) -> bool:
        key = f.dedupe_key or f.id
        ttl = int((f.expire_at - now_utc()).total_seconds()) if f.expire_at else self.config.default_ttl_sec
        was = self._dedup.get(key)
        if was:
            return True
        self._dedup.set(key, True, ttl)
        return False


# ==============================
# Детекторы
# ==============================

class BruteForceDetector(Detector):
    """
    Детектирование перебора: X неуспешных логинов за окно с IP или по principal, без последующего успеха.
    config:
      window_sec: 900
      threshold: 10
      key: "ip"|"principal"
      cooldown_sec: 900
    """
    name = "brute-force"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind not in ("login", "access") or event.action not in ("auth.failed", "auth.login", "auth.denied"):
            return []
        window_sec = int(self.config.get("window_sec", 900))
        thr = int(self.config.get("threshold", 10))
        key_mode = str(self.config.get("key", "ip"))
        cooldown = int(self.config.get("cooldown_sec", 900))

        key_val = event.network.ip if key_mode == "ip" else (event.actor.principal_id or "unknown")
        tenant_key = _dedupe_key([event.tenant_id, "bf", key_mode, key_val])

        # Успешный логин - сброс счетчика
        if event.action == "auth.login" and event.outcome == "success":
            self.state.clear_prefix(tenant_key)
            return []

        # Учитываем только неуспешные
        if event.outcome not in ("failure", "denied"):
            return []
        count = self.state.incr(tenant_key + "|fail", ttl_seconds=window_sec)
        self.window.add(tenant_key, event.ts, 1)

        recent = self.window.sum(tenant_key, last_seconds=window_sec)
        if recent >= thr:
            score = clamp(40 + 6 * (recent - thr + 1), 30, 95)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "bf", key_mode, key_val, int(event.ts.timestamp() // cooldown)])
            exp = now_utc() + timedelta(seconds=cooldown)
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Brute-force login attempts detected",
                description=f"{recent} failed authentication attempts for {key_mode}={key_val} in last {window_sec}s",
                ttp=["TA0006", "T1110"],
                confidence=0.8,
                dedupe_key=dedupe,
                expire_at=exp,
                labels={"key": key_mode, "value": str(key_val), "window_sec": str(window_sec)},
                evidence={"count_window": recent, "threshold": thr},
            )]
        return []


class ImpossibleTravelDetector(Detector):
    """
    'Невозможное перемещение': скорость между двумя успехами > max_kmh.
    config:
      max_kmh: 1000
      min_minutes_gap: 5
      cooldown_sec: 3600
    """
    name = "impossible-travel"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind != "login" or event.action != "auth.login" or event.outcome != "success":
            return []
        if event.network.lat is None or event.network.lon is None:
            return []

        max_kmh = float(self.config.get("max_kmh", 1000.0))
        min_gap = int(self.config.get("min_minutes_gap", 5))
        cooldown = int(self.config.get("cooldown_sec", 3600))

        pid = event.actor.principal_id or "unknown"
        key = _dedupe_key([event.tenant_id, "it", pid])

        last = self.state.get(key)
        self.state.set(key, {"ts": event.ts, "lat": event.network.lat, "lon": event.network.lon, "country": event.network.country}, ttl_seconds=7*24*3600)
        if not last:
            return []

        tdelta = (event.ts - last["ts"]).total_seconds() / 3600.0
        if tdelta * 60 < min_gap:
            return []

        dist = haversine_km(last["lat"], last["lon"], event.network.lat, event.network.lon)
        speed = dist / max(tdelta, 1e-6)
        if speed > max_kmh:
            score = clamp(60 + 10 * math.log(speed / max_kmh + 1), 50, 95)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "it", pid, int(event.ts.timestamp() // cooldown)])
            exp = now_utc() + timedelta(seconds=cooldown)
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Impossible travel detected",
                description=f"Login speed {speed:.0f} km/h between {last.get('country')} and {event.network.country}",
                ttp=["TA0001", "TA0006"],
                confidence=0.75,
                dedupe_key=dedupe,
                expire_at=exp,
                labels={"principal": pid},
                evidence={"prev": last, "curr": {"lat": event.network.lat, "lon": event.network.lon}, "distance_km": dist, "speed_kmh": speed},
            )]
        return []


class RareCountryDetector(Detector):
    """
    Редкая страна для пользователя (нет в базовой корзине стран за baseline_days).
    config:
      baseline_days: 30
      min_successes: 3
      cooldown_sec: 86400
    """
    name = "rare-country"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind != "login" or event.action != "auth.login" or event.outcome != "success":
            return []
        country = (event.network.country or "").upper()
        if not country:
            return []
        pid = event.actor.principal_id or "unknown"
        baseline_days = int(self.config.get("baseline_days", 30))
        min_success = int(self.config.get("min_successes", 3))
        cooldown = int(self.config.get("cooldown_sec", 86400))

        base_key = _dedupe_key([event.tenant_id, "rc", pid, "countries"])
        # Обновим baseline корзину стран (храним словарь страна->последний ts, счётчик)
        bag = self.state.get(base_key) or {}
        # Очистка по давности
        cutoff = now_utc() - timedelta(days=baseline_days)
        bag = {c: v for c, v in bag.items() if datetime.fromisoformat(v["last"]) >= cutoff}
        # Проверка "редкости"
        seen = country in bag and bag[country]["count"] >= min_success
        # Обновление
        v = bag.get(country, {"count": 0, "last": now_utc().isoformat()})
        v["count"] = int(v["count"]) + 1
        v["last"] = now_utc().isoformat()
        bag[country] = v
        self.state.set(base_key, bag, ttl_seconds=baseline_days*24*3600)

        if not seen:
            score = clamp(45 + 5 * max(0, min_success - v["count"]), 30, 80)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "rc", pid, country, int(event.ts.timestamp() // cooldown)])
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Login from unusual country",
                description=f"Country {country} not in {baseline_days}-day baseline for principal {pid}",
                ttp=["TA0001"],
                confidence=0.6,
                dedupe_key=dedupe,
                expire_at=now_utc() + timedelta(seconds=cooldown),
                labels={"principal": pid, "country": country},
                evidence={"baseline": bag},
            )]
        return []


class TokenReplayDetector(Detector):
    """
    Повторное использование токена (один token_id с разных IP/устройств в окне).
    config:
      window_sec: 3600
      max_unique_ips: 1
      max_unique_devices: 1
      cooldown_sec: 3600
    """
    name = "token-replay"

    def process(self, event: SecurityEvent) -> List[Finding]:
        tok = event.auth.token_id
        if not tok:
            return []
        window_sec = int(self.config.get("window_sec", 3600))
        max_ips = int(self.config.get("max_unique_ips", 1))
        max_dev = int(self.config.get("max_unique_devices", 1))
        cooldown = int(self.config.get("cooldown_sec", 3600))

        base = _dedupe_key([event.tenant_id, "tr", tok])
        snap = self.state.get(base) or {"ips": {}, "devs": {}, "first": now_utc().isoformat()}
        ts = now_utc().isoformat()
        if event.network.ip:
            snap["ips"][event.network.ip] = ts
        if event.auth.device_id:
            snap["devs"][event.auth.device_id] = ts
        # Очистка по окну
        cutoff = now_utc() - timedelta(seconds=window_sec)
        snap["ips"] = {ip: t for ip, t in snap["ips"].items() if datetime.fromisoformat(t) >= cutoff}
        snap["devs"] = {d: t for d, t in snap["devs"].items() if datetime.fromisoformat(t) >= cutoff}
        self.state.set(base, snap, ttl_seconds=window_sec)

        if len(snap["ips"]) > max_ips or len(snap["devs"]) > max_dev:
            score = clamp(70 + 10 * (len(snap["ips"]) - max_ips + len(snap["devs"]) - max_dev), 60, 95)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "tr", tok, int(event.ts.timestamp() // cooldown)])
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Possible token replay",
                description=f"Token {tok} used from {len(snap['ips'])} IPs and {len(snap['devs'])} devices in {window_sec}s",
                ttp=["TA0006", "T1550"],
                confidence=0.85,
                dedupe_key=dedupe,
                expire_at=now_utc() + timedelta(seconds=cooldown),
                labels={"token_id": tok},
                evidence=snap,
            )]
        return []


class SuspiciousNoMFADetector(Detector):
    """
    Подозрительный успешный вход без MFA (или с понижением уровня) при высоком риске/новом устройстве/после серии фейлов.
    config:
      risk_threshold: 60
      recent_fail_window_sec: 900
      recent_fail_threshold: 5
      cooldown_sec: 3600
    """
    name = "suspicious-nomfa"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind != "login" or event.action != "auth.login" or event.outcome != "success":
            return []
        risk_thr = float(self.config.get("risk_threshold", 60))
        win = int(self.config.get("recent_fail_window_sec", 900))
        thr = int(self.config.get("recent_fail_threshold", 5))
        cooldown = int(self.config.get("cooldown_sec", 3600))

        pid = event.actor.principal_id or "unknown"
        key_fail = _dedupe_key([event.tenant_id, "bf", "principal", pid])

        # recent fails
        recent_fails = self.window.sum(key_fail, last_seconds=win)

        suspicious = False
        reasons = []
        if not event.auth.mfa or (event.auth.mfa_level or 0) < 1:
            if (event.auth.risk_score or 0) >= risk_thr:
                suspicious = True; reasons.append("high risk without MFA")
            if event.auth.new_device:
                suspicious = True; reasons.append("new device without MFA")
            if recent_fails >= thr:
                suspicious = True; reasons.append("recent multiple failures without MFA")

        if suspicious:
            score = clamp((event.auth.risk_score or 50) + 10 * (1 if event.auth.new_device else 0) + 5 * (recent_fails >= thr), 40, 92)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "nomfa", pid, int(event.ts.timestamp() // cooldown)])
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Suspicious login without MFA",
                description="; ".join(reasons),
                ttp=["TA0006", "T1078"],
                confidence=0.7,
                dedupe_key=dedupe,
                expire_at=now_utc() + timedelta(seconds=cooldown),
                labels={"principal": pid},
                evidence={"risk": event.auth.risk_score, "recent_fails": recent_fails, "mfa_level": event.auth.mfa_level},
            )]
        return []


class PrivilegeEscalationDetector(Detector):
    """
    Эскалация привилегий: выдача ролей вне доверенного контура.
    Ожидается event.kind='iam.change', action='iam.role.grant'.
    config:
      allowed_granters_regex: r"^svc:iam-admin|u:security"
      sensitive_roles_regex: r"(^admin)|(:owner$)|(:*root)"
      cooldown_sec: 3600
    """
    name = "priv-esc"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind != "iam.change" or event.action != "iam.role.grant":
            return []
        allowed = re.compile(self.config.get("allowed_granters_regex", r"^svc:iam-admin|u:security"))
        sensitive = re.compile(self.config.get("sensitive_roles_regex", r"(^admin)|(:owner$)|(:*root)"))
        cooldown = int(self.config.get("cooldown_sec", 3600))

        granter = event.actor.principal_id or ""
        role = (event.target.attributes or {}).get("role") or ""
        target_principal = (event.target.attributes or {}).get("principal_id") or event.target.id or "unknown"

        if not allowed.search(granter) and sensitive.search(role):
            score = 85.0
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "pe", target_principal, role, int(event.ts.timestamp() // cooldown)])
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Sensitive role granted by non-authorized actor",
                description=f"Role '{role}' granted to {target_principal} by {granter}",
                ttp=["TA0003", "T1098"],
                confidence=0.9,
                dedupe_key=dedupe,
                expire_at=now_utc() + timedelta(seconds=cooldown),
                labels={"granter": granter, "grantee": target_principal, "role": role},
                evidence={"event": event.dict()},
            )]
        return []


class AnomalousDownloadDetector(Detector):
    """
    Аномальное скачивание данных: обьем/частота выше базовой линии.
    config:
      window_sec: 3600
      threshold_bytes: 5_000_000_000
      threshold_reads: 500
      resource_type_regex: r"dataset|object|report"
      cooldown_sec: 3600
    """
    name = "anomalous-download"

    def process(self, event: SecurityEvent) -> List[Finding]:
        if event.kind not in ("access", "download") or (event.action not in ("data.read", "data.download")):
            return []
        if not event.target or not event.actor or not event.actor.principal_id:
            return []
        rtype = event.target.type or ""
        if not re.search(self.config.get("resource_type_regex", r"dataset|object|report"), rtype):
            return []

        win = int(self.config.get("window_sec", 3600))
        thr_b = int(self.config.get("threshold_bytes", 5_000_000_000))
        thr_n = int(self.config.get("threshold_reads", 500))
        cooldown = int(self.config.get("cooldown_sec", 3600))

        pid = event.actor.principal_id
        k_reads = _dedupe_key([event.tenant_id, "dl", pid, "reads"])
        k_bytes = _dedupe_key([event.tenant_id, "dl", pid, "bytes"])
        self.window.add(k_reads, event.ts, 1)
        bytes_inc = int(event.target.bytes or 0)
        if bytes_inc > 0:
            # для байтов используем TTLStore как аккумулятор по окну (простая аппроксимация)
            cur = int(self.state.get(k_bytes) or 0) + bytes_inc
            self.state.set(k_bytes, cur, ttl_seconds=win)

        reads = self.window.sum(k_reads, last_seconds=win)
        total_bytes = int(self.state.get(k_bytes) or 0)

        if reads >= thr_n or total_bytes >= thr_b:
            ratio_n = reads / max(1, thr_n)
            ratio_b = total_bytes / max(1, thr_b)
            score = clamp(55 + 15 * max(ratio_n - 1, ratio_b - 1), 50, 95)
            sev = severity_from_score(score)
            dedupe = _dedupe_key([event.tenant_id, "dl", pid, int(event.ts.timestamp() // cooldown)])
            return [Finding(
                tenant_id=event.tenant_id,
                detector=self.name,
                severity=sev,
                score=score,
                title="Anomalous data exfiltration pattern",
                description=f"{reads} reads and {total_bytes} bytes in {win}s window",
                ttp=["TA0010", "T1020"],
                confidence=0.7,
                dedupe_key=dedupe,
                expire_at=now_utc() + timedelta(seconds=cooldown),
                labels={"principal": pid},
                evidence={"reads": reads, "bytes": total_bytes, "threshold_reads": thr_n, "threshold_bytes": thr_b},
            )]
        return []


# ==============================
# Фабрики для регистрации
# ==============================

def brute_force_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return BruteForceDetector(state, window, cfg)

def impossible_travel_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return ImpossibleTravelDetector(state, window, cfg)

def rare_country_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return RareCountryDetector(state, window, cfg)

def token_replay_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return TokenReplayDetector(state, window, cfg)

def suspicious_nomfa_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return SuspiciousNoMFADetector(state, window, cfg)

def priv_esc_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return PrivilegeEscalationDetector(state, window, cfg)

def anomalous_download_factory(state: TTLStore, window: SlidingWindow, cfg: Mapping[str, Any]) -> Detector:
    return AnomalousDownloadDetector(state, window, cfg)


# ==============================
# Пример использования
# ==============================
"""
engine = DetectorEngine()
engine.register(brute_force_factory, config={"window_sec": 900, "threshold": 8, "key": "ip"})
engine.register(impossible_travel_factory, config={"max_kmh": 900})
engine.register(rare_country_factory, config={"baseline_days": 30})
engine.register(token_replay_factory, config={"window_sec": 3600, "max_unique_ips": 1, "max_unique_devices": 1})
engine.register(suspicious_nomfa_factory, config={"risk_threshold": 70})
engine.register(priv_esc_factory, config={})
engine.register(anomalous_download_factory, config={"threshold_bytes": 10_000_000_000})

ev = SecurityEvent(
    tenant_id="acme",
    kind="login",
    action="auth.login",
    outcome="success",
    actor=ActorInfo(principal_id="u:alice"),
    network=NetworkInfo(ip="203.0.113.1", country="SE", lat=59.3293, lon=18.0686),
    auth=AuthInfo(mfa=False, mfa_level=0, risk_score=75, device_id="dev-1", new_device=True),
)

findings = engine.handle(ev)
for f in findings:
    print(f.severity, f.title, f.description)
"""
