# veilmind-core/veilmind/dp/mechanisms.py
# -*- coding: utf-8 -*-
"""
VeilMind — Data Protection mechanisms:
- PolicyEngine: региональные правила, возрастной контроль, истечение согласий.
- ConsentMechanism: выдача/отзыв согласий + проверка разрешений по целям.
- ConsentStore: интерфейсы хранения (in-memory; опционально PostgreSQL, если установлен asyncpg).
- ProofSigner: криптодоказуемость событий (JWS при наличии PyJWT, иначе HMAC-SHA256).
- AuditWriter: append-only журнал (JSONL).
Все внешние зависимости опциональны; модуль деградирует безопасно.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Опциональные зависимости
try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None  # type: ignore


# -------------------------
# Константы и типы
# -------------------------

class Purpose(str, Enum):
    ESSENTIAL = "essential_services"
    SECURITY = "security_fraud"
    ANALYTICS = "analytics"
    EMAIL = "email_comm"
    ADS = "ads_personalization"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_MFA = "MFA"       # для совместимости с Zero Trust-порогами
    LIMITED = "LIMITED"
    QUARANTINE = "QUARANTINE"


class Action(str, Enum):
    GRANT = "grant"
    DENY = "deny"
    WITHDRAW = "withdraw"
    UPDATE = "update"
    EXPIRE = "expire"
    MIGRATE = "migrate"


@dataclass(frozen=True)
class ConsentEvent:
    """
    Событие изменения согласия (append-only).
    """
    event_id: str
    user_hash: str
    purpose_id: str
    granted: bool
    region: str
    policy_version: str
    ts: datetime
    source: str  # web|mobile|api|import
    proof_jws: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "user_hash": self.user_hash,
            "purpose_id": self.purpose_id,
            "granted": self.granted,
            "region": self.region,
            "policy_version": self.policy_version,
            "ts": self.ts.replace(tzinfo=timezone.utc).isoformat(),
            "source": self.source,
            "proof_jws": self.proof_jws,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ConsentStatus:
    granted: bool
    policy_version: str
    region: str
    ts: datetime
    proof_jws: Optional[str] = None


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str
    purpose_id: str
    policy_version: str
    expires_at: Optional[datetime]
    effective_region: str
    require_banner: bool
    # Для Zero Trust интеграции:
    thresholds: Dict[str, float] = field(default_factory=dict)


# -------------------------
# Утилиты
# -------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ulid_like() -> str:
    # Без внешних зависимостей генерируем UUID4 hex — детерминированность не требуется
    return uuid.uuid4().hex


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_user_hash(user_id: str, salt: str, pepper: Optional[str] = None) -> str:
    """
    Устойчивое хэширование идентификатора.
    salt: долгоживущая соль (ENV).
    pepper: короткоживущий «перец» (например, из KMS/секрет-хранилища); может быть None.
    """
    if not user_id:
        raise ValueError("user_id is empty")
    m = hashlib.sha256()
    m.update(salt.encode("utf-8"))
    if pepper:
        m.update(pepper.encode("utf-8"))
    m.update(user_id.encode("utf-8"))
    return m.hexdigest()


# -------------------------
# ProofSigner (JWS/HMAC)
# -------------------------

class ProofSigner:
    """
    Формирует криптодоказательство события согласия.
    Если доступен PyJWT — выпускает JWS; иначе HMAC-SHA256 в формате: "hmac:<b64>"
    """
    def __init__(self, secret: str, issuer: str = "veilmind-core", algo: str = "HS256"):
        self.secret = secret
        self.issuer = issuer
        self.algo = algo

    def sign_event(self, payload: Mapping[str, Any]) -> str:
        body = {
            "iss": self.issuer,
            "iat": int(time.time()),
            "jti": _ulid_like(),
            **dict(payload),
        }
        if jwt is not None:
            return jwt.encode(body, self.secret, algorithm=self.algo)  # type: ignore
        # HMAC fallback
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        mac = hmac.new(self.secret.encode("utf-8"), raw, hashlib.sha256).digest()
        return "hmac:" + base64.b64encode(mac).decode("ascii")


# -------------------------
# PolicyEngine
# -------------------------

@dataclass(frozen=True)
class RegionalPolicy:
    require_prior_consent_for: Tuple[str, ...] = ()
    consent_expiry_days: int = 365
    show_reject_all_button: bool = True
    respect_gpc_signal: bool = True  # для US: do not sell/share


@dataclass
class PolicyEngine:
    """
    Минимальная политика исполнения, совместимая с configs/consent.yaml.
    """
    version: str
    regional: Dict[str, RegionalPolicy]
    age_min: int = 16
    underage_block: Tuple[str, ...] = (Purpose.ANALYTICS.value, Purpose.ADS.value, Purpose.EMAIL.value)
    expiry_overrides: Dict[str, int] = field(default_factory=lambda: {
        Purpose.ANALYTICS.value: 180,
        Purpose.ADS.value: 180,
    })
    # Zero Trust thresholds — информационно
    thresholds: Dict[str, float] = field(default_factory=lambda: {
        "allow": float(os.getenv("ZT_RISK_THRESH_ALLOW", "40")),
        "mfa": float(os.getenv("ZT_RISK_THRESH_MFA", "70")),
        "deny": float(os.getenv("ZT_RISK_THRESH_DENY", "85")),
        "quarantine": float(os.getenv("ZT_RISK_THRESH_QUARANTINE", "95")),
    })

    def effective_region(self, region: Optional[str]) -> str:
        # простая нормализация региона
        r = (region or "EEA").upper()
        return r if r in self.regional else "EEA"

    def consent_expiry_for(self, purpose_id: str, region: str) -> int:
        rp = self.regional[self.effective_region(region)]
        return self.expiry_overrides.get(purpose_id, rp.consent_expiry_days)

    def prior_consent_required(self, purpose_id: str, region: str) -> bool:
        rp = self.regional[self.effective_region(region)]
        return purpose_id in rp.require_prior_consent_for

    def gpc_blocks(self, purpose_id: str, region: str, gpc: bool) -> bool:
        rp = self.regional[self.effective_region(region)]
        if not gpc or not rp.respect_gpc_signal:
            return False
        # Для US и аналогов — блокируем профайлинг/рекламу
        return purpose_id in (Purpose.ADS.value,)

    def underage_blocks(self, purpose_id: str, age: Optional[int]) -> bool:
        return age is not None and age < self.age_min and purpose_id in self.underage_block


# -------------------------
# Хранилища согласий
# -------------------------

class ConsentStore:
    """
    Интерфейс хранилища согласий. Минимальные операции для механизма.
    Сюда сохраняются только стабильные хэши и метаданные без PII.
    """
    def record(self, event: ConsentEvent) -> None:
        raise NotImplementedError

    def last_status(self, user_hash: str, purpose_id: str) -> Optional[ConsentStatus]:
        raise NotImplementedError


class InMemoryConsentStore(ConsentStore):
    def __init__(self) -> None:
        self._last: Dict[Tuple[str, str], ConsentStatus] = {}
        self._events: List[ConsentEvent] = []

    def record(self, event: ConsentEvent) -> None:
        self._events.append(event)
        self._last[(event.user_hash, event.purpose_id)] = ConsentStatus(
            granted=event.granted,
            policy_version=event.policy_version,
            region=event.region,
            ts=event.ts,
            proof_jws=event.proof_jws,
        )

    def last_status(self, user_hash: str, purpose_id: str) -> Optional[ConsentStatus]:
        return self._last.get((user_hash, purpose_id))


class PostgresConsentStore(ConsentStore):  # pragma: no cover
    """
    Опциональное PostgreSQL-хранилище. Требует asyncpg.
    Таблица (минимально):
      CREATE TABLE IF NOT EXISTS user_consent_events (
        id TEXT PRIMARY KEY,
        user_hash TEXT NOT NULL,
        purpose_id TEXT NOT NULL,
        granted BOOLEAN NOT NULL,
        region TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        ts TIMESTAMPTZ NOT NULL,
        source TEXT NOT NULL,
        proof_jws TEXT,
        metadata JSONB NOT NULL DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_consent_last ON user_consent_events(user_hash, purpose_id, ts DESC);
    """
    def __init__(self, pool: "asyncpg.pool.Pool") -> None:
        if asyncpg is None:
            raise RuntimeError("asyncpg is not installed")
        self.pool = pool

    def record(self, event: ConsentEvent) -> None:
        # Синхронный интерфейс оборачивает асинхронный вызов — для совместимости.
        import asyncio
        asyncio.run(self._record_async(event))

    def last_status(self, user_hash: str, purpose_id: str) -> Optional[ConsentStatus]:
        import asyncio
        return asyncio.run(self._last_status_async(user_hash, purpose_id))

    async def _record_async(self, event: ConsentEvent) -> None:
        async with self.pool.acquire() as con:
            await con.execute(
                """
                INSERT INTO user_consent_events (id, user_hash, purpose_id, granted, region,
                    policy_version, ts, source, proof_jws, metadata)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                """,
                event.event_id,
                event.user_hash,
                event.purpose_id,
                event.granted,
                event.region,
                event.policy_version,
                event.ts,
                event.source,
                event.proof_jws,
                json.dumps(event.metadata, ensure_ascii=False),
            )

    async def _last_status_async(self, user_hash: str, purpose_id: str) -> Optional[ConsentStatus]:
        async with self.pool.acquire() as con:
            row = await con.fetchrow(
                """
                SELECT granted, policy_version, region, ts, proof_jws
                FROM user_consent_events
                WHERE user_hash=$1 AND purpose_id=$2
                ORDER BY ts DESC
                LIMIT 1
                """,
                user_hash,
                purpose_id,
            )
            if not row:
                return None
            return ConsentStatus(
                granted=bool(row["granted"]),
                policy_version=str(row["policy_version"]),
                region=str(row["region"]),
                ts=row["ts"],
                proof_jws=row["proof_jws"],
            )


# -------------------------
# Аудит
# -------------------------

class AuditWriter:
    """
    Простое append-only логирование в JSONL без PII.
    Для production можно заменить на Kafka/S3.
    """
    def __init__(self, path: str = "/var/log/veilmind/consent_audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Mapping[str, Any]) -> None:
        line = json.dumps(dict(record), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


# -------------------------
# ConsentMechanism
# -------------------------

@dataclass
class ConsentMechanism:
    """
    Высокоуровневый фасад: выдача/отзыв/проверка согласий и расчет решений.
    """
    policy: PolicyEngine
    store: ConsentStore
    signer: ProofSigner
    audit: AuditWriter
    # Настройки хэширования идентификаторов:
    user_hash_salt: str = os.getenv("CONSENT_USER_SALT", "CHANGE_ME_SALT")
    user_hash_pepper: Optional[str] = None  # может подгружаться из KMS/секретов

    def _hash_user(self, user_id: str) -> str:
        return stable_user_hash(user_id, self.user_hash_salt, self.user_hash_pepper)

    # ---- Команды изменения состояния согласия ----

    def grant(self, user_id: str, purpose_id: str, region: str, source: str = "api",
              policy_version: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> ConsentEvent:
        uhash = self._hash_user(user_id)
        ts = _utcnow()
        payload = {"user_hash": uhash, "purpose_id": purpose_id, "region": region, "action": Action.GRANT.value, "ts": ts.isoformat()}
        proof = self.signer.sign_event(payload)
        ev = ConsentEvent(
            event_id=_ulid_like(),
            user_hash=uhash,
            purpose_id=purpose_id,
            granted=True,
            region=self.policy.effective_region(region),
            policy_version=policy_version or self.policy.version,
            ts=ts,
            source=source,
            proof_jws=proof,
            metadata=metadata or {},
        )
        self.store.record(ev)
        self.audit.write({"type": "consent", "action": "grant", **ev.to_json()})
        return ev

    def withdraw(self, user_id: str, purpose_id: str, region: str, source: str = "api",
                 policy_version: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> ConsentEvent:
        uhash = self._hash_user(user_id)
        ts = _utcnow()
        payload = {"user_hash": uhash, "purpose_id": purpose_id, "region": region, "action": Action.WITHDRAW.value, "ts": ts.isoformat()}
        proof = self.signer.sign_event(payload)
        ev = ConsentEvent(
            event_id=_ulid_like(),
            user_hash=uhash,
            purpose_id=purpose_id,
            granted=False,
            region=self.policy.effective_region(region),
            policy_version=policy_version or self.policy.version,
            ts=ts,
            source=source,
            proof_jws=proof,
            metadata=metadata or {},
        )
        self.store.record(ev)
        self.audit.write({"type": "consent", "action": "withdraw", **ev.to_json()})
        return ev

    # ---- Чтение статуса ----

    def status(self, user_id: str, purpose_id: str) -> Optional[ConsentStatus]:
        uhash = self._hash_user(user_id)
        return self.store.last_status(uhash, purpose_id)

    # ---- Вычисление решения для запроса обработки ----

    def decide(self, user_id: str, purpose_id: str, region: Optional[str], age: Optional[int],
               gpc_signal: bool, now: Optional[datetime] = None) -> DecisionResult:
        now = now or _utcnow()
        region_eff = self.policy.effective_region(region)

        # 1) Жесткие блокировки (возраст, GPC)
        if self.policy.underage_blocks(purpose_id, age):
            return DecisionResult(
                decision=Decision.DENY,
                reason="underage_limit",
                purpose_id=purpose_id,
                policy_version=self.policy.version,
                expires_at=None,
                effective_region=region_eff,
                require_banner=False,
                thresholds=self.policy.thresholds,
            )
        if self.policy.gpc_blocks(purpose_id, region_eff, gpc_signal):
            return DecisionResult(
                decision=Decision.DENY,
                reason="gpc_signal",
                purpose_id=purpose_id,
                policy_version=self.policy.version,
                expires_at=None,
                effective_region=region_eff,
                require_banner=False,
                thresholds=self.policy.thresholds,
            )

        # 2) Цели, не требующие согласия (essential/security) — допустимы по договору/легитимному интересу
        if purpose_id in (Purpose.ESSENTIAL.value, Purpose.SECURITY.value):
            return DecisionResult(
                decision=Decision.ALLOW,
                reason="legal_basis:necessary",
                purpose_id=purpose_id,
                policy_version=self.policy.version,
                expires_at=None,
                effective_region=region_eff,
                require_banner=False,
                thresholds=self.policy.thresholds,
            )

        # 3) Проверка статуса согласия
        status = self.status(user_id, purpose_id)
        expiry_days = self.policy.consent_expiry_for(purpose_id, region_eff)
        expires_at = (status.ts + timedelta(days=expiry_days)) if status else None
        is_expired = bool(expires_at and now >= expires_at)

        if self.policy.prior_consent_required(purpose_id, region_eff):
            # Для EEA/UK и т.п.: до изъявления согласия — запрещено.
            if not status or not status.granted or is_expired:
                return DecisionResult(
                    decision=Decision.DENY,
                    reason="no_consent_or_expired",
                    purpose_id=purpose_id,
                    policy_version=self.policy.version,
                    expires_at=expires_at,
                    effective_region=region_eff,
                    require_banner=True,
                    thresholds=self.policy.thresholds,
                )
            # Имеется действующее согласие
            return DecisionResult(
                decision=Decision.ALLOW,
                reason="consent_granted",
                purpose_id=purpose_id,
                policy_version=self.policy.version,
                expires_at=expires_at,
                effective_region=region_eff,
                require_banner=False,
                thresholds=self.policy.thresholds,
            )

        # 4) Регионы с «opt-out» (например, US) — analytics может быть включена по умолчанию,
        #    но при отзыве согласия или GPC — запрещаем. До этого — ALLOW.
        if status and (not status.granted or is_expired):
            return DecisionResult(
                decision=Decision.DENY,
                reason="withdrawn_or_expired",
                purpose_id=purpose_id,
                policy_version=self.policy.version,
                expires_at=expires_at,
                effective_region=region_eff,
                require_banner=False,
                thresholds=self.policy.thresholds,
            )
        return DecisionResult(
            decision=Decision.ALLOW,
            reason="optout_region_default",
            purpose_id=purpose_id,
            policy_version=self.policy.version,
            expires_at=expires_at,
            effective_region=region_eff,
            require_banner=False,
            thresholds=self.policy.thresholds,
        )


# -------------------------
# Фабрика по умолчанию
# -------------------------

def default_policy_engine() -> PolicyEngine:
    """
    Консервативная политика по умолчанию, согласованная с примером configs/consent.yaml.
    """
    return PolicyEngine(
        version=os.getenv("CONSENT_POLICY_VERSION", "2025-08-21-1"),
        regional={
            "EEA": RegionalPolicy(
                require_prior_consent_for=(Purpose.ANALYTICS.value, Purpose.EMAIL.value, Purpose.ADS.value),
                consent_expiry_days=180,
                show_reject_all_button=True,
                respect_gpc_signal=True,
            ),
            "UK": RegionalPolicy(
                require_prior_consent_for=(Purpose.ANALYTICS.value, Purpose.EMAIL.value, Purpose.ADS.value),
                consent_expiry_days=180,
                show_reject_all_button=True,
                respect_gpc_signal=True,
            ),
            "US": RegionalPolicy(
                require_prior_consent_for=(Purpose.ADS.value,),
                consent_expiry_days=365,
                show_reject_all_button=True,
                respect_gpc_signal=True,
            ),
            "BR": RegionalPolicy(
                require_prior_consent_for=(Purpose.ANALYTICS.value, Purpose.ADS.value),
                consent_expiry_days=365,
                show_reject_all_button=True,
                respect_gpc_signal=True,
            ),
        },
        age_min=int(os.getenv("CONSENT_MIN_AGE", "16")),
    )


def build_default_mechanism(store: Optional[ConsentStore] = None,
                            signer_secret: Optional[str] = None,
                            audit_path: Optional[str] = None) -> ConsentMechanism:
    policy = default_policy_engine()
    store = store or InMemoryConsentStore()
    signer = ProofSigner(secret=signer_secret or os.getenv("CONSENT_JWS_SECRET", "CHANGE_ME_SECRET"))
    audit = AuditWriter(path=audit_path or os.getenv("CONSENT_AUDIT_PATH", "/var/log/veilmind/consent_audit.jsonl"))
    mech = ConsentMechanism(
        policy=policy,
        store=store,
        signer=signer,
        audit=audit,
        user_hash_salt=os.getenv("CONSENT_USER_SALT", "CHANGE_ME_SALT"),
        user_hash_pepper=os.getenv("CONSENT_USER_PEPPER", None),
    )
    return mech


# -------------------------
# Пример использования (док‑тест)
# -------------------------

if __name__ == "__main__":  # pragma: no cover
    mech = build_default_mechanism()
    user = "01J2ZK5R3TS6Q4H2P8XWY9ABCD"
    region = "EEA"

    # До согласия — analytics запрещена
    d0 = mech.decide(user, Purpose.ANALYTICS.value, region, age=25, gpc_signal=False)
    print("pre-consent analytics:", d0.decision, d0.reason)

    # Даем согласие на analytics
    mech.grant(user, Purpose.ANALYTICS.value, region, source="web")
    d1 = mech.decide(user, Purpose.ANALYTICS.value, region, age=25, gpc_signal=False)
    print("post-consent analytics:", d1.decision, d1.reason)

    # В US без согласия реклама блокируется GPC
    d2 = mech.decide(user, Purpose.ADS.value, "US", age=25, gpc_signal=True)
    print("us ads with gpc:", d2.decision, d2.reason)
