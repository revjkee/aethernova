# zero-trust-core/zero_trust/session/revocation.py
# -*- coding: utf-8 -*-
"""
Единый сервис отзыва токенов/сессий для Zero-Trust ядра.

Возможности:
- Отзыв по JTI (конкретный токен), SID (сессия) и по «семейству» сессий (например, все refresh в «семействе»).
- Причины/метаданные отзыва, TTL/истечения, идемпотентность.
- Атомарность в Redis (Lua) + InMemory fallback без внешних зависимостей.
- Публикация событий в Redis Streams (XADD) или noop.
- Хэширование идентификаторов (salted SHA-256) для приватности при хранении/передаче.
- Проверка состояния: `is_revoked(jti, sid, family)` возвращает флаг и причину.
- Совместимость: ожидает стандартные JWT/PASETO claims: jti, sid, optional sfid (session_family).

Окружение:
- REV_REDIS_URL=redis://127.0.0.1:6379/0 (если недоступно — in-memory)
- REV_NAMESPACE=zt:rev:
- REV_EVENT_STREAM=revocation-events
- REV_SALT=случайная строка для хэширования идентификаторов
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from hashlib import sha256
from typing import Any, Dict, Mapping, Optional, Tuple

logger = logging.getLogger("zero_trust.revocation")
logger.setLevel(logging.INFO)

# Опциональная зависимость: redis.asyncio
_HAS_REDIS = False
try:  # pragma: no cover
    from redis.asyncio import Redis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False


# ==============================
# Модель и утилиты
# ==============================

def _now() -> int:
    return int(time.time())

def _btoi(x: Optional[bytes]) -> Optional[int]:
    if not x:
        return None
    try:
        return int(x.decode("ascii"))
    except Exception:
        return None

def _salt() -> str:
    return os.getenv("REV_SALT", "default-salt-change-me")

def _hash_id(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    h = sha256()
    h.update(_salt().encode("utf-8"))
    h.update(b"|")
    h.update(value.encode("utf-8"))
    return h.hexdigest()

class Reason:
    USER_LOGOUT = "user_logout"
    PASSWORD_RESET = "password_reset"
    ADMIN_REVOKE = "admin_revoke"
    TOKEN_REUSE = "token_reuse_detected"
    BREACH_SUSPECTED = "breach_suspected"
    MFA_RESET = "mfa_reset"
    SESSION_EXPIRED = "session_expired"
    OTHER = "other"

@dataclass
class RevocationRecord:
    scope: str               # jti|sid|family
    key: str                 # хэшированный идентификатор
    reason: str              # Reason.*
    created_at: int          # epoch seconds
    expires_at: int          # epoch seconds (ожидаемое истечение токена/сессии)
    meta: Dict[str, Any]     # произвольные атрибуты (не PII)

@dataclass
class CheckResult:
    revoked: bool
    scope: Optional[str] = None  # jti|sid|family
    reason: Optional[str] = None
    record: Optional[RevocationRecord] = None


# ==============================
# Бэкенд интерфейс
# ==============================

class RevocationBackend:
    async def revoke_jti(self, jti: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        raise NotImplementedError

    async def revoke_sid(self, sid: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        raise NotImplementedError

    async def revoke_family(self, family: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        raise NotImplementedError

    async def is_revoked(self, jti: Optional[str], sid: Optional[str], family: Optional[str]) -> CheckResult:
        raise NotImplementedError

    async def get_status(self, scope: str, key: str) -> Optional[RevocationRecord]:
        raise NotImplementedError

    async def publish_event(self, record: RevocationRecord) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# ==============================
# In-memory backend (fallback)
# ==============================

class InMemoryBackend(RevocationBackend):
    def __init__(self, namespace: str = "zt:rev:"):
        self.ns = namespace
        self._store: Dict[str, RevocationRecord] = {}
        self._lock = asyncio.Lock()

    def _nk(self, scope: str, key: str) -> str:
        return f"{self.ns}{scope}:{key}"

    async def revoke_jti(self, jti: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._write("jti", jti, expires_at, reason, meta)

    async def revoke_sid(self, sid: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._write("sid", sid, expires_at, reason, meta)

    async def revoke_family(self, family: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._write("family", family, expires_at, reason, meta)

    async def _write(self, scope: str, raw: str, exp: int, reason: str, meta: Dict[str, Any] | None) -> bool:
        key = _hash_id(raw)
        rec = RevocationRecord(scope=scope, key=key, reason=reason, created_at=_now(), expires_at=exp, meta=meta or {})
        nk = self._nk(scope, key)
        async with self._lock:
            prev = self._store.get(nk)
            if prev:
                # продлеваем TTL до max(prev, new)
                prev.expires_at = max(prev.expires_at, exp)
                prev.reason = prev.reason or reason
                prev.meta.update(rec.meta)
                self._store[nk] = prev
            else:
                self._store[nk] = rec
        return True

    async def is_revoked(self, jti: Optional[str], sid: Optional[str], family: Optional[str]) -> CheckResult:
        now = _now()
        async with self._lock:
            for scope, raw in (("jti", jti), ("sid", sid), ("family", family)):
                if not raw:
                    continue
                key = self._nk(scope, _hash_id(raw))
                rec = self._store.get(key)
                if rec and rec.expires_at >= now:
                    return CheckResult(True, scope, rec.reason, rec)
                # очистка просроченных
                if rec and rec.expires_at < now:
                    self._store.pop(key, None)
        return CheckResult(False)

    async def get_status(self, scope: str, key: str) -> Optional[RevocationRecord]:
        nk = self._nk(scope, key)
        async with self._lock:
            return self._store.get(nk)

    async def publish_event(self, record: RevocationRecord) -> None:
        # noop в памяти
        return

    async def close(self) -> None:
        self._store.clear()


# ==============================
# Redis backend (атомарные Lua)
# ==============================

# Скрипт: установить запись и TTL=max(текущий, новый). Храним JSON в value.
# KEYS[1] - ключ, ARGV: now, expires_at, json
# Возвращает: 1 если установлено/обновлено, ttl_ms
_REDIS_UPSERT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local expires_at = tonumber(ARGV[2])
local payload = ARGV[3]
local ttl_ms_new = math.max(0, (expires_at - now) * 1000)

local exists = redis.call('EXISTS', key)
if exists == 1 then
  -- прочитаем текущий TTL и payload (для совместимости можно просто обновить TTL)
  local pttl = redis.call('PTTL', key)
  if pttl < 0 then
    pttl = 0
  end
  local ttl_ms = math.max(pttl, ttl_ms_new)
  redis.call('SET', key, payload, 'PX', ttl_ms)
  return {1, ttl_ms}
else
  redis.call('SET', key, payload, 'PX', ttl_ms_new)
  return {1, ttl_ms_new}
end
"""

class RedisBackend(RevocationBackend):
    def __init__(self, redis: "Redis", namespace: str = "zt:rev:", event_stream: str = "revocation-events"):
        if not _HAS_REDIS:
            raise RuntimeError("redis.asyncio is not available")
        self.r = redis
        self.ns = namespace
        self.stream = event_stream
        self._sha_upsert: Optional[str] = None

    async def _ensure_scripts(self):
        if self._sha_upsert is None:
            self._sha_upsert = await self.r.script_load(_REDIS_UPSERT_LUA)

    def _k(self, scope: str, raw: str) -> str:
        return f"{self.ns}{scope}:{_hash_id(raw)}"

    async def revoke_jti(self, jti: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._upsert("jti", jti, expires_at, reason, meta)

    async def revoke_sid(self, sid: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._upsert("sid", sid, expires_at, reason, meta)

    async def revoke_family(self, family: str, expires_at: int, reason: str, meta: Dict[str, Any] | None = None) -> bool:
        return await self._upsert("family", family, expires_at, reason, meta)

    async def _upsert(self, scope: str, raw: str, exp: int, reason: str, meta: Dict[str, Any] | None) -> bool:
        await self._ensure_scripts()
        now = _now()
        rec = RevocationRecord(scope=scope, key=_hash_id(raw), reason=reason, created_at=now, expires_at=exp, meta=meta or {})
        payload = json.dumps(asdict(rec), separators=(",", ":"), ensure_ascii=False)
        try:
            res = await self.r.evalsha(self._sha_upsert, 1, self._k(scope, raw), now, exp, payload)  # type: ignore
            # res = {1, ttl_ms}
            await self.publish_event(rec)
            return True if res and int(res[0]) == 1 else False
        except Exception as e:
            logger.exception("Redis revoke error: %s", e)
            return False

    async def is_revoked(self, jti: Optional[str], sid: Optional[str], family: Optional[str]) -> CheckResult:
        now = _now()
        try:
            # Порядок проверки: JTI -> SID -> FAMILY
            for scope, raw in (("jti", jti), ("sid", sid), ("family", family)):
                if not raw:
                    continue
                key = self._k(scope, raw)
                val = await self.r.get(key)  # type: ignore
                if not val:
                    continue
                try:
                    data = json.loads(val.decode("utf-8"))
                    exp = int(data.get("expires_at", now - 1))
                    if exp >= now:
                        rec = RevocationRecord(**data)
                        return CheckResult(True, scope, rec.reason, rec)
                except Exception:
                    # При повреждении записей — считаем отозванным (безопасная семантика)
                    ttl = await self.r.ttl(key)  # type: ignore
                    return CheckResult(True, scope, Reason.OTHER, None) if (ttl is None or ttl > 0) else CheckResult(False)
        except Exception as e:
            logger.exception("Redis is_revoked error: %s", e)
            # На сбоях: безопасный дефолт — НЕ считать отозванным, чтобы не допускать ложные блокировки.
            return CheckResult(False)
        return CheckResult(False)

    async def get_status(self, scope: str, key: str) -> Optional[RevocationRecord]:
        try:
            val = await self.r.get(f"{self.ns}{scope}:{key}")  # type: ignore
            if not val:
                return None
            data = json.loads(val.decode("utf-8"))
            return RevocationRecord(**data)
        except Exception:
            return None

    async def publish_event(self, record: RevocationRecord) -> None:
        # Публикуем в Redis Streams (если доступно)
        try:
            await self.r.xadd(self.stream, {
                b"scope": record.scope.encode(),
                b"key": record.key.encode(),
                b"reason": record.reason.encode(),
                b"created_at": str(record.created_at).encode(),
                b"expires_at": str(record.expires_at).encode(),
                b"meta": json.dumps(record.meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            })  # type: ignore
        except Exception:
            # Логи — без выбрасывания ошибки
            logger.debug("Failed to publish revocation event", exc_info=True)

    async def close(self) -> None:
        try:
            await self.r.aclose()  # type: ignore[attr-defined]
        except Exception:
            try:
                await self.r.close()  # type: ignore
            except Exception:
                pass


# ==============================
# Фабрика бэкенда
# ==============================

async def build_backend_from_env() -> RevocationBackend:
    """
    Возвращает RedisBackend при наличии библиотеки/доступности Redis, иначе InMemoryBackend.
    """
    ns = os.getenv("REV_NAMESPACE", "zt:rev:")
    if _HAS_REDIS:
        url = os.getenv("REV_REDIS_URL", "redis://127.0.0.1:6379/0")
        try:
            r = Redis.from_url(url, encoding="utf-8", decode_responses=False)  # type: ignore
            await r.ping()
            return RedisBackend(r, namespace=ns, event_stream=os.getenv("REV_EVENT_STREAM", "revocation-events"))
        except Exception as e:
            logger.warning("Redis unavailable (%s), using InMemory backend", e)
    return InMemoryBackend(namespace=ns)


# ==============================
# Высокоуровневый сервис
# ==============================

class RevocationService:
    """
    Высокоуровневое API с хэшированием идентификаторов и валидацией входа.
    """
    def __init__(self, backend: RevocationBackend):
        self.backend = backend

    @staticmethod
    def _validate_exp(expires_at: int) -> None:
        if not isinstance(expires_at, int) or expires_at <= _now():
            raise ValueError("expires_at must be epoch seconds in the future")

    async def revoke_token(self, jti: str, exp: int, reason: str = Reason.OTHER, meta: Dict[str, Any] | None = None) -> bool:
        self._validate_exp(exp)
        return await self.backend.revoke_jti(jti, exp, reason, meta)

    async def revoke_session(self, sid: str, exp: int, reason: str = Reason.USER_LOGOUT, meta: Dict[str, Any] | None = None) -> bool:
        self._validate_exp(exp)
        return await self.backend.revoke_sid(sid, exp, reason, meta)

    async def revoke_family(self, family: str, exp: int, reason: str = Reason.ADMIN_REVOKE, meta: Dict[str, Any] | None = None) -> bool:
        self._validate_exp(exp)
        return await self.backend.revoke_family(family, exp, reason, meta)

    async def is_revoked(self, claims: Mapping[str, Any]) -> CheckResult:
        """
        Быстрая проверка для JWT/PASETO claims. Поддерживает поля: jti, sid, sfid (session family id).
        Возвращает CheckResult с деталями.
        """
        jti = claims.get("jti") if isinstance(claims, Mapping) else None
        sid = claims.get("sid") if isinstance(claims, Mapping) else None
        sfid = claims.get("sfid") if isinstance(claims, Mapping) else None
        if not jti and not sid and not sfid:
            return CheckResult(False)
        return await self.backend.is_revoked(str(jti) if jti else None,
                                            str(sid) if sid else None,
                                            str(sfid) if sfid else None)

    async def close(self) -> None:
        await self.backend.close()


# ==============================
# Пример использования (докстринг)
# ==============================

"""
Пример:
    backend = await build_backend_from_env()
    svc = RevocationService(backend)

    # Отзыв конкретного токена (JTI)
    await svc.revoke_token(jti="abc-123", exp=int(time.time())+3600, reason=Reason.TOKEN_REUSE, meta={"sub":"u1"})

    # Отзыв всей сессии (SID)
    await svc.revoke_session(sid="sid-456", exp=int(time.time())+86400, reason=Reason.USER_LOGOUT)

    # Отзыв семейства (например, все refresh по устройству)
    await svc.revoke_family(family="sfid-789", exp=int(time.time())+2592000, reason=Reason.ADMIN_REVOKE)

    # Проверка при авторизации запроса:
    claims = {"jti":"abc-123","sid":"sid-456"}
    res = await svc.is_revoked(claims)
    if res.revoked:
        # отклонить запрос с причиной res.reason и областью res.scope
        pass
"""
