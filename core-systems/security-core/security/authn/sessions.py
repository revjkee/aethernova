# -*- coding: utf-8 -*-
"""
security-core.sessions — управление сессиями и refresh-токенами.

Возможности:
- Opaque-токены с HMAC-SHA256 и ротацией ключей (kid.<b64url(payload|mac)>).
- Серверные записи сессий: скользящий ACCESS_TTL и абсолютный ABSOLUTE_TTL.
- Refresh с rotate-on-use и анти-replay (one-time) + черный список использованных.
- Pre-session (PSID) для step-up MFA и онбординга MFA.
- Привязка к устройству (device_id), опциональный pin по IP и User-Agent.
- Ограничение количества одновременных сессий на пользователя (policy evict_oldest|reject_new).
- Индексация по пользователю/устройству, массовая отзывка, пометка «suspicious».
- Потокобезопасность (RLock), события хуков (audit) на create/refresh/revoke/upgrade.
- InMemory реализация; заготовка AsyncRedisStore (опционально).

Зависимости: только стандартная библиотека Python.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

# ======================================================================
# Утилиты
# ======================================================================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _ts() -> float:
    return time.time()

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _randbytes(n: int = 32) -> bytes:
    return os.urandom(n)

# ======================================================================
# Конфигурация и политики
# ======================================================================

@dataclass(frozen=True)
class SessionPolicy:
    access_ttl: timedelta = timedelta(minutes=15)      # sliding
    refresh_ttl: timedelta = timedelta(days=30)        # absolute
    absolute_ttl: timedelta = timedelta(days=7)        # абсолютный life-time access-сессии
    pre_session_ttl: timedelta = timedelta(minutes=5)
    pin_ip: bool = True
    pin_ua: bool = True
    max_user_sessions: int = 10
    on_limit: str = "evict_oldest"  # "evict_oldest" | "reject_new"
    device_required_for_admin: bool = False

# ======================================================================
# Модель данных
# ======================================================================

@dataclass
class PreSession:
    id: str
    user_id: str
    username: str
    device_id: str
    created_at: datetime
    expires_at: datetime
    labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class SessionRecord:
    id: str
    user_id: str
    username: str
    device_id: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime               # скользящее окно
    absolute_expires_at: datetime      # абсолютный предел
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    mfa_level: Optional[str] = None    # AAL1|AAL2|AAL3
    risk_score: int = 0
    suspicious: bool = False
    revoked: bool = False
    labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class RefreshRecord:
    id: str
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime               # абсолютный срок
    used: bool = False                 # анти-replay
    labels: Dict[str, str] = field(default_factory=dict)

# ======================================================================
# События (hooks) — для аудита/метрик
# ======================================================================

@dataclass(frozen=True)
class SessionEvent:
    kind: str               # created|refreshed|revoked|upgraded|marked_suspicious|pruned
    at: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    refresh_id: Optional[str] = None
    meta: Mapping[str, Any] = field(default_factory=dict)

EventHook = Callable[[SessionEvent], None]

# ======================================================================
# Токены: HMAC + ротация ключей
# ======================================================================

class TokenCodec:
    """
    Формат токена: "<kid>.<b64url(nonce(32B)||ts(8B)||mac(32B))>"
    mac = HMAC-SHA256( key[kid], nonce||ts||prefix )
    prefix: b"SID", b"RID", b"PSID"
    """
    def __init__(self, keyring: Mapping[str, bytes], active_kid: str):
        if active_kid not in keyring:
            raise ValueError("active_kid must exist in keyring")
        self._keyring = dict(keyring)
        self._active_kid = active_kid

    @property
    def active_kid(self) -> str:
        return self._active_kid

    def rotate(self, new_kid: str, key: bytes) -> None:
        self._keyring[new_kid] = key
        self._active_kid = new_kid

    def _sign(self, kid: str, payload: bytes, prefix: bytes) -> bytes:
        key = self._keyring.get(kid)
        if not key:
            raise ValueError("unknown kid")
        mac = hmac.new(key, payload + prefix, hashlib.sha256).digest()
        return payload + mac

    def _verify(self, token: str, prefix: bytes) -> Tuple[str, bytes, float]:
        try:
            kid, body = token.split(".", 1)
            raw = _b64u_dec(body)
            if len(raw) != 32 + 8 + 32:
                raise ValueError("bad token length")
            nonce = raw[:32]
            ts_bytes = raw[32:40]
            mac = raw[40:]
            key = self._keyring.get(kid)
            if not key:
                raise ValueError("unknown kid")
            expected = hmac.new(key, nonce + ts_bytes + prefix, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected):
                raise ValueError("bad mac")
            ts = int.from_bytes(ts_bytes, "big", signed=False)
            return kid, nonce, float(ts)
        except Exception as e:
            raise ValueError(f"invalid token: {e}")

    def mint(self, prefix: bytes) -> str:
        kid = self._active_kid
        nonce = _randbytes(32)
        ts_bytes = int(_ts()).to_bytes(8, "big", signed=False)
        signed = self._sign(kid, nonce + ts_bytes, prefix)
        return f"{kid}.{_b64u(signed)}"

    def verify_sid(self, token: str) -> Tuple[str, bytes, float]:
        return self._verify(token, b"SID")

    def verify_rid(self, token: str) -> Tuple[str, bytes, float]:
        return self._verify(token, b"RID")

    def verify_psid(self, token: str) -> Tuple[str, bytes, float]:
        return self._verify(token, b"PSID")

    def new_sid(self) -> str:
        return self.mint(b"SID")

    def new_rid(self) -> str:
        return self.mint(b"RID")

    def new_psid(self) -> str:
        return self.mint(b"PSID")

# ======================================================================
# Интерфейс стора
# ======================================================================

class SessionStore:
    """
    Базовый интерфейс стора. Реализации должны обеспечивать атомарность refresh
    (rotate-on-use) и устойчивость к гонкам.
    """
    def create_pre_session(self, user_id: str, username: str, device_id: str, *, labels: Optional[Mapping[str, str]] = None) -> PreSession: ...
    def get_pre_session(self, psid: str) -> Optional[PreSession]: ...
    def upgrade_pre_session(self, psid: str, *, ip: Optional[str], ua: Optional[str], mfa_level: Optional[str], risk_score: int) -> Tuple[SessionRecord, RefreshRecord]: ...
    def create_session(self, user_id: str, username: str, device_id: str, *, ip: Optional[str], ua: Optional[str], mfa_level: Optional[str], risk_score: int, labels: Optional[Mapping[str, str]] = None) -> Tuple[SessionRecord, RefreshRecord]: ...
    def get_session(self, sid: str, *, ip: Optional[str], ua: Optional[str]) -> Optional[SessionRecord]: ...
    def touch(self, sid: str) -> bool: ...
    def refresh(self, rid: str, *, ip: Optional[str], ua: Optional[str]) -> Tuple[Optional[SessionRecord], Optional[RefreshRecord]]: ...
    def revoke(self, sid: Optional[str] = None, rid: Optional[str] = None, reason: Optional[str] = None) -> None: ...
    def revoke_all_for_user(self, user_id: str, *, keep_device_id: Optional[str] = None, reason: Optional[str] = None) -> int: ...
    def list_active_for_user(self, user_id: str) -> List[SessionRecord]: ...
    def mark_suspicious(self, sid: str, reason: str) -> bool: ...
    def prune_expired(self) -> int: ...
    def register_hook(self, cb: EventHook) -> None: ...

# ======================================================================
# In-Memory реализация
# ======================================================================

class InMemorySessionStore(SessionStore):
    def __init__(self, codec: TokenCodec, policy: SessionPolicy):
        self._codec = codec
        self._policy = policy
        self._lock = threading.RLock()
        # Основные индексы
        self._sessions: Dict[str, SessionRecord] = {}
        self._refresh: Dict[str, RefreshRecord] = {}
        self._pre: Dict[str, PreSession] = {}
        self._by_user: Dict[str, List[str]] = {}      # user_id -> [sid...], упорядочены по created_at
        self._rid_used: set[str] = set()              # анти-replay (RID, которые были использованы)
        self._hooks: List[EventHook] = []

    # --------------- Вспомогательные ---------------

    def _emit(self, ev: SessionEvent) -> None:
        for h in list(self._hooks):
            try:
                h(ev)
            except Exception:
                pass

    def register_hook(self, cb: EventHook) -> None:
        with self._lock:
            self._hooks.append(cb)

    def _now(self) -> datetime:
        return _utcnow()

    def _apply_user_limit(self, user_id: str) -> None:
        sids = self._by_user.get(user_id, [])
        limit = self._policy.max_user_sessions
        if len(sids) <= limit:
            return
        if self._policy.on_limit == "reject_new":
            raise RuntimeError("max user sessions reached")
        # evict_oldest
        to_evict = len(sids) - limit
        for sid in list(sids)[:to_evict]:
            self._revoke_sid(sid, reason="evict_oldest")

    def _bind_ok(self, rec: SessionRecord, ip: Optional[str], ua: Optional[str]) -> bool:
        if self._policy.pin_ip and rec.ip and ip and rec.ip != ip:
            return False
        if self._policy.pin_ua and rec.user_agent and ua and rec.user_agent != ua:
            return False
        return True

    def _revoke_sid(self, sid: str, reason: Optional[str]) -> None:
        rec = self._sessions.pop(sid, None)
        if not rec:
            return
        rec.revoked = True
        # убрать из индекса
        arr = self._by_user.get(rec.user_id, [])
        if sid in arr:
            arr.remove(sid)
        # удалить все refresh, связанные с sid
        doomed = [rid for rid, r in self._refresh.items() if r.session_id == sid]
        for rid in doomed:
            self._refresh.pop(rid, None)
        self._emit(SessionEvent(kind="revoked", at=self._now(), user_id=rec.user_id, session_id=sid, meta={"reason": reason or "revoked"}))

    def _new_session(self, user_id: str, username: str, device_id: str, ip: Optional[str], ua: Optional[str], mfa_level: Optional[str], risk_score: int, labels: Optional[Mapping[str, str]]) -> Tuple[str, SessionRecord]:
        now = self._now()
        sid = self._codec.new_sid()
        rec = SessionRecord(
            id=sid,
            user_id=user_id,
            username=username,
            device_id=device_id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + self._policy.access_ttl,
            absolute_expires_at=now + self._policy.absolute_ttl,
            ip=ip,
            user_agent=ua,
            mfa_level=mfa_level,
            risk_score=risk_score,
            labels=dict(labels or {}),
        )
        self._sessions[sid] = rec
        self._by_user.setdefault(user_id, []).append(sid)
        return sid, rec

    def _new_refresh(self, sid: str, user_id: str, labels: Optional[Mapping[str, str]]) -> Tuple[str, RefreshRecord]:
        now = self._now()
        rid = self._codec.new_rid()
        rr = RefreshRecord(
            id=rid,
            session_id=sid,
            user_id=user_id,
            created_at=now,
            expires_at=now + self._policy.refresh_ttl,
            labels=dict(labels or {}),
        )
        self._refresh[rid] = rr
        return rid, rr

    # --------------- API ---------------

    def create_pre_session(self, user_id: str, username: str, device_id: str, *, labels: Optional[Mapping[str, str]] = None) -> PreSession:
        with self._lock:
            psid = self._codec.new_psid()
            now = self._now()
            pre = PreSession(
                id=psid,
                user_id=user_id,
                username=username,
                device_id=device_id,
                created_at=now,
                expires_at=now + self._policy.pre_session_ttl,
                labels=dict(labels or {}),
            )
            self._pre[psid] = pre
            self._emit(SessionEvent(kind="created", at=now, user_id=user_id, session_id=None, refresh_id=None, meta={"pre_session": True}))
            return pre

    def get_pre_session(self, psid: str) -> Optional[PreSession]:
        with self._lock:
            pre = self._pre.get(psid)
            if not pre:
                return None
            if self._now() > pre.expires_at:
                self._pre.pop(psid, None)
                return None
            return pre

    def upgrade_pre_session(self, psid: str, *, ip: Optional[str], ua: Optional[str], mfa_level: Optional[str], risk_score: int) -> Tuple[SessionRecord, RefreshRecord]:
        with self._lock:
            pre = self._pre.pop(psid, None)
            if not pre:
                raise KeyError("invalid pre-session")
            sid, srec = self._new_session(pre.user_id, pre.username, pre.device_id, ip, ua, mfa_level, risk_score, labels={"upgraded": "true"})
            self._apply_user_limit(pre.user_id)
            rid, rrec = self._new_refresh(sid, pre.user_id, labels=None)
            self._emit(SessionEvent(kind="upgraded", at=self._now(), user_id=pre.user_id, session_id=sid, refresh_id=rid, meta={}))
            return srec, rrec

    def create_session(self, user_id: str, username: str, device_id: str, *, ip: Optional[str], ua: Optional[str], mfa_level: Optional[str], risk_score: int, labels: Optional[Mapping[str, str]] = None) -> Tuple[SessionRecord, RefreshRecord]:
        with self._lock:
            sid, srec = self._new_session(user_id, username, device_id, ip, ua, mfa_level, risk_score, labels)
            self._apply_user_limit(user_id)
            rid, rrec = self._new_refresh(sid, user_id, labels=None)
            self._emit(SessionEvent(kind="created", at=self._now(), user_id=user_id, session_id=sid, refresh_id=rid, meta={}))
            return srec, rrec

    def get_session(self, sid: str, *, ip: Optional[str], ua: Optional[str]) -> Optional[SessionRecord]:
        with self._lock:
            rec = self._sessions.get(sid)
            if not rec:
                return None
            now = self._now()
            if rec.revoked or now > rec.expires_at or now > rec.absolute_expires_at:
                # истекла/отозвана
                self._revoke_sid(sid, reason="expired")
                return None
            # pinning
            if not self._bind_ok(rec, ip, ua):
                # пометим как подозрительную и отзовем
                rec.suspicious = True
                self._revoke_sid(sid, reason="pinning_mismatch")
                self._emit(SessionEvent(kind="marked_suspicious", at=now, user_id=rec.user_id, session_id=sid, meta={"reason": "pinning_mismatch"}))
                return None
            return rec

    def touch(self, sid: str) -> bool:
        with self._lock:
            rec = self._sessions.get(sid)
            if not rec:
                return False
            now = self._now()
            if now > rec.absolute_expires_at:
                self._revoke_sid(sid, reason="absolute_expired")
                return False
            if now <= rec.expires_at:
                # продлим скользящее окно
                rec.last_seen_at = now
                rec.expires_at = now + self._policy.access_ttl
                return True
            # иначе — истекла
            self._revoke_sid(sid, reason="expired")
            return False

    def refresh(self, rid: str, *, ip: Optional[str], ua: Optional[str]) -> Tuple[Optional[SessionRecord], Optional[RefreshRecord]]:
        with self._lock:
            rr = self._refresh.get(rid)
            if not rr:
                return None, None
            now = self._now()
            if rr.used or now > rr.expires_at:
                # анти-replay
                self._refresh.pop(rid, None)
                self._rid_used.add(rid)
                return None, None
            srec = self._sessions.get(rr.session_id)
            if not srec:
                # связанной сессии уже нет
                rr.used = True
                self._refresh.pop(rid, None)
                self._rid_used.add(rid)
                return None, None
            if srec.revoked or now > srec.absolute_expires_at:
                self._revoke_sid(srec.id, reason="absolute_expired")
                rr.used = True
                self._refresh.pop(rid, None)
                self._rid_used.add(rid)
                return None, None
            # pinning при refresh
            if not self._bind_ok(srec, ip, ua):
                srec.suspicious = True
                self._revoke_sid(srec.id, reason="pinning_mismatch_refresh")
                rr.used = True
                self._refresh.pop(rid, None)
                self._rid_used.add(rid)
                self._emit(SessionEvent(kind="marked_suspicious", at=now, user_id=srec.user_id, session_id=srec.id, meta={"reason": "pinning_mismatch_refresh"}))
                return None, None
            # rotate SID и RID
            # 1) создаем новый SID на основе старых атрибутов
            new_sid, new_srec = self._new_session(
                srec.user_id, srec.username, srec.device_id,
                srec.ip, srec.user_agent, srec.mfa_level, srec.risk_score, labels=srec.labels
            )
            # переносим индекс пользователя (добавиться уже добавился; удалим старый)
            arr = self._by_user.get(srec.user_id, [])
            if srec.id in arr:
                arr.remove(srec.id)
            # отзываем старый SID
            srec.revoked = True
            self._sessions.pop(srec.id, None)
            # 2) помечаем использованный RID и создаем новый
            rr.used = True
            self._refresh.pop(rid, None)
            self._rid_used.add(rid)
            new_rid, new_rr = self._new_refresh(new_sid, srec.user_id, labels=None)
            self._emit(SessionEvent(kind="refreshed", at=now, user_id=srec.user_id, session_id=new_sid, refresh_id=new_rid, meta={"rotated_from": srec.id}))
            return new_srec, new_rr

    def revoke(self, sid: Optional[str] = None, rid: Optional[str] = None, reason: Optional[str] = None) -> None:
        with self._lock:
            if sid:
                self._revoke_sid(sid, reason=reason)
            if rid:
                rr = self._refresh.pop(rid, None)
                if rr:
                    rr.used = True
                    self._rid_used.add(rid)
                    self._emit(SessionEvent(kind="revoked", at=self._now(), user_id=rr.user_id, session_id=rr.session_id, refresh_id=rid, meta={"reason": reason or "revoked"}))

    def revoke_all_for_user(self, user_id: str, *, keep_device_id: Optional[str] = None, reason: Optional[str] = None) -> int:
        with self._lock:
            sids = list(self._by_user.get(user_id, []))
            count = 0
            for sid in sids:
                rec = self._sessions.get(sid)
                if not rec:
                    continue
                if keep_device_id and rec.device_id == keep_device_id:
                    continue
                self._revoke_sid(sid, reason=reason or "bulk_revoke")
                count += 1
            return count

    def list_active_for_user(self, user_id: str) -> List[SessionRecord]:
        with self._lock:
            out: List[SessionRecord] = []
            for sid in list(self._by_user.get(user_id, [])):
                rec = self._sessions.get(sid)
                if not rec:
                    continue
                now = self._now()
                if rec.revoked or now > rec.expires_at or now > rec.absolute_expires_at:
                    self._revoke_sid(sid, reason="expired")
                    continue
                out.append(rec)
            return sorted(out, key=lambda r: (r.created_at, r.id))

    def mark_suspicious(self, sid: str, reason: str) -> bool:
        with self._lock:
            rec = self._sessions.get(sid)
            if not rec:
                return False
            rec.suspicious = True
            self._emit(SessionEvent(kind="marked_suspicious", at=self._now(), user_id=rec.user_id, session_id=sid, meta={"reason": reason}))
            return True

    def prune_expired(self) -> int:
        with self._lock:
            now = self._now()
            removed = 0
            # sessions
            for sid, rec in list(self._sessions.items()):
                if rec.revoked or now > rec.expires_at or now > rec.absolute_expires_at:
                    self._revoke_sid(sid, reason="expired/prune")
                    removed += 1
            # refresh
            for rid, rr in list(self._refresh.items()):
                if rr.used or now > rr.expires_at:
                    self._refresh.pop(rid, None)
                    self._rid_used.add(rid)
            if removed:
                self._emit(SessionEvent(kind="pruned", at=now, meta={"removed": removed}))
            return removed

# ======================================================================
# Заготовка Redis (опционально). Реализацию заполните по потребности.
# ======================================================================

class AsyncRedisSessionStore(SessionStore):
    """
    Заготовка под Redis (redis.asyncio). Для продакшена:
    - используйте ключевые пространства: sess:<sid>, ref:<rid>, pre:<psid>, uidx:<user_id>
    - выставляйте EX по TTL, применяйте Lua-скрипты для атомарного refresh (rotate).
    - храните минимальные поля (JSON/Hash), индексы по user_id.
    Здесь оставлен скелет для совместимости API.
    """
    def __init__(self, codec: TokenCodec, policy: SessionPolicy, redis_client: Any):
        raise NotImplementedError("Implement using redis.asyncio with Lua for atomic refresh")

# ======================================================================
# Фабрика по умолчанию
# ======================================================================

def default_inmemory_store(secret: bytes, policy: Optional[SessionPolicy] = None) -> InMemorySessionStore:
    """
    Быстрая фабрика in-memory стора с единственным активным ключом kid="v1".
    В продакшене используйте KMS/Vault и периодическую ротацию ключей.
    """
    codec = TokenCodec(keyring={"v1": secret}, active_kid="v1")
    return InMemorySessionStore(codec=codec, policy=policy or SessionPolicy())

# ======================================================================
# Пример подключаемых хуков (аудит/метрики)
# ======================================================================

def audit_hook_printer(ev: SessionEvent) -> None:
    # Пример: отправьте в ваш аудито-роутер/логгер
    # Здесь — лишь иллюстрация; удалите в продакшене.
    pass

# ======================================================================
# Публичный интерфейс
# ======================================================================

__all__ = [
    "SessionPolicy",
    "PreSession",
    "SessionRecord",
    "RefreshRecord",
    "SessionEvent",
    "EventHook",
    "TokenCodec",
    "SessionStore",
    "InMemorySessionStore",
    "AsyncRedisSessionStore",
    "default_inmemory_store",
]
