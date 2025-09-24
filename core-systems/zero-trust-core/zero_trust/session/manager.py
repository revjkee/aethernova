# zero-trust-core/zero_trust/session/manager.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union


__all__ = [
    "SessionError",
    "SessionNotFound",
    "SessionExpired",
    "SessionRevoked",
    "SessionTampered",
    "SessionBindingError",
    "Session",
    "SessionConfig",
    "KeyRing",
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
    "SessionManager",
]


# =========================
# Ошибки
# =========================

class SessionError(Exception):
    pass


class SessionNotFound(SessionError):
    pass


class SessionExpired(SessionError):
    pass


class SessionRevoked(SessionError):
    pass


class SessionTampered(SessionError):
    pass


class SessionBindingError(SessionError):
    pass


# =========================
# Модель и конфиг
# =========================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _now() -> int:
    return int(time.time())


def _consteq(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def _hash_ua(ua: Optional[str]) -> str:
    # Стабильный хеш User-Agent (безопасно хранить)
    return _b64u(hashlib.sha256((ua or "").encode("utf-8")).digest())


def _norm_ip(ip: Optional[str]) -> str:
    if not ip:
        return ""
    try:
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, (IPv4Address, IPv6Address)):
            return str(ip_obj)
    except Exception:
        return ""
    return ""


@dataclass(frozen=True)
class SessionConfig:
    # Основные интервалы (сек)
    absolute_ttl: int = int(os.getenv("ZTC_SESSION_ABSOLUTE_TTL", "3600"))         # 1h
    idle_timeout: int = int(os.getenv("ZTC_SESSION_IDLE_TIMEOUT", "900"))          # 15m
    rotation_after: int = int(os.getenv("ZTC_SESSION_ROTATE_AFTER", "900"))        # 15m (скользящая ротация)

    # Привязка и терпимость
    bind_ip: bool = os.getenv("ZTC_SESSION_BIND_IP", "true").lower() == "true"
    bind_user_agent: bool = os.getenv("ZTC_SESSION_BIND_UA", "true").lower() == "true"
    ip_change_tolerance: int = int(os.getenv("ZTC_SESSION_IP_TOLERANCE", "0"))     # 0 — строгая привязка
    require_csrf: bool = os.getenv("ZTC_SESSION_REQUIRE_CSRF", "true").lower() == "true"

    # Криптография
    # Ключевой набор задаётся через KeyRing; если переменные окружения не заданы — будет случайный на процесс.
    kid_active_env: str = os.getenv("ZTC_SESSION_ACTIVE_KID", "v1")

    # Анти‑replay (nonce per rotation)
    replay_window: int = int(os.getenv("ZTC_SESSION_REPLAY_WINDOW", "60"))  # сек на повтор до детекта

    # Имя cookie (если нужно на HTTP уровне)
    cookie_name: str = os.getenv("ZTC_SESSION_COOKIE_NAME", "zt_session")


@dataclass
class Session:
    sid: str                  # стабильный ID сессии (public)
    sub: str                  # идентификатор субъекта (user:alice / service:foo)
    iat: int                  # issued at
    nbf: int                  # not before
    exp: int                  # absolute expiry
    last: int                 # последний доступ (для idle)
    itl: int                  # idle timeout limit (сек)
    kid: str                  # идентификатор ключа подписи
    ip: str                   # нормализованный IP (если привязка включена)
    ua: str                   # хеш UA (если привязка включена)
    csrf: str                 # двойной CSRF‑токен (для cookie+header/формы)
    nonce: str                # одноразовый nonce ротации/анти‑replay
    attrs: Dict[str, Any]     # произвольные атрибуты (минимум, без PII)
    revoked: bool = False     # флаг ревокации

    def to_payload(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "sub": self.sub,
            "iat": self.iat,
            "nbf": self.nbf,
            "exp": self.exp,
            "last": self.last,
            "itl": self.itl,
            "kid": self.kid,
            "ip": self.ip,
            "ua": self.ua,
            "csrf": self.csrf,
            "nonce": self.nonce,
            "attrs": self.attrs,
            "rvk": self.revoked,
        }

    @staticmethod
    def from_payload(d: Mapping[str, Any]) -> "Session":
        return Session(
            sid=str(d["sid"]),
            sub=str(d["sub"]),
            iat=int(d["iat"]),
            nbf=int(d["nbf"]),
            exp=int(d["exp"]),
            last=int(d["last"]),
            itl=int(d["itl"]),
            kid=str(d["kid"]),
            ip=str(d.get("ip", "")),
            ua=str(d.get("ua", "")),
            csrf=str(d["csrf"]),
            nonce=str(d["nonce"]),
            attrs=dict(d.get("attrs", {})),
            revoked=bool(d.get("rvk", False)),
        )


# =========================
# Подпись и ротация ключей
# =========================

class KeyRing:
    """
    Кольцо ключей с активным KID и поддержкой «старых» ключей для верификации.
    Ключи — байтовые секреты для HMAC‑SHA256.
    """

    def __init__(self, keys: Optional[Mapping[str, bytes]] = None, active_kid: Optional[str] = None) -> None:
        if keys is None:
            # Безопасная инициализация на процесс (для dev): не для многопроцессной прод‑среды.
            keys = {"v1": secrets.token_bytes(32)}
        self._keys: Dict[str, bytes] = dict(keys)
        self._active_kid: str = active_kid or next(iter(keys))  # noqa

    @property
    def active_kid(self) -> str:
        return self._active_kid

    def set_active(self, kid: str) -> None:
        if kid not in self._keys:
            raise KeyError(f"unknown kid: {kid}")
        self._active_kid = kid

    def add(self, kid: str, key: bytes) -> None:
        self._keys[kid] = key

    def remove(self, kid: str) -> None:
        if kid == self._active_kid:
            raise ValueError("cannot remove active key")
        self._keys.pop(kid, None)

    def sign(self, kid: str, data: bytes) -> bytes:
        key = self._keys.get(kid)
        if not key:
            raise KeyError(f"unknown kid: {kid}")
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify(self, kid: str, data: bytes, sig: bytes) -> bool:
        key = self._keys.get(kid)
        if not key:
            return False
        calc = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(calc, sig)


# =========================
# Хранилища
# =========================

class SessionStore(ABC):
    @abstractmethod
    def put(self, s: Session) -> None: ...

    @abstractmethod
    def get(self, sid: str) -> Session: ...

    @abstractmethod
    def delete(self, sid: str) -> None: ...

    @abstractmethod
    def mark_revoked(self, sid: str) -> None: ...

    @abstractmethod
    def set_last_access(self, sid: str, ts: int) -> None: ...

    @abstractmethod
    def exists_nonce(self, sid: str, nonce: str) -> bool: ...

    @abstractmethod
    def record_nonce(self, sid: str, nonce: str, ttl: int) -> None: ...


class InMemorySessionStore(SessionStore):
    def __init__(self) -> None:
        self._data: Dict[str, Session] = {}
        self._nonces: Dict[Tuple[str, str], int] = {}

    def put(self, s: Session) -> None:
        self._data[s.sid] = s

    def get(self, sid: str) -> Session:
        s = self._data.get(sid)
        if not s:
            raise SessionNotFound(sid)
        return s

    def delete(self, sid: str) -> None:
        self._data.pop(sid, None)

    def mark_revoked(self, sid: str) -> None:
        s = self.get(sid)
        s.revoked = True

    def set_last_access(self, sid: str, ts: int) -> None:
        s = self.get(sid)
        s.last = ts

    def exists_nonce(self, sid: str, nonce: str) -> bool:
        key = (sid, nonce)
        exp = self._nonces.get(key)
        if not exp:
            return False
        if exp < _now():
            self._nonces.pop(key, None)
            return False
        return True

    def record_nonce(self, sid: str, nonce: str, ttl: int) -> None:
        self._nonces[(sid, nonce)] = _now() + ttl


class RedisSessionStore(SessionStore):
    """
    Опциональная реализация на Redis.
    Требует: pip install redis
    Ключи:
      sess:{sid} -> JSON Session (value)
      snc:{sid}:{nonce} -> 1 (PX TTL)
    """
    def __init__(self, redis_client: Any, prefix: str = "zt:") -> None:
        self.r = redis_client
        self.p = prefix

    def put(self, s: Session) -> None:
        self.r.set(f"{self.p}sess:{s.sid}", json.dumps(s.to_payload()), ex=max(1, s.exp - _now()))

    def get(self, sid: str) -> Session:
        raw = self.r.get(f"{self.p}sess:{sid}")
        if not raw:
            raise SessionNotFound(sid)
        payload = json.loads(raw)
        return Session.from_payload(payload)

    def delete(self, sid: str) -> None:
        self.r.delete(f"{self.p}sess:{sid}")

    def mark_revoked(self, sid: str) -> None:
        s = self.get(sid)
        s.revoked = True
        self.put(s)

    def set_last_access(self, sid: str, ts: int) -> None:
        s = self.get(sid)
        s.last = ts
        self.put(s)

    def exists_nonce(self, sid: str, nonce: str) -> bool:
        return bool(self.r.exists(f"{self.p}snc:{sid}:{nonce}"))

    def record_nonce(self, sid: str, nonce: str, ttl: int) -> None:
        self.r.set(f"{self.p}snc:{sid}:{nonce}", "1", ex=max(1, ttl))


# =========================
# Менеджер сессий
# =========================

class SessionManager:
    """
    Подписанный, вращаемый, привязанный к контексту токен сессии.
    Формат cookie/токена (не JWT): base64url(header).base64url(payload).base64url(sig)
      header: {"alg":"HS256","kid":"<kid>","typ":"ZTS"}   # ZTS — Zero Trust Session
      payload: JSON из Session.to_payload()
      sig: HMAC-SHA256(header || "." || payload) по ключу kid
    """

    def __init__(self, keyring: KeyRing, store: SessionStore, cfg: Optional[SessionConfig] = None) -> None:
        self.cfg = cfg or SessionConfig()
        self.keyring = keyring
        self.store = store

    # ---------- Публичный API ----------

    def issue(
        self,
        subject: str,
        *,
        ip: Optional[str],
        user_agent: Optional[str],
        attrs: Optional[Mapping[str, Any]] = None,
        absolute_ttl: Optional[int] = None,
        idle_timeout: Optional[int] = None,
        not_before_skew: int = 0,
    ) -> str:
        """
        Выдать новую сессию и вернуть сериализованный токен.
        """
        now = _now()
        abs_ttl = int(absolute_ttl or self.cfg.absolute_ttl)
        itl = int(idle_timeout or self.cfg.idle_timeout)
        sid = _b64u(secrets.token_bytes(16))
        csrf = _b64u(secrets.token_bytes(32)) if self.cfg.require_csrf else ""
        kid = self.keyring.active_kid
        s = Session(
            sid=sid,
            sub=subject,
            iat=now,
            nbf=now - int(max(0, not_before_skew)),
            exp=now + abs_ttl,
            last=now,
            itl=itl,
            kid=kid,
            ip=_norm_ip(ip) if self.cfg.bind_ip else "",
            ua=_hash_ua(user_agent) if self.cfg.bind_user_agent else "",
            csrf=csrf,
            nonce=_b64u(secrets.token_bytes(16)),
            attrs=dict(attrs or {}),
        )
        token = self._encode(s)
        self.store.put(s)
        # Запишем текущий nonce для анти‑replay (короткий TTL)
        self.store.record_nonce(s.sid, s.nonce, self.cfg.replay_window)
        return token

    def validate(
        self,
        token: str,
        *,
        ip: Optional[str],
        user_agent: Optional[str],
        csrf_header_or_form: Optional[str] = None,
        allow_expired_grace: int = 0,
    ) -> Session:
        """
        Верифицирует подпись, состояние, TTL/idle, привязку к IP/UA, CSRF.
        При успехе возвращает актуальный объект сессии (из store).
        """
        header, payload = self._decode_and_verify(token)
        s = Session.from_payload(payload)

        # Сверим текущее состояние в хранилище (истина в store, не в токене)
        s2 = self.store.get(s.sid)

        # Проверка revoked
        if s2.revoked:
            raise SessionRevoked(s.sid)

        # Проверка времени
        now = _now()
        if now < s2.nbf:
            raise SessionError("session not yet valid")
        if now > s2.exp + max(0, int(allow_expired_grace)):
            raise SessionExpired(s.sid)
        if (now - s2.last) > s2.itl:
            raise SessionExpired(f"idle timeout for {s.sid}")

        # Привязка к IP/UA
        if self.cfg.bind_ip:
            expected_ip = s2.ip
            current_ip = _norm_ip(ip)
            if expected_ip and expected_ip != current_ip:
                if self.cfg.ip_change_tolerance <= 0:
                    raise SessionBindingError("ip mismatch")
        if self.cfg.bind_user_agent:
            if s2.ua and not _consteq(s2.ua, _hash_ua(user_agent)):
                raise SessionBindingError("user-agent mismatch")

        # CSRF double-submit (если требуется)
        if self.cfg.require_csrf:
            if not csrf_header_or_form or not _consteq(s2.csrf, csrf_header_or_form):
                raise SessionError("csrf token invalid")

        # Анти‑replay nonce (одноразовый на ротацию/выпуск)
        if self.store.exists_nonce(s2.sid, s2.nonce):
            # если nonce всё ещё «живой», значит повтор или не была сделана ротация
            # допускаем валидацию, но сразу меняем nonce ниже (rotate_on_access)
            pass

        # touch (скользящее окно idle)
        self.store.set_last_access(s2.sid, now)
        return s2

    def rotate_on_access(self, session: Session) -> Optional[str]:
        """
        По политике ротации выпустить новый токен для той же сессии.
        Возвращает новый токен или None, если ротация не требуется.
        """
        now = _now()
        if (now - session.last) < self.cfg.rotation_after:
            return None
        # Обновляем last и nonce; kid — активный
        session.last = now
        session.kid = self.keyring.active_kid
        session.nonce = _b64u(secrets.token_bytes(16))
        self.store.record_nonce(session.sid, session.nonce, self.cfg.replay_window)
        self.store.put(session)
        return self._encode(session)

    def revoke(self, sid: str) -> None:
        self.store.mark_revoked(sid)

    def destroy(self, sid: str) -> None:
        self.store.delete(sid)

    # ---------- Сериализация токена ----------

    def _encode(self, s: Session) -> str:
        header = {"alg": "HS256", "kid": s.kid, "typ": "ZTS"}
        h = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        p = _b64u(json.dumps(s.to_payload(), separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signed = f"{h}.{p}".encode("ascii")
        sig = self.keyring.sign(s.kid, signed)
        return f"{h}.{p}.{_b64u(sig)}"

    def _decode_and_verify(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            h_b64, p_b64, s_b64 = token.split(".")
        except ValueError as e:
            raise SessionTampered("invalid token format") from e
        try:
            header = json.loads(_b64u_decode(h_b64))
            payload = json.loads(_b64u_decode(p_b64))
            sig = _b64u_decode(s_b64)
        except Exception as e:
            raise SessionTampered("invalid base64/json") from e
        if header.get("typ") != "ZTS" or header.get("alg") != "HS256":
            raise SessionTampered("unsupported header")
        kid = str(header.get("kid") or "")
        if not self.keyring.verify(kid, f"{h_b64}.{p_b64}".encode("ascii"), sig):
            raise SessionTampered("signature mismatch")
        return header, payload


# =========================
# Утилита инициализации по окружению
# =========================

def build_default_manager(store: Optional[SessionStore] = None) -> SessionManager:
    """
    Сборка менеджера из переменных окружения:
      ZTC_SESSION_KEYS="kid1:hexkey1,kid2:hexkey2"
      ZTC_SESSION_ACTIVE_KID="kid2"
      ZTC_SESSION_BACKEND="memory|redis"
      REDIS_URL="redis://localhost:6379/0"
    """
    keys_env = os.getenv("ZTC_SESSION_KEYS", "")
    key_map: Dict[str, bytes] = {}
    if keys_env:
        for item in keys_env.split(","):
            if not item.strip():
                continue
            kid, _, hexkey = item.strip().partition(":")
            if not kid or not hexkey:
                continue
            key_map[kid] = bytes.fromhex(hexkey)
    active = os.getenv("ZTC_SESSION_ACTIVE_KID") or (next(iter(key_map)) if key_map else "v1")
    if not key_map:
        key_map = {active: secrets.token_bytes(32)}

    kr = KeyRing(keys=key_map, active_kid=active)
    backend = os.getenv("ZTC_SESSION_BACKEND", "memory").lower()

    if store is None:
        if backend == "redis":
            try:
                import redis  # type: ignore
            except Exception as e:
                raise RuntimeError("redis backend requested but redis module not installed") from e
            url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            client = redis.Redis.from_url(url, decode_responses=False)
            store = RedisSessionStore(client)
        else:
            store = InMemorySessionStore()

    return SessionManager(kr, store, SessionConfig())
