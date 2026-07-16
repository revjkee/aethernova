# human-sovereignty-core/webui/server/auth/session_store.py
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _utcnow_ts() -> float:
    return time.time()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secure_token(bytes_len: int = 32) -> str:
    return secrets.token_urlsafe(bytes_len)


@dataclass(frozen=True)
class Session:
    """
    Неизменяемая модель серверной сессии.
    """
    session_id: str
    user_id: str
    created_at: str
    last_access_at: str
    expires_at_ts: float

    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    roles: tuple[str, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)
    rotated_from: Optional[str] = None

    def is_expired(self, now_ts: Optional[float] = None) -> bool:
        return (now_ts or _utcnow_ts()) >= self.expires_at_ts

    def touch(self, ttl_seconds: int) -> "Session":
        """
        Возвращает новую версию сессии с обновлённым last_access_at.
        """
        return Session(
            session_id=self.session_id,
            user_id=self.user_id,
            created_at=self.created_at,
            last_access_at=_utcnow_iso(),
            expires_at_ts=_utcnow_ts() + ttl_seconds,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            roles=self.roles,
            metadata=self.metadata,
            rotated_from=self.rotated_from,
        )


class SessionStore:
    """
    Server-side session store.
    Потокобезопасен.
    Не хранит чувствительные данные на клиенте.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 1800,
        max_sessions_per_user: int = 5,
        audit_hook: Optional[callable] = None,
    ) -> None:
        self._ttl_seconds = int(ttl_seconds)
        self._max_sessions_per_user = int(max_sessions_per_user)
        self._audit_hook = audit_hook

        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        roles: Optional[tuple[str, ...]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """
        Создаёт новую сессию.
        """
        with self._lock:
            self._enforce_user_limit(user_id)

            sid = _secure_token()
            now_iso = _utcnow_iso()
            now_ts = _utcnow_ts()

            session = Session(
                session_id=sid,
                user_id=user_id,
                created_at=now_iso,
                last_access_at=now_iso,
                expires_at_ts=now_ts + self._ttl_seconds,
                ip_address=ip_address,
                user_agent=user_agent,
                roles=roles or (),
                metadata=metadata or {},
            )

            self._sessions[sid] = session
            self._audit("session_created", session)
            return session

    def get(self, session_id: str) -> Optional[Session]:
        """
        Возвращает активную сессию или None.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            if session.is_expired():
                self._delete_locked(session_id, reason="expired")
                return None

            updated = session.touch(self._ttl_seconds)
            self._sessions[session_id] = updated
            return updated

    def rotate(self, session_id: str) -> Optional[Session]:
        """
        Ротация session id.
        Используется при повышении прав или sensitive actions.
        """
        with self._lock:
            old = self._sessions.get(session_id)
            if old is None or old.is_expired():
                return None

            new_sid = _secure_token()
            now_iso = _utcnow_iso()
            now_ts = _utcnow_ts()

            new_session = Session(
                session_id=new_sid,
                user_id=old.user_id,
                created_at=old.created_at,
                last_access_at=now_iso,
                expires_at_ts=now_ts + self._ttl_seconds,
                ip_address=old.ip_address,
                user_agent=old.user_agent,
                roles=old.roles,
                metadata=old.metadata,
                rotated_from=old.session_id,
            )

            del self._sessions[session_id]
            self._sessions[new_sid] = new_session

            self._audit("session_rotated", new_session)
            return new_session

    def revoke(self, session_id: str) -> None:
        """
        Немедленный отзыв сессии.
        """
        with self._lock:
            self._delete_locked(session_id, reason="revoked")

    def revoke_user(self, user_id: str) -> int:
        """
        Отзывает все сессии пользователя.
        """
        with self._lock:
            to_delete = [sid for sid, s in self._sessions.items() if s.user_id == user_id]
            for sid in to_delete:
                self._delete_locked(sid, reason="user_revoked")
            return len(to_delete)

    def cleanup_expired(self) -> int:
        """
        Удаляет протухшие сессии.
        """
        with self._lock:
            now_ts = _utcnow_ts()
            expired = [sid for sid, s in self._sessions.items() if s.is_expired(now_ts)]
            for sid in expired:
                self._delete_locked(sid, reason="expired")
            return len(expired)

    def _delete_locked(self, session_id: str, *, reason: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session:
            self._audit("session_deleted", session, reason=reason)

    def _enforce_user_limit(self, user_id: str) -> None:
        """
        Ограничивает количество активных сессий на пользователя.
        """
        sessions = [s for s in self._sessions.values() if s.user_id == user_id]
        if len(sessions) < self._max_sessions_per_user:
            return

        sessions.sort(key=lambda s: s.expires_at_ts)
        for s in sessions[:-self._max_sessions_per_user + 1]:
            self._delete_locked(s.session_id, reason="limit_exceeded")

    def _audit(self, event: str, session: Session, **extra: Any) -> None:
        if not self._audit_hook:
            return
        try:
            self._audit_hook(
                event,
                {
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "created_at": session.created_at,
                    "last_access_at": session.last_access_at,
                    "expires_at_ts": session.expires_at_ts,
                    "roles": session.roles,
                    "rotated_from": session.rotated_from,
                    **extra,
                },
            )
        except Exception:
            return
