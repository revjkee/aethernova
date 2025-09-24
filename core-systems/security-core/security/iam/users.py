# file: security-core/security/iam/users.py
from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import string
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, Field, EmailStr, StrictBool, StrictStr, validator

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------

logger = logging.getLogger("security_core.iam.users")

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _redact(v: Optional[str]) -> str:
    if not v:
        return ""
    if len(v) <= 6:
        return "****"
    return v[:3] + "…" + v[-2:]

# -----------------------------------------------------------------------------
# Исключения домена
# -----------------------------------------------------------------------------

class IamError(Exception):
    pass

class NotFound(IamError):
    pass

class Conflict(IamError):
    pass

class ConcurrencyError(IamError):
    pass

class Validation(IamError):
    pass

# -----------------------------------------------------------------------------
# Утилиты нормализации/валидации
# -----------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
_PHONE_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")  # ITU-T E.164

def normalize_email(email: Optional[str]) -> Optional[str]:
    return email.strip().lower() if email else None

def normalize_username(username: Optional[str]) -> Optional[str]:
    if not username:
        return None
    username = username.strip()
    return username.lower()

def validate_username(username: str) -> None:
    if not _USERNAME_RE.match(username):
        raise Validation("username must be 3..64 chars, alnum plus . _ -")

def validate_phone_e164(phone: Optional[str]) -> None:
    if phone and not _PHONE_E164_RE.match(phone):
        raise Validation("phone must be in E.164 format")

def gen_id() -> str:
    return str(uuid.uuid4())

def _cursor_encode(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def _cursor_decode(cur: str) -> Dict[str, Any]:
    pad = "=" * (-len(cur) % 4)
    data = base64.urlsafe_b64decode(cur + pad)
    return json.loads(data.decode("utf-8"))

# -----------------------------------------------------------------------------
# Модели домена
# -----------------------------------------------------------------------------

class ExternalIdentity(BaseModel):
    provider: StrictStr
    issuer: Optional[str] = None
    subject: StrictStr
    email: Optional[EmailStr] = None
    linked_at: Optional[str] = None

class User(BaseModel):
    id: StrictStr
    tenant_id: Optional[StrictStr] = None
    external_id: Optional[StrictStr] = None
    username: Optional[StrictStr] = None
    email: Optional[EmailStr] = None
    phone_e164: Optional[StrictStr] = None
    display_name: Optional[StrictStr] = None
    roles: List[StrictStr] = Field(default_factory=list)
    disabled: StrictBool = False
    deleted_at: Optional[str] = None
    attributes: Dict[str, StrictStr] = Field(default_factory=dict)
    external_identities: List[ExternalIdentity] = Field(default_factory=list)
    created_at: StrictStr
    updated_at: StrictStr
    version: int = 0  # для оптимистической конкуренции

    @validator("username")
    def _v_username(cls, v):
        if v:
            validate_username(v)
        return v

    @validator("phone_e164")
    def _v_phone(cls, v):
        validate_phone_e164(v)
        return v

class CreateUserInput(BaseModel):
    tenant_id: Optional[str] = None
    external_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_e164: Optional[str] = None
    display_name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    attributes: Dict[str, str] = Field(default_factory=dict)

    @validator("username")
    def _n_username(cls, v):
        if v:
            validate_username(v.strip().lower())
        return v.strip().lower() if v else None

    @validator("email")
    def _n_email(cls, v):
        return normalize_email(v) if v else None

    @validator("phone_e164")
    def _n_phone(cls, v):
        validate_phone_e164(v)
        return v

class UpdateUserInput(BaseModel):
    # частичное обновление
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_e164: Optional[str] = None
    display_name: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None
    disabled: Optional[bool] = None

    @validator("username")
    def _n_username(cls, v):
        if v is None:
            return v
        validate_username(v.strip().lower())
        return v.strip().lower()

    @validator("email")
    def _n_email(cls, v):
        return normalize_email(v) if v else None

    @validator("phone_e164")
    def _n_phone(cls, v):
        validate_phone_e164(v)
        return v

class UsersSearchQuery(BaseModel):
    tenant_id: Optional[str] = None
    text: Optional[str] = None        # fulltext по username/email/display_name
    role: Optional[str] = None
    disabled: Optional[bool] = None
    deleted: Optional[bool] = None
    created_from: Optional[str] = None
    created_to: Optional[str] = None
    page_size: int = 20
    page_cursor: Optional[str] = None

class PagedUsers(BaseModel):
    items: List[User]
    next_page_cursor: Optional[str] = None

# -----------------------------------------------------------------------------
# Абстракции хранения, транзакций и событий
# -----------------------------------------------------------------------------

class UnitOfWork(ABC):
    @abstractmethod
    def begin(self) -> None: ...

    @abstractmethod
    def commit(self) -> None: ...

    @abstractmethod
    def rollback(self) -> None: ...

class EventPublisher(ABC):
    @abstractmethod
    def publish(self, topic: str, key: str, value: Dict[str, Any]) -> None: ...

class NoopPublisher(EventPublisher):
    def publish(self, topic: str, key: str, value: Dict[str, Any]) -> None:
        logger.debug("event.publish.noop", extra={"topic": topic, "key": key})

class UsersRepository(ABC):
    @abstractmethod
    def get_by_id(self, tenant_id: Optional[str], user_id: str) -> User: ...

    @abstractmethod
    def get_by_username_or_email(self, tenant_id: Optional[str], identifier: str) -> Optional[User]: ...

    @abstractmethod
    def create(self, user: User) -> User: ...

    @abstractmethod
    def update(self, user: User, expected_version: Optional[int]) -> User: ...

    @abstractmethod
    def soft_delete(self, tenant_id: Optional[str], user_id: str, expected_version: Optional[int]) -> None: ...

    @abstractmethod
    def exists_username(self, tenant_id: Optional[str], username: str) -> bool: ...

    @abstractmethod
    def exists_email(self, tenant_id: Optional[str], email: str) -> bool: ...

    @abstractmethod
    def list_search(self, q: UsersSearchQuery) -> PagedUsers: ...

# -----------------------------------------------------------------------------
# DEV In-Memory реализация репозитория и UoW
# -----------------------------------------------------------------------------

@dataclass
class _Row:
    data: User

class MemoryUnitOfWork(UnitOfWork):
    def __init__(self) -> None:
        self._active = False

    def begin(self) -> None:
        self._active = True

    def commit(self) -> None:
        self._active = False

    def rollback(self) -> None:
        self._active = False

class InMemoryUsersRepository(UsersRepository):
    """DEV‑хранилище. Не для продакшена."""
    def __init__(self) -> None:
        self._by_id: Dict[Tuple[Optional[str], str], _Row] = {}
        self._by_username: Dict[Tuple[Optional[str], str], str] = {}
        self._by_email: Dict[Tuple[Optional[str], str], str] = {}

    def _k(self, tenant_id: Optional[str], user_id: str) -> Tuple[Optional[str], str]:
        return (tenant_id or None, user_id)

    def get_by_id(self, tenant_id: Optional[str], user_id: str) -> User:
        row = self._by_id.get(self._k(tenant_id, user_id))
        if not row or row.data.deleted_at:
            raise NotFound("user not found")
        return row.data

    def get_by_username_or_email(self, tenant_id: Optional[str], identifier: str) -> Optional[User]:
        ident = normalize_email(identifier) or normalize_username(identifier) or identifier
        # check username
        key_u = (tenant_id or None, ident)
        if key_u in self._by_username:
            uid = self._by_username[key_u]
            row = self._by_id.get(self._k(tenant_id, uid))
            if row and not row.data.deleted_at:
                return row.data
        # check email
        key_e = (tenant_id or None, ident)
        if key_e in self._by_email:
            uid = self._by_email[key_e]
            row = self._by_id.get(self._k(tenant_id, uid))
            if row and not row.data.deleted_at:
                return row.data
        return None

    def create(self, user: User) -> User:
        if user.username and self.exists_username(user.tenant_id, user.username):
            raise Conflict("username already exists")
        if user.email and self.exists_email(user.tenant_id, user.email):
            raise Conflict("email already exists")
        self._by_id[self._k(user.tenant_id, user.id)] = _Row(user)
        if user.username:
            self._by_username[(user.tenant_id or None, user.username)] = user.id
        if user.email:
            self._by_email[(user.tenant_id or None, user.email)] = user.id
        return user

    def update(self, user: User, expected_version: Optional[int]) -> User:
        key = self._k(user.tenant_id, user.id)
        row = self._by_id.get(key)
        if not row or row.data.deleted_at:
            raise NotFound("user not found")
        if expected_version is not None and row.data.version != expected_version:
            raise ConcurrencyError("version mismatch")
        # уникальность username/email
        if user.username and user.username != row.data.username:
            if self.exists_username(user.tenant_id, user.username):
                raise Conflict("username already exists")
            if row.data.username:
                self._by_username.pop((user.tenant_id or None, row.data.username), None)
            self._by_username[(user.tenant_id or None, user.username)] = user.id
        if user.email and user.email != row.data.email:
            if self.exists_email(user.tenant_id, user.email):
                raise Conflict("email already exists")
            if row.data.email:
                self._by_email.pop((user.tenant_id or None, row.data.email), None)
            self._by_email[(user.tenant_id or None, user.email)] = user.id
        user.version = row.data.version + 1
        self._by_id[key] = _Row(user)
        return user

    def soft_delete(self, tenant_id: Optional[str], user_id: str, expected_version: Optional[int]) -> None:
        key = self._k(tenant_id, user_id)
        row = self._by_id.get(key)
        if not row or row.data.deleted_at:
            raise NotFound("user not found")
        if expected_version is not None and row.data.version != expected_version:
            raise ConcurrencyError("version mismatch")
        if row.data.username:
            self._by_username.pop((tenant_id or None, row.data.username), None)
        if row.data.email:
            self._by_email.pop((tenant_id or None, row.data.email), None)
        row.data.deleted_at = _iso(_now_utc())
        row.data.version += 1
        self._by_id[key] = row

    def exists_username(self, tenant_id: Optional[str], username: str) -> bool:
        return (tenant_id or None, username) in self._by_username

    def exists_email(self, tenant_id: Optional[str], email: str) -> bool:
        return (tenant_id or None, email) in self._by_email

    def list_search(self, q: UsersSearchQuery) -> PagedUsers:
        items: List[User] = []
        # сбор кандидатов
        for (tenant, uid), row in self._by_id.items():
            u = row.data
            if q.tenant_id and (tenant or None) != (q.tenant_id or None):
                continue
            if q.deleted is False and u.deleted_at:
                continue
            if q.deleted is True and not u.deleted_at:
                continue
            if q.disabled is not None and u.disabled != q.disabled:
                continue
            if q.role and q.role not in (u.roles or []):
                continue
            if q.text:
                t = q.text.lower()
                hay = " ".join(filter(None, [u.username or "", u.email or "", u.display_name or ""])).lower()
                if t not in hay:
                    continue
            if q.created_from and u.created_at < q.created_from:
                continue
            if q.created_to and u.created_at > q.created_to:
                continue
            items.append(u)

        # упорядочим по created_at, затем id
        items.sort(key=lambda x: (x.created_at, x.id))

        # курсор
        start_idx = 0
        if q.page_cursor:
            cur = _cursor_decode(q.page_cursor)
            anchor = (cur.get("created_at"), cur.get("id"))
            for i, u in enumerate(items):
                if (u.created_at, u.id) > anchor:
                    start_idx = i
                    break

        slice_items = items[start_idx:start_idx + q.page_size]
        next_cur = None
        if len(items) > start_idx + q.page_size:
            last = slice_items[-1]
            next_cur = _cursor_encode({"created_at": last.created_at, "id": last.id})

        return PagedUsers(items=slice_items, next_page_cursor=next_cur)

# -----------------------------------------------------------------------------
# UsersService
# -----------------------------------------------------------------------------

PROTECTED_ATTRIBUTE_KEYS = {"id", "tenant_id", "username", "email", "phone_e164", "disabled", "deleted_at", "created_at", "updated_at", "version"}

class UsersService:
    """
    Домашний сервис управления пользователями IAM.
    Для продакшна внедрите реальные реализации UnitOfWork/UsersRepository/EventPublisher.
    """

    def __init__(self, repo: UsersRepository, uow: UnitOfWork, publisher: Optional[EventPublisher] = None) -> None:
        self.repo = repo
        self.uow = uow
        self.publisher = publisher or NoopPublisher()

    # --------- CRUD ---------

    def create_user(self, data: CreateUserInput, actor_id: Optional[str] = None) -> User:
        self.uow.begin()
        try:
            username = normalize_username(data.username)
            email = normalize_email(data.email)
            if username:
                validate_username(username)
                if self.repo.exists_username(data.tenant_id, username):
                    raise Conflict("username already exists")
            if email:
                if self.repo.exists_email(data.tenant_id, email):
                    raise Conflict("email already exists")
            validate_phone_e164(data.phone_e164)

            now = _now_utc()
            user = User(
                id=gen_id(),
                tenant_id=data.tenant_id,
                external_id=data.external_id,
                username=username,
                email=email,
                phone_e164=data.phone_e164,
                display_name=data.display_name,
                roles=sorted(set(data.roles or [])),
                disabled=False,
                deleted_at=None,
                attributes={k: str(v) for k, v in (data.attributes or {}).items() if k not in PROTECTED_ATTRIBUTE_KEYS},
                external_identities=[],
                created_at=_iso(now),
                updated_at=_iso(now),
                version=0,
            )
            user = self.repo.create(user)
            self.uow.commit()

            self._emit("iam.user.created", user.tenant_id, user.id, {
                "principal": {"id": user.id, "tenant_id": user.tenant_id, "username": user.username, "email": user.email},
                "occurred_at": user.created_at,
                "actor_id": actor_id,
            })
            logger.info("iam.user.created", extra={"user_id": user.id, "tenant": user.tenant_id})
            return user
        except Exception:
            self.uow.rollback()
            raise

    def get_user(self, tenant_id: Optional[str], user_id: str) -> User:
        return self.repo.get_by_id(tenant_id, user_id)

    def find_by_login(self, tenant_id: Optional[str], identifier: str) -> Optional[User]:
        return self.repo.get_by_username_or_email(tenant_id, identifier)

    def update_user(self, tenant_id: Optional[str], user_id: str, patch: UpdateUserInput, expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)

            new_username = user.username if patch.username is None else normalize_username(patch.username)
            new_email = user.email if patch.email is None else normalize_email(patch.email)
            new_phone = user.phone_e164 if patch.phone_e164 is None else patch.phone_e164
            new_display = user.display_name if patch.display_name is None else patch.display_name
            new_disabled = user.disabled if patch.disabled is None else bool(patch.disabled)
            new_attrs = user.attributes if patch.attributes is None else {
                k: str(v) for k, v in patch.attributes.items() if k not in PROTECTED_ATTRIBUTE_KEYS
            }

            if new_username and new_username != user.username:
                validate_username(new_username)
                if self.repo.exists_username(tenant_id, new_username):
                    raise Conflict("username already exists")
            if new_email and new_email != user.email:
                if self.repo.exists_email(tenant_id, new_email):
                    raise Conflict("email already exists")
            validate_phone_e164(new_phone)

            updated = user.copy(update={
                "username": new_username,
                "email": new_email,
                "phone_e164": new_phone,
                "display_name": new_display,
                "disabled": new_disabled,
                "attributes": new_attrs,
                "updated_at": _iso(_now_utc()),
            })
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()

            self._emit("iam.user.updated", updated.tenant_id, updated.id, {
                "principal": {"id": updated.id, "tenant_id": updated.tenant_id},
                "changes": {
                    "username": [user.username, updated.username] if user.username != updated.username else None,
                    "email": [user.email, updated.email] if user.email != updated.email else None,
                    "phone_e164": [user.phone_e164, updated.phone_e164] if user.phone_e164 != updated.phone_e164 else None,
                    "disabled": [user.disabled, updated.disabled] if user.disabled != updated.disabled else None,
                },
                "occurred_at": updated.updated_at,
                "actor_id": actor_id,
            })
            logger.info("iam.user.updated", extra={"user_id": updated.id, "tenant": updated.tenant_id})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    def soft_delete_user(self, tenant_id: Optional[str], user_id: str, expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> None:
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            self.repo.soft_delete(tenant_id, user_id, expected_version)
            self.uow.commit()
            self._emit("iam.user.deleted", tenant_id, user_id, {
                "principal": {"id": user_id, "tenant_id": tenant_id},
                "occurred_at": _iso(_now_utc()),
                "actor_id": actor_id,
            })
            logger.info("iam.user.deleted", extra={"user_id": user_id, "tenant": tenant_id})
        except Exception:
            self.uow.rollback()
            raise

    # --------- Роли ---------

    def set_roles(self, tenant_id: Optional[str], user_id: str, roles: List[str], expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        roles_norm = sorted(set([r.strip() for r in roles if r and r.strip()]))
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            updated = user.copy(update={"roles": roles_norm, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.roles.set", updated.tenant_id, updated.id, {
                "principal": {"id": updated.id, "tenant_id": updated.tenant_id},
                "roles": updated.roles,
                "occurred_at": updated.updated_at,
                "actor_id": actor_id,
            })
            logger.info("iam.user.roles.set", extra={"user_id": updated.id, "roles": roles_norm})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    def add_roles(self, tenant_id: Optional[str], user_id: str, roles: List[str], expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        to_add = [r.strip() for r in roles if r and r.strip()]
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            merged = sorted(set(user.roles + to_add))
            updated = user.copy(update={"roles": merged, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.roles.added", updated.tenant_id, updated.id, {"roles_added": to_add, "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.roles.added", extra={"user_id": updated.id, "roles": to_add})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    def remove_roles(self, tenant_id: Optional[str], user_id: str, roles: List[str], expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        to_remove = set([r.strip() for r in roles if r and r.strip()])
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            remaining = [r for r in (user.roles or []) if r not in to_remove]
            updated = user.copy(update={"roles": remaining, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.roles.removed", updated.tenant_id, updated.id, {"roles_removed": list(to_remove), "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.roles.removed", extra={"user_id": updated.id, "roles": list(to_remove)})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    # --------- Атрибуты ---------

    def upsert_attributes(self, tenant_id: Optional[str], user_id: str, patch: Dict[str, str], expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        for k in patch.keys():
            if k in PROTECTED_ATTRIBUTE_KEYS:
                raise Validation(f"attribute '{k}' is protected")
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            new_attrs = user.attributes.copy()
            for k, v in patch.items():
                new_attrs[k] = str(v)
            updated = user.copy(update={"attributes": new_attrs, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.attributes.upserted", updated.tenant_id, updated.id, {"keys": list(patch.keys()), "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.attributes.upserted", extra={"user_id": updated.id, "keys": list(patch.keys())})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    def remove_attributes(self, tenant_id: Optional[str], user_id: str, keys: List[str], expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        for k in keys:
            if k in PROTECTED_ATTRIBUTE_KEYS:
                raise Validation(f"attribute '{k}' is protected")
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            new_attrs = {k: v for k, v in user.attributes.items() if k not in set(keys)}
            updated = user.copy(update={"attributes": new_attrs, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.attributes.removed", updated.tenant_id, updated.id, {"keys": keys, "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.attributes.removed", extra={"user_id": updated.id, "keys": keys})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    # --------- Внешние идентичности (OIDC/SAML) ---------

    def link_external_identity(self, tenant_id: Optional[str], user_id: str, provider: str, issuer: Optional[str], subject: str, email: Optional[str] = None, expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            idn = ExternalIdentity(provider=provider, issuer=issuer, subject=subject, email=normalize_email(email), linked_at=_iso(_now_utc()))
            if any((ei.provider, ei.issuer, ei.subject) == (idn.provider, idn.issuer, idn.subject) for ei in user.external_identities):
                self.uow.rollback()
                return user  # идемпотентно
            updated = user.copy(update={"external_identities": user.external_identities + [idn], "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.external.linked", updated.tenant_id, updated.id, {"provider": provider, "issuer": issuer, "subject": _redact(subject), "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.external.linked", extra={"user_id": updated.id, "provider": provider})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    def unlink_external_identity(self, tenant_id: Optional[str], user_id: str, provider: str, issuer: Optional[str], subject: str, expected_version: Optional[int] = None, actor_id: Optional[str] = None) -> User:
        self.uow.begin()
        try:
            user = self.repo.get_by_id(tenant_id, user_id)
            filt = [(ei.provider, ei.issuer, ei.subject) != (provider, issuer, subject) for ei in user.external_identities]
            if all(filt):
                self.uow.rollback()
                return user  # не было — идемпотентно
            new_list = [ei for ei in user.external_identities if (ei.provider, ei.issuer, ei.subject) != (provider, issuer, subject)]
            updated = user.copy(update={"external_identities": new_list, "updated_at": _iso(_now_utc())})
            updated = self.repo.update(updated, expected_version)
            self.uow.commit()
            self._emit("iam.user.external.unlinked", updated.tenant_id, updated.id, {"provider": provider, "issuer": issuer, "subject": _redact(subject), "occurred_at": updated.updated_at, "actor_id": actor_id})
            logger.info("iam.user.external.unlinked", extra={"user_id": updated.id, "provider": provider})
            return updated
        except Exception:
            self.uow.rollback()
            raise

    # --------- Поиск/Список ---------

    def search(self, q: UsersSearchQuery) -> PagedUsers:
        # защита от слишком больших страниц
        if q.page_size > 200:
            q.page_size = 200
        return self.repo.list_search(q)

    # --------- Вспомогательное ---------

    def _emit(self, topic: str, tenant_id: Optional[str], key_id: str, value: Dict[str, Any]) -> None:
        try:
            key = f"{tenant_id or '_'}:{key_id}"
            self.publisher.publish(topic, key, value)
        except Exception as e:
            # события не должны ломать бизнес‑операцию
            logger.warning("event.publish.failed", extra={"topic": topic, "key": key_id, "err": str(e)})

# -----------------------------------------------------------------------------
# Пример инициализации DEV‑сервиса
# -----------------------------------------------------------------------------

def dev_users_service() -> UsersService:
    repo = InMemoryUsersRepository()
    uow = MemoryUnitOfWork()
    pub = NoopPublisher()
    return UsersService(repo=repo, uow=uow, publisher=pub)

# -----------------------------------------------------------------------------
# Пример использования (для локальной проверки)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    svc = dev_users_service()

    # Создание
    u = svc.create_user(CreateUserInput(username="Alice", email="Alice@example.com", display_name="Alice A.", roles=["user"]))
    print("created:", u.dict())

    # Обновление
    u2 = svc.update_user(u.tenant_id, u.id, UpdateUserInput(display_name="Alice Anderson"), expected_version=u.version)
    print("updated:", u2.dict())

    # Роли
    u3 = svc.add_roles(u.tenant_id, u.id, ["admin"], expected_version=u2.version)
    print("roles:", u3.roles)

    # Поиск
    page = svc.search(UsersSearchQuery(text="alice", page_size=10))
    print("search count:", len(page.items), "next:", page.next_page_cursor)

    # Мягкое удаление
    svc.soft_delete_user(u.tenant_id, u.id, expected_version=u3.version)
    try:
        svc.get_user(u.tenant_id, u.id)
    except NotFound:
        print("deleted: OK")
