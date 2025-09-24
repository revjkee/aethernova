# security-core/security/iam/directory_bridge.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

# -------------------------------
# Опциональные зависимости
# -------------------------------

_HAS_HTTPX = False
try:  # pragma: no cover
    import httpx  # type: ignore

    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    pass

_HAS_LDAP3 = False
try:  # pragma: no cover
    import ldap3  # type: ignore

    _HAS_LDAP3 = True
except Exception:  # pragma: no cover
    pass

# -------------------------------
# Логирование (структурированное)
# -------------------------------

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.iam.directory_bridge")
    if not logger.handlers:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.setLevel(os.getenv("SEC_CORE_IAM_LOG_LEVEL", "INFO").upper())
    return logger

log = _get_logger()

def jlog(level: int, message: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level),
        "message": message,
    }
    payload.update(fields)
    try:
        log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        # fallback — не ломаем поток
        log.log(level, f"{message} | {fields}")

# -------------------------------
# Утилиты времени/строк/идемпотентности
# -------------------------------

_RFC3339_Z = re.compile(r"Z$")

def parse_rfc3339(s: str) -> datetime:
    # SCIM meta.lastModified обычно в RFC3339 с 'Z'
    s = _RFC3339_Z.sub("+00:00", s.strip())
    return datetime.fromisoformat(s).astimezone(timezone.utc)

def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def gen_request_id() -> str:
    return str(uuid.uuid4())

# -------------------------------
# Ограничители и бэкофф
# -------------------------------

class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill = float(refill_per_sec)
        self.updated = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

async def with_backoff(
    func: Callable[[], Awaitable[Any]],
    *,
    retries: int = 5,
    base_delay: float = 0.25,
    max_delay: float = 5.0,
    jitter: float = 0.2,
    on_error: Optional[Callable[[int, BaseException], None]] = None,
) -> Any:
    attempt = 0
    while True:
        try:
            return await func()
        except Exception as e:
            attempt += 1
            if attempt > retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay *= random.uniform(1 - jitter, 1 + jitter)
            if on_error:
                on_error(attempt, e)
            await asyncio.sleep(delay)

# -------------------------------
# Модели сущностей
# -------------------------------

def _lc(s: Optional[str]) -> Optional[str]:
    return s.lower() if isinstance(s, str) else s

@dataclass(frozen=True)
class UserRecord:
    tenant: str
    ext_id: str
    username: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    active: bool = True
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    groups: Tuple[str, ...] = field(default_factory=tuple)  # список внешних id групп
    attrs: Mapping[str, Any] = field(default_factory=dict)
    updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    source: str = "unknown"  # scim|ldap|custom

    def normalized(self) -> "UserRecord":
        # Нормализация: username/email в нижний регистр
        return dataclasses.replace(self, username=_lc(self.username) or "", email=_lc(self.email))

@dataclass(frozen=True)
class GroupRecord:
    tenant: str
    ext_id: str
    name: str
    description: Optional[str] = None
    members: Tuple[str, ...] = field(default_factory=tuple)  # внешние id пользователей
    attrs: Mapping[str, Any] = field(default_factory=dict)
    updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    source: str = "unknown"

# -------------------------------
# Синк (внутренний IAM)
# -------------------------------

class IamSink(Protocol):
    async def upsert_user(self, user: UserRecord) -> str: ...
    async def deactivate_user(self, tenant: str, ext_id: str) -> None: ...
    async def upsert_group(self, group: GroupRecord) -> str: ...
    async def set_group_members(self, tenant: str, group_ext_id: str, member_ext_ids: Sequence[str]) -> None: ...

class NullSink(IamSink):
    """Безопасный sink по умолчанию — только логирование."""
    async def upsert_user(self, user: UserRecord) -> str:
        jlog(logging.INFO, "iam.upsert_user", user=asdict(user.normalized()))
        return user.ext_id

    async def deactivate_user(self, tenant: str, ext_id: str) -> None:
        jlog(logging.INFO, "iam.deactivate_user", tenant=tenant, ext_id=ext_id)

    async def upsert_group(self, group: GroupRecord) -> str:
        jlog(logging.INFO, "iam.upsert_group", group=asdict(group))
        return group.ext_id

    async def set_group_members(self, tenant: str, group_ext_id: str, member_ext_ids: Sequence[str]) -> None:
        jlog(logging.INFO, "iam.set_group_members", tenant=tenant, group_ext_id=group_ext_id, members=list(member_ext_ids))

# -------------------------------
# Хранилище состояния
# -------------------------------

class StateStore(Protocol):
    async def load(self, key: str) -> Dict[str, Any]: ...
    async def save(self, key: str, state: Mapping[str, Any]) -> None: ...

class JsonFileStateStore(StateStore):
    def __init__(self, root: Union[str, Path] = "./.sync_state") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    async def load(self, key: str) -> Dict[str, Any]:
        p = self.root / f"{_safe_name(key)}.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

    async def save(self, key: str, state: Mapping[str, Any]) -> None:
        p = self.root / f"{_safe_name(key)}.json"
        tmp = p.with_suffix(".tmp")
        data = json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        tmp.write_text(data, encoding="utf-8")
        tmp.replace(p)

def _safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)

# -------------------------------
# Клиенты внешних каталогов
# -------------------------------

class DirectoryClient(Protocol):
    name: str
    tenant: str
    async def iter_users(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[UserRecord]: ...
    async def iter_groups(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[GroupRecord]: ...
    async def close(self) -> None: ...

# ---------- SCIM 2.0 ----------

class ScimClient:
    """
    Минимально достаточный SCIM 2.0 клиент для Users/Groups.
    Требует httpx. Синхронизация по meta.lastModified (RFC7644) + пейджинг.
    """
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        tenant: str,
        verify_tls: bool = True,
        rate_capacity: int = 10,
        rate_refill_per_sec: float = 5.0,
        timeout: float = 15.0,
        user_filter: Optional[str] = None,
        group_filter: Optional[str] = None,
        source_label: str = "scim",
    ) -> None:
        if not _HAS_HTTPX:
            raise RuntimeError("httpx not installed: SCIM client unavailable")
        self.name = f"scim:{tenant}"
        self.tenant = tenant
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/scim+json, application/json",
            "Content-Type": "application/scim+json",
            "User-Agent": "security-core-iam-bridge/1.0",
        }
        self.timeout = timeout
        self.bucket = TokenBucket(rate_capacity, rate_refill_per_sec)
        self.user_filter = user_filter
        self.group_filter = group_filter
        self.source_label = source_label
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=verify_tls)

    async def close(self) -> None:
        await self._client.aclose()

    # Core iterator
    async def iter_users(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[UserRecord]:
        async for item in self._scim_iter("/Users", since, page_size, self.user_filter):
            yield self._map_user(item)

    async def iter_groups(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[GroupRecord]:
        async for item in self._scim_iter("/Groups", since, page_size, self.group_filter):
            yield self._map_group(item)

    async def _scim_iter(
        self, path: str, since: Optional[datetime], page_size: int, extra_filter: Optional[str]
    ) -> AsyncIterator[Dict[str, Any]]:
        start = 1
        # SCIM filter на lastModified (допускается не везде; если не поддерживается — вернется 400/501)
        fil = None
        if since:
            fil = f'meta.lastModified gt "{to_rfc3339(since)}"'
        if extra_filter:
            fil = f"({fil}) and ({extra_filter})" if fil else extra_filter

        while True:
            if not self.bucket.allow(1):
                await asyncio.sleep(0.05)
                continue

            params = {"startIndex": start, "count": page_size}
            if fil:
                params["filter"] = fil

            async def do_get() -> httpx.Response:
                return await self._client.get(f"{self.base_url}{path}", headers=self.headers, params=params)

            def on_err(attempt: int, e: BaseException) -> None:
                jlog(logging.WARNING, "scim.get.retry", attempt=attempt, path=path, error=str(e))

            resp: httpx.Response = await with_backoff(do_get, on_error=on_err)
            if resp.status_code == 400 and fil:
                # фильтр не поддерживается — повтор без фильтра
                jlog(logging.WARNING, "scim.filter.unsupported", path=path)
                fil = None
                start = 1
                continue
            if resp.status_code >= 500:
                raise RuntimeError(f"SCIM server error {resp.status_code}: {resp.text}")
            if resp.status_code >= 400:
                raise RuntimeError(f"SCIM client error {resp.status_code}: {resp.text}")

            data = resp.json()
            resources = data.get("Resources") or []
            total = int(data.get("totalResults") or 0)
            items_returned = int(data.get("itemsPerPage") or len(resources))
            for it in resources:
                yield it

            # Пагинация
            if start + items_returned > total or items_returned == 0:
                break
            start += items_returned

    # Маппинг SCIM -> внутренние модели
    def _map_user(self, it: Mapping[str, Any]) -> UserRecord:
        ext_id = str(it.get("id"))
        user_name = str(it.get("userName") or it.get("externalId") or ext_id)
        name = it.get("name") or {}
        emails = it.get("emails") or []
        email = None
        if emails:
            # Выбираем primary или первый
            prim = next((e for e in emails if e.get("primary")), None)
            email = str((prim or emails[0]).get("value") or "")
        groups = tuple(str(g.get("value")) for g in it.get("groups") or [] if g.get("value"))
        active = bool(it.get("active", True))
        meta = it.get("meta") or {}
        created = meta.get("created")
        modified = meta.get("lastModified") or created
        return UserRecord(
            tenant=self.tenant,
            ext_id=ext_id,
            username=user_name,
            email=email or None,
            display_name=str(it.get("displayName") or it.get("name", {}).get("formatted") or user_name),
            active=active,
            given_name=(name.get("givenName") if isinstance(name, dict) else None),
            family_name=(name.get("familyName") if isinstance(name, dict) else None),
            groups=groups,
            attrs={"externalId": it.get("externalId"), "raw": it},
            created_at=parse_rfc3339(created) if created else None,
            updated_at=parse_rfc3339(modified) if modified else None,
            source=self.source_label,
        ).normalized()

    def _map_group(self, it: Mapping[str, Any]) -> GroupRecord:
        ext_id = str(it.get("id"))
        name = str(it.get("displayName") or it.get("id"))
        members = tuple(str(m.get("value")) for m in it.get("members") or [] if m.get("value"))
        meta = it.get("meta") or {}
        created = meta.get("created")
        modified = meta.get("lastModified") or created
        return GroupRecord(
            tenant=self.tenant,
            ext_id=ext_id,
            name=name,
            description=None,
            members=members,
            attrs={"externalId": it.get("externalId"), "raw": it},
            created_at=parse_rfc3339(created) if created else None,
            updated_at=parse_rfc3339(modified) if modified else None,
            source=self.source_label,
        )

# ---------- LDAP (опционально) ----------

class LdapClient:
    """
    Paged LDAP client (если установлен ldap3). Маппинг минимальный и настраиваемый.
    """
    def __init__(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
        base_dn: str,
        *,
        tenant: str,
        user_filter: str = "(objectClass=person)",
        group_filter: str = "(objectClass=groupOfNames)",
        user_attrs: Sequence[str] = ("uid", "mail", "cn", "sn", "givenName", "memberOf"),
        group_attrs: Sequence[str] = ("cn", "description", "member"),
        page_size: int = 500,
        source_label: str = "ldap",
    ) -> None:
        if not _HAS_LDAP3:
            raise RuntimeError("ldap3 not installed: LDAP client unavailable")
        self.name = f"ldap:{tenant}"
        self.tenant = tenant
        self.base_dn = base_dn
        self.user_filter = user_filter
        self.group_filter = group_filter
        self.user_attrs = tuple(user_attrs)
        self.group_attrs = tuple(group_attrs)
        self.page_size = page_size
        self.source_label = source_label

        self._server = ldap3.Server(server_uri, get_info=ldap3.NONE)
        self._conn = ldap3.Connection(self._server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=15)

    async def close(self) -> None:
        try:
            self._conn.unbind()
        except Exception:
            pass

    async def iter_users(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[UserRecord]:
        # Поскольку у LDAP нет универсального lastModified, используем простую пагинацию
        cookie = None
        while True:
            self._conn.extend.standard.paged_search(
                search_base=self.base_dn,
                search_filter=self.user_filter,
                search_scope=ldap3.SUBTREE,
                attributes=list(self.user_attrs),
                paged_size=min(self.page_size, page_size),
                generator=False,
            )
            for entry in self._conn.response or []:
                attr = entry.get("attributes") or {}
                uid = str(attr.get("uid") or entry.get("dn"))
                email = attr.get("mail")
                groups = tuple(_ensure_list(attr.get("memberOf")))
                given = attr.get("givenName")
                sn = attr.get("sn")
                cn = attr.get("cn")
                yield UserRecord(
                    tenant=self.tenant,
                    ext_id=uid,
                    username=str(uid),
                    email=str(email) if email else None,
                    display_name=str(cn or uid),
                    active=True,
                    given_name=str(given) if given else None,
                    family_name=str(sn) if sn else None,
                    groups=tuple(map(str, groups)),
                    attrs={"dn": entry.get("dn"), "raw": entry},
                    created_at=None,
                    updated_at=None,
                    source=self.source_label,
                ).normalized()
            cookie = self._conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break

    async def iter_groups(self, since: Optional[datetime], page_size: int = 200) -> AsyncIterator[GroupRecord]:
        self._conn.extend.standard.paged_search(
            search_base=self.base_dn,
            search_filter=self.group_filter,
            search_scope=ldap3.SUBTREE,
            attributes=list(self.group_attrs),
            paged_size=min(self.page_size, page_size),
            generator=False,
        )
        for entry in self._conn.response or []:
            attr = entry.get("attributes") or {}
            cn = attr.get("cn") or entry.get("dn")
            members = tuple(str(x) for x in _ensure_list(attr.get("member")))
            yield GroupRecord(
                tenant=self.tenant,
                ext_id=str(cn),
                name=str(cn),
                description=str(attr.get("description")) if attr.get("description") else None,
                members=members,
                attrs={"dn": entry.get("dn"), "raw": entry},
                created_at=None,
                updated_at=None,
                source=self.source_label,
            )

def _ensure_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [v]

# -------------------------------
# ACL/фильтры сущностей
# -------------------------------

EntityFilter = Callable[[Union[UserRecord, GroupRecord]], bool]

def default_entity_filter(ent: Union[UserRecord, GroupRecord]) -> bool:
    # Пример: отбрасываем сервисные и пустые учетные записи
    if isinstance(ent, UserRecord):
        if not ent.username:
            return False
        if ent.email and ent.email.endswith("@example.invalid"):
            return False
    return True

# -------------------------------
# Оркестратор (Bridge)
# -------------------------------

@dataclass
class SyncStats:
    users_upserted: int = 0
    users_deactivated: int = 0
    groups_upserted: int = 0
    memberships_set: int = 0
    started_at: str = field(default_factory=lambda: now_utc().isoformat())
    finished_at: Optional[str] = None
    source: str = "unknown"

class DirectoryBridge:
    """
    Асинхронный мост синхронизации пользователей/групп из внешнего каталога в IAM.
    """
    def __init__(
        self,
        client: DirectoryClient,
        sink: Optional[IamSink] = None,
        state_store: Optional[StateStore] = None,
        *,
        entity_filter: EntityFilter = default_entity_filter,
        users_page_size: int = 300,
        groups_page_size: int = 300,
        concurrent_upserts: int = 16,
        deactivate_missing: bool = False,
        state_key_prefix: str = "iam_bridge",
    ) -> None:
        self.client = client
        self.sink = sink or NullSink()
        self.state_store = state_store or JsonFileStateStore()
        self.entity_filter = entity_filter
        self.users_page_size = users_page_size
        self.groups_page_size = groups_page_size
        self.sem = asyncio.Semaphore(concurrent_upserts)
        self.deactivate_missing = deactivate_missing
        self.state_key = f"{state_key_prefix}:{client.name}"
        self.stats = SyncStats(source=client.name)

    # Основной метод: одна итерация синхронизации
    async def sync_once(self) -> SyncStats:
        state = await self.state_store.load(self.state_key)
        since_users = _parse_opt_dt(state.get("since_users"))
        since_groups = _parse_opt_dt(state.get("since_groups"))

        jlog(logging.INFO, "sync.start", client=self.client.name, since_users=state.get("since_users"), since_groups=state.get("since_groups"))

        seen_users: set[str] = set()
        seen_groups: set[str] = set()

        # Синхронизируем пользователей
        max_user_ts = since_users
        async for user in self.client.iter_users(since=since_users, page_size=self.users_page_size):
            if not self.entity_filter(user):
                continue
            await self._upsert_user(user)
            seen_users.add(user.ext_id)
            if user.updated_at and (not max_user_ts or user.updated_at > max_user_ts):
                max_user_ts = user.updated_at

        # Синхронизируем группы (и состав)
        max_group_ts = since_groups
        async for group in self.client.iter_groups(since=since_groups, page_size=self.groups_page_size):
            if not self.entity_filter(group):
                continue
            await self._upsert_group(group)
            seen_groups.add(group.ext_id)
            if group.updated_at and (not max_group_ts or group.updated_at > max_group_ts):
                max_group_ts = group.updated_at
            # Обновляем состав группы (могут быть пользователи, которых мы не видели — IAM сам справится)
            await self.sink.set_group_members(group.tenant, group.ext_id, group.members)
            self.stats.memberships_set += 1

        # Деактивация пропавших (опционально, осторожно!)
        if self.deactivate_missing and since_users is None:
            # Только в полном прогоне (без delta) — иначе риск ложной деактивации
            await self._deactivate_missing_users(seen_users)

        # Сохраняем прогресс
        new_state = {
            "since_users": to_rfc3339(max_user_ts) if max_user_ts else state.get("since_users"),
            "since_groups": to_rfc3339(max_group_ts) if max_group_ts else state.get("since_groups"),
            "finished_at": now_utc().isoformat(),
        }
        await self.state_store.save(self.state_key, {**state, **new_state})
        self.stats.finished_at = new_state["finished_at"]
        jlog(logging.INFO, "sync.done", client=self.client.name, stats=asdict(self.stats))
        return self.stats

    async def _upsert_user(self, user: UserRecord) -> None:
        async with self.sem:
            await self.sink.upsert_user(user)
            self.stats.users_upserted += 1

    async def _upsert_group(self, group: GroupRecord) -> None:
        async with self.sem:
            await self.sink.upsert_group(group)
            self.stats.groups_upserted += 1

    async def _deactivate_missing_users(self, seen_ext_ids: set[str]) -> None:
        # В production здесь должен быть источник правды о всех известных ext_id. В NullSink примера нет.
        # Оставляем заглушку вызова: пользовательский sink обязан реализовать список известных ext_id.
        try:
            get_all_ext_ids = getattr(self.sink, "list_all_user_ext_ids")  # type: ignore[attr-defined]
        except Exception:
            jlog(logging.INFO, "deactivate_missing.skipped", reason="sink_has_no_list_all_user_ext_ids")
            return
        all_ids: Iterable[str] = await get_all_ext_ids(self.client.tenant)  # type: ignore[misc]
        to_deactivate = [x for x in all_ids if x not in seen_ext_ids]
        for ext_id in to_deactivate:
            await self.sink.deactivate_user(self.client.tenant, ext_id)
            self.stats.users_deactivated += 1

# -------------------------------
# Вспомогательные функции
# -------------------------------

def _parse_opt_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        return parse_rfc3339(str(v))
    except Exception:
        return None

# -------------------------------
# Фабрики клиентов (ENV)
# -------------------------------

def scim_client_from_env(*, tenant: str) -> ScimClient:
    base = os.environ["SEC_CORE_SCIM_BASE_URL"]
    token = os.environ["SEC_CORE_SCIM_TOKEN"]
    verify = os.getenv("SEC_CORE_SCIM_VERIFY_TLS", "true").lower() in ("1", "true", "yes", "on")
    cap = int(os.getenv("SEC_CORE_SCIM_RATE_CAP", "10"))
    refill = float(os.getenv("SEC_CORE_SCIM_RATE_REFILL", "5"))
    tout = float(os.getenv("SEC_CORE_SCIM_TIMEOUT", "15"))
    ufilter = os.getenv("SEC_CORE_SCIM_USER_FILTER")
    gfilter = os.getenv("SEC_CORE_SCIM_GROUP_FILTER")
    return ScimClient(
        base_url=base,
        token=token,
        tenant=tenant,
        verify_tls=verify,
        rate_capacity=cap,
        rate_refill_per_sec=refill,
        timeout=tout,
        user_filter=ufilter,
        group_filter=gfilter,
    )

def ldap_client_from_env(*, tenant: str) -> LdapClient:
    if not _HAS_LDAP3:
        raise RuntimeError("ldap3 not installed")
    server = os.environ["SEC_CORE_LDAP_URI"]
    bind_dn = os.environ["SEC_CORE_LDAP_BIND_DN"]
    bind_pw = os.environ["SEC_CORE_LDAP_BIND_PW"]
    base_dn = os.environ["SEC_CORE_LDAP_BASE_DN"]
    user_filter = os.getenv("SEC_CORE_LDAP_USER_FILTER", "(objectClass=person)")
    group_filter = os.getenv("SEC_CORE_LDAP_GROUP_FILTER", "(objectClass=groupOfNames)")
    return LdapClient(
        server_uri=server,
        bind_dn=bind_dn,
        bind_password=bind_pw,
        base_dn=base_dn,
        tenant=tenant,
        user_filter=user_filter,
        group_filter=group_filter,
    )

# -------------------------------
# Пример интеграции (для справки)
# -------------------------------
# async def run_sync():
#     client = scim_client_from_env(tenant="acme")
#     sink = YourProductionIamSink(...)
#     bridge = DirectoryBridge(client=client, sink=sink, deactivate_missing=False)
#     try:
#         await bridge.sync_once()
#     finally:
#         await client.close()
#
# Переменные окружения SCIM:
#   SEC_CORE_SCIM_BASE_URL=https://idp.example.com/scim/v2
#   SEC_CORE_SCIM_TOKEN=...
#   SEC_CORE_SCIM_VERIFY_TLS=true
#   SEC_CORE_SCIM_RATE_CAP=10
#   SEC_CORE_SCIM_RATE_REFILL=5
#   SEC_CORE_SCIM_TIMEOUT=15
#   SEC_CORE_SCIM_USER_FILTER=active eq true
#   SEC_CORE_SCIM_GROUP_FILTER=
#
# Переменные окружения LDAP:
#   SEC_CORE_LDAP_URI=ldaps://ldap.example.com:636
#   SEC_CORE_LDAP_BIND_DN=cn=sync,ou=svc,dc=example,dc=com
#   SEC_CORE_LDAP_BIND_PW=...
#   SEC_CORE_LDAP_BASE_DN=dc=example,dc=com
#
# Гарантии:
#  - Идемпотентность на стороне sink (upsert) + сохранение "since_*" в JSON.
#  - Строгие лимиты: размер страниц, rate-limit, экспоненциальный бэкофф.
#  - Безопасная нормализация e-mail/username, фильтры сущностей.
# -------------------------------

__all__ = [
    "UserRecord",
    "GroupRecord",
    "IamSink",
    "NullSink",
    "StateStore",
    "JsonFileStateStore",
    "DirectoryClient",
    "ScimClient",
    "LdapClient",
    "DirectoryBridge",
    "SyncStats",
    "scim_client_from_env",
    "ldap_client_from_env",
]
