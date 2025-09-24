# security-core/security/iam/groups.py
# Промышленный модуль IAM Groups: многоарендность, транзитивные группы (DAG), роли (RBAC),
# оптимистичные блокировки (ETag), аудит-хуки, TTL-кэш членства, in-memory backend.
# Зависимости: pydantic

from __future__ import annotations

import base64
import json
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple

from pydantic import BaseModel, Field, validator, root_validator

# =========================
# Утилиты / константы
# =========================

GROUP_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,62}$")  # 3..63, строчные, цифры, ._- (читаемо и кросс-платформенно)
PRINCIPAL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{3,128}$")  # для user/service/device id
TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
LABEL_KEY_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def compute_etag(obj: Any) -> str:
    import hashlib
    return hashlib.sha256(_canonical_json(obj)).hexdigest()

def new_uid() -> str:
    return str(uuid.uuid4())

# =========================
# Ошибки домена
# =========================

class IAMError(Exception):
    code: str = "IAM_ERROR"
    def __init__(self, message: str, *, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code:
            self.code = code

class NotFound(IAMError):       code = "NOT_FOUND"
class AlreadyExists(IAMError):  code = "ALREADY_EXISTS"
class Conflict(IAMError):       code = "CONFLICT"
class Validation(IAMError):     code = "VALIDATION"
class Forbidden(IAMError):      code = "FORBIDDEN"
class CycleDetected(IAMError):  code = "CYCLE_DETECTED"

# =========================
# Модели (Pydantic)
# =========================

class Labels(BaseModel):
    __root__: Dict[str, str] = Field(default_factory=dict)
    @validator("__root__")
    def _validate(cls, v: Dict[str, str]) -> Dict[str, str]:
        if len(v) > 256:
            raise ValueError("labels: too many keys")
        for k, val in v.items():
            if not LABEL_KEY_RE.match(k):
                raise ValueError(f"invalid label key: {k}")
            if not isinstance(val, str) or len(val) > 128:
                raise ValueError(f"invalid label value for {k}")
        return v
    def dict(self, *a, **kw):  # type: ignore[override]
        return self.__root__

class Attributes(BaseModel):
    __root__: Dict[str, Any] = Field(default_factory=dict)
    @validator("__root__")
    def _validate(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if len(v) > 2048:
            raise ValueError("attributes: too many keys")
        return v
    def dict(self, *a, **kw):  # type: ignore[override]
        return self.__root__

class MemberRef(BaseModel):
    """
    Ссылка на участника группы. Поддерживаются:
    - type=user|service|device: principal_id обязателен
    - type=group: group_id обязателен (вложенные группы)
    """
    type: str = Field(regex=r"^(user|service|device|group)$")
    principal_id: Optional[str] = None
    group_id: Optional[str] = None

    @root_validator
    def _check(cls, values):
        t = values.get("type")
        pid = values.get("principal_id")
        gid = values.get("group_id")
        if t == "group":
            if not gid or not GROUP_ID_RE.match(gid):
                raise ValueError("group member must have valid group_id")
            values["principal_id"] = None
        else:
            if not pid or not PRINCIPAL_ID_RE.match(pid):
                raise ValueError("principal member must have valid principal_id")
            values["group_id"] = None
        return values

    def key(self) -> Tuple[str, str]:
        return (self.type, self.group_id or self.principal_id or "")

class Group(BaseModel):
    tenant_id: str = Field(..., description="Многоарендный сегмент")
    group_id: str = Field(..., description="Уникальный id группы в рамках tenant")
    uid: str = Field(default_factory=new_uid)
    display_name: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    labels: Labels = Field(default_factory=Labels)
    attributes: Attributes = Field(default_factory=Attributes)
    roles: List[str] = Field(default_factory=list, description="Роли, которые группа делегирует своим участникам")
    # Состав группы (прямые участники, не транзитивные)
    members: List[MemberRef] = Field(default_factory=list)
    # Технические поля
    create_time: datetime = Field(default_factory=now_utc)
    update_time: datetime = Field(default_factory=now_utc)
    etag: Optional[str] = None
    disabled: bool = False

    @validator("tenant_id")
    def _tenant(cls, v: str) -> str:
        if not TENANT_ID_RE.match(v):
            raise ValueError("invalid tenant_id")
        return v

    @validator("group_id")
    def _gid(cls, v: str) -> str:
        if not GROUP_ID_RE.match(v):
            raise ValueError("invalid group_id")
        return v

    @validator("roles", each_item=True)
    def _role(cls, v: str) -> str:
        if not re.match(r"^[a-z][a-z0-9._:-]{1,63}$", v):
            raise ValueError(f"invalid role name: {v}")
        return v

    def compute_etag(self) -> str:
        payload = self.dict()
        payload.pop("etag", None)
        return compute_etag(payload)

class GroupSnapshot(BaseModel):
    """
    Снимок арендатора для бэкапа/миграций.
    """
    tenant_id: str
    groups: List[Group]
    created_at: datetime = Field(default_factory=now_utc)

# =========================
# Аудит-хуки
# =========================

class AuditHook:
    """Интерфейс хуков аудита/событий. Реализация по умолчанию — no-op."""
    def on_group_created(self, g: Group) -> None: ...
    def on_group_updated(self, g: Group, changed_fields: List[str]) -> None: ...
    def on_group_deleted(self, tenant_id: str, group_id: str) -> None: ...
    def on_members_changed(self, g: Group, added: List[MemberRef], removed: List[MemberRef]) -> None: ...

class NoopAuditHook(AuditHook):
    pass

# =========================
# TTL-кэш для membership
# =========================

class TTLCache:
    def __init__(self, ttl_seconds: int = 30_000, max_size: int = 100_000) -> None:
        self.ttl = ttl_seconds
        self.max = max_size
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def _key(self, *parts: str) -> str:
        return "|".join(parts)

    def get(self, *parts: str) -> Optional[Any]:
        k = self._key(*parts)
        with self._lock:
            item = self._data.get(k)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                self._data.pop(k, None)
                return None
            return val

    def set(self, value: Any, *parts: str) -> None:
        k = self._key(*parts)
        with self._lock:
            if len(self._data) >= self.max:
                # простая эвакуация: очищаем просроченные
                now = time.time()
                for kk, (exp, _) in list(self._data.items())[: self.max // 10]:
                    if exp < now:
                        self._data.pop(kk, None)
            self._data[k] = (time.time() + self.ttl, value)

    def clear_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in list(self._data.keys()):
                if k.startswith(prefix):
                    self._data.pop(k, None)

# =========================
# Репозиторий (in-memory, потокобезопасный)
# =========================

class GroupRepository:
    """
    Базовый интерфейс хранилища. Для продакшн-БД реализуйте тот же контракт.
    """
    def create(self, g: Group) -> Group: raise NotImplementedError
    def get(self, tenant_id: str, group_id: str) -> Group: raise NotImplementedError
    def update(self, g: Group, *, expect_etag: Optional[str]) -> Group: raise NotImplementedError
    def delete(self, tenant_id: str, group_id: str, *, expect_etag: Optional[str]) -> None: raise NotImplementedError
    def list(self, tenant_id: str, *, prefix: Optional[str], limit: int, cursor: Optional[str]) -> Tuple[List[Group], Optional[str]]: raise NotImplementedError
    def upsert_members(self, tenant_id: str, group_id: str, add: List[MemberRef], remove: List[MemberRef], *, expect_etag: Optional[str]) -> Group: raise NotImplementedError
    def snapshot(self, tenant_id: str) -> GroupSnapshot: raise NotImplementedError
    def import_snapshot(self, snap: GroupSnapshot, *, overwrite: bool) -> None: raise NotImplementedError

class InMemoryGroupRepository(GroupRepository):
    """
    Хранение в памяти с индексами:
    - groups[tenant][group_id] = Group
    - by_member[tenant][principal_id] = set(group_id)
    - edges[tenant][group_id] = {child_group_ids}
    - reverse_edges[tenant][group_id] = {parent_group_ids}
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.groups: Dict[str, Dict[str, Group]] = {}
        self.by_member: Dict[str, Dict[str, Set[str]]] = {}
        self.edges: Dict[str, Dict[str, Set[str]]] = {}
        self.rev_edges: Dict[str, Dict[str, Set[str]]] = {}

    # ------- helpers -------
    def _ensure_tenant(self, tenant: str) -> None:
        self.groups.setdefault(tenant, {})
        self.by_member.setdefault(tenant, {})
        self.edges.setdefault(tenant, {})
        self.rev_edges.setdefault(tenant, {})

    def _put_indexes(self, g: Group, *, old: Optional[Group]) -> None:
        t = g.tenant_id
        # очистка старых индексов
        if old:
            # principals
            for m in old.members:
                if m.type == "group":
                    self.edges[t].get(old.group_id, set()).discard(m.group_id)  # child link
                    self.rev_edges[t].get(m.group_id, set()).discard(old.group_id)
                else:
                    self.by_member[t].setdefault(m.principal_id, set()).discard(old.group_id)
        # новые индексы
        for m in g.members:
            if m.type == "group":
                self.edges[t].setdefault(g.group_id, set()).add(m.group_id)  # child link
                self.rev_edges[t].setdefault(m.group_id, set()).add(g.group_id)
            else:
                self.by_member[t].setdefault(m.principal_id, set()).add(g.group_id)

    # ------- CRUD -------
    def create(self, g: Group) -> Group:
        with self._lock:
            self._ensure_tenant(g.tenant_id)
            if g.group_id in self.groups[g.tenant_id]:
                raise AlreadyExists(f"group '{g.group_id}' already exists in tenant '{g.tenant_id}'")
            g.create_time = now_utc()
            g.update_time = g.create_time
            g.etag = g.compute_etag()
            self.groups[g.tenant_id][g.group_id] = g
            self._put_indexes(g, old=None)
            return g

    def get(self, tenant_id: str, group_id: str) -> Group:
        with self._lock:
            self._ensure_tenant(tenant_id)
            g = self.groups[tenant_id].get(group_id)
            if not g:
                raise NotFound(f"group '{group_id}' not found in tenant '{tenant_id}'")
            return g

    def update(self, g: Group, *, expect_etag: Optional[str]) -> Group:
        with self._lock:
            self._ensure_tenant(g.tenant_id)
            current = self.groups[g.tenant_id].get(g.group_id)
            if not current:
                raise NotFound(f"group '{g.group_id}' not found")
            if expect_etag and current.etag != expect_etag:
                raise Conflict("etag mismatch")
            # пересчёт etag
            g.update_time = now_utc()
            g.etag = g.compute_etag()
            self.groups[g.tenant_id][g.group_id] = g
            self._put_indexes(g, old=current)
            return g

    def delete(self, tenant_id: str, group_id: str, *, expect_etag: Optional[str]) -> None:
        with self._lock:
            self._ensure_tenant(tenant_id)
            g = self.groups[tenant_id].get(group_id)
            if not g:
                raise NotFound(f"group '{group_id}' not found")
            if expect_etag and g.etag != expect_etag:
                raise Conflict("etag mismatch")
            # запретим удаление, если на группу ссылаются другие группы
            parents = self.rev_edges[tenant_id].get(group_id, set())
            if parents:
                raise Conflict(f"group '{group_id}' is referenced by parent groups: {sorted(parents)}")
            # удаление индексов
            self.groups[tenant_id].pop(group_id, None)
            for m in g.members:
                if m.type == "group":
                    self.edges[tenant_id].get(group_id, set()).discard(m.group_id)
                    self.rev_edges[tenant_id].get(m.group_id, set()).discard(group_id)
                else:
                    self.by_member[tenant_id].get(m.principal_id, set()).discard(group_id)

    def list(self, tenant_id: str, *, prefix: Optional[str], limit: int, cursor: Optional[str]) -> Tuple[List[Group], Optional[str]]:
        with self._lock:
            self._ensure_tenant(tenant_id)
            gids = sorted(self.groups[tenant_id].keys())
            start = 0
            if cursor:
                try:
                    decoded = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("ascii")
                    # cursor = group_id последнего элемента предыдущей страницы
                    if decoded in gids:
                        start = gids.index(decoded) + 1
                except Exception:
                    start = 0
            if prefix:
                gids = [g for g in gids if g.startswith(prefix)]
            slice_ids = gids[start : start + max(1, min(limit, 1000))]
            items = [self.groups[tenant_id][gid] for gid in slice_ids]
            next_cursor = base64.urlsafe_b64encode(slice_ids[-1].encode("ascii")).decode("ascii") if len(slice_ids) == (start + min(limit, 1000) - start) and slice_ids else None
            return items, next_cursor

    def upsert_members(self, tenant_id: str, group_id: str, add: List[MemberRef], remove: List[MemberRef], *, expect_etag: Optional[str]) -> Group:
        with self._lock:
            g = self.get(tenant_id, group_id)
            if expect_etag and g.etag != expect_etag:
                raise Conflict("etag mismatch")
            # подготовим множества
            cur = {(m.type, m.group_id or m.principal_id) for m in g.members}
            rem = {(m.type, m.group_id or m.principal_id) for m in remove}
            addk = {(m.type, m.group_id or m.principal_id) for m in add}
            # применим изменения
            new_members_map: Dict[Tuple[str, str], MemberRef] = {(m.type, m.group_id or m.principal_id): m for m in g.members}
            for k in rem:
                new_members_map.pop(k, None)
            for m in add:
                new_members_map[(m.type, m.group_id or m.principal_id)] = m
            new_members = list(new_members_map.values())

            # проверка циклов для добавляемых связей group->group
            children_to_add = [m.group_id for m in add if m.type == "group"]
            if children_to_add:
                # построим временный граф и проверим, что group_id не достижим из новых детей
                if self._would_create_cycle(tenant_id, parent=group_id, new_children=children_to_add):
                    raise CycleDetected(f"adding {children_to_add} to '{group_id}' would create a cycle")

            new_g = g.copy(update={"members": new_members, "update_time": now_utc()})
            new_g.etag = new_g.compute_etag()
            # обновим индексы
            self.groups[tenant_id][group_id] = new_g
            self._put_indexes(new_g, old=g)
            return new_g

    def _would_create_cycle(self, tenant_id: str, *, parent: str, new_children: List[str]) -> bool:
        # Проверяем достижимость parent из любого child (т.е. существует путь child -> ... -> parent)
        rev = self.rev_edges.setdefault(tenant_id, {})
        seen: Set[str] = set()
        dq: deque[str] = deque(new_children)
        while dq:
            cur = dq.popleft()
            if cur == parent:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            for p in rev.get(cur, set()):
                dq.append(p)
        return False

    def snapshot(self, tenant_id: str) -> GroupSnapshot:
        with self._lock:
            self._ensure_tenant(tenant_id)
            return GroupSnapshot(tenant_id=tenant_id, groups=list(self.groups[tenant_id].values()))

    def import_snapshot(self, snap: GroupSnapshot, *, overwrite: bool) -> None:
        with self._lock:
            self._ensure_tenant(snap.tenant_id)
            if not overwrite and self.groups[snap.tenant_id]:
                raise Conflict("tenant has existing groups; set overwrite=True to replace")
            # сброс
            self.groups[snap.tenant_id] = {}
            self.by_member[snap.tenant_id] = {}
            self.edges[snap.tenant_id] = {}
            self.rev_edges[snap.tenant_id] = {}
            # загрузка
            for g in snap.groups:
                if g.tenant_id != snap.tenant_id:
                    raise Validation(f"group '{g.group_id}' has different tenant_id")
                g = g.copy(update={"etag": g.compute_etag(), "update_time": now_utc()})
                self.groups[snap.tenant_id][g.group_id] = g
                self._put_indexes(g, old=None)

# =========================
# Сервис IAM Groups (бизнес-логика)
# =========================

@dataclass
class GroupsConfig:
    membership_ttl_seconds: int = 30  # TTL кэша is_member/effective_roles
    audit_hook: AuditHook = NoopAuditHook()

class GroupService:
    def __init__(self, repo: GroupRepository, cfg: Optional[GroupsConfig] = None) -> None:
        self.repo = repo
        self.cfg = cfg or GroupsConfig()
        self._cache = TTLCache(ttl_seconds=self.cfg.membership_ttl_seconds)

    # ---------- CRUD ----------
    def create_group(
        self,
        tenant_id: str,
        group_id: str,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        attributes: Optional[Mapping[str, Any]] = None,
        roles: Optional[Iterable[str]] = None,
        members: Optional[Iterable[MemberRef]] = None,
    ) -> Group:
        g = Group(
            tenant_id=tenant_id,
            group_id=group_id,
            display_name=display_name,
            description=description,
            labels=Labels(__root__=dict(labels or {})),
            attributes=Attributes(__root__=dict(attributes or {})),
            roles=list(roles or []),
            members=list(members or []),
        )
        # запрет циклов при создании (если в members есть вложенные группы)
        group_children = [m.group_id for m in g.members if m.type == "group"]
        if group_children:
            # временно разместим группу без индексов, проверку сделаем после create и upsert_members
            pass
        created = self.repo.create(g)
        self._cache.clear_prefix(f"{tenant_id}|")  # инвалидируем кэш арендатора
        self.cfg.audit_hook.on_group_created(created)
        return created

    def get_group(self, tenant_id: str, group_id: str) -> Group:
        return self.repo.get(tenant_id, group_id)

    def update_group(
        self,
        tenant_id: str,
        group_id: str,
        *,
        expect_etag: Optional[str],
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        attributes: Optional[Mapping[str, Any]] = None,
        roles: Optional[Iterable[str]] = None,
        disabled: Optional[bool] = None,
    ) -> Group:
        g = self.repo.get(tenant_id, group_id)
        updates: Dict[str, Any] = {}
        fields: List[str] = []
        if display_name is not None: updates["display_name"] = display_name; fields.append("display_name")
        if description is not None: updates["description"] = description; fields.append("description")
        if labels is not None: updates["labels"] = Labels(__root__=dict(labels)); fields.append("labels")
        if attributes is not None: updates["attributes"] = Attributes(__root__=dict(attributes)); fields.append("attributes")
        if roles is not None: updates["roles"] = list(roles); fields.append("roles")
        if disabled is not None: updates["disabled"] = bool(disabled); fields.append("disabled")
        if not fields:
            return g
        ng = g.copy(update=updates)
        saved = self.repo.update(ng, expect_etag=expect_etag)
        self._cache.clear_prefix(f"{tenant_id}|")
        self.cfg.audit_hook.on_group_updated(saved, fields)
        return saved

    def delete_group(self, tenant_id: str, group_id: str, *, expect_etag: Optional[str]) -> None:
        self.repo.delete(tenant_id, group_id, expect_etag=expect_etag)
        self._cache.clear_prefix(f"{tenant_id}|")
        self.cfg.audit_hook.on_group_deleted(tenant_id, group_id)

    def list_groups(self, tenant_id: str, *, prefix: Optional[str] = None, limit: int = 100, cursor: Optional[str] = None) -> Tuple[List[Group], Optional[str]]:
        return self.repo.list(tenant_id, prefix=prefix, limit=limit, cursor=cursor)

    # ---------- Члены ----------
    def add_members(self, tenant_id: str, group_id: str, members: Iterable[MemberRef], *, expect_etag: Optional[str]) -> Group:
        g = self.repo.upsert_members(tenant_id, group_id, add=list(members), remove=[], expect_etag=expect_etag)
        self._cache.clear_prefix(f"{tenant_id}|")
        self.cfg.audit_hook.on_members_changed(g, added=list(members), removed=[])
        return g

    def remove_members(self, tenant_id: str, group_id: str, members: Iterable[MemberRef], *, expect_etag: Optional[str]) -> Group:
        g = self.repo.upsert_members(tenant_id, group_id, add=[], remove=list(members), expect_etag=expect_etag)
        self._cache.clear_prefix(f"{tenant_id}|")
        self.cfg.audit_hook.on_members_changed(g, added=[], removed=list(members))
        return g

    # ---------- Транзитивное членство / DAG ----------
    def _expand_groups(self, tenant_id: str, start_groups: Iterable[str]) -> Set[str]:
        """
        Возвращает транзитивное множество групп (включая начальные), обход по дочерним рёбрам.
        """
        # Доступ только через repo.in-memory (нужно API для внешних реализаций),
        # но для совместимости используем публичные методы get(); получим прямых детей из модели.
        visited: Set[str] = set()
        dq: deque[str] = deque(start_groups)
        while dq:
            gid = dq.popleft()
            if gid in visited:
                continue
            visited.add(gid)
            g = self.repo.get(tenant_id, gid)
            for m in g.members:
                if m.type == "group":
                    dq.append(m.group_id)
        return visited

    def is_member(self, tenant_id: str, group_id: str, principal_id: str) -> bool:
        cache_key_prefix = f"{tenant_id}|is_member|{group_id}|{principal_id}"
        cached = self._cache.get(cache_key_prefix)
        if cached is not None:
            return bool(cached)
        # Пробежимся по графу вниз от group_id и проверим наличие principal среди прямых участников каждой группы
        dq: deque[str] = deque([group_id])
        seen: Set[str] = set()
        result = False
        while dq:
            gid = dq.popleft()
            if gid in seen:
                continue
            seen.add(gid)
            g = self.repo.get(tenant_id, gid)
            # прямые участники-принципы
            for m in g.members:
                if m.type != "group" and m.principal_id == principal_id:
                    result = True
                    dq.clear()
                    break
            # добавить дочерние группы
            for m in g.members:
                if m.type == "group":
                    dq.append(m.group_id)
        self._cache.set(result, cache_key_prefix)
        return result

    def principal_groups(self, tenant_id: str, principal_id: str) -> Set[str]:
        """
        Возвращает множество групп, в которых PRINCIPAL состоит транзитивно.
        Для in-memory реализации используем обратный обход (по родителям).
        """
        # Попробуем воспользоваться снапшотом для повышения совместимости бэкендов.
        snap = self.repo.snapshot(tenant_id)
        # построим обратные рёбра child->parents
        rev: Dict[str, Set[str]] = {}
        direct_groups: Set[str] = set()
        for g in snap.groups:
            for m in g.members:
                if m.type == "group":
                    rev.setdefault(m.group_id, set()).add(g.group_id)
                else:
                    if m.principal_id == principal_id:
                        direct_groups.add(g.group_id)
        # поднимемся вверх
        res: Set[str] = set()
        dq: deque[str] = deque(direct_groups)
        while dq:
            gid = dq.popleft()
            if gid in res:
                continue
            res.add(gid)
            for p in rev.get(gid, set()):
                dq.append(p)
        return res

    # ---------- Роли ----------
    def effective_roles(self, tenant_id: str, principal_id: str) -> Set[str]:
        cache_key = f"{tenant_id}|roles|{principal_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return set(cached)
        snap = self.repo.snapshot(tenant_id)
        roles: Set[str] = set()
        # сначала соберём группы принципа
        groups_of_principal = self.principal_groups(tenant_id, principal_id)
        groups_of_principal.update(self._find_direct_groups_for_principal(snap, principal_id))
        # теперь добавим роли всех транзитивно нижестоящих групп (группы содержат роли, наследование вверх)
        gid_to_group = {g.group_id: g for g in snap.groups}
        for gid in list(groups_of_principal):
            if gid not in gid_to_group:
                continue
            # поднимемся вниз по дочерним рёбрам и захватим роли
            visited: Set[str] = set()
            dq: deque[str] = deque([gid])
            while dq:
                cur = dq.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                g = gid_to_group.get(cur)
                if not g:
                    continue
                roles.update(g.roles)
                for m in g.members:
                    if m.type == "group":
                        dq.append(m.group_id)
        self._cache.set(list(roles), cache_key)
        return roles

    def _find_direct_groups_for_principal(self, snap: GroupSnapshot, principal_id: str) -> Set[str]:
        res: Set[str] = set()
        for g in snap.groups:
            for m in g.members:
                if m.type != "group" and m.principal_id == principal_id:
                    res.add(g.group_id)
                    break
        return res

    # ---------- Снапшоты ----------
    def export_snapshot(self, tenant_id: str) -> GroupSnapshot:
        return self.repo.snapshot(tenant_id)

    def import_snapshot(self, snap: GroupSnapshot, *, overwrite: bool = False) -> None:
        self.repo.import_snapshot(snap, overwrite=overwrite)
        self._cache.clear_prefix(f"{snap.tenant_id}|")

# =========================
# Пример использования (доп. документация в коде)
# =========================
#
# repo = InMemoryGroupRepository()
# svc = GroupService(repo)
#
# # Создание группы
# g = svc.create_group(
#     tenant_id="acme",
#     group_id="analytics",
#     display_name="Analytics Team",
#     roles=["role.read.data", "role.query.bi"],
# )
#
# # Добавление участников
# svc.add_members("acme", "analytics", [
#     MemberRef(type="user", principal_id="u:alice"),
#     MemberRef(type="group", group_id="data-readers"),
# ], expect_etag=g.etag)
#
# # Проверка членства
# svc.is_member("acme", "analytics", "u:alice")  # True/False
#
# # Эффективные роли пользователя
# svc.effective_roles("acme", "u:alice")  # set([...])
#
# # Экспорт/импорт снапшота (бэкап/миграция)
# snap = svc.export_snapshot("acme")
# svc.import_snapshot(snap, overwrite=True)
