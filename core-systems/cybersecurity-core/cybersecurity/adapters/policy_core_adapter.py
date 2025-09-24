# cybersecurity-core/cybersecurity/adapters/policy_core_adapter.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Mapping, MutableMapping, Optional, Protocol, Tuple, TypedDict
from uuid import UUID, uuid4

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

# Опциональный Redis (используется, если доступен и включен в settings)
try:
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False

logger = logging.getLogger(__name__)

# ==========================
# Конфигурация и утилиты
# ==========================

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9\.-]+)?$")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _now_ts() -> float:
    return time.time()

def _model_to_dict(obj: Any) -> Dict[str, Any]:
    """
    Универсальная нормализация входных моделей (Pydantic v1/v2 или словари).
    """
    if obj is None:
        return {}
    # Pydantic v2
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json")
        except Exception:
            return obj.model_dump()
    # Pydantic v1
    if hasattr(obj, "dict"):
        return obj.dict()
    if isinstance(obj, Mapping):
        return dict(obj)
    raise TypeError("Unsupported model type")

def _deep_update(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if v is None:
            out[k] = None
        elif isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = _deep_update(out[k], v)  # type: ignore[arg-type]
        else:
            out[k] = v
    return out

# ==========================
# Типы/контракты
# ==========================

PolicyType = Literal["rbac", "ids", "edr", "ti", "blocklist"]
PolicyStatus = Literal["draft", "active", "deprecated"]

class PolicyRule(TypedDict, total=False):
    id: UUID
    description: str
    condition: Dict[str, Any]
    actions: List[Dict[str, Any]]

class PolicyRecord(TypedDict, total=False):
    id: UUID
    name: str
    title: str
    type: PolicyType
    version: str
    status: PolicyStatus
    description: str
    tags: List[str]
    scope: Dict[str, Any]
    rules: List[PolicyRule]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    revision: int

class Pagination(TypedDict, total=False):
    limit: int
    next_cursor: Optional[str]
    prev_cursor: Optional[str]

class EvaluateRequestDict(TypedDict, total=False):
    payload: Dict[str, Any]
    mode: Literal["dry_run", "enforce"]
    context: Dict[str, Any]
    policy_id: Optional[str]
    embedded_policy: Optional[Dict[str, Any]]

class EvaluateResponseDict(TypedDict, total=False):
    decision: Literal["allow", "deny"]
    matched_rules: List[UUID]
    reasons: List[str]
    metrics: Dict[str, Any]

# ==========================
# Репозиторий (по умолчанию in-memory)
# ==========================

class PolicyRepository(Protocol):
    async def list(
        self,
        *,
        limit: int,
        cursor: Optional[str],
        type_: Optional[PolicyType],
        status_: Optional[PolicyStatus],
        q: Optional[str],
        tags: Optional[List[str]],
        tenant_id: Optional[str],
    ) -> Tuple[List[PolicyRecord], Pagination]:
        ...

    async def get(self, *, policy_id: UUID) -> PolicyRecord:
        ...

    async def create(self, *, record: PolicyRecord) -> PolicyRecord:
        ...

    async def replace(self, *, policy_id: UUID, new_record: PolicyRecord, expected_revision: Optional[int]) -> PolicyRecord:
        ...

    async def patch(self, *, policy_id: UUID, patch_data: Dict[str, Any], expected_revision: Optional[int]) -> PolicyRecord:
        ...

    async def delete(self, *, policy_id: UUID) -> None:
        ...

    async def set_status(self, *, policy_id: UUID, status_: PolicyStatus) -> PolicyRecord:
        ...


@dataclass
class _Cursor:
    created_at: float
    id_hex: str

    @staticmethod
    def encode(dt: datetime, id_: UUID) -> str:
        payload = json.dumps({"t": dt.timestamp(), "i": id_.hex}, separators=(",", ":"))
        return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")

    @staticmethod
    def decode(cursor: str) -> "_Cursor":
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        obj = json.loads(raw)
        return _Cursor(created_at=float(obj["t"]), id_hex=str(obj["i"]))


class InMemoryPolicyRepository(PolicyRepository):
    """
    Потокобезопасный in-memory репозиторий для разработки/тестов.
    """
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._items: Dict[UUID, PolicyRecord] = {}

    async def list(
        self,
        *,
        limit: int,
        cursor: Optional[str],
        type_: Optional[PolicyType],
        status_: Optional[PolicyStatus],
        q: Optional[str],
        tags: Optional[List[str]],
        tenant_id: Optional[str],
    ) -> Tuple[List[PolicyRecord], Pagination]:
        async with self._lock:
            items = list(self._items.values())

        def _match(it: PolicyRecord) -> bool:
            if type_ and it.get("type") != type_:
                return False
            if status_ and it.get("status") != status_:
                return False
            if q:
                s = json.dumps({k: it.get(k) for k in ("name","title","description","tags")}, ensure_ascii=False).lower()
                if q.lower() not in s:
                    return False
            if tags:
                itags = set(it.get("tags", []))
                if not set(tags).issubset(itags):
                    return False
            return True

        filtered = [it for it in items if _match(it)]
        filtered.sort(key=lambda r: (r["created_at"], r["id"]))  # стабильность

        start = 0
        if cursor:
            try:
                c = _Cursor.decode(cursor)
                def _pos(rec: PolicyRecord) -> bool:
                    return (rec["created_at"].timestamp(), rec["id"].hex) > (c.created_at, c.id_hex)
                for i, rec in enumerate(filtered):
                    if _pos(rec):
                        start = i
                        break
            except Exception:
                start = 0

        slice_ = filtered[start:start + limit]
        next_cursor = None
        if len(filtered) > start + len(slice_):
            last = slice_[-1]
            next_cursor = _Cursor.encode(last["created_at"], last["id"])
        page: Pagination = {"limit": limit, "next_cursor": next_cursor, "prev_cursor": None}
        return slice_, page

    async def get(self, *, policy_id: UUID) -> PolicyRecord:
        async with self._lock:
            rec = self._items.get(policy_id)
            if not rec:
                raise KeyError("not found")
            return dict(rec)

    async def create(self, *, record: PolicyRecord) -> PolicyRecord:
        async with self._lock:
            if record["id"] in self._items:
                raise KeyError("duplicate")
            self._items[record["id"]] = dict(record)
            return dict(record)

    async def replace(self, *, policy_id: UUID, new_record: PolicyRecord, expected_revision: Optional[int]) -> PolicyRecord:
        async with self._lock:
            old = self._items.get(policy_id)
            if not old:
                raise KeyError("not found")
            if expected_revision is not None and int(old["revision"]) != int(expected_revision):
                raise ValueError("revision_mismatch")
            new_record["revision"] = int(old["revision"]) + 1
            new_record["updated_at"] = utc_now()
            self._items[policy_id] = dict(new_record)
            return dict(new_record)

    async def patch(self, *, policy_id: UUID, patch_data: Dict[str, Any], expected_revision: Optional[int]) -> PolicyRecord:
        async with self._lock:
            cur = self._items.get(policy_id)
            if not cur:
                raise KeyError("not found")
            if expected_revision is not None and int(cur["revision"]) != int(expected_revision):
                raise ValueError("revision_mismatch")
            merged = _deep_update(cur, patch_data)
            merged["revision"] = int(cur["revision"]) + 1
            merged["updated_at"] = utc_now()
            self._items[policy_id] = dict(merged)
            return dict(merged)

    async def delete(self, *, policy_id: UUID) -> None:
        async with self._lock:
            if policy_id in self._items:
                del self._items[policy_id]

    async def set_status(self, *, policy_id: UUID, status_: PolicyStatus) -> PolicyRecord:
        async with self._lock:
            cur = self._items.get(policy_id)
            if not cur:
                raise KeyError("not found")
            cur = dict(cur)
            cur["status"] = status_
            cur["revision"] = int(cur["revision"]) + 1
            cur["updated_at"] = utc_now()
            self._items[policy_id] = dict(cur)
            return dict(cur)

# ==========================
# Идемпотентность и кэш
# ==========================

class IdempotencyStore(Protocol):
    async def get(self, key: str) -> Optional[str]: ...
    async def set(self, key: str, value: str, ttl_sec: int) -> None: ...

class CacheStore(Protocol):
    async def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None: ...
    async def delete(self, key: str) -> None: ...

class MemoryIdempotencyStore(IdempotencyStore):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            value, exp = v
            if _now_ts() > exp:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: str, ttl_sec: int) -> None:
        async with self._lock:
            self._data[key] = (value, _now_ts() + ttl_sec)

class MemoryCacheStore(CacheStore):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            value, exp = v
            if _now_ts() > exp:
                self._data.pop(key, None)
                return None
            return dict(value)

    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None:
        async with self._lock:
            self._data[key] = (dict(value), _now_ts() + ttl_sec)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

class RedisIdempotencyStore(IdempotencyStore):
    def __init__(self, client: "aioredis.Redis") -> None:
        self._r = client

    async def get(self, key: str) -> Optional[str]:
        v = await self._r.get(key)
        return v.decode("utf-8") if v else None

    async def set(self, key: str, value: str, ttl_sec: int) -> None:
        await self._r.set(key, value, ex=ttl_sec, nx=True)

class RedisCacheStore(CacheStore):
    def __init__(self, client: "aioredis.Redis") -> None:
        self._r = client

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        v = await self._r.get(key)
        if not v:
            return None
        return json.loads(v.decode("utf-8"))

    async def set(self, key: str, value: Dict[str, Any], ttl_sec: int) -> None:
        await self._r.set(key, json.dumps(value, separators=(",", ":")), ex=ttl_sec)

    async def delete(self, key: str) -> None:
        await self._r.delete(key)

# ==========================
# Мини-политический движок (оценка)
# ==========================

class MiniPolicyEngine:
    """
    Упрощённый движок: проход по правилам, матчинг condition и агрегирование actions.
    Поддерживаемые операторы condition:
    - {"eq": {"path": "object.user.role", "value": "admin"}}
    - {"in": {"path": "object.country", "value": ["SE","NO"]}}
    - {"regex": {"path": "object.url", "value": "^/admin"}}
    - {"gt"/"lt": {"path": "object.risk", "value": 50}}
    - логика AND/OR: {"and": [<cond>, <cond>]} / {"or": [<cond>, <cond>]}
    Действия:
    - {"type": "deny", "reason": "..."} -> приводит к deny при совпадении
    - {"type": "allow"} -> отмечает согласие; при отсутствии deny итог allow
    """
    def __init__(self) -> None:
        pass

    def evaluate(self, *, policy: PolicyRecord, payload: Dict[str, Any], context: Dict[str, Any]) -> EvaluateResponseDict:
        matched: List[UUID] = []
        reasons: List[str] = []
        denied = False
        rules: List[PolicyRule] = policy.get("rules", []) or []

        for rule in rules:
            cond = rule.get("condition") or {}
            if self._match(cond, payload=payload, context=context):
                matched.append(rule.get("id") or uuid4())
                for act in rule.get("actions", []) or []:
                    t = (act.get("type") or "").lower()
                    if t == "deny":
                        denied = True
                        if act.get("reason"):
                            reasons.append(str(act["reason"]))
                    elif t == "allow":
                        # positive marker; окончательное решение ниже
                        if act.get("reason"):
                            reasons.append(str(act["reason"]))

        decision: Literal["allow", "deny"] = "deny" if denied else "allow"
        return {
            "decision": decision,
            "matched_rules": matched,
            "reasons": reasons,
            "metrics": {"rules_total": len(rules), "rules_matched": len(matched)},
        }

    # ----------------- matching -----------------

    def _match(self, cond: Any, *, payload: Dict[str, Any], context: Dict[str, Any]) -> bool:
        if not cond:
            return True
        if isinstance(cond, Mapping):
            if "and" in cond:
                return all(self._match(c, payload=payload, context=context) for c in cond["and"])
            if "or" in cond:
                return any(self._match(c, payload=payload, context=context) for c in cond["or"])
            for op, body in cond.items():
                if op in ("eq", "neq", "in", "regex", "gt", "lt"):
                    if not self._eval_op(op, body, payload=payload, context=context):
                        return False if op != "neq" else True
            return True
        return False

    def _eval_op(self, op: str, body: Mapping[str, Any], *, payload: Dict[str, Any], context: Dict[str, Any]) -> bool:
        path = str(body.get("path") or "")
        value = body.get("value")
        source = {"object": payload, "context": context}
        actual = self._get_by_path(source, path)
        try:
            if op == "eq":
                return actual == value
            if op == "neq":
                return actual != value
            if op == "in":
                return actual in (value or [])
            if op == "regex":
                return bool(re.search(str(value), str(actual or "")))
            if op == "gt":
                return float(actual) > float(value)
            if op == "lt":
                return float(actual) < float(value)
        except Exception:
            return False
        return False

    def _get_by_path(self, root: Dict[str, Any], path: str) -> Any:
        # path пример: "object.user.role"
        node: Any = root
        for part in path.split("."):
            if part == "":
                continue
            if isinstance(node, Mapping) and part in node:
                node = node[part]  # type: ignore[index]
            else:
                return None
        return node

# ==========================
# PolicyCoreAdapter
# ==========================

class PolicyCoreAdapter:
    """
    Реализация сервисного слоя Policies для FastAPI-роутера.
    """
    def __init__(
        self,
        repo: PolicyRepository,
        *,
        idempotency: Optional[IdempotencyStore] = None,
        cache: Optional[CacheStore] = None,
        idempotency_ttl_sec: int = 24 * 3600,
        cache_ttl_sec: int = 10,
        audit_logger: Optional[logging.Logger] = None,
        tenant_scoping: bool = True,
    ) -> None:
        self.repo = repo
        self.idemp = idempotency or MemoryIdempotencyStore()
        self.cache = cache or MemoryCacheStore()
        self.idemp_ttl_sec = idempotency_ttl_sec
        self.cache_ttl_sec = cache_ttl_sec
        self.audit = audit_logger or logger.getChild("audit")
        self.engine = MiniPolicyEngine()
        self.tenant_scoping = tenant_scoping

    # ---------- API: list ----------
    async def list_policies(
        self,
        *,
        limit: int,
        cursor: Optional[str],
        type_: Optional[PolicyType],
        status_: Optional[PolicyStatus],
        q: Optional[str],
        tags: Optional[List[str]],
        tenant_id: Optional[str],
    ) -> Tuple[List[PolicyRecord], Pagination]:
        return await self.repo.list(
            limit=limit, cursor=cursor, type_=type_, status_=status_, q=q, tags=tags, tenant_id=tenant_id
        )

    # ---------- API: create (idempotent) ----------
    async def create_policy(self, *, data: Any, idempotency_key: Optional[str], subject: str) -> PolicyRecord:
        payload = _model_to_dict(data)
        self._validate_create_payload(payload)

        if idempotency_key:
            found = await self.idemp.get(self._idemp_key(idempotency_key))
            if found:
                # возврат уже созданного ресурса
                try:
                    return await self.repo.get(policy_id=UUID(found))
                except Exception:
                    # запись потеряна — очищаем ключ
                    pass

        now = utc_now()
        rec: PolicyRecord = {
            "id": uuid4(),
            "name": payload["name"],
            "title": payload.get("title"),
            "type": payload["type"],
            "version": payload["version"],
            "status": payload.get("status") or "draft",
            "description": payload.get("description"),
            "tags": payload.get("tags") or [],
            "scope": payload.get("scope"),
            "rules": payload.get("rules") or [],
            "metadata": payload.get("metadata") or {},
            "created_at": now,
            "updated_at": now,
            "revision": 0,
        }
        rec = await self.repo.create(record=rec)
        if idempotency_key:
            await self.idemp.set(self._idemp_key(idempotency_key), str(rec["id"]), ttl_sec=self.idemp_ttl_sec)

        await self.cache.set(self._cache_key(rec["id"]), dict(rec), ttl_sec=self.cache_ttl_sec)
        self._audit("create", subject=subject, resource=rec)
        return rec

    # ---------- API: get (with cache) ----------
    async def get_policy(self, *, policy_id: UUID) -> PolicyRecord:
        ck = self._cache_key(policy_id)
        cached = await self.cache.get(ck)
        if cached:
            # Преобразуем типы минимально — datetime при сериализации в JSON может потеряться; в in-memory мы не сериализуем
            if isinstance(cached.get("created_at"), str):
                cached["created_at"] = datetime.fromisoformat(cached["created_at"])  # type: ignore[assignment]
            if isinstance(cached.get("updated_at"), str):
                cached["updated_at"] = datetime.fromisoformat(cached["updated_at"])  # type: ignore[assignment]
            return cached  # type: ignore[return-value]
        rec = await self.repo.get(policy_id=policy_id)
        await self.cache.set(ck, dict(rec), ttl_sec=self.cache_ttl_sec)
        return rec

    # ---------- API: update (PUT) ----------
    async def update_policy_put(self, *, policy_id: UUID, data: Any, expected_revision: Optional[int]) -> PolicyRecord:
        payload = _model_to_dict(data)
        self._validate_create_payload(payload)  # для PUT — полная валидация
        # сохраняем поля, которые не переданы в PUT? — при полном обновлении ожидаем замены
        new_rec = await self.repo.replace(
            policy_id=policy_id,
            new_record={
                "id": policy_id,
                "name": payload["name"],
                "title": payload.get("title"),
                "type": payload["type"],
                "version": payload["version"],
                "status": payload.get("status") or "draft",
                "description": payload.get("description"),
                "tags": payload.get("tags") or [],
                "scope": payload.get("scope"),
                "rules": payload.get("rules") or [],
                "metadata": payload.get("metadata") or {},
                "created_at": utc_now(),  # может быть перезаписан на стороне БД триггером; здесь задаем безопасно
                "updated_at": utc_now(),
                "revision": 0,  # будет увеличен в repo
            },
            expected_revision=expected_revision,
        )
        await self.cache.set(self._cache_key(policy_id), dict(new_rec), ttl_sec=self.cache_ttl_sec)
        return new_rec

    # ---------- API: update (PATCH) ----------
    async def update_policy_patch(self, *, policy_id: UUID, data: Any, expected_revision: Optional[int]) -> PolicyRecord:
        patch = _model_to_dict(data)
        # опциональная валидация версии
        if "version" in patch and patch["version"] is not None and not SEMVER_RE.match(patch["version"]):
            raise ValueError("Invalid semantic version")
        new_rec = await self.repo.patch(policy_id=policy_id, patch_data=patch, expected_revision=expected_revision)
        await self.cache.set(self._cache_key(policy_id), dict(new_rec), ttl_sec=self.cache_ttl_sec)
        return new_rec

    # ---------- API: delete ----------
    async def delete_policy(self, *, policy_id: UUID, subject: str) -> None:
        await self.repo.delete(policy_id=policy_id)
        await self.cache.delete(self._cache_key(policy_id))
        self._audit("delete", subject=subject, resource={"id": str(policy_id)})

    # ---------- API: set_status ----------
    async def set_status(self, *, policy_id: UUID, status_: PolicyStatus, subject: str) -> PolicyRecord:
        new_rec = await self.repo.set_status(policy_id=policy_id, status_=status_)
        await self.cache.set(self._cache_key(policy_id), dict(new_rec), ttl_sec=self.cache_ttl_sec)
        self._audit("status", subject=subject, resource={"id": str(policy_id), "status": status_})
        return new_rec

    # ---------- API: evaluate ----------
    async def evaluate(self, *, request: Any) -> EvaluateResponseDict:
        req = _model_to_dict(request)
        payload: Dict[str, Any] = req.get("payload") or {}
        context: Dict[str, Any] = req.get("context") or {}
        mode: str = req.get("mode") or "dry_run"

        policy: Optional[PolicyRecord] = None
        if req.get("embedded_policy"):
            emb = _model_to_dict(req["embedded_policy"])
            self._validate_create_payload(emb)
            policy = self._embedded_to_record(emb)
        else:
            pid = req.get("policy_id")
            if not pid:
                raise ValueError("policy_id or embedded_policy required")
            policy = await self.get_policy(policy_id=UUID(str(pid)))

        result = self.engine.evaluate(policy=policy, payload=payload, context=context)
        # режим enforce пока влияет только на семантику вызывающей стороны; здесь возвращаем решение
        return result

    # ---------- API: export ----------
    async def export(self, *, policy_id: UUID, fmt: Literal["json","yaml"], pretty: bool) -> Tuple[str, str]:
        rec = await self.get_policy(policy_id=policy_id)
        serializable = self._to_serializable(rec)
        if fmt == "yaml":
            if not _HAS_YAML:
                # Фоллбек на JSON
                return "application/json", json.dumps(serializable, indent=(2 if pretty else None), ensure_ascii=False)
            return "application/yaml", yaml.safe_dump(serializable, sort_keys=False, allow_unicode=True)
        return "application/json", json.dumps(serializable, indent=(2 if pretty else None), ensure_ascii=False)

    # ==========================
    # Внутренние методы
    # ==========================

    def _validate_create_payload(self, p: Mapping[str, Any]) -> None:
        missing = [k for k in ("name","type","version") if not p.get(k)]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
        if not SEMVER_RE.match(str(p["version"])):
            raise ValueError("Invalid semantic version")
        if not re.match(r"^[a-z][a-z0-9_\-]{1,63}$", str(p["name"])):
            raise ValueError("Invalid policy name")
        if p.get("status") and p["status"] not in ("draft","active","deprecated"):
            raise ValueError("Invalid status")

    def _cache_key(self, policy_id: UUID) -> str:
        return f"policy:{policy_id.hex}"

    def _idemp_key(self, key: str) -> str:
        return f"idemp:policies:{key}"

    def _embedded_to_record(self, emb: Mapping[str, Any]) -> PolicyRecord:
        now = utc_now()
        return {
            "id": uuid4(),
            "name": str(emb["name"]),
            "title": emb.get("title"),
            "type": emb["type"],
            "version": emb["version"],
            "status": emb.get("status") or "draft",
            "description": emb.get("description"),
            "tags": emb.get("tags") or [],
            "scope": emb.get("scope"),
            "rules": emb.get("rules") or [],
            "metadata": emb.get("metadata") or {},
            "created_at": now,
            "updated_at": now,
            "revision": 0,
        }

    def _to_serializable(self, rec: PolicyRecord) -> Dict[str, Any]:
        out = dict(rec)
        # datetime -> isoformat
        for k in ("created_at","updated_at"):
            if isinstance(out.get(k), datetime):
                out[k] = out[k].isoformat()  # type: ignore[assignment]
        # UUID -> str
        for k in ("id",):
            if isinstance(out.get(k), UUID):
                out[k] = str(out[k])  # type: ignore[assignment]
        # rules ids
        rules = out.get("rules") or []
        for r in rules:
            if isinstance(r.get("id"), UUID):
                r["id"] = str(r["id"])
        out["rules"] = rules
        return out

    def _audit(self, action: str, *, subject: str, resource: Mapping[str, Any]) -> None:
        try:
            self.audit.info(
                "audit",
                extra={"action": action, "subject": subject, "resource": json.dumps(self._to_strings(resource), ensure_ascii=False)},
            )
        except Exception:
            logger.debug("audit logging failed")

    def _to_strings(self, m: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in m.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            else:
                out[k] = str(v)
        return out


# ==========================
# Фабрика адаптера для DI
# ==========================

_adapter_singleton: Optional[PolicyCoreAdapter] = None

async def _build_redis_client():
    # Пытаемся взять параметры из глобальных настроек, если они есть
    try:
        from cybersecurity.settings import settings  # type: ignore
        if getattr(settings.redis, "enabled", False) and getattr(settings.redis, "url", None) and _HAS_REDIS:
            client = aioredis.from_url(str(settings.redis.url), decode_responses=False, socket_timeout=settings.redis.socket_timeout)
            # ping для проверки соединения
            await client.ping()
            return client
    except Exception:
        return None
    return None

def _memory_adapter() -> PolicyCoreAdapter:
    repo = InMemoryPolicyRepository()
    return PolicyCoreAdapter(repo=repo)

async def provide_policy_service() -> PolicyCoreAdapter:
    """
    Фабрика для FastAPI Depends.
    Пример подключения:
        from cybersecurity.adapters.policy_core_adapter import provide_policy_service
        app.dependency_overrides[get_policy_service] = provide_policy_service
    """
    global _adapter_singleton
    if _adapter_singleton is not None:
        return _adapter_singleton

    repo: PolicyRepository = InMemoryPolicyRepository()
    idemp: IdempotencyStore
    cache: CacheStore

    client = await _build_redis_client()
    if client is not None:
        idemp = RedisIdempotencyStore(client)
        cache = RedisCacheStore(client)
        logger.info("PolicyCoreAdapter: Redis enabled for idempotency/cache")
    else:
        idemp = MemoryIdempotencyStore()
        cache = MemoryCacheStore()
        logger.info("PolicyCoreAdapter: using in-memory idempotency/cache")

    _adapter_singleton = PolicyCoreAdapter(repo=repo, idempotency=idemp, cache=cache)
    return _adapter_singleton
