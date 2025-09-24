# -*- coding: utf-8 -*-
"""
Patch API (industrial-grade)

Функционал:
- RFC 6902 JSON Patch: add/replace/remove/move/copy/test
- RFC 7386 JSON Merge Patch
- Optimistic Concurrency: version + ETag (SHA1 по нормализованному JSON)
- Идемпотентность по operation_id (TTL store)
- Dry-run, транзакции (атомарное применение пачки операций)
- Конфликтная защита: проверка ETag/версии, защита от "потерянного обновления"
- Хуки: authorize, validate, transform (до применения), pre_commit/post_commit
- Политики: allowlist/denylist путей, максимальные размеры/глубина
- Аудит и метрики (заглушки), trace_id/span_id для корреляции
- Интеграционный интерфейс DataStore (in-memory реализация внутри)
- Снапшоты и утилиты diff->patch (простая стратегическая реализация)
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union, Set

Json = Union[dict, list, str, int, float, bool, None]

# =============================================================================
# Метрики/Аудит (заглушки)
# =============================================================================

class Metrics:
    @staticmethod
    def inc(name: str, **labels) -> None:
        pass

    @staticmethod
    def observe(name: str, value: float, **labels) -> None:
        pass

class Audit:
    @staticmethod
    def emit(event: str, payload: Dict[str, Any]) -> None:
        pass

# =============================================================================
# Исключения
# =============================================================================

class PatchError(Exception): ...

class VersionConflict(PatchError): ...
class PreconditionFailed(PatchError): ...
class InvalidPatch(PatchError): ...
class Unauthorized(PatchError): ...
class ForbiddenPath(PatchError): ...
class PathNotFound(PatchError): ...

# =============================================================================
# Утилиты JSON Pointer (RFC 6901)
# =============================================================================

def _ptr_unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")

def _split_pointer(ptr: str) -> List[str]:
    if ptr == "" or ptr == "/":
        return []
    if not ptr.startswith("/"):
        raise InvalidPatch("JSON Pointer must start with '/'")
    return [_ptr_unescape(p) for p in ptr.split("/")[1:]]

def _traverse(doc: Json, ptr: str, *, create_missing_parent: bool = False) -> Tuple[Any, Optional[str], Any]:
    """
    Возвращает (parent, last_token, target_or_None) для пути ptr.
    Если create_missing_parent=True, создаёт промежуточные объекты-словарики.
    """
    tokens = _split_pointer(ptr)
    if not tokens:
        return (None, None, doc)  # корень
    cur = doc
    for i, tok in enumerate(tokens[:-1]):
        if isinstance(cur, list):
            if tok == "-":
                raise InvalidPatch("'-' not allowed in middle of pointer for arrays")
            idx = int(tok)
            if idx < 0 or idx >= len(cur):
                raise PathNotFound(f"Index out of range: {ptr}")
            cur = cur[idx]
        elif isinstance(cur, dict):
            if tok not in cur:
                if create_missing_parent:
                    cur[tok] = {}
                else:
                    raise PathNotFound(f"Path not found: {ptr}")
            cur = cur[tok]
        else:
            raise PathNotFound(f"Cannot traverse into non-container at {tok}")
    last = tokens[-1]
    target = None
    if isinstance(cur, list):
        if last == "-":
            target = None
        else:
            try:
                idx = int(last)
                target = cur[idx]
            except (ValueError, IndexError):
                raise PathNotFound(f"Bad array index at {ptr}")
    elif isinstance(cur, dict):
        target = cur.get(last, None)
    else:
        raise PathNotFound(f"Cannot traverse leaf for {ptr}")
    return cur, last, target

# =============================================================================
# Этикетка/версия/хеш
# =============================================================================

def _stable_json(data: Json) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def compute_etag(data: Json) -> str:
    return hashlib.sha1(_stable_json(data)).hexdigest()

# =============================================================================
# Идемпотентность
# =============================================================================

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 900):
        self.ttl = ttl_seconds
        self._store: Dict[str, float] = {}
        self._lock = threading.RLock()

    def seen(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            # GC
            for k, ts in list(self._store.items()):
                if now - ts > self.ttl:
                    self._store.pop(k, None)
            if key in self._store:
                return True
            self._store[key] = now
            return False

# =============================================================================
# Хранилище
# =============================================================================

@dataclass
class Record:
    key: str
    value: Json
    version: int
    etag: str
    updated_at: float

class DataStore:
    """
    Интерфейс хранилища. Реализуйте для БД/кэша. В комплекте — InMemoryDataStore.
    """
    def get(self, key: str) -> Optional[Record]: ...
    def upsert(self, key: str, value: Json, expected_version: Optional[int]) -> Record: ...
    def snapshot(self) -> Dict[str, Record]: ...

class InMemoryDataStore(DataStore):
    def __init__(self):
        self._data: Dict[str, Record] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Record]:
        with self._lock:
            rec = self._data.get(key)
            return copy.deepcopy(rec) if rec else None

    def upsert(self, key: str, value: Json, expected_version: Optional[int]) -> Record:
        with self._lock:
            now = time.time()
            rec = self._data.get(key)
            if rec is None:
                if expected_version not in (None, 0):
                    raise VersionConflict("Expected version mismatch on create")
                ver = 1
            else:
                if expected_version is not None and expected_version != rec.version:
                    raise VersionConflict("Expected version mismatch")
                ver = rec.version + 1
            etag = compute_etag(value)
            rec = Record(key=key, value=copy.deepcopy(value), version=ver, etag=etag, updated_at=now)
            self._data[key] = rec
            return copy.deepcopy(rec)

    def snapshot(self) -> Dict[str, Record]:
        with self._lock:
            return copy.deepcopy(self._data)

# =============================================================================
# Политики и хуки
# =============================================================================

@dataclass
class PatchPolicy:
    allow_paths: Optional[Iterable[str]] = None
    deny_paths: Optional[Iterable[str]] = None
    max_operations: int = 1000
    max_doc_size_bytes: int = 2_000_000
    max_depth: int = 64

    def is_allowed(self, path: str) -> bool:
        if self.deny_paths:
            for p in self.deny_paths:
                if path.startswith(p):
                    return False
        if self.allow_paths:
            for p in self.allow_paths:
                if path.startswith(p):
                    return True
            return False
        return True

@dataclass
class Hooks:
    authorize: Optional[Callable[["Context"], None]] = None
    validate: Optional[Callable[[Json, List[dict]], None]] = None
    transform: Optional[Callable[[Json, List[dict]], Tuple[Json, List[dict]]]] = None
    pre_commit: Optional[Callable[["Context", Json, List[dict]], None]] = None
    post_commit: Optional[Callable[["Context", Record, List[dict]], None]] = None

# =============================================================================
# Запрос/ответ
# =============================================================================

@dataclass
class PatchRequest:
    key: str
    operations: List[dict]                  # JSON Patch ops ИЛИ один Merge Patch (op="merge", value=<object>)
    expected_etag: Optional[str] = None
    expected_version: Optional[int] = None
    operation_id: Optional[str] = None
    dry_run: bool = False
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PatchResult:
    key: str
    version: int
    etag: str
    value: Json
    updated_at: float
    applied_ops: int
    dry_run: bool

# =============================================================================
# Ядро применения патчей
# =============================================================================

def _json_merge_patch(doc: Json, merge_obj: Json) -> Json:
    if not isinstance(merge_obj, dict):
        # RFC 7386: если не объект — заменяем целиком
        return copy.deepcopy(merge_obj)
    if not isinstance(doc, dict):
        doc = {}
    out = copy.deepcopy(doc)
    for k, v in merge_obj.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = _json_merge_patch(out.get(k), v) if isinstance(v, dict) else copy.deepcopy(v)
    return out

def _apply_op(doc: Json, op: dict, policy: PatchPolicy) -> None:
    t = op.get("op")
    if t is None:
        raise InvalidPatch("Missing 'op'")
    if t == "merge":
        # семантика Merge Patch: ожидается op={"op":"merge","value":{...}}
        val = op.get("value")
        if val is None:
            raise InvalidPatch("merge requires 'value'")
        new = _json_merge_patch(doc, val)
        # заменяем корень doc на месте
        if isinstance(doc, dict):
            doc.clear(); doc.update(new) if isinstance(new, dict) else (_ for _ in ()).throw(InvalidPatch("merge root must remain object"))
        else:
            raise InvalidPatch("merge root must be object")
        return

    path = op.get("path")
    if path is None:
        raise InvalidPatch("Missing 'path'")
    if not policy.is_allowed(path):
        raise ForbiddenPath(f"Path {path} is not allowed by policy")
    parent, last, target = _traverse(doc, path, create_missing_parent=(t == "add"))
    if t == "test":
        val = op.get("value")
        if target != val:
            raise PreconditionFailed(f"test failed at {path}")
        return
    if t == "add":
        value = copy.deepcopy(op.get("value"))
        if parent is None:
            # замена корня
            raise InvalidPatch("add at root without value container not supported; use merge")
        if isinstance(parent, list):
            if last == "-":
                parent.append(value)
            else:
                idx = int(last)
                if idx < 0 or idx > len(parent):
                    raise InvalidPatch(f"add index out of range at {path}")
                parent.insert(idx, value)
        elif isinstance(parent, dict):
            parent[last] = value
        else:
            raise InvalidPatch(f"add invalid parent at {path}")
        return
    if t == "replace":
        value = copy.deepcopy(op.get("value"))
        if parent is None:
            raise InvalidPatch("replace at root not supported; use merge")
        if isinstance(parent, list):
            idx = int(last)  # may raise
            parent[idx] = value
        elif isinstance(parent, dict):
            if last not in parent:
                raise PathNotFound(f"replace path not found {path}")
            parent[last] = value
        else:
            raise InvalidPatch(f"replace invalid parent at {path}")
        return
    if t == "remove":
        if parent is None:
            raise InvalidPatch("remove at root not supported; use merge")
        if isinstance(parent, list):
            idx = int(last)
            del parent[idx]
        elif isinstance(parent, dict):
            if last not in parent:
                raise PathNotFound(f"remove path not found {path}")
            del parent[last]
        else:
            raise InvalidPatch(f"remove invalid parent at {path}")
        return
    if t in ("move", "copy"):
        from_ = op.get("from")
        if not from_:
            raise InvalidPatch(f"{t} requires 'from'")
        src_parent, src_last, src_target = _traverse(doc, from_)
        if t == "move":
            # удалим из источника
            if isinstance(src_parent, list):
                del src_parent[int(src_last)]
            elif isinstance(src_parent, dict):
                if src_last not in src_parent:
                    raise PathNotFound(f"move from not found {from_}")
                val = src_parent.pop(src_last)
            else:
                raise InvalidPatch("move invalid source parent")
        # для copy/move вставим значение в path
        val = src_target if t == "copy" else (val if 'val' in locals() else src_target)
        if parent is None:
            raise InvalidPatch(f"{t} at root not supported; use merge")
        if isinstance(parent, list):
            if last == "-":
                parent.append(copy.deepcopy(val))
            else:
                parent.insert(int(last), copy.deepcopy(val))
        elif isinstance(parent, dict):
            parent[last] = copy.deepcopy(val)
        else:
            raise InvalidPatch(f"{t} invalid parent at {path}")
        return
    raise InvalidPatch(f"Unknown op: {t}")

def _max_depth(obj: Json, depth: int = 0) -> int:
    if not isinstance(obj, (dict, list)):
        return depth
    if isinstance(obj, dict):
        return max([depth] + [_max_depth(v, depth + 1) for v in obj.values()])
    return max([depth] + [_max_depth(v, depth + 1) for v in obj])

# =============================================================================
# Контекст исполнения
# =============================================================================

@dataclass
class Context:
    req: PatchRequest
    before: Optional[Record]
    actor: Optional[str] = None
    tags: Set[str] = field(default_factory=set)

# =============================================================================
# Публичный API
# =============================================================================

class PatchAPI:
    def __init__(
        self,
        *,
        store: Optional[DataStore] = None,
        policy: Optional[PatchPolicy] = None,
        hooks: Optional[Hooks] = None,
        idem_ttl_s: int = 900,
    ):
        self.store = store or InMemoryDataStore()
        self.policy = policy or PatchPolicy()
        self.hooks = hooks or Hooks()
        self._idem = IdempotencyStore(ttl_seconds=idem_ttl_s)
        self._lock = threading.RLock()

    # ---------- Основной метод ---------- #

    def apply(self, req: PatchRequest, *, actor: Optional[str] = None) -> PatchResult:
        t_start = time.perf_counter()
        key = req.key
        ctx = Context(req=req, before=self.store.get(key), actor=actor)

        # идемпотентность
        if req.operation_id:
            idem_key = f"{key}:{req.operation_id}"
            if self._idem.seen(idem_key):
                # Возвращаем текущее состояние (идемпотентность)
                cur = self.store.get(key)
                if cur is None:
                    raise PreconditionFailed("Idempotent replay but record not found")
                return PatchResult(key=key, version=cur.version, etag=cur.etag, value=cur.value,
                                   updated_at=cur.updated_at, applied_ops=0, dry_run=False)

        # авторизация
        if self.hooks.authorize:
            self.hooks.authorize(ctx)

        # предзагрузка/инициализация документа
        base_doc: Json = copy.deepcopy(ctx.before.value) if ctx.before else {}

        # ожидания клиента
        if req.expected_etag and ctx.before and req.expected_etag != ctx.before.etag:
            raise VersionConflict("ETag mismatch")
        if req.expected_version is not None:
            exp = 0 if not ctx.before else ctx.before.version
            if req.expected_version != exp:
                raise VersionConflict("Version mismatch")

        ops = copy.deepcopy(req.operations)
        if not ops:
            raise InvalidPatch("No operations")

        # предварительная валидация и трансформации
        if self.hooks.validate:
            self.hooks.validate(base_doc, ops)
        if self.hooks.transform:
            base_doc, ops = self.hooks.transform(base_doc, ops)

        # лимиты
        if len(ops) > self.policy.max_operations:
            raise InvalidPatch("Too many operations")

        # применяем на копии для dry-run/атомарности
        work = copy.deepcopy(base_doc)

        # Если единственная операция merge — применим Merge Patch
        if len(ops) == 1 and ops[0].get("op") == "merge":
            _apply_op(work, ops[0], self.policy)
            applied = 1
        else:
            applied = 0
            for op in ops:
                _apply_op(work, op, self.policy)
                applied += 1

        # пост-проверки размера/глубины
        raw = _stable_json(work)
        if len(raw) > self.policy.max_doc_size_bytes:
            raise InvalidPatch("Document too large")
        if _max_depth(work) > self.policy.max_depth:
            raise InvalidPatch("Document too deep")

        # хуки pre_commit
        if self.hooks.pre_commit:
            self.hooks.pre_commit(ctx, work, ops)

        # dry-run быстрый выход
        if req.dry_run:
            # вычислим "виртуальную" версию/etag
            v = (ctx.before.version if ctx.before else 0) + 1
            e = compute_etag(work)
            Metrics.observe("patch_apply_latency_s", time.perf_counter() - t_start, type="dry_run")
            return PatchResult(key=key, version=v, etag=e, value=work, updated_at=time.time(),
                               applied_ops=applied, dry_run=True)

        # коммит
        with self._lock:
            expected_version = ctx.before.version if ctx.before else 0
            rec = self.store.upsert(key, work, expected_version=expected_version)

        # post_commit
        if self.hooks.post_commit:
            self.hooks.post_commit(ctx, rec, ops)

        Audit.emit("patch_apply", {
            "key": key, "actor": actor, "ops": applied, "version": rec.version,
            "trace": req.trace_id, "span": req.span_id
        })
        Metrics.observe("patch_apply_latency_s", time.perf_counter() - t_start, type="commit")

        return PatchResult(key=key, version=rec.version, etag=rec.etag, value=rec.value,
                           updated_at=rec.updated_at, applied_ops=applied, dry_run=False)

    # ---------- Диагностика/снапшоты ---------- #

    def get(self, key: str) -> Optional[Record]:
        return self.store.get(key)

    def snapshot(self) -> Dict[str, Record]:
        return self.store.snapshot()

# =============================================================================
# Diff утилита (простой JSON Patch генератор)
# =============================================================================

def _diff(a: Json, b: Json, path: str = "") -> List[dict]:
    ops: List[dict] = []
    if type(a) != type(b):
        # заменить целиком
        if path == "":
            return [{"op": "merge", "value": copy.deepcopy(b)}]
        else:
            return [{"op": "replace", "path": path, "value": copy.deepcopy(b)}]
    if isinstance(a, dict):
        akeys = set(a.keys()); bkeys = set(b.keys())
        for k in akeys - bkeys:
            ops.append({"op": "remove", "path": f"{path}/{_escape(k)}" if path else f"/{_escape(k)}"})
        for k in bkeys - akeys:
            ops.append({"op": "add", "path": f"{path}/{_escape(k)}" if path else f"/{_escape(k)}", "value": copy.deepcopy(b[k])})
        for k in akeys & bkeys:
            ops.extend(_diff(a[k], b[k], f"{path}/{_escape(k)}" if path else f"/{_escape(k)}"))
        return ops
    if isinstance(a, list):
        # простая стратегия: если разный размер или элементы — replace всего массива
        if len(a) != len(b) or any(_stable_json(a[i]) != _stable_json(b[i]) for i in range(len(a))):
            return [{"op": "replace", "path": path or "/", "value": copy.deepcopy(b)}]
        return []
    # скаляры
    if a != b:
        return [{"op": "replace", "path": path or "/", "value": copy.deepcopy(b)}]
    return []

def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")

def json_diff_to_patch(old: Json, new: Json) -> List[dict]:
    return _diff(old, new, "")

# =============================================================================
# Пример использования
# =============================================================================

if __name__ == "__main__":
    api = PatchAPI()

    # создание документа через merge
    req1 = PatchRequest(
        key="player:1",
        operations=[{"op": "merge", "value": {"profile": {"name": "Ava", "lvl": 3}, "inv": {"gold": 100}}}],
        expected_version=0,
        operation_id="op-1",
    )
    res1 = api.apply(req1)
    print("v1", res1.version, res1.etag, res1.value)

    # json patch — инкремент золота и добавление предмета
    req2 = PatchRequest(
        key="player:1",
        operations=[
            {"op": "replace", "path": "/inv/gold", "value": 150},
            {"op": "add", "path": "/inv/items", "value": []},
            {"op": "add", "path": "/inv/items/-", "value": {"id": "potion", "qty": 2}},
        ],
        expected_etag=res1.etag,
        operation_id="op-2",
    )
    res2 = api.apply(req2)
    print("v2", res2.version, res2.etag, res2.value)

    # dry-run — что будет, если поднять уровень
    req3 = PatchRequest(
        key="player:1",
        operations=[{"op": "replace", "path": "/profile/lvl", "value": 4}],
        expected_version=res2.version,
        dry_run=True,
    )
    res3 = api.apply(req3)
    print("dry-run v", res3.version, res3.etag, res3.value)

    # конфликт по неверной версии
    try:
        api.apply(PatchRequest(key="player:1", operations=[{"op": "replace", "path": "/inv/gold", "value": 1}],
                               expected_version=1))
    except VersionConflict as e:
        print("conflict:", str(e))

    # diff -> patch
    old = res2.value
    new = {"profile": {"name": "Ava", "lvl": 5}, "inv": {"gold": 200, "items": [{"id": "potion", "qty": 3}]}}
    patch = json_diff_to_patch(old, new)
    res4 = api.apply(PatchRequest(key="player:1", operations=patch, expected_etag=res2.etag))
    print("v3", res4.version, res4.etag, res4.value)
