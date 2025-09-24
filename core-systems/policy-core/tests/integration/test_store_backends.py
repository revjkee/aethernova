# -*- coding: utf-8 -*-
"""
Интеграционные контракт-тесты для backends policy-core.

Запуск:
  POLICY_STORE_URLS="memory://,sqlite+aiosqlite:///tmp/policy.db" pytest -q
или:
  POLICY_STORE_DSN="redis://localhost:6379/0" pytest -q

Контракт (минимум):
  - put(ns, key, value, *, if_match=None, ttl=None) -> meta | None
  - get(ns, key) -> value | (value, meta) | {'value':..., 'meta':...} | None
  - delete(ns, key, *, if_match=None) -> bool | None
  - list(ns, *, prefix=None, limit=None, cursor=None, sort='asc')
        -> (items, next_cursor) | {'items': [...], 'cursor': ...}
    где items: [ (key, value, meta) | {'key':..., 'value':..., 'meta':...} ]

Опционально:
  - capabilities: set|list|dict со флагами {'ttl','watch','batch','etag','paginate'}
  - watch(ns, *, prefix=None) -> async-iterable событий {'type','key','value','meta'}
  - batch(ops) атомарно применяет список операций
  - health() -> {'status':'ok', ...} | True

Тесты авто-адаптируются к sync/async реализациям и форматам ответов.
"""

import asyncio
import inspect
import json
import os
import time
import uuid
import types
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import pytest

# ---------- Маркеры ----------
pytestmark = [pytest.mark.integration]

# ---------- Утилиты совместимости ----------

def _now_ms() -> int:
    return int(time.time() * 1000)

async def maybe_await(x):
    if inspect.isawaitable(x):
        return await x
    return x

def _as_meta(x: Any) -> Dict[str, Any]:
    if x is None:
        return {}
    if isinstance(x, dict):
        return x
    return {"_raw": x}

def _unpack_get(ret: Any) -> Tuple[Optional[Any], Dict[str, Any]]:
    if ret is None:
        return None, {}
    if isinstance(ret, dict):
        # {'value': v, 'meta': m} или {'data': v, ...}
        if "value" in ret:
            return ret.get("value"), _as_meta(ret.get("meta"))
        if "data" in ret:
            return ret.get("data"), _as_meta({k: v for k, v in ret.items() if k != "data"})
        # иначе считаем, что это raw value в dict-обёртке
        return ret, {}
    if isinstance(ret, tuple) and len(ret) == 2:
        v, m = ret
        return v, _as_meta(m)
    # raw значение
    return ret, {}

def _unpack_list(ret: Any) -> Tuple[List[Tuple[str, Any, Dict[str, Any]]], Optional[str]]:
    items: List[Tuple[str, Any, Dict[str, Any]]] = []
    cursor = None
    if isinstance(ret, dict):
        seq = ret.get("items") or ret.get("results") or []
        cursor = ret.get("cursor") or ret.get("next") or None
    elif isinstance(ret, tuple) and len(ret) == 2:
        seq, cursor = ret
    else:
        seq = ret or []
    for it in seq:
        if isinstance(it, dict):
            key = it.get("key")
            val = it.get("value", it.get("data"))
            meta = _as_meta(it.get("meta"))
        elif isinstance(it, (list, tuple)) and len(it) >= 2:
            key = it[0]
            val = it[1]
            meta = _as_meta(it[2] if len(it) > 2 else {})
        else:
            # неизвестный формат — пропустим
            continue
        if key is None:
            continue
        items.append((str(key), val, meta))
    return items, cursor

def _capset_from(obj: Any) -> Dict[str, bool]:
    caps = getattr(obj, "capabilities", None)
    if isinstance(caps, dict):
        d = {str(k): bool(v) for k, v in caps.items()}
    elif isinstance(caps, (set, list, tuple)):
        d = {str(k): True for k in caps}
    else:
        d = {}
    # эвристики
    if hasattr(obj, "watch"):
        d.setdefault("watch", True)
    if hasattr(obj, "batch"):
        d.setdefault("batch", True)
    d.setdefault("paginate", True)  # контракт list рекомендует пагинацию
    return d

def _meta_etag(meta: Dict[str, Any]) -> Optional[str]:
    for k in ("etag", "version", "rev", "cas"):
        v = meta.get(k)
        if v is not None:
            return str(v)
    return None

# ---------- Открытие стора из DSN ----------

def _iter_candidate_callables():
    """
    Пытаемся найти фабрики подключения в разных местах без жёсткой связки.
    Возвращаем список callables (url:str) -> store.
    """
    cands: List = []

    def try_add(modname: str, attr: str):
        try:
            mod = __import__(modname, fromlist=[attr])
            fn = getattr(mod, attr, None)
            if callable(fn):
                cands.append(fn)
        except Exception:
            pass

    # Наиболее вероятные точки
    try_add("policy_core.store", "open_store")
    try_add("policy_core.store", "connect")
    try_add("policy_core.stores", "open_store")
    try_add("policy_core.stores", "connect")
    try_add("policy_core", "open_store")
    try_add("policy_core", "connect")

    # Попытка через entry_points (если проект их объявляет)
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        groups = []
        # Новая/старая сигнатуры entry_points
        for g in ("policy_core.stores", "policy_core.store_backends", "policy_core.backends"):
            try:
                groups.extend(list(eps.select(group=g)))
            except Exception:
                # старый интерфейс
                groups.extend([ep for ep in eps.get(g, [])])
        for ep in groups:
            try:
                obj = ep.load()
                if callable(obj):
                    cands.append(obj)
            except Exception:
                continue
    except Exception:
        pass

    # Удаляем дубликаты (по id)
    unique = []
    seen = set()
    for fn in cands:
        if id(fn) not in seen:
            unique.append(fn)
            seen.add(id(fn))
    return unique

async def open_store_from_url(url: str):
    """
    Открывает стор из DSN. Если есть несколько фабрик — используем первую, что сработает.
    Для memory:// пробуем встроённую простую реализацию, если фабрик нет.
    """
    last_err = None
    for fn in _iter_candidate_callables():
        try:
            ret = fn(url)
            return await maybe_await(ret)
        except Exception as e:
            last_err = e
            continue

    # Фоллбэк для memory:// — простая in-memory реализация, чтобы тесты могли запуститься.
    if url.startswith("memory://"):
        return _MemoryStore()
    if last_err:
        raise last_err
    raise RuntimeError(f"Не удалось найти фабрику подключения для URL: {url}")

# ---------- Простая in-memory реализация (фоллбэк только для тестов) ----------

@dataclass
class _Item:
    value: Any
    meta: Dict[str, Any]

class _MemoryStore:
    """
    Минимальная in-memory реализация контракта для фоллбэка.
    Поддерживает etag (rev), list с пагинацией, prefix, ttl, batch, health, watch (упрощённо).
    """
    def __init__(self):
        self._data: Dict[Tuple[str, str], _Item] = {}
        self._rev = 0
        self._watchers: Dict[str, List[asyncio.Queue]] = {}

    def capabilities(self):
        return {"ttl": True, "etag": True, "batch": True, "watch": True, "paginate": True}

    async def put(self, ns: str, key: str, value: Any, *, if_match: Optional[str] = None, ttl: Optional[float] = None):
        k = (ns, key)
        now = _now_ms()
        prev = self._data.get(k)
        if if_match is not None:
            prev_rev = prev.meta.get("rev") if prev else None
            if str(prev_rev) != str(if_match):
                raise _Conflict("etag/rev mismatch")
        self._rev += 1
        meta = {
            "rev": self._rev,
            "updated_at": now,
            "created_at": prev.meta.get("created_at") if prev else now,
        }
        if ttl:
            meta["expires_at"] = now + int(ttl * 1000)
        self._data[k] = _Item(value=value, meta=meta)
        await self._emit(ns, {"type": "put", "key": key, "value": value, "meta": meta})
        return meta

    async def get(self, ns: str, key: str):
        k = (ns, key)
        it = self._data.get(k)
        if not it:
            return None
        # TTL
        exp = it.meta.get("expires_at")
        if exp and exp <= _now_ms():
            # lazy expire
            self._data.pop(k, None)
            return None
        return it.value, dict(it.meta)

    async def delete(self, ns: str, key: str, *, if_match: Optional[str] = None):
        k = (ns, key)
        it = self._data.get(k)
        if not it:
            return False
        if if_match is not None:
            if str(it.meta.get("rev")) != str(if_match):
                raise _Conflict("etag/rev mismatch")
        self._data.pop(k, None)
        await self._emit(ns, {"type": "delete", "key": key, "meta": dict(it.meta)})
        return True

    async def list(self, ns: str, *, prefix: Optional[str] = None, limit: Optional[int] = None,
                   cursor: Optional[str] = None, sort: str = "asc"):
        # простая реализация курсора: это индекс среза в отсортированном списке ключей
        keys = []
        now = _now_ms()
        for (n, k), it in self._data.items():
            if n != ns:
                continue
            exp = it.meta.get("expires_at")
            if exp and exp <= now:
                continue
            if prefix and not k.startswith(prefix):
                continue
            keys.append(k)
        keys.sort(reverse=(sort == "desc"))
        start = int(cursor or 0)
        lim = limit or len(keys)
        part = keys[start:start + lim]
        items = []
        for k in part:
            v, meta = await self.get(ns, k)
            if v is None:
                continue
            items.append({"key": k, "value": v, "meta": meta})
        next_cursor = str(start + len(part)) if (start + len(part)) < len(keys) else None
        return {"items": items, "cursor": next_cursor}

    async def health(self):
        return {"status": "ok", "backend": "memory"}

    async def batch(self, ops: List[Dict[str, Any]]):
        # простая полуаатомарность (ошибка — откат в рамках операции через снимок)
        snapshot = dict(self._data)
        try:
            results = []
            for op in ops:
                kind = op.get("op")
                ns = op["ns"]
                key = op["key"]
                if kind == "put":
                    meta = await self.put(ns, key, op.get("value"), if_match=op.get("if_match"), ttl=op.get("ttl"))
                    results.append({"op": "put", "meta": meta})
                elif kind == "delete":
                    ok = await self.delete(ns, key, if_match=op.get("if_match"))
                    results.append({"op": "delete", "ok": ok})
                else:
                    raise ValueError(f"unknown op: {kind}")
            return results
        except Exception:
            self._data = snapshot
            raise

    async def watch(self, ns: str, *, prefix: Optional[str] = None):
        q = asyncio.Queue()
        key = f"{ns}|{prefix or ''}"
        self._watchers.setdefault(key, []).append(q)
        try:
            while True:
                evt = await q.get()
                yield evt
        finally:
            self._watchers[key].remove(q)

    async def _emit(self, ns: str, evt: Dict[str, Any]):
        # широковещательно по namespace и по (namespace+prefix)
        to_notify = []
        ns_key = f"{ns}|"
        for key, queues in self._watchers.items():
            w_ns, w_pref = key.split("|", 1)
            if w_ns != ns:
                continue
            if w_pref and not evt["key"].startswith(w_pref):
                continue
            to_notify.extend(queues)
        for q in to_notify:
            await q.put(evt)

class _Conflict(RuntimeError):
    pass

# ---------- Фикстуры pytest ----------

def _urls_from_env() -> List[str]:
    env_urls = os.environ.get("POLICY_STORE_URLS") or os.environ.get("POLICY_STORE_DSN") or ""
    urls = [u.strip() for u in env_urls.split(",") if u.strip()]
    if not urls:
        # по умолчанию пытаемся memory://
        urls = ["memory://"]
    return urls

@pytest.fixture(scope="session", params=_urls_from_env())
def backend_url(request):
    return request.param

@pytest.fixture(scope="session")
def event_loop():
    # Гарантируем общий event loop для session-фикстур
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def store(backend_url):
    # Открываем стор
    s = await open_store_from_url(backend_url)
    caps = _capset_from(s)

    # Уникальный namespace на тест
    ns = f"it-{uuid.uuid4().hex[:12]}"

    # Обёртка с namespace для удобства
    class _NSStore:
        def __init__(self, inner, namespace, caps):
            self._inner = inner
            self.ns = namespace
            self.capabilities = caps

        async def put(self, key, value, **kw):
            return await maybe_await(self._inner.put(self.ns, key, value, **kw))

        async def get(self, key):
            return await maybe_await(self._inner.get(self.ns, key))

        async def delete(self, key, **kw):
            return await maybe_await(self._inner.delete(self.ns, key, **kw))

        async def list(self, **kw):
            return await maybe_await(self._inner.list(self.ns, **kw))

        async def watch(self, **kw):
            if hasattr(self._inner, "watch"):
                async for evt in self._inner.watch(self.ns, **kw):
                    yield evt
            else:
                raise pytest.skip("watch не поддерживается")

        async def health(self):
            if hasattr(self._inner, "health"):
                return await maybe_await(self._inner.health())
            return True

        async def batch(self, ops: List[Dict[str, Any]]):
            if hasattr(self._inner, "batch"):
                # дополним ns для удобства, если не указан
                fixed = []
                for op in ops:
                    op = dict(op)
                    op.setdefault("ns", self.ns)
                    fixed.append(op)
                return await maybe_await(self._inner.batch(fixed))
            raise pytest.skip("batch не поддерживается")

        async def _cleanup(self):
            # Зачистка namespace
            cursor = None
            while True:
                res = await self.list(limit=200, cursor=cursor)
                items, cursor = _unpack_list(res)
                for k, _, meta in items:
                    try:
                        await self.delete(k)
                    except Exception:
                        # игнорируем ошибки зачистки, чтобы не валить тест
                        pass
                if not cursor:
                    break

    wrapped = _NSStore(s, ns, caps)
    try:
        yield wrapped
    finally:
        try:
            await wrapped._cleanup()
        except Exception:
            # последний шанс: не валим сессию из-за очистки
            pass

# ---------- Хелперы для проверок ----------

async def _put(store, key, value, **kw) -> Dict[str, Any]:
    ret = await store.put(key, value, **kw)
    return _as_meta(ret)

async def _get(store, key) -> Tuple[Optional[Any], Dict[str, Any]]:
    ret = await store.get(key)
    return _unpack_get(ret)

async def _delete(store, key, **kw) -> bool:
    ret = await store.delete(key, **kw)
    return bool(ret)

async def _list_all(store, **kw) -> Tuple[List[Tuple[str, Any, Dict[str, Any]]], Optional[str]]:
    ret = await store.list(**kw)
    return _unpack_list(ret)

def _expect_conflict(exc: BaseException) -> bool:
    msg = f"{type(exc).__name__}: {exc}"
    return any(x in msg.lower() for x in ("conflict", "etag", "cas", "precondition", "412"))

# ---------- Тесты ----------

@pytest.mark.asyncio
async def test_basic_crud(store):
    key = "user/policies/admin"
    payload = {"rules": ["read", "write"], "v": 1}
    meta1 = await _put(store, key, payload)
    assert isinstance(meta1, dict)

    val, meta2 = await _get(store, key)
    assert val == payload
    assert isinstance(meta2, dict)
    assert meta2.get("created_at") is not None or meta2.get("updated_at") is not None

    # update
    payload2 = {"rules": ["read", "write", "delete"], "v": 2}
    meta3 = await _put(store, key, payload2)
    assert meta3 != {}

    val2, _ = await _get(store, key)
    assert val2 == payload2

    # delete
    ok = await _delete(store, key)
    assert ok is True
    val3, _ = await _get(store, key)
    assert val3 is None

@pytest.mark.asyncio
async def test_namespace_isolation(store):
    # Ключи за пределами текущего namespace недоступны (проверяем на уровне list по всему ns)
    # В рамках обёртки _NSStore мы видим только свой ns, поэтому создаём два префикса
    for i in range(5):
        await _put(store, f"teamA/k{i}", {"i": i})
    for i in range(5):
        await _put(store, f"teamB/k{i}", {"i": i})
    items, _ = await _list_all(store, prefix="teamA/")
    assert len(items) == 5
    assert all(k.startswith("teamA/") for k, _, _ in items)

@pytest.mark.asyncio
async def test_prefix_and_pagination(store):
    # создаём 35 записей
    for i in range(35):
        await _put(store, f"proj/role/{i:02d}", {"idx": i})
    # Пагинация по 10
    seen = []
    cursor = None
    iter_guard = 0
    while True:
        items, cursor = await _list_all(store, prefix="proj/role/", limit=10, cursor=cursor, sort="asc")
        seen.extend([k for k, _, _ in items])
        iter_guard += 1
        assert iter_guard <= 20, "слишком много итераций пагинации — вероятен цикл"
        if not cursor:
            break
    assert len(seen) == 35
    assert seen == sorted(seen)

@pytest.mark.asyncio
async def test_conditional_updates_with_etag_if_supported(store):
    caps = _capset_from(store)
    key = "cond/etag"
    meta1 = await _put(store, key, {"v": 1})
    etag = _meta_etag(meta1)
    if not etag and not caps.get("etag"):
        pytest.skip("etag/version не поддерживается")
    # успешный CAS
    meta2 = await _put(store, key, {"v": 2}, if_match=etag)
    assert _meta_etag(meta2) != etag

    # конфликт CAS
    try:
        await _put(store, key, {"v": 3}, if_match=etag)
        # некоторые реализации возвращают False/None на конфликт
        val, _ = await _get(store, key)
        assert val == {"v": 2}, "ожидался конфликт CAS, но значение сменилось"
    except Exception as e:
        assert _expect_conflict(e), f"ожидаемая ошибка конфликта CAS, получили: {e!r}"

@pytest.mark.asyncio
async def test_ttl_expiry_if_supported(store):
    caps = _capset_from(store)
    if not caps.get("ttl"):
        pytest.skip("TTL не поддерживается")
    key = "ttl/item"
    await _put(store, key, {"once": True}, ttl=0.7)
    val1, _ = await _get(store, key)
    assert val1 is not None
    await asyncio.sleep(1.1)
    val2, _ = await _get(store, key)
    assert val2 is None

@pytest.mark.asyncio
async def test_batch_atomicity_if_supported(store):
    caps = _capset_from(store)
    if not caps.get("batch"):
        pytest.skip("batch/atomic не поддерживается")
    # Подготовка etag для конфликта
    await _put(store, "batch/a", {"v": 1})
    _, meta_a = await _get(store, "batch/a")
    good_etag = _meta_etag(meta_a) or "1"

    ops = [
        {"op": "put", "key": "batch/x", "value": {"x": 1}},
        {"op": "put", "key": "batch/a", "value": {"v": 2}, "if_match": "stale-etag"},  # конфликт
        {"op": "put", "key": "batch/y", "value": {"y": 2}},
    ]
    # Проверяем, что при ошибке атомарная партия не применена (ни x, ни y)
    with pytest.raises(Exception):
        await store.batch(ops)

    v_x, _ = await _get(store, "batch/x")
    v_y, _ = await _get(store, "batch/y")
    v_a, _ = await _get(store, "batch/a")
    assert v_x is None and v_y is None and v_a == {"v": 1}

    # Успешная партия
    ops_ok = [
        {"op": "put", "key": "batch/a", "value": {"v": 3}, "if_match": good_etag},
        {"op": "put", "key": "batch/z", "value": {"z": 9}},
    ]
    res = await store.batch(ops_ok)
    assert isinstance(res, list) and len(res) == 2
    v_a2, _ = await _get(store, "batch/a")
    v_z, _ = await _get(store, "batch/z")
    assert v_a2 == {"v": 3} and v_z == {"z": 9}

@pytest.mark.asyncio
async def test_watch_stream_if_supported(store):
    caps = _capset_from(store)
    if not caps.get("watch"):
        pytest.skip("watch/subscribe не поддерживается")

    async def consumer(prefix: str, acc: List[Dict[str, Any]]):
        async for evt in store.watch(prefix=prefix):
            acc.append(evt)
            if len(acc) >= 2:
                break

    acc: List[Dict[str, Any]] = []
    task = asyncio.create_task(consumer("watch/", acc))
    try:
        await asyncio.sleep(0.05)
        await _put(store, "watch/alpha", {"a": 1})
        await _put(store, "watch/beta", {"b": 2})
        # событие delete не попадает в лимит, но можем проверить при желании
        await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(Exception):
                await task
    assert len(acc) >= 2
    keys = [e.get("key") for e in acc]
    assert "watch/alpha" in keys and "watch/beta" in keys

@pytest.mark.asyncio
async def test_healthcheck(store):
    h = await store.health()
    if isinstance(h, dict):
        assert (h.get("status") or "").lower() in ("ok", "healthy", "up")
    else:
        assert bool(h) is True

@pytest.mark.asyncio
async def test_unicode_and_binary_payloads(store):
    text_key = "payload/unicode"
    bin_key = "payload/binary"

    payload_text = {"msg": "Привет, мир", "snowman": "☃", "emoji_like": ":)"}  # текстовые символы
    meta1 = await _put(store, text_key, payload_text)
    assert isinstance(meta1, dict)
    got_text, _ = await _get(store, text_key)
    # допускаем сериализацию/десериализацию JSON -> строки
    assert got_text == payload_text

    # Бинарные данные — как bytes (если бэкенд не поддерживает, ожидаем SerializableError/TypeError)
    blob = b"\x00\x01\x02\xffpayload"
    try:
        await _put(store, bin_key, blob)
        got_bin, _ = await _get(store, bin_key)
        assert isinstance(got_bin, (bytes, bytearray))
        assert bytes(got_bin) == blob
    except Exception as e:
        # Разрешаем отсутствие бинарной поддержки
        assert any(x in str(e).lower() for x in ("binary", "bytes", "serialize", "type"))

@pytest.mark.asyncio
async def test_large_payload_limit_soft(store):
    # Мягкая проверка на средний размер записи (~256 KiB).
    # Если бэкенд ограничен, допускаем ошибку с понятным сообщением.
    key = "payload/large"
    data = {"pad": "x" * (256 * 1024)}
    try:
        await _put(store, key, data)
        got, _ = await _get(store, key)
        assert got == data
    except Exception as e:
        # Сообщение должно содержать limit/size/too large
        assert any(x in str(e).lower() for x in ("limit", "size", "too", "large", "payload"))

# ---------- Импорт для контекстного suppress ----------
import contextlib
