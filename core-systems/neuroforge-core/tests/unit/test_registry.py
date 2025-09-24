# neuroforge-core/tests/unit/test_registry.py
# Контрактные тесты для Registry.
# Статус: UNVERIFIED — фактический интерфейс вашего реестра мне неизвестен. I cannot verify this.
# Запуск: pytest -q tests/unit/test_registry.py
# Адаптер: установить NEUROFORGE_REGISTRY_ADAPTER="package.module:factory"
# Если переменная не указана — используется встроенный InMemory-бэкенд (для самопроверки).
#
# Требования (опционально):
#   - pytest
#   - hypothesis (если есть — property-тесты включатся автоматически)
#
# Контракт ожидает "способности" (capabilities), которые может объявить адаптер:
#   {"gc", "pin", "leases", "idempotency", "delete_soft", "delete_hard", "pagination"}
#
# Адаптер должен предоставить объект с методами:
#   create(ns, name, version, data: bytes, metadata: dict|None = None, dedup_key: str|None = None) -> Artifact
#   get(ns, name, version="latest") -> Artifact
#   list(ns, name=None, limit=100, cursor=None, order="asc") -> (items, next_cursor)
#   delete(ns, name, version=None, hard=False) -> int
#   pin(ns, name, version) -> None
#   unpin(ns, name, version) -> None
#   gc(older_than_s: float, batch_size: int = 1000) -> int
#   acquire_lease(key: str, owner: str, ttl_s: float) -> bool
#   renew_lease(key: str, owner: str, ttl_s: float) -> bool
#   release_lease(key: str, owner: str) -> bool
#   capabilities() -> set[str]
#
# Artifact (duck-typing) должен иметь атрибуты/ключи:
#   namespace, name, version, data (bytes), metadata (dict), created_at (float), pinned (bool, optional), hash (str, optional)
#
# Все проверки построены так, чтобы при отсутствии способности — тест был пропущен корректно (pytest.skip).

from __future__ import annotations

import os
import time
import math
import json
import base64
import random
import string
import threading
from dataclasses import dataclass, asdict
from typing import Any, Dict, Tuple, List, Optional, Callable

import pytest

try:
    from hypothesis import given, settings, strategies as st
    HAS_HYPOTHESIS = True
except Exception:
    HAS_HYPOTHESIS = False


# -------------------- УТИЛИТЫ --------------------

def _rand_ns(prefix: str = "ns") -> str:
    return f"{prefix}_{_rand_token(8)}"

def _rand_name(prefix: str = "item") -> str:
    return f"{prefix}_{_rand_token(8)}"

def _rand_token(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def _now() -> float:
    return time.time()

def _b(s: str) -> bytes:
    return s.encode("utf-8")

def _artifact_asdict(a: Any) -> Dict[str, Any]:
    # Пытаемся аккуратно привести артефакт к dict для логов
    if isinstance(a, dict):
        d = dict(a)
    elif hasattr(a, "__dict__"):
        d = dict(vars(a))
    else:
        # попытка доступа как атрибуты
        keys = ["namespace", "name", "version", "data", "metadata", "created_at", "pinned", "hash"]
        d = {k: getattr(a, k, None) for k in keys}
    if isinstance(d.get("data"), (bytes, bytearray)):
        d["data_b64"] = base64.b64encode(d["data"]).decode("ascii")
        d.pop("data", None)
    return d


# -------------------- ВСТРОЕННЫЙ InMemory-АДАПТЕР (на случай отсутствия внешнего) --------------------

@dataclass
class _MemArtifact:
    namespace: str
    name: str
    version: str
    data: bytes
    metadata: Dict[str, Any]
    created_at: float
    pinned: bool = False
    hash: Optional[str] = None
    deleted_soft: bool = False

class _InMemoryRegistry:
    """
    Минимально промышленный in-memory backend для контракта:
    - версии уникальны в пределах (ns, name)
    - latest = max по сверке (числовая если возможно, иначе лексикографически)
    - soft delete помечает флагом; hard delete реально удаляет запись
    - GC чистит старые и/или soft-deleted непинованные артефакты
    - лизы реализованы примитивно через (owner, expiry_ts)
    - идемпотентность по dedup_key (при условии совпадения данных)
    - пагинация cursor=offset
    """
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Dict[str, _MemArtifact]]] = {}
        self._dedup: Dict[str, Tuple[str, str, str]] = {}  # key -> (ns, name, version)
        self._leases: Dict[str, Tuple[str, float]] = {}    # key -> (owner, expiry_ts)

    # Capabilities заявляем все, что поддерживаем
    def capabilities(self) -> set[str]:
        return {"gc", "pin", "leases", "idempotency", "delete_soft", "delete_hard", "pagination"}

    # Helpers
    def _versions(self, ns: str, name: str) -> List[str]:
        return list(self._store.get(ns, {}).get(name, {}).keys())

    @staticmethod
    def _ver_key(v: str) -> Tuple[int, str]:
        # попытка числовой сортировки; иначе лексикографически
        try:
            return (0, str(int(v)))
        except Exception:
            return (1, v)

    def _get_latest_version(self, ns: str, name: str) -> str:
        vs = self._versions(ns, name)
        if not vs:
            raise KeyError("not found")
        vs.sort(key=self._ver_key)
        return vs[-1]

    def _put(self, art: _MemArtifact) -> _MemArtifact:
        self._store.setdefault(art.namespace, {}).setdefault(art.name, {})
        if art.version in self._store[art.namespace][art.name]:
            raise ValueError("version conflict")
        self._store[art.namespace][art.name][art.version] = art
        return art

    # Contract API
    def create(self, ns: str, name: str, version: str, data: bytes, metadata: Optional[Dict[str, Any]] = None,
               dedup_key: Optional[str] = None) -> _MemArtifact:
        if dedup_key:
            if dedup_key in self._dedup:
                ns0, name0, ver0 = self._dedup[dedup_key]
                a = self.get(ns0, name0, ver0)
                # простой критерий идемпотентности: байты и метаданные совпадают
                if a.data == data and (metadata or {}) == (a.metadata or {}):
                    return a
                else:
                    raise ValueError("dedup_key conflict with different payload")
        art = _MemArtifact(
            namespace=ns,
            name=name,
            version=str(version),
            data=bytes(data),
            metadata=dict(metadata or {}),
            created_at=_now(),
            pinned=False,
            hash=None,
        )
        self._put(art)
        if dedup_key:
            self._dedup[dedup_key] = (ns, name, str(version))
        return art

    def get(self, ns: str, name: str, version: str = "latest") -> _MemArtifact:
        if version == "latest":
            version = self._get_latest_version(ns, name)
        art = self._store.get(ns, {}).get(name, {}).get(str(version))
        if not art or art.deleted_soft:
            raise KeyError("not found")
        return art

    def list(self, ns: str, name: Optional[str] = None, limit: int = 100, cursor: Optional[str] = None,
             order: str = "asc") -> Tuple[List[_MemArtifact], Optional[str]]:
        # Плоская выдача в пределах namespace; cursor=offset
        items: List[_MemArtifact] = []
        if ns not in self._store:
            return [], None
        for nm, versions in self._store[ns].items():
            if name and nm != name:
                continue
            for v, a in versions.items():
                if a.deleted_soft:
                    continue
                items.append(a)
        items.sort(key=lambda a: (a.name, self._ver_key(a.version), a.created_at))
        if order == "desc":
            items = list(reversed(items))
        offset = int(cursor or 0)
        window = items[offset: offset + int(limit)]
        next_cursor = str(offset + len(window)) if (offset + len(window)) < len(items) else None
        return window, next_cursor

    def delete(self, ns: str, name: str, version: Optional[str] = None, hard: bool = False) -> int:
        bucket = self._store.get(ns, {}).get(name, {})
        if not bucket:
            return 0
        versions = [version] if version is not None else list(bucket.keys())
        cnt = 0
        for v in versions:
            a = bucket.get(str(v))
            if not a:
                continue
            if hard:
                if a.pinned:
                    continue
                del bucket[str(v)]
                cnt += 1
            else:
                a.deleted_soft = True
                cnt += 1
        return cnt

    def pin(self, ns: str, name: str, version: str) -> None:
        a = self.get(ns, name, version)
        a.pinned = True

    def unpin(self, ns: str, name: str, version: str) -> None:
        a = self.get(ns, name, version)
        a.pinned = False

    def gc(self, older_than_s: float, batch_size: int = 1000) -> int:
        now = _now()
        removed = 0
        for ns, names in list(self._store.items()):
            for name, versions in list(names.items()):
                for v, a in list(versions.items()):
                    if removed >= batch_size:
                        return removed
                    age = now - a.created_at
                    if a.pinned:
                        continue
                    if a.deleted_soft or age > older_than_s:
                        del versions[v]
                        removed += 1
        return removed

    # Примитивные лизы (не защищены процессными границами, только для контракта)
    def acquire_lease(self, key: str, owner: str, ttl_s: float) -> bool:
        now = _now()
        lease = self._leases.get(key)
        if lease:
            cur_owner, expiry = lease
            if expiry > now and cur_owner != owner:
                return False
        self._leases[key] = (owner, now + ttl_s)
        return True

    def renew_lease(self, key: str, owner: str, ttl_s: float) -> bool:
        now = _now()
        lease = self._leases.get(key)
        if not lease:
            return False
        cur_owner, expiry = lease
        if cur_owner != owner or expiry <= now:
            return False
        self._leases[key] = (owner, now + ttl_s)
        return True

    def release_lease(self, key: str, owner: str) -> bool:
        lease = self._leases.get(key)
        if not lease:
            return False
        cur_owner, _ = lease
        if cur_owner != owner:
            return False
        del self._leases[key]
        return True


def _load_adapter_factory() -> Callable[[], Any]:
    spec = os.getenv("NEUROFORGE_REGISTRY_ADAPTER", "").strip()
    if not spec:
        return _InMemoryRegistry  # по умолчанию
    # Форматы: "pkg.mod:factory" или "pkg.mod.FactoryClass"
    module, _, attr = spec.partition(":")
    if not attr:
        parts = module.split(".")
        module, attr = ".".join(parts[:-1]), parts[-1]
    mod = __import__(module, fromlist=[attr])
    factory = getattr(mod, attr)
    if not callable(factory):
        raise RuntimeError("Adapter factory is not callable")
    return factory


@pytest.fixture(scope="function")
def registry():
    # Каждый тест получает «свежий» instance
    factory = _load_adapter_factory()
    return factory()


@pytest.fixture(scope="function")
def ns() -> str:
    return _rand_ns("ns")


@pytest.fixture(scope="function")
def name() -> str:
    return _rand_name("obj")


# -------------------- ХЕЛПЕРЫ ДЛЯ SKIP ПО СПОСОБНОСТЯМ --------------------

def require_capability(reg, cap: str):
    caps = set()
    try:
        caps = set(reg.capabilities())
    except Exception:
        pass
    if cap not in caps:
        pytest.skip(f"registry lacks capability: {cap}")


# -------------------- ТЕСТЫ CRUD / ВЕРСИОНИРОВАНИЯ --------------------

def test_create_and_get_roundtrip(registry, ns, name):
    v = "1"
    data = _b("hello world")
    meta = {"k": "v", "n": 1}
    a = registry.create(ns, name, v, data, meta)
    assert a.namespace == ns and a.name == name and a.version == v
    g = registry.get(ns, name, v)
    assert g.data == data
    assert g.metadata == meta
    assert isinstance(g.created_at, float) and g.created_at > 0

def test_latest_resolution(registry, ns, name):
    registry.create(ns, name, "1", _b("a"), {})
    registry.create(ns, name, "2", _b("b"), {})
    g = registry.get(ns, name, "latest")
    assert g.version in ("2", 2)

def test_version_conflict(registry, ns, name):
    registry.create(ns, name, "1", _b("x"), {})
    with pytest.raises(Exception):
        registry.create(ns, name, "1", _b("y"), {})  # другая нагрузка той же версии запрещена

def test_namespace_isolation(registry):
    ns1, ns2 = _rand_ns("a"), _rand_ns("b")
    name = _rand_name("item")
    registry.create(ns1, name, "1", _b("x"), {})
    with pytest.raises(Exception):
        # latest для пустого ns2 должен упасть
        registry.get(ns2, name, "latest")


# -------------------- ПАГИНАЦИЯ --------------------

def test_list_pagination(registry, ns):
    require_capability(registry, "pagination")
    name = _rand_name("pag")
    for i in range(10):
        registry.create(ns, name, str(i), _b(f"p{i}"), {})
    items, cursor = registry.list(ns, name=name, limit=4, order="asc")
    assert len(items) == 4 and cursor is not None
    items2, cursor2 = registry.list(ns, name=name, limit=4, cursor=cursor, order="asc")
    assert len(items2) == 4 and cursor2 is not None
    items3, cursor3 = registry.list(ns, name=name, limit=4, cursor=cursor2, order="asc")
    assert len(items3) == 2 and cursor3 is None
    # Проверим порядок версий
    vs = [it.version for it in items + items2 + items3]
    assert vs == [str(i) for i in range(10)]


# -------------------- ПИНЫ И GC --------------------

def test_pin_blocks_gc(registry, ns, name):
    require_capability(registry, "pin")
    require_capability(registry, "gc")
    registry.create(ns, name, "1", _b("x"), {})
    registry.pin(ns, name, "1")
    time.sleep(0.01)
    removed = registry.gc(older_than_s=0.0, batch_size=100)
    assert removed == 0  # пин блокирует GC
    registry.unpin(ns, name, "1")
    removed2 = registry.gc(older_than_s=0.0, batch_size=100)
    # должен удалить непинованный
    assert removed2 >= 1

def test_soft_delete_and_gc(registry, ns, name):
    require_capability(registry, "delete_soft")
    require_capability(registry, "gc")
    registry.create(ns, name, "1", _b("x"), {})
    deleted = registry.delete(ns, name, version="1", hard=False)
    assert deleted == 1
    removed = registry.gc(older_than_s=0.0)
    assert removed >= 1
    with pytest.raises(Exception):
        registry.get(ns, name, "1")

def test_hard_delete(registry, ns, name):
    require_capability(registry, "delete_hard")
    registry.create(ns, name, "1", _b("x"), {})
    deleted = registry.delete(ns, name, version="1", hard=True)
    assert deleted == 1
    with pytest.raises(Exception):
        registry.get(ns, name, "1")


# -------------------- ЛИЗЫ (ВЗАИМНОЕ ИСКЛЮЧЕНИЕ И TTL) --------------------

def test_leases_mutual_exclusion_and_ttl(registry):
    require_capability(registry, "leases")
    key = f"lease:{_rand_token(6)}"
    a_owner = _rand_token(4)
    b_owner = _rand_token(4)
    assert registry.acquire_lease(key, a_owner, ttl_s=0.2) is True
    assert registry.acquire_lease(key, b_owner, ttl_s=0.2) is False  # взаимное исключение
    assert registry.renew_lease(key, a_owner, ttl_s=0.2) is True
    time.sleep(0.25)  # дать истечь
    # после истечения другой владелец сможет взять
    assert registry.acquire_lease(key, b_owner, ttl_s=0.2) is True
    assert registry.release_lease(key, b_owner) is True
    assert registry.release_lease(key, b_owner) is False  # повторное освобождение

# -------------------- ИДЕМПОТЕНТНОСТЬ --------------------

def test_idempotency_with_dedup_key(registry, ns, name):
    require_capability(registry, "idempotency")
    key = f"dedup:{_rand_token(6)}"
    a1 = registry.create(ns, name, "1", _b("payload"), {"a": 1}, dedup_key=key)
    # повтор с теми же данными/метаданными должен вернуть тот же артефакт или эквивалент
    a2 = registry.create(ns, name, "1_dup", _b("payload"), {"a": 1}, dedup_key=key)
    assert a1.namespace == a2.namespace and a1.name == a2.name
    # конфликт по ключу при иных данных
    with pytest.raises(Exception):
        registry.create(ns, name, "2", _b("DIFF"), {"a": 2}, dedup_key=key)

# -------------------- КОНКУРЕНТНАЯ ЗАПИСЬ --------------------

def test_concurrent_writes_same_version(registry, ns):
    name = _rand_name("con")
    N = 8
    failures = 0
    def writer(ver: str):
        nonlocal failures
        try:
            registry.create(ns, name, ver, _b("x"), {})
        except Exception:
            failures += 1
    threads = [threading.Thread(target=writer, args=("1",)) for _ in range(N)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    # допускается только 1 успех, остальные — конфликт
    assert failures >= N - 1

# -------------------- УДАЛЕНИЕ И ПЕРЕСОЗДАНИЕ --------------------

def test_delete_and_recreate_same_version(registry, ns, name):
    registry.create(ns, name, "1", _b("x"), {})
    # мягкое удаление предпочтительнее, если есть
    has_soft = "delete_soft" in getattr(registry, "capabilities", lambda: set())()
    if has_soft:
        registry.delete(ns, name, "1", hard=False)
        registry.create(ns, name, "1", _b("x2"), {})  # допускаем пересоздание после soft-delete
        g = registry.get(ns, name, "1")
        assert g.data == _b("x2")
    else:
        # если soft-delete нет — ожидаем, что пересоздание той же версии запрещено
        with pytest.raises(Exception):
            registry.create(ns, name, "1", _b("x2"), {})

# -------------------- PROPERTY-ТЕСТЫ (ОПЦИОНАЛЬНО) --------------------

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    meta=st.dictionaries(
        keys=st.text(min_size=1, max_size=10),
        values=st.one_of(st.integers(), st.text(max_size=50), st.booleans(), st.none()),
        max_size=8,
    ),
    payload=st.binary(min_size=0, max_size=256),
)
@settings(deadline=None, max_examples=60)
def test_property_metadata_payload_roundtrip(registry, ns, name, meta, payload):
    a = registry.create(ns, name, "1", payload, meta)
    g = registry.get(ns, name, "1")
    assert g.data == payload
    # допускаем, что реализация может нормализовывать метаданные (но по ключам/значениям равносильна)
    assert dict(g.metadata) == dict(meta)

# -------------------- СПИСКИ / ORDER DESC --------------------

def test_list_order_desc(registry, ns, name):
    require_capability(registry, "pagination")
    for i in range(5):
        registry.create(ns, name, str(i), _b(f"v{i}"), {})
    items, _ = registry.list(ns, name=name, limit=10, order="desc")
    vs = [it.version for it in items]
    assert vs == [str(i) for i in reversed(range(5))]
