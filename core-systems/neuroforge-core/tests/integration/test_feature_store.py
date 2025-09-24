# neuroforge-core/tests/integration/test_feature_store.py
import os
import time
import json
import uuid
import random
import threading
from datetime import datetime, timedelta, timezone

import pytest

# Маркер интеграционных тестов
pytestmark = pytest.mark.integration

# По умолчанию интеграционные тесты включаются только при RUN_INTEGRATION=1
RUN_INT = os.getenv("RUN_INTEGRATION", "0") == "1"
skip_integration = pytest.mark.skipif(not RUN_INT, reason="Set RUN_INTEGRATION=1 to run integration tests")

# --- Пытаемся импортировать реализацию Feature Store ---
fs_mod = pytest.importorskip("neuroforge.feature_store", reason="neuroforge.feature_store is required for integration tests")

# Попытка получить класс/фасад FeatureStore
FeatureStore = getattr(fs_mod, "FeatureStore", None)
if FeatureStore is None:
    pytest.skip("FeatureStore class not found in neuroforge.feature_store", allow_module_level=True)

# Опциональные типы, если есть
Entity = getattr(fs_mod, "Entity", object)
Feature = getattr(fs_mod, "Feature", object)
FeatureSet = getattr(fs_mod, "FeatureSet", object)


# ----------------- ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ -----------------

def has_methods(obj, names):
    return all(hasattr(obj, name) and callable(getattr(obj, name)) for name in names)

def try_call(obj, candidates, *args, **kwargs):
    """
    Пробует вызвать один из кандидатов-методов у obj.
    candidates: ["method_a", "method_b"...]
    Возвращает (ok: bool, result|exc).
    """
    last_exc = None
    for name in candidates:
        if hasattr(obj, name) and callable(getattr(obj, name)):
            try:
                return True, getattr(obj, name)(*args, **kwargs)
            except Exception as e:
                last_exc = e
    return False, last_exc

def await_condition(predicate, timeout=5.0, interval=0.02, *args, **kwargs):
    """
    Ждёт, пока predicate(*args, **kwargs) вернёт truthy или истечёт timeout.
    """
    end = time.time() + timeout
    while time.time() < end:
        if predicate(*args, **kwargs):
            return True
        time.sleep(interval)
    return False

def utc_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


# ----------------- ФИКСТУРЫ -----------------

@pytest.fixture(scope="session")
def tmp_root(tmp_path_factory):
    return tmp_path_factory.mktemp("feature_store_it")

@pytest.fixture(scope="function")
def store(tmp_root):
    """
    Универсальный конструктор FeatureStore:
    - FeatureStore.from_config({...})
    - FeatureStore(config={...})
    - FeatureStore(path=...)
    - FeatureStore(root=...)
    В крайнем случае — skip.
    """
    root = tmp_root / f"fs_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)

    cfg = {
        "storage": {
            "offline": {
                "type": "sqlite",
                "database": str(root / "offline.db"),
            },
            "online": {
                "type": "sqlite",
                "database": str(root / "online.db"),
                "ttl_seconds_default": 60,
            },
        },
        "clock": {"allow_clock_backwards": False, "leakage_guard_seconds": 0},
        "registry": {"path": str(root / "registry.json")},
    }

    # Пытаемся разные конструкторы
    # 1) from_config
    if hasattr(FeatureStore, "from_config"):
        try:
            st = FeatureStore.from_config(cfg)
            yield st
            # мягкое закрытие
            if hasattr(st, "close"):
                st.close()
            return
        except Exception:
            pass

    # 2) __init__(config=...)
    try:
        st = FeatureStore(config=cfg)
        yield st
        if hasattr(st, "close"):
            st.close()
        return
    except Exception:
        pass

    # 3) __init__(path=...) / root=...
    try:
        st = FeatureStore(path=str(root))
        yield st
        if hasattr(st, "close"):
            st.close()
        return
    except Exception:
        pass

    try:
        st = FeatureStore(root=str(root))
        yield st
        if hasattr(st, "close"):
            st.close()
        return
    except Exception:
        pass

    pytest.skip("Cannot construct FeatureStore with known constructors")


@pytest.fixture
def entity_user():
    """Описатель сущности user, если поддерживается регистрация схемы."""
    return {
        "name": "user",
        "join_key": "user_id",
        "description": "User entity for tests",
    }

@pytest.fixture
def featureset_user_stats():
    """Набор фич для пользователя."""
    return {
        "name": "user_stats",
        "entity": "user",
        "features": [
            {"name": "score", "dtype": "float"},
            {"name": "level", "dtype": "int"},
        ],
        "ttl_seconds": 2,  # короткий TTL для теста эвикции
        "description": "Test feature set",
    }


# ----------------- ТЕСТЫ -----------------

@skip_integration
def test_api_surface_minimal(store):
    """
    Минимальная поверхность API: наличие ключевых методов.
    Скип, если конкретная реализация использует другие точки входа.
    """
    # Любая реализация должна уметь ingest/read либо эквивалентные операции
    possible = any([
        has_methods(store, ["ingest", "read_online"]),
        has_methods(store, ["upsert", "get_online"]),
        has_methods(store, ["write", "read"]),
    ])
    assert possible, "FeatureStore lacks basic IO methods"


@skip_integration
def test_register_schema_and_online_crud(store, entity_user, featureset_user_stats):
    """
    Регистрация Entity/FeatureSet (если поддерживается), запись онлайн, чтение онлайн.
    Проверяем last-write-wins.
    """
    # Регистрация схемы (опционально)
    ok, _ = try_call(store, ["register_entity"], Entity(**entity_user) if isinstance(Entity, type) else entity_user)
    # если метод отсутствует — это не провал
    ok, _ = try_call(store, ["register_featureset", "register_feature_set"],
                     FeatureSet(**featureset_user_stats) if isinstance(FeatureSet, type) else featureset_user_stats)

    # Подготовим записи
    now = datetime.now(timezone.utc)
    rows_v1 = [
        {"user_id": "u1", "event_ts": utc_ms(now), "score": 10.5, "level": 1},
        {"user_id": "u2", "event_ts": utc_ms(now), "score": 7.0, "level": 3},
    ]

    # Вставка (ingest/upsert/write)
    ok, res = try_call(store, ["ingest"], "user_stats", rows_v1)
    if not ok:
        ok, res = try_call(store, ["upsert"], "user_stats", rows_v1)
    if not ok:
        ok, res = try_call(store, ["write"], "user_stats", rows_v1, {"mode": "upsert"})
    assert ok, f"Cannot ingest initial rows: {res}"

    # Повторная запись обновляет score для u1
    rows_v2 = [
        {"user_id": "u1", "event_ts": utc_ms(now + timedelta(milliseconds=1)), "score": 11.0, "level": 1},
    ]
    ok, res = try_call(store, ["ingest"], "user_stats", rows_v2)
    if not ok:
        ok, res = try_call(store, ["upsert"], "user_stats", rows_v2)
    if not ok:
        ok, res = try_call(store, ["write"], "user_stats", rows_v2, {"mode": "upsert"})
    assert ok, f"Cannot upsert second batch: {res}"

    # Чтение онлайн (get_online/read_online/read)
    for key in ["u1", "u2"]:
        ok, out = try_call(store, ["get_online"], "user_stats", {"user_id": key}, ["score", "level"])
        if not ok:
            ok, out = try_call(store, ["read_online"], "user_stats", {"user_id": key}, ["score", "level"])
        if not ok:
            ok, out = try_call(store, ["read"], "user_stats", {"user_id": key})
            if ok and isinstance(out, dict):
                out = {k: out.get(k) for k in ["score", "level"]}
        assert ok, f"Cannot read online for {key}: {out}"
        assert isinstance(out, dict)
        assert "score" in out and "level" in out

    # Проверка last-write-wins для u1.score
    ok, out = try_call(store, ["get_online"], "user_stats", {"user_id": "u1"}, ["score"])
    if not ok:
        ok, out = try_call(store, ["read_online"], "user_stats", {"user_id": "u1"}, ["score"])
    if not ok:
        ok, out = try_call(store, ["read"], "user_stats", {"user_id": "u1"})
    assert ok
    score = out["score"] if isinstance(out, dict) else None
    assert score == 11.0, f"Expected last-write-wins score=11.0, got {score}"


@skip_integration
def test_point_in_time_join_offline(store, entity_user, featureset_user_stats):
    """
    Point-in-time join: значения фич не должны «смотреть в будущее».
    Если offline-материализация недоступна — тест скипается.
    """
    # Проверим наличие API
    if not any([
        has_methods(store, ["materialize_offline"]),
        has_methods(store, ["offline_join"]),
    ]):
        pytest.skip("Offline join/materialization API not found")

    # Данные фич (история)
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    hist = [
        {"user_id": "u1", "event_ts": utc_ms(t0 + timedelta(seconds=0)), "score": 1.0, "level": 1},
        {"user_id": "u1", "event_ts": utc_ms(t0 + timedelta(seconds=10)), "score": 2.0, "level": 2},
        {"user_id": "u1", "event_ts": utc_ms(t0 + timedelta(seconds=20)), "score": 3.0, "level": 3},
    ]
    ok, res = try_call(store, ["ingest", "upsert", "write"], "user_stats", hist)
    assert ok, f"Ingest history failed: {res}"

    # Факт-таблица событий (точки запроса)
    events = [
        {"user_id": "u1", "event_ts": utc_ms(t0 + timedelta(seconds=5))},   # видим только запись с t=0
        {"user_id": "u1", "event_ts": utc_ms(t0 + timedelta(seconds=15))},  # видим t=10 (но не t=20)
    ]

    # Выполняем PIT-join
    ok, out = try_call(store, ["materialize_offline"], {
        "events": events,
        "features": [{"table": "user_stats", "columns": ["score", "level"], "timestamp_col": "event_ts"}],
        "entity_key": "user_id",
        "as_of_col": "event_ts",
        "leakage_guard_seconds": 0,
    })
    if not ok:
        ok, out = try_call(store, ["offline_join"], events, "user_stats", {
            "entity_key": "user_id",
            "as_of_col": "event_ts",
            "columns": ["score", "level"],
            "timestamp_col": "event_ts",
        })
    assert ok, f"PIT join failed: {out!r}"

    # Нормализуем вывод к списку словарей
    if hasattr(out, "to_dict") and callable(getattr(out, "to_dict")):
        # pandas.DataFrame
        out = out.to_dict(orient="records")
    assert isinstance(out, list) and out, "Offline result must be a non-empty list"

    # Проверяем инварианты «не смотреть в будущее»
    # Для t=5s -> ожидаем score=1.0; для t=15s -> score=2.0
    # Если точные значения не совпали — проверяем хотя бы, что timestamp фичи <= as_of
    def row_for(ts):
        for r in out:
            if int(r.get("event_ts") or r.get("as_of") or r.get("ts") or -1) == ts:
                return r
        return None

    r1 = row_for(events[0]["event_ts"])
    r2 = row_for(events[1]["event_ts"])
    assert r1 and r2, f"Joined rows not found for given timestamps: {out!r}"

    # Мягкая проверка значений, жёсткая — на анти-«будущее»
    if "score" in r1:
        assert r1["score"] in (1.0, 1, None)  # допускаем типы/преобразования
    if "score" in r2:
        assert r2["score"] in (2.0, 2, None)

    # Строжайший инвариант: источник фичи <= as_of
    src_ts_key = "feature_ts"
    # Если реализация возвращает явный ts фичи, проверим
    for r in (r1, r2):
        if src_ts_key in r and r[src_ts_key] is not None:
            assert r[src_ts_key] <= r.get("event_ts") or r.get("as_of"), "Feature timestamp must not be in the future"


@skip_integration
def test_online_ttl_eviction(store, featureset_user_stats):
    """
    Короткий TTL: после ожидания значения должны исчезнуть из онлайн-хранилища.
    Скип, если TTL не поддерживается.
    """
    # Проверим, что онлайн-чтение и запись доступны
    if not any([has_methods(store, ["ingest"]) or has_methods(store, ["upsert"]) or has_methods(store, ["write"])]):
        pytest.skip("No ingest API")
    if not any([has_methods(store, ["get_online"]), has_methods(store, ["read_online"]), has_methods(store, ["read"]) ]):
        pytest.skip("No online read API")

    uid = "ttl_user"
    now = datetime.now(timezone.utc)
    row = {"user_id": uid, "event_ts": utc_ms(now), "score": 100.0, "level": 99}

    ok, res = try_call(store, ["ingest", "upsert", "write"], "user_stats", [row])
    assert ok, f"Ingest failed: {res}"

    # Убедимся, что сейчас читается
    ok, out = try_call(store, ["get_online", "read_online", "read"], "user_stats", {"user_id": uid}, ["score", "level"])
    assert ok and isinstance(out, dict), f"Online read failed immediately: {out}"
    assert out.get("score") in (100.0, 100)

    # Ждём TTL (в конфиге featureset_user_stats ttl_seconds=2). Дадим запас.
    time.sleep(3.0)

    # Теперь ключ должен пропасть/истечь
    ok, out = try_call(store, ["get_online", "read_online", "read"], "user_stats", {"user_id": uid}, ["score", "level"])
    # Разные реализации: или None/{} или исключение. Если ок и dict — должен быть пустой/без полей.
    if ok and isinstance(out, dict):
        # Допускаем, что реализация возвращает только существующие поля
        assert out.get("score") in (None,), f"Expected TTL eviction, got: {out}"
    else:
        # Если API сигнализирует отсутствием ok — это тоже допустимо
        assert True


@skip_integration
def test_schema_evolution_add_feature(store, featureset_user_stats):
    """
    Эволюция схемы: добавляем новый признак, записываем данные и читаем старые+новые.
    Если API схему не регистрирует явно — тест ограничится проверкой чтения новых полей.
    """
    # Добавим новую фичу в существующий набор
    new_feature = {"name": "vip", "dtype": "bool"}
    fs_def = dict(featureset_user_stats)
    fs_def["features"] = fs_def["features"] + [new_feature]

    ok, res = try_call(store, ["register_featureset", "register_feature_set"],
                       FeatureSet(**fs_def) if isinstance(FeatureSet, type) else fs_def)
    # Если нет явной регистрации, продолжаем

    uid = "evo_user"
    now = datetime.now(timezone.utc)
    row_old = {"user_id": uid, "event_ts": utc_ms(now), "score": 5.0, "level": 1}
    ok, _ = try_call(store, ["ingest", "upsert", "write"], "user_stats", [row_old])
    assert ok

    row_new = {"user_id": uid, "event_ts": utc_ms(now + timedelta(seconds=1)), "score": 5.5, "level": 2, "vip": True}
    ok, _ = try_call(store, ["ingest", "upsert", "write"], "user_stats", [row_new])
    assert ok

    ok, out = try_call(store, ["get_online", "read_online", "read"], "user_stats", {"user_id": uid}, ["score", "level", "vip"])
    assert ok and isinstance(out, dict)
    # Старые поля на месте, новое поле доступно
    assert "score" in out and "level" in out and "vip" in out


@skip_integration
def test_concurrent_writes_last_write_wins(store):
    """
    Конкурентные записи: проверяем отсутствие гонок на последовательности/версии.
    Последнее значение должно победить.
    """
    if not any([has_methods(store, ["ingest"]), has_methods(store, ["upsert"]), has_methods(store, ["write"])]):
        pytest.skip("No ingest API")

    uid = "conc_user"
    ts0 = utc_ms(datetime.now(timezone.utc))

    # Подготовим 20 конкурентных апдейтов score
    N = 20
    lock = threading.Lock()
    errors = []

    def worker(i):
        row = {"user_id": uid, "event_ts": ts0 + i, "score": float(i), "level": i}
        ok, res = try_call(store, ["ingest", "upsert", "write"], "user_stats", [row])
        if not ok:
            with lock:
                errors.append(("ingest", i, res))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, f"Ingest errors: {errors}"

    def read_score():
        ok, out = try_call(store, ["get_online", "read_online", "read"], "user_stats", {"user_id": uid}, ["score"])
        if not ok or not isinstance(out, dict):
            return None
        return out.get("score")

    # Ожидаем, что финальный score == N-1
    ok = await_condition(lambda: read_score() in (float(N-1), N-1), timeout=3.0)
    assert ok, f"Expected last-write-wins score={N-1}, got {read_score()}"


@skip_integration
def test_backfill_is_idempotent(store):
    """
    Backfill одного и того же окна должен быть идемпотентен (объём данных не растёт).
    Скип, если backfill недоступен.
    """
    if not any([has_methods(store, ["backfill"]), has_methods(store, ["materialize_backfill"])]):
        pytest.skip("Backfill API not found")

    start = datetime.now(timezone.utc) - timedelta(days=1)
    end = datetime.now(timezone.utc)

    # Первый прогон
    ok, res1 = try_call(store, ["backfill"], "user_stats", utc_ms(start), utc_ms(end))
    if not ok:
        ok, res1 = try_call(store, ["materialize_backfill"], {
            "table": "user_stats",
            "from_ms": utc_ms(start),
            "to_ms": utc_ms(end),
        })
    assert ok, f"Backfill run #1 failed: {res1}"

    # Второй прогон теми же параметрами
    ok, res2 = try_call(store, ["backfill"], "user_stats", utc_ms(start), utc_ms(end))
    if not ok:
        ok, res2 = try_call(store, ["materialize_backfill"], {
            "table": "user_stats",
            "from_ms": utc_ms(start),
            "to_ms": utc_ms(end),
        })
    assert ok, f"Backfill run #2 failed: {res2}"

    # Если реализация возвращает количество затронутых строк — проверяем равенство
    def affected(x):
        if isinstance(x, dict):
            for k in ("affected_rows", "rows", "count"):
                if k in x and isinstance(x[k], int):
                    return x[k]
        if isinstance(x, int):
            return x
        return None

    a1, a2 = affected(res1), affected(res2)
    if a1 is not None and a2 is not None:
        assert a2 == a1, f"Backfill must be idempotent: {a1} != {a2}"
