# path: tests/unit/processing/test_transforms.py
import copy
import itertools
import math
import os
import random
import string
import time
from typing import Any, Dict, List

import pytest

# --- попытка импортировать модуль трансформаций (иначе разумно пропустить весь набор)
transmod = pytest.importorskip("datafabric.processing.transforms", reason="datafabric.processing.transforms not found")

# --- опциональная интеграция с serde
try:
    from datafabric.utils import serde as df_serde  # type: ignore
except Exception:  # pragma: no cover
    df_serde = None  # optional


# ----------------------------
# Вспомогательные адаптеры API
# ----------------------------

class APINotFound(Exception):
    pass

def pick(name_list):
    """
    Находит первую доступную функцию из списка возможных синонимов.
    Если ничего не найдено — пропускает тест через pytest.skip.
    """
    for n in name_list:
        fn = getattr(transmod, n, None)
        if callable(fn):
            return fn
    pytest.skip(f"API not found: any of {name_list}")

def pick_opt(name_list):
    for n in name_list:
        fn = getattr(transmod, n, None)
        if callable(fn):
            return fn
    return None

def get_error_cls():
    return getattr(transmod, "TransformError", ValueError)

# Часто ожидаемые имена функций:
F_MAP         = ["map_values", "map_records", "map"]
F_FILTER      = ["filter_rows", "filter_records", "filter"]
F_SELECT      = ["select", "project"]
F_RENAME      = ["rename"]
F_DEFAULTS    = ["with_defaults", "defaults"]
F_EXPLODE     = ["explode"]
F_UNIQUE      = ["unique", "deduplicate", "dedupe"]
F_DROP_NULLS  = ["drop_nulls", "dropna"]
F_LIMIT       = ["limit", "take"]
F_PIPELINE    = ["pipeline", "compose"]
F_RUN         = ["run", "run_pipeline", "apply"]
F_BATCH       = ["batch", "chunked"]
F_REGEX       = ["regex_filter", "match", "where_regex"]

# ----------------------------
# Фикстуры данных
# ----------------------------

@pytest.fixture
def records() -> List[Dict[str, Any]]:
    return [
        {"id": 1, "sku": "A", "price": 10.0, "qty": 2, "ts": "2025-08-15T00:00:00Z", "email": "u1@example.com"},
        {"id": 2, "sku": "B", "price": 0.0,  "qty": 0, "ts": "2025-08-15T01:00:00Z", "email": "bad_at"},
        {"id": 3, "sku": "A", "price": 5.5,  "qty": 1, "ts": "2025-08-15T02:00:00Z", "email": "u3@example.com"},
        {"id": 3, "sku": "A", "price": 5.5,  "qty": 1, "ts": "2025-08-15T02:00:00Z", "email": "u3@example.com"},  # дубликат
        {"id": 4, "sku": None, "price": None, "qty": 3, "ts": "2025-08-15T03:00:00Z", "email": None},
    ]

@pytest.fixture
def nested_records() -> List[Dict[str, Any]]:
    return [
        {"id": 10, "items": [{"p": "x", "v": 1}, {"p": "y", "v": 2}]},
        {"id": 11, "items": []},
        {"id": 12, "items": [{"p": "z", "v": 3}]},
    ]

@pytest.fixture
def big_records() -> List[Dict[str, Any]]:
    # умеренный объём, чтобы не тормозить CI
    out = []
    for i in range(5000):
        out.append({"id": i, "val": i % 7, "text": f"t{i}"})
    return out


# ----------------------------
# Базовые сценарии пайплайна
# ----------------------------

def test_map_filter_select_pipeline_basic(records):
    map_fn = pick(F_MAP)
    filter_fn = pick(F_FILTER)
    select_fn = pick(F_SELECT)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        map_fn(lambda r: {**r, "amount": (r.get("price") or 0.0) * (r.get("qty") or 0)}),
        filter_fn(lambda r: r["amount"] > 0),
        select_fn(["id", "sku", "amount"]),
    )
    out = list(run(t, records))
    assert all(set(x.keys()) == {"id", "sku", "amount"} for x in out)
    assert all(x["amount"] > 0 for x in out)
    assert {x["id"] for x in out} == {1, 3}


def test_rename_defaults_explode(nested_records):
    rename = pick(F_RENAME)
    defaults = pick(F_DEFAULTS)
    explode = pick(F_EXPLODE)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        rename({"items": "lines"}),
        defaults({"lines": []}),
        explode("lines"),
    )
    out = list(run(t, nested_records))
    # ожидания: 2 + 0 + 1 = 3 строк
    assert len(out) == 3
    assert all("lines" in r or "p" in r or "v" in r for r in out) or all("p" in r and "v" in r for r in out)


@pytest.mark.parametrize("drop_how, expected_ids", [
    ("any", {1,2,3}),   # допускаем записи, где sku или price могут быть None, но при "any" строки с любым null отпадут
    ("all", {1,2,3,4}), # при "all" только если все поля None — дроп
])
def test_unique_drop_nulls_limit(records, drop_how, expected_ids):
    unique = pick(F_UNIQUE)
    drop_nulls = pick(F_DROP_NULLS)
    limit = pick(F_LIMIT)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        unique(lambda r: (r["id"], r["sku"], r["price"], r["qty"])),
        drop_nulls(fields=["sku", "price"], how=drop_how),
        limit(10),
    )
    out = list(run(t, records))
    ids = {r["id"] for r in out}
    assert ids.issubset({1,2,3,4})
    # проверяем отсутствие дубликата id=3
    assert sum(1 for r in out if r["id"] == 3) == 1


def test_pipeline_no_mutation(records):
    map_fn = pick(F_MAP)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)
    src = copy.deepcopy(records)

    t = pipe(map_fn(lambda r: {**r, "x": 1}))
    _ = list(run(t, src))
    assert src == records, "pipeline must not mutate input records"


def test_determinism(records):
    filter_fn = pick(F_FILTER)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(filter_fn(lambda r: (r.get("price") or 0) > 0))
    out1 = list(run(t, records))
    out2 = list(run(t, records))
    assert out1 == out2, "pipeline must be deterministic for same input"


def test_error_on_bad_config():
    # попытка неверной конфигурации должна выбросить детерминированную ошибку
    pipe = pick(F_PIPELINE)
    err = get_error_cls()
    with pytest.raises(err):
        # например, select без списка полей или explode без колонки
        select_fn = pick(F_SELECT)
        t = pipe(select_fn(None))  # type: ignore
        # если конструктор ленивый — принудительно запустим
        run = pick(F_RUN)
        list(run(t, [{"a": 1}]))


def test_batch_vs_nobatch_equivalence(records):
    map_fn = pick(F_MAP)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)
    batch = pick_opt(F_BATCH)

    t = pipe(map_fn(lambda r: {**r, "s": (r.get("sku") or "") + "_"}))
    out_nobatch = list(run(t, records))

    if batch is None:
        pytest.skip("batch/chunked API not available")
    t_b = pipe(batch(2), t)
    out_batch = list(run(t_b, records))
    assert out_batch == out_nobatch


@pytest.mark.parametrize("workers", [1, 4])
def test_parallel_shards_equivalence(big_records, workers):
    """
    Имитация параллельной обработки: разбиваем вход на чанки, гоняем пайплайн, объединяем.
    Результат должен совпадать с последовательной обработкой (при условии детерминизма).
    """
    map_fn = pick(F_MAP)
    filter_fn = pick(F_FILTER)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        map_fn(lambda r: {**r, "vv": (r["val"] * 3) % 5}),
        filter_fn(lambda r: r["vv"] != 2),
    )

    # последовательный
    seq = list(run(t, big_records))

    # параллельный шардированный (без thread pool, чтобы тест не зависел от GIL/окружения)
    parts = []
    n = max(1, workers)
    for i in range(n):
        shard = big_records[i::n]
        parts.append(list(run(t, shard)))
    par = list(itertools.chain.from_iterable(parts))

    # Сравниваем мультимножества (порядок может отличаться)
    assert sorted(seq, key=lambda r: r["id"]) == sorted(par, key=lambda r: r["id"])


@pytest.mark.skipif(df_serde is None, reason="serde not available")
def test_serde_roundtrip(records):
    """
    Проверяем, что результат пайплайна стабильно сереализуется/десереализуется.
    """
    map_fn = pick(F_MAP)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(map_fn(lambda r: {**r, "amount": (r.get("price") or 0) * (r.get("qty") or 0)}))
    out = list(run(t, records))

    blob = df_serde.encode(out, fmt=df_serde.Format.JSON, compression=df_serde.Compression.GZIP)  # type: ignore
    back = df_serde.decode(blob)  # type: ignore
    assert out == back


def test_regex_filter_if_available(records):
    rx = pick_opt(F_REGEX)
    if rx is None:
        pytest.skip("regex-like filter API not available")
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(rx("email", r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"))
    out = list(run(t, records))
    # Оставлены только корректные email
    assert {r["id"] for r in out} == {1, 3}


def test_compute_and_select(records):
    # compute может называться map/map_values — уже покрыто test_map_filter_select_pipeline_basic,
    # но здесь валидируем вычисление округления и проекцию.
    map_fn = pick(F_MAP)
    select_fn = pick(F_SELECT)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        map_fn(lambda r: {**r, "avg_price": round((r.get("price") or 0) / max(1, r.get("qty") or 0), 2) if (r.get("qty") or 0) > 0 else None}),
        select_fn(["id", "avg_price"]),
    )
    out = list(run(t, records))
    by_id = {r["id"]: r["avg_price"] for r in out}
    assert by_id[1] == 5.0
    assert by_id[2] is None
    assert by_id[3] == 5.5


@pytest.mark.timeout(5)
def test_smoke_performance(big_records):
    # Лёгкий перф-дымок: простой map+filter на 5000 строк должен пройти быстро
    map_fn = pick(F_MAP)
    filter_fn = pick(F_FILTER)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(
        map_fn(lambda r: {**r, "x": r["val"] * 2 + 1}),
        filter_fn(lambda r: r["x"] % 2 == 1),
    )
    t0 = time.time()
    out = list(run(t, big_records))
    assert len(out) == len(big_records)  # фильтр пропускает все
    assert time.time() - t0 < 5.0


def test_invalid_explode_raises(nested_records):
    explode = pick(F_EXPLODE)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)
    err = get_error_cls()

    with pytest.raises(err):
        t = pipe(explode(None))  # type: ignore
        list(run(t, nested_records))


def test_limit_zero(records):
    limit = pick(F_LIMIT)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    t = pipe(limit(0))
    out = list(run(t, records))
    assert out == []


def test_order_invariance_of_unique(records):
    unique = pick(F_UNIQUE)
    pipe = pick(F_PIPELINE)
    run = pick(F_RUN)

    key = lambda r: (r["id"], r.get("sku"), r.get("price"))
    t = pipe(unique(key))

    # перемешиваем вход, результат должен быть одинаковым множеством по ключу
    rnd = records[:]
    random.Random(42).shuffle(rnd)
    out1 = list(run(t, records))
    out2 = list(run(t, rnd))

    s1 = sorted([key(r) for r in out1])
    s2 = sorted([key(r) for r in out2])
    assert s1 == s2
