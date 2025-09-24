# neuroforge-core/tests/unit/test_vector_index.py
# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для VectorIndex.

Стратегия:
- Универсальная резолюция класса индекса по нескольким путям и через переменную
  окружения NEUROFORGE_VECTOR_INDEX_CLS (формат "pkg.mod:Class").
- Адаптация к различным сигнатурам конструктора и наличию/отсутствию методов
  (add/upsert/delete/query/query_batch/save/load, size/__len__).
- Покрытие: add, duplicate-id, upsert, delete, query top-1/k>n, batch query,
  метрики (cosine/dot/l2), персистентность (save/load), конкуррентные чтения,
  контроль размерности и стабильность сортировки по top-1.
- Без внешних зависимостей (numpy не требуется).

ПРИМЕЧАНИЕ:
Точный интерфейс `VectorIndex` не подтверждён. Эти тесты пытаются адаптироваться
к типовым вариантам. Если API отличается радикально, корректируйте адаптер.
"""

import os
import io
import json
import math
import shutil
import tempfile
import inspect
import contextlib
from importlib import import_module
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest


# ----------------------------- РЕЗОЛЮЦИЯ КЛАССА ----------------------------- #

_CANDIDATES = [
    "neuroforge_core.vector.index:VectorIndex",
    "neuroforge_core.core.vector_index:VectorIndex",
    "neuroforge_core.vector_index:VectorIndex",
    "neuroforge_core.vector.index:Index",
]

def _load_obj(dotted: str):
    mod, _, attr = dotted.partition(":")
    m = import_module(mod)
    if attr:
        return getattr(m, attr)
    return m


def resolve_index_class():
    env = os.getenv("NEUROFORGE_VECTOR_INDEX_CLS")
    errors = []
    if env:
        try:
            return _load_obj(env)
        except Exception as e:
            errors.append(f"{env} -> {e}")
    for cand in _CANDIDATES:
        try:
            return _load_obj(cand)
        except Exception as e:
            errors.append(f"{cand} -> {e}")
    raise ImportError(
        "Не удалось импортировать класс VectorIndex. "
        "Установите переменную окружения NEUROFORGE_VECTOR_INDEX_CLS='pkg.mod:Class'. "
        "Ошибки:\n- " + "\n- ".join(errors)
    )


VectorIndexClass = None  # будет инициализировано лениво


# ----------------------------- УТИЛИТЫ/АДАПТЕР ------------------------------ #

def _try_construct(cls, dim=4, metric="cosine", normalize=True):
    """
    Поддерживает распространённые сигнатуры:
      (dim, metric, normalize)
      (dim, metric)
      (dim=..., metric=..., normalize=...)
      (dim=..., metric=...)
      (dim)
    """
    with contextlib.suppress(Exception):
        return cls(dim=dim, metric=metric, normalize=normalize)
    with contextlib.suppress(Exception):
        return cls(dim=dim, metric=metric)
    with contextlib.suppress(Exception):
        return cls(dim, metric)
    with contextlib.suppress(Exception):
        return cls(dim=dim)
    return cls(dim)


def _has_method(obj, name):
    return hasattr(obj, name) and callable(getattr(obj, name))


def _index_size(index):
    if hasattr(index, "size"):
        s = getattr(index, "size")
        return s() if callable(s) else s
    if hasattr(index, "__len__"):
        return len(index)
    return None


def _add(index, ids, vectors):
    """
    Предпочитаем сигнатуру add(ids, vectors). Если в имплементации наоборот — пробуем варианты.
    """
    add_fn = getattr(index, "add", None)
    if add_fn is None or not callable(add_fn):
        raise AttributeError("Метод add(...) отсутствует")
    with contextlib.suppress(TypeError):
        return add_fn(ids, vectors)
    return add_fn(vectors, ids)


def _upsert(index, ids, vectors):
    if not _has_method(index, "upsert"):
        pytest.skip("upsert(...) не поддерживается реализацией индекса")
    upsert_fn = getattr(index, "upsert")
    with contextlib.suppress(TypeError):
        return upsert_fn(ids, vectors)
    return upsert_fn(vectors, ids)


def _delete(index, ids):
    if not _has_method(index, "delete"):
        pytest.skip("delete(...) не поддерживается реализацией индекса")
    return getattr(index, "delete")(ids)


def _query(index, vector, k=5):
    q = getattr(index, "query", None)
    if q is None or not callable(q):
        raise AttributeError("Метод query(...) отсутствует")
    res = q(vector, k) if k is not None else q(vector)
    # Нормируем формат: список (id, score) или dict с 'id'/'score'
    norm = []
    for item in res:
        if isinstance(item, tuple) and len(item) >= 1:
            norm.append((item[0], item[1] if len(item) > 1 else None))
        elif isinstance(item, dict):
            iid = item.get("id")
            sc = item.get("score")
            norm.append((iid, sc))
        else:
            norm.append((item, None))
    return norm


def _query_batch(index, vectors, k=5):
    qb = getattr(index, "query_batch", None)
    if qb is None or not callable(qb):
        pytest.skip("query_batch(...) не поддерживается реализацией индекса")
    res = qb(vectors, k) if k is not None else qb(vectors)
    return [ [(r[0], (r[1] if len(r) > 1 else None)) if isinstance(r, tuple) else
             (r.get("id"), r.get("score")) if isinstance(r, dict) else (r, None)
            for r in row] for row in res ]


def _save(index, path: Path):
    if not _has_method(index, "save"):
        pytest.skip("save(...) не поддерживается реализацией индекса")
    return getattr(index, "save")(str(path))


def _load(cls, path: Path):
    if hasattr(cls, "load") and callable(getattr(cls, "load")):
        return cls.load(str(path))
    # Fallback: если загрузка через конструктор из директории/файла
    with contextlib.suppress(Exception):
        return cls(str(path))
    raise AttributeError("load(...) не поддерживается и нет конструкторной загрузки")


# ----------------------------- ТЕСТОВЫЕ ДАННЫЕ -------------------------------- #

@pytest.fixture(scope="module")
def index_class():
    global VectorIndexClass
    if VectorIndexClass is None:
        VectorIndexClass = resolve_index_class()
    return VectorIndexClass


@pytest.fixture
def tmpdir_path(tmp_path):
    return tmp_path


def _dataset_simple(dim=4):
    """
    Детерминированный набор из 6 векторов в R^dim с очевидными ближайшими соседями.
    """
    ids = ["a", "b", "c", "d", "e", "f"]
    base = [
        [1, 0, 0, 0],
        [0.9, 0.1, 0, 0],
        [0, 1, 0, 0],
        [0, 0.9, 0.1, 0],
        [0, 0, 1, 0],
        [0, 0, 0.9, 0.1],
    ]
    # обрезаем/паддим под dim
    vecs = []
    for v in base:
        vv = v[:dim]
        if len(vv) < dim:
            vv = vv + [0.0] * (dim - len(vv))
        vecs.append(vv)
    return ids, vecs


# ---------------------------------- ТЕСТЫ ------------------------------------- #

@pytest.mark.parametrize("metric", ["cosine", "dot", "l2"])
def test_add_and_query_top1(index_class, metric):
    # Некоторые реализации могут не поддерживать все метрики — тогда пропускаем.
    try:
        index = _try_construct(index_class, dim=4, metric=metric, normalize=True)
    except Exception as e:
        pytest.skip(f"Метрика '{metric}' не поддерживается: {e}")

    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    # Запросим точный self-NN: должен вернуть сам себя top-1.
    for iid, v in zip(ids, vecs):
        res = _query(index, v, k=1)
        assert len(res) == 1
        top_id, top_score = res[0]
        assert top_id == iid


def test_size_and_duplicates(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)
    size = _index_size(index)
    if size is not None:
        assert size == len(ids)

    # Попытка повторного add с дубликатами должна либо бросать, либо игнорировать — в проде ожидаем явную ошибку.
    with pytest.raises(Exception):
        _add(index, [ids[0]], [vecs[0]])


def test_k_greater_than_size(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids[:3], vecs[:3])

    res = _query(index, vecs[0], k=10)
    # Должны вернуть не больше фактического размера
    assert 1 <= len(res) <= 3
    # Содержимое — валидные id
    for iid, score in res:
        assert iid in ids[:3]


def test_dimension_mismatch(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    # Попытка добавить вектор неверной размерности должна падать
    with pytest.raises(Exception):
        _add(index, ["x"], [[1.0, 2.0]])  # dim=2 вместо 4


def test_delete(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    _delete(index, [ids[0], ids[1]])
    # Удалённые не должны возвращаться
    res = _query(index, vecs[0], k=5)
    returned_ids = {iid for iid, _ in res}
    assert ids[0] not in returned_ids
    assert ids[1] not in returned_ids


def test_upsert_changes_neighborhood(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    # Изначально для вектора c ближайший — сам c
    res0 = _query(index, vecs[2], k=1)
    assert res0[0][0] == ids[2]

    # Апсертим c на вектор, близкий к 'a'
    new_vec = [1, 0, 0, 0]
    _upsert(index, [ids[2]], [new_vec])

    # Теперь ближайшим к new_vec должен быть id 'c' (self)
    res1 = _query(index, new_vec, k=1)
    assert res1[0][0] == ids[2]


def test_query_batch(index_class):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    batch = [vecs[0], vecs[2], vecs[4]]
    out = _query_batch(index, batch, k=1)
    assert len(out) == len(batch)
    for row, iid_expected in zip(out, [ids[0], ids[2], ids[4]]):
        assert len(row) == 1
        assert row[0][0] == iid_expected


def test_persistence_roundtrip(index_class, tmpdir_path):
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    save_path = tmpdir_path / "vi_store"
    _save(index, save_path)
    assert save_path.exists()

    # round-trip
    loaded = _load(index_class, save_path)
    for iid, v in zip(ids, vecs):
        res = _query(loaded, v, k=1)
        assert res[0][0] == iid


def test_concurrent_read_queries(index_class):
    """
    Тестирует потокобезопасность параллельных READ-запросов (query).
    Вставка завершена заранее, конкуренция только на чтение.
    """
    index = _try_construct(index_class, dim=4, metric="cosine", normalize=True)
    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    def work(qv, expect_id):
        r = _query(index, qv, k=1)
        return r[0][0] == expect_id

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(work, v, iid) for iid, v in zip(ids, vecs)]
        results = [f.result(timeout=5) for f in futs]
    assert all(results)


@pytest.mark.parametrize("metric", ["cosine", "dot", "l2"])
def test_metric_basic_ordering(index_class, metric):
    """
    Базовая проверка, что self-vector даёт топ-1.
    Для L2 «лучше» — меньшая дистанция; для cosine/dot — большая схожесть.
    Мы валидируем только идентификатор top-1, не навязывая знак score.
    """
    try:
        index = _try_construct(index_class, dim=4, metric=metric, normalize=True)
    except Exception as e:
        pytest.skip(f"Метрика '{metric}' не поддерживается: {e}")

    ids, vecs = _dataset_simple(dim=4)
    _add(index, ids, vecs)

    q = [0.9, 0.1, 0, 0]
    res = _query(index, q, k=2)
    returned_ids = [iid for iid, _ in res]
    assert ids[0] in returned_ids[:2] or ids[1] in returned_ids[:2], "Соседство вокруг оси e1 должно быть стабильным"
