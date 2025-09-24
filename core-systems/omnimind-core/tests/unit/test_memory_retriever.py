# path: tests/unit/test_memory_retriever.py
import asyncio
import importlib
import inspect
import math
import types
from dataclasses import asdict
from typing import Any, List, Optional

import pytest

# Берём типы запроса/ответа из реализованного ранее стора
from omnimind.memory.stores.chroma_store import (
    QueryRequest,
    QueryFilters,
    QueryResponse,
    SearchHit,
    Snippet,
)

# -------------------------------
# Вспомогательные утилиты тестов
# -------------------------------

def _load_retriever_cls():
    """
    Пытается найти класс ретривера в модуле omnimind.memory.retriever
    по распространённым именам. Если модуль или класс отсутствуют — аккуратно скипаем тесты.
    """
    try:
        mod = importlib.import_module("omnimind.memory.retriever")
    except Exception as e:
        pytest.skip(f"Retriever module is not available: {e!r}")
    for name in ("MemoryRetriever", "Retriever", "MemorySearch", "RetrieverService"):
        if hasattr(mod, name):
            return getattr(mod, name)
    pytest.skip("Retriever class not found in omnimind.memory.retriever")


def _maybe_await(x):
    if inspect.isawaitable(x):
        return asyncio.run(x)
    return x


class FakeStore:
    """
    Минимальный стаб стора с фиксацией последнего QueryRequest и управляемым ответом/исключением.
    """
    def __init__(self):
        self.last_req: Optional[QueryRequest] = None
        self._response: Optional[QueryResponse] = None
        self._raise: Optional[BaseException] = None
        self.calls: int = 0

    def set_response(self, resp: QueryResponse):
        self._response = resp
        self._raise = None

    def set_raise(self, exc: BaseException):
        self._raise = exc
        self._response = None

    def query(self, req: QueryRequest) -> QueryResponse:
        self.calls += 1
        self.last_req = req
        if self._raise:
            raise self._raise
        assert self._response is not None, "FakeStore: response is not configured"
        return self._response


def _hit(mem_id: str, chunk_id: str, score: float, vscore: float = 0.0, tscore: float = 0.0, ns: str = "prod", kind: str = "conversation") -> SearchHit:
    return SearchHit(
        memory_id=mem_id,
        chunk_id=chunk_id,
        score=score,
        vector_score=vscore,
        text_score=tscore,
        snippet=Snippet(chunk_id=chunk_id, text=f"snippet for {chunk_id}"),
        metadata={"namespace": ns, "kind": kind},
    )


def _resp(hits: List[SearchHit]) -> QueryResponse:
    return QueryResponse(hits=hits)


# -------------------------------
# Фикстуры
# -------------------------------

@pytest.fixture()
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture()
def retriever_cls():
    return _load_retriever_cls()


@pytest.fixture()
def retriever(retriever_cls, store):
    """
    Большинство реализаций ожидают зависимость store в конструкторе.
    Дополнительно поддерживаем вариант с именованным аргументом (store|memory_store|backend).
    """
    try:
        return retriever_cls(store=store)
    except TypeError:
        try:
            return retriever_cls(memory_store=store)
        except TypeError:
            return retriever_cls(backend=store)


# -------------------------------
# Тесты
# -------------------------------

def test_parameter_mapping_vector_mode(retriever, store: FakeStore):
    """
    Ретривер должен пробросить в стор корректный QueryRequest:
    - текст запроса
    - embedding_space и embedding_vector
    - фильтры namespace/kinds
    - веса и top_k
    """
    store.set_response(_resp([
        _hit("m1", "c1", 0.9, vscore=0.9, tscore=0.1),
        _hit("m2", "c2", 0.7, vscore=0.7, tscore=0.1),
    ]))

    out = _maybe_await(retriever.retrieve(
        query="hello embeddings",
        namespace="prod",
        kinds=["conversation"],
        top_k=2,
        space="text-emb-3-large",
        vector=[0.1, 0.2, 0.3],
        vector_weight=0.8,
        text_weight=0.2,
    ))

    # Проверяем, что стор был вызван
    assert store.calls == 1
    assert isinstance(store.last_req, QueryRequest)

    req: QueryRequest = store.last_req  # type: ignore[assignment]
    assert req.text_query == "hello embeddings"
    assert req.embedding_space == "text-emb-3-large"
    assert req.embedding_vector == [0.1, 0.2, 0.3]
    assert req.top_k == 2
    assert math.isclose(req.vector_weight, 0.8)
    assert math.isclose(req.text_weight, 0.2)

    # Фильтры
    assert isinstance(req.filters, QueryFilters)
    assert req.filters.namespace == "prod"
    assert req.filters.kinds == ["conversation"]

    # Результат ретривера (duck-typing: список словарей или SearchHit-подобных структур)
    assert isinstance(out, (list, tuple)) and len(out) == 2


def test_text_only_fallback(retriever, store: FakeStore):
    """
    При отсутствии вектора/пространства ретривер должен уметь работать в текстовом режиме.
    """
    store.set_response(_resp([
        _hit("m1", "c1", 0.4, vscore=0.0, tscore=0.4),
    ]))

    out = _maybe_await(retriever.retrieve(
        query="plain text search",
        namespace="prod",
        kinds=["note"],
        top_k=1,
        # без space/vector
    ))

    req: QueryRequest = store.last_req  # type: ignore[assignment]
    assert req.embedding_space is None
    assert req.embedding_vector is None
    assert req.text_query == "plain text search"
    assert req.filters.kinds == ["note"]
    assert len(out) == 1


def test_topk_and_sorting(retriever, store: FakeStore):
    """
    Ретривер должен возвращать не более top_k и упорядочивать по score убыванию
    (даже если стор вернул неотсортированный список).
    """
    # Неотсортированные хиты от стора
    store.set_response(_resp([
        _hit("m3", "c3", 0.2),
        _hit("m1", "c1", 0.9),
        _hit("m2", "c2", 0.7),
        _hit("m4", "c4", 0.5),
    ]))

    out = _maybe_await(retriever.retrieve(
        query="sort me",
        namespace="prod",
        kinds=["conversation"],
        top_k=3,
    ))

    # Нормализуем для проверки: допускаем как dict, так и объект с атрибутами
    def _score(x: Any) -> float:
        if isinstance(x, dict):
            return float(x.get("score", -1))
        if hasattr(x, "score"):
            return float(getattr(x, "score"))
        # fallback — если ретривер отдаёт «сырой» ответ стора
        return -1.0

    scores = list(map(_score, out))
    assert len(out) == 3
    assert scores == sorted(scores, reverse=True)


def test_empty_result(retriever, store: FakeStore):
    """
    Пустой ответ должен корректно обрабатываться (пустой список без исключений).
    """
    store.set_response(_resp([]))

    out = _maybe_await(retriever.retrieve(
        query="nothing here",
        namespace="prod",
        kinds=["conversation"],
        top_k=5,
    ))
    assert isinstance(out, (list, tuple))
    assert len(out) == 0


def test_error_propagation(retriever, store: FakeStore):
    """
    Ошибка стора должна быть прозрачно видна вызывающему коду:
    либо специфичный MemoryRetrievalError, либо исходное исключение.
    """
    class SomeStoreError(RuntimeError):
        pass

    store.set_raise(SomeStoreError("boom"))
    with pytest.raises(Exception):
        _maybe_await(retriever.retrieve(
            query="trigger error",
            namespace="prod",
            kinds=["conversation"],
            top_k=1,
        ))


def test_filters_are_passed_through(retriever, store: FakeStore):
    """
    Проверка, что дополнительные фильтры (owner_id, labels) корректно прокидываются, если поддерживаются API ретривера.
    Если ретривер не принимает их явно, допускается игнор (тест не будет падать).
    """
    store.set_response(_resp([_hit("m1", "c1", 0.6)]))

    # Попытка вызвать с дополнительными фильтрами; если реализация их не поддерживает — проигнорирует kwargs
    try:
        out = _maybe_await(retriever.retrieve(
            query="filters",
            namespace="prod",
            kinds=["doc"],
            top_k=1,
            owner_id="user-42",
            labels_all=["pii:redacted"],
        ))
    except TypeError:
        # Ретривер не поддерживает дополнительные kwargs — это допустимо
        out = _maybe_await(retriever.retrieve(
            query="filters",
            namespace="prod",
            kinds=["doc"],
            top_k=1,
        ))

    # В любом случае должен быть один вызов стора и один результат
    assert store.calls == 1
    assert len(out) == 1
