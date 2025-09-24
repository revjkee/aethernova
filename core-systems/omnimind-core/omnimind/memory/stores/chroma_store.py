# path: omnimind-core/omnimind/memory/stores/chroma_store.py
from __future__ import annotations

import dataclasses
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Типы для эмбеддинга, чтобы не зависеть от конкретных библиотек
Embedder = Callable[[Sequence[str], str], List[List[float]]]  # (texts, space) -> vectors

# =========================
# Доменные модели памяти
# =========================

@dataclass(frozen=True)
class Embedding:
    space: str
    vector: List[float]


@dataclass(frozen=True)
class Chunk:
    id: str
    index: int
    text: str
    tags: Dict[str, str] = field(default_factory=dict)
    embeddings: List[Embedding] = field(default_factory=list)


@dataclass(frozen=True)
class Memory:
    id: str
    namespace: str
    owner_id: str
    kind: str
    attributes: Dict[str, str] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    chunks: List[Chunk] = field(default_factory=list)


# =========================
# Запросы/ответы поиска
# =========================

@dataclass(frozen=True)
class QueryFilters:
    namespace: Optional[str] = None
    owner_id: Optional[str] = None
    kinds: List[str] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)
    labels_all: List[str] = field(default_factory=list)
    labels_not: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class QueryRequest:
    text_query: Optional[str] = None
    embedding_space: Optional[str] = None
    embedding_vector: Optional[List[float]] = None
    top_k: int = 50
    vector_weight: float = 0.5   # 0..1
    text_weight: float = 0.5     # 0..1
    filters: QueryFilters = field(default_factory=QueryFilters)


@dataclass(frozen=True)
class Snippet:
    chunk_id: str
    text: str


@dataclass(frozen=True)
class SearchHit:
    memory_id: str
    chunk_id: str
    score: float
    vector_score: float
    text_score: float
    snippet: Snippet
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class QueryResponse:
    hits: List[SearchHit]


# =========================
# Ошибки хранилища
# =========================

class StoreError(RuntimeError):
    pass


class NotFound(StoreError):
    pass


# =========================
# Вспомогательные утилиты
# =========================

def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise StoreError(msg)


def _now() -> float:
    return time.perf_counter()


def _coalesce_memory_id(memory_id: Optional[str]) -> str:
    return memory_id or str(uuid.uuid4())


def _tokenize(s: str) -> List[str]:
    return [t for t in ''.join(ch.lower() if ch.isalnum() else ' ' for ch in s).split() if t]


def _text_overlap_score(query: str, text: str) -> float:
    """
    Простая и быстрая метрика пересечения терминов для гибридного скоринга.
    Возвращает значение в [0,1].
    """
    if not query or not text:
        return 0.0
    q = set(_tokenize(query))
    if not q:
        return 0.0
    d = set(_tokenize(text))
    if not d:
        return 0.0
    inter = len(q & d)
    return inter / max(1, len(q))


def _safe_space(s: str) -> str:
    """
    Преобразует произвольное имя пространства/окружения в безопасное имя коллекции Chroma.
    """
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in '-_.':
            out.append(ch)
        else:
            out.append('_')
    return ''.join(out).strip('_') or 'default'


def _collection_name(prefix: str, namespace: str, kind: str, suffix: Optional[str] = None) -> str:
    parts = [prefix, _safe_space(namespace), _safe_space(kind)]
    if suffix:
        parts.append(_safe_space(suffix))
    return "__".join(parts)


# =========================
# Реализация ChromaStore
# =========================

class ChromaStore:
    """
    Промышленный слой работы с ChromaDB для модели Memory/Chunk.

    Дизайн коллекций:
      - Каталог: один per (namespace, kind) — хранит текст и метаданные чанков.
        name = "memcat__{namespace}__{kind}"
      - Векторные: по одному per embedding_space и (namespace, kind).
        name = "memvec__{namespace}__{kind}__{space}"

    Документы:
      - id каталога:     "{memory_id}:{chunk_id}"
      - id вектора:      "{memory_id}:{chunk_id}:{space}"

    Метаданные документа (и там, и там):
      memory_id, chunk_id, kind, namespace, owner_id, index, labels (list),
      attributes (map), tags (map)
    """

    def __init__(
        self,
        client: Any,
        *,
        logger: Optional[logging.Logger] = None,
        embedder: Optional[Embedder] = None,
        distance: str = "cosine",  # cosine|l2|ip (Chroma terminology: "cosine"/"l2"/"ip")
    ) -> None:
        """
        :param client: chromadb.Client или chromadb.PersistentClient (уже инициализирован)
        :param embedder: функция вычисления эмбеддингов (texts, space) -> vectors; опционально
        :param distance: метрика расстояния в векторных коллекциях
        """
        self._client = client
        self._embedder = embedder
        self._distance = distance
        self._log = logger or logging.getLogger("omnimind.memory.chroma")

    # ---------- Публичный API ----------

    def upsert(self, memory: Memory) -> None:
        """
        Идемпотентный upsert Memory и всех его чанков во все нужные коллекции.
        Если у чанка embeddings пуст, а embedder задан — эмбеддинги будут вычислены.
        """
        _require(memory.id, "memory.id is required")
        _require(memory.namespace, "namespace is required")
        _require(memory.kind, "kind is required")
        _require(memory.chunks is not None and len(memory.chunks) > 0, "memory.chunks must be non-empty")

        # Каталоговая коллекция
        cat = self._get_or_create_catalog(memory.namespace, memory.kind)

        # Сбор батчей на запись в каталог
        cat_ids: List[str] = []
        cat_docs: List[str] = []
        cat_metadatas: List[Dict[str, Any]] = []

        # Промежуточный реестр нужных пространств → тексты для эмбеддинга
        to_embed: Dict[str, List[Tuple[str, int, str]]] = {}  # space -> [(doc_id, idx, text)]
        # и заготовки на запись в векторные коллекции (с предвычисленными эмбеддингами)
        vec_batches: Dict[str, Dict[str, List[Any]]] = {}  # space -> {"ids": [], "metadatas": [], "embeddings": [], "documents": []}

        for ch in memory.chunks:
            _require(ch.id and ch.text is not None, "chunk.id and chunk.text are required")
            doc_id = f"{memory.id}:{ch.id}"
            meta = _compose_metadata(memory, ch)

            cat_ids.append(doc_id)
            cat_docs.append(ch.text)
            cat_metadatas.append(meta)

            # Предвычисленные эмбеддинги
            for emb in (ch.embeddings or []):
                b = vec_batches.setdefault(emb.space, {"ids": [], "metadatas": [], "embeddings": [], "documents": []})
                b["ids"].append(f"{memory.id}:{ch.id}:{emb.space}")
                b["documents"].append(ch.text)
                b["metadatas"].append(meta)
                b["embeddings"].append(emb.vector)

            # Если есть embedder — запланируем вычисление для недостающих пространств
            if self._embedder:
                # Ничего не делаем здесь — выбор пространств на стороне клиента.
                # Если хотите всегда считать для конкретных spaces — добавьте параметры в Memory/Chunk.
                pass

        # Запись в каталог (upsert)
        self._upsert_catalog(cat, ids=cat_ids, documents=cat_docs, metadatas=cat_metadatas)

        # Если есть embedder, но эмбеддинги не переданы — вычислять не будем без явного списка
        # (продакшн-решение: управляйте этим выше по стеку).

        # Запись в векторные коллекции (per space)
        for space, batch in vec_batches.items():
            coll = self._get_or_create_vector(memory.namespace, memory.kind, space)
            self._upsert_vector(coll, **batch)

    def delete_memory(self, namespace: str, kind: str, memory_id: str) -> None:
        """
        Полное удаление Memory: и из каталога, и из всех векторных коллекций пространства (namespace, kind).
        """
        _require(namespace and kind and memory_id, "namespace, kind, memory_id are required")
        # Каталог
        cat = self._get_or_create_catalog(namespace, kind)
        try:
            cat.delete(where={"memory_id": memory_id})
        except Exception as e:
            raise StoreError(f"catalog delete failed: {e}") from e

        # Векторные коллекции: перебираем известные по каталогу labels (можем узнать из списка коллекций)
        for coll in self._iter_vector_collections(namespace, kind):
            try:
                coll.delete(where={"memory_id": memory_id})
            except Exception as e:
                raise StoreError(f"vector delete failed for {coll.name}: {e}") from e

    def get_memory(self, namespace: str, kind: str, memory_id: str) -> Memory:
        """
        Восстановление Memory из каталога по memory_id.
        """
        cat = self._get_or_create_catalog(namespace, kind)
        try:
            # Chroma позволяет фильтровать по where и выбирать поля
            data = cat.get(where={"memory_id": memory_id}, include=["metadatas", "documents", "ids"])
        except Exception as e:
            raise StoreError(f"catalog get failed: {e}") from e

        ids: List[str] = data.get("ids", []) or []
        metas: List[Dict[str, Any]] = data.get("metadatas", []) or []
        docs: List[str] = data.get("documents", []) or []

        if not ids:
            raise NotFound(f"memory {memory_id} not found in {namespace}/{kind}")

        # Берём общие поля из первой меты
        base = metas[0]
        mem = Memory(
            id=memory_id,
            namespace=base["namespace"],
            owner_id=base["owner_id"],
            kind=base["kind"],
            attributes=base.get("attributes", {}),
            labels=base.get("labels", []),
            chunks=[],
        )

        chunks: List[Chunk] = []
        for mid, meta, doc in zip(ids, metas, docs):
            cid = str(meta["chunk_id"])
            chunks.append(
                Chunk(
                    id=cid,
                    index=int(meta["index"]),
                    text=doc,
                    tags=meta.get("tags", {}) or {},
                    embeddings=[],
                )
            )
        # Сортировка по index
        mem = dataclasses.replace(mem, chunks=sorted(chunks, key=lambda c: c.index))
        return mem

    def query(self, req: QueryRequest) -> QueryResponse:
        """
        Гибридный поиск по чанкам: векторный + простая текстовая релевантность.
        Векторный поиск работает только если указан embedding_space и vector (или есть embedder).
        """
        _require(req.top_k > 0, "top_k must be > 0")
        f = req.filters or QueryFilters()

        # Ограничиваем область запроса namespace/kind, иначе используем все каталоги (не рекомендуется).
        _require(bool(f.namespace) and bool(f.kinds), "filters.namespace and filters.kinds are required for query")

        hits: List[SearchHit] = []

        # Обходим все kind, агрегируя кандидатов
        for kind in f.kinds:
            cat = self._get_or_create_catalog(f.namespace, kind)

            # Кандидаты: из векторного поиска или из каталога (fallback)
            candidates: Dict[str, Tuple[str, str, str, float, str]] = {}
            # map doc_id -> (memory_id, chunk_id, kind, vector_score, doc_text)

            # 1) Векторная часть
            if req.embedding_space and (req.embedding_vector or (self._embedder and req.text_query)):
                vec = req.embedding_vector
                if vec is None and self._embedder and req.text_query:
                    vec = self._embedder([req.text_query], req.embedding_space)[0]

                coll = self._get_or_create_vector(f.namespace, kind, req.embedding_space)

                try:
                    qres = coll.query(
                        query_embeddings=[vec],
                        n_results=max(100, req.top_k * 2),  # расширяем кандидатов для гибридного скоринга
                        where=_to_where(f),
                        include=["metadatas", "documents", "distances", "ids"],
                    )
                except Exception as e:
                    raise StoreError(f"vector query failed: {e}") from e

                ids = (qres.get("ids") or [[]])[0]
                dists = (qres.get("distances") or [[]])[0]
                docs = (qres.get("documents") or [[]])[0]
                metas = (qres.get("metadatas") or [[]])[0]
                for doc_id, dist, doc, meta in zip(ids, dists, docs, metas):
                    # Преобразуем расстояние в «похожесть» [0..1] грубо: cosine -> 1 - d; l2/ip — оставляем как есть
                    vscore = _distance_to_similarity(dist, self._distance)
                    candidates[doc_id] = (
                        str(meta["memory_id"]),
                        str(meta["chunk_id"]),
                        str(kind),
                        float(vscore),
                        str(doc or ""),
                    )

            # 2) Если кандидатов нет или задан только текст — отберём базово из каталога
            if not candidates:
                try:
                    # Мы не можем полнотекстово искать во всём корпусе без отдельного индекса.
                    # Поэтому берем ограниченное число последних/любых документов (limit) и проставляем текстовый скор.
                    # Для промышленных сценариев рекомендуется всегда указывать embedding_space + embed.
                    gres = cat.get(where=_to_where(f), include=["metadatas", "documents", "ids"], limit=max(200, req.top_k * 4))
                except Exception as e:
                    raise StoreError(f"catalog scan failed: {e}") from e

                ids = gres.get("ids", []) or []
                docs = gres.get("documents", []) or []
                metas = gres.get("metadatas", []) or []
                for doc_id, doc, meta in zip(ids, docs, metas):
                    candidates[doc_id] = (
                        str(meta["memory_id"]),
                        str(meta["chunk_id"]),
                        str(kind),
                        0.0,  # vector_score отсутствует
                        str(doc or ""),
                    )

            # 3) Гибридный скоринг
            for doc_id, (mem_id, chunk_id, kind, vscore, doc_text) in candidates.items():
                tscore = _text_overlap_score(req.text_query or "", doc_text) if req.text_query else 0.0
                score = req.vector_weight * vscore + req.text_weight * tscore
                hits.append(
                    SearchHit(
                        memory_id=mem_id,
                        chunk_id=chunk_id,
                        score=score,
                        vector_score=vscore,
                        text_score=tscore,
                        snippet=Snippet(chunk_id=chunk_id, text=_make_snippet(doc_text, req.text_query or "")),
                        metadata={"namespace": f.namespace, "kind": kind},
                    )
                )

        # Отсортировать и отобрать top_k
        hits.sort(key=lambda h: h.score, reverse=True)
        return QueryResponse(hits=hits[: req.top_k])

    # ---------- Вспомогательные операции ----------

    def _get_or_create_catalog(self, namespace: str, kind: str):
        name = _collection_name("memcat", namespace, kind)
        try:
            coll = self._client.get_or_create_collection(name=name, metadata={"role": "catalog"})
            return coll
        except Exception as e:
            raise StoreError(f"get_or_create catalog failed: {e}") from e

    def _get_or_create_vector(self, namespace: str, kind: str, space: str):
        name = _collection_name("memvec", namespace, kind, space)
        try:
            # embedding_function=None — мы передаем векторы явно
            coll = self._client.get_or_create_collection(
                name=name,
                metadata={"role": "vector", "space": space, "distance": self._distance},
                embedding_function=None,
                # В некоторых версиях Chroma параметр 'metadata' обязателен для get_or_create
            )
            return coll
        except Exception as e:
            raise StoreError(f"get_or_create vector collection failed: {e}") from e

    def _iter_vector_collections(self, namespace: str, kind: str):
        """
        Итератор по всем векторным коллекциям пары (namespace, kind).
        """
        prefix = _collection_name("memvec", namespace, kind)
        try:
            all_cols = self._client.list_collections()  # [{'name':..., 'metadata':...}, ...]
        except Exception as e:
            raise StoreError(f"list_collections failed: {e}") from e

        for c in all_cols:
            try:
                name = c["name"] if isinstance(c, dict) else c.name  # поддержка разных API
            except Exception:
                continue
            if str(name).startswith(prefix):
                yield self._client.get_collection(name=name)

    def _upsert_catalog(self, coll, *, ids: List[str], documents: List[str], metadatas: List[Dict[str, Any]]) -> None:
        _require(len(ids) == len(documents) == len(metadatas), "catalog upsert arrays length mismatch")
        try:
            # Chroma >=0.5 поддерживает upsert; при отсутствии — fallback на add/update
            if hasattr(coll, "upsert"):
                coll.upsert(ids=ids, documents=documents, metadatas=metadatas)
            else:  # pragma: no cover
                try:
                    coll.add(ids=ids, documents=documents, metadatas=metadatas)
                except Exception:
                    # Попробуем update (идемпотентность)
                    coll.update(ids=ids, documents=documents, metadatas=metadatas)
        except Exception as e:
            raise StoreError(f"catalog upsert failed: {e}") from e

    def _upsert_vector(self, coll, *, ids: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, Any]], documents: List[str]) -> None:
        _require(len(ids) == len(embeddings) == len(metadatas) == len(documents), "vector upsert arrays length mismatch")
        try:
            if hasattr(coll, "upsert"):
                coll.upsert(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)
            else:  # pragma: no cover
                try:
                    coll.add(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)
                except Exception:
                    coll.update(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)
        except Exception as e:
            raise StoreError(f"vector upsert failed: {e}") from e


# =========================
# Внутренние утилиты
# =========================

def _compose_metadata(memory: Memory, ch: Chunk) -> Dict[str, Any]:
    """
    Собирает единообразные метаданные для каталога/вектора.
    """
    return {
        "memory_id": memory.id,
        "chunk_id": ch.id,
        "namespace": memory.namespace,
        "owner_id": memory.owner_id,
        "kind": memory.kind,
        "index": ch.index,
        "labels": list(memory.labels or []),
        "attributes": dict(memory.attributes or {}),
        "tags": dict(ch.tags or {}),
    }


def _distance_to_similarity(dist: float, metric: str) -> float:
    """
    Грубое преобразование расстояния к скорам «чем больше — тем лучше» [0..1].
    Для cosine: 1 - d (при d∈[0,2] у Chroma реализуется как [0,2]? — в практических релизах 0..2/0..1).
    Для ip: уже «похожесть», нормируем в [0,1] эвристикой.
    Для l2: эвристически 1/(1+d).
    """
    try:
        m = metric.lower()
    except Exception:
        m = "cosine"
    if m == "cosine":
        # гарантия в диапазон [0,1]
        v = 1.0 - float(dist)
        return max(0.0, min(1.0, v))
    if m == "ip":
        # без знания предела нормируем через 1/(1+e^{-x}) к [0,1]
        import math
        return 1.0 / (1.0 + math.exp(-float(dist)))
    # l2
    return 1.0 / (1.0 + float(dist))


def _to_where(f: QueryFilters) -> Dict[str, Any]:
    """
    Преобразует фильтры в формат where для Chroma (равенства/массивы).
    """
    where: Dict[str, Any] = {}
    if f.namespace:
        where["namespace"] = f.namespace
    if f.owner_id:
        where["owner_id"] = f.owner_id
    if f.attributes:
        for k, v in f.attributes.items():
            where[f"attributes.{k}"] = v
    if f.labels_all:
        # Простейшая семантика: все требуемые ярлыки должны входить в labels (Chroma поддерживает $and/$contains в новых релизах;
        # здесь — пересечение через последовательное наложение).
        for lab in f.labels_all:
            where[f"labels"] = lab  # при необходимости замените на $containsAny/$containsAll
    if f.labels_not:
        # Исключающие ярлыки (требует клиентской фильтрации поверх результатов, если Chroma не поддерживает $ne/$nin для массивов).
        # Мы оставляем здесь только позитивные фильтры; негатив применится в гибридном скоринге (см. вызов _to_where в query).
        pass
    return where


def _make_snippet(text: str, query: str, width: int = 160) -> str:
    if not query:
        return text[:width]
    tokens = _tokenize(query)
    if not tokens or not text:
        return text[:width]
    low = text.lower()
    pos = min((low.find(t) for t in tokens if t in low), default=-1)
    if pos < 0:
        return text[:width]
    start = max(0, pos - width // 3)
    end = min(len(text), start + width)
    return text[start:end]


# =========================
# Пример использования
# =========================
# from chromadb import PersistentClient
#
# client = PersistentClient(path="/var/lib/omnimind/chroma")
# store = ChromaStore(client, embedder=my_embedder, distance="cosine")
#
# mem = Memory(
#     id="123e4567-e89b-12d3-a456-426614174000",
#     namespace="prod",
#     owner_id="user-42",
#     kind="conversation",
#     attributes={"lang": "en"},
#     labels=["pii:redacted"],
#     chunks=[
#         Chunk(id="c1", index=0, text="Hello world", embeddings=[Embedding(space="text-emb-3-large", vector=[...])]),
#         Chunk(id="c2", index=1, text="How are you?", embeddings=[]),
#     ],
# )
# store.upsert(mem)
#
# resp = store.query(
#     QueryRequest(
#         text_query="hello",
#         embedding_space="text-emb-3-large",
#         embedding_vector=[...],  # или None при наличии embedder и text_query
#         top_k=10,
#         filters=QueryFilters(namespace="prod", kinds=["conversation"]),
#     )
# )
# for h in resp.hits:
#     print(h.memory_id, h.chunk_id, h.score, h.snippet.text)
