from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import math
import os
import sqlite3
import statistics
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

import numpy as np

try:
    # Опционально: асинхронная работа с PostgreSQL через SQLAlchemy Core
    # в проекте уже используется async SQLAlchemy — это согласовано с остальным кодом
    from sqlalchemy import text as sqla_text
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
    _HAVE_SQLALCHEMY = True
except Exception:  # pragma: no cover
    _HAVE_SQLALCHEMY = False

log = logging.getLogger(__name__)

# =========================
# Параметры и типы
# =========================

Vector = np.ndarray  # shape: (dim,)

class EmbeddingModelProtocol(Protocol):
    """
    Протокол провайдера эмбеддингов.
    Реализуйте этот интерфейс для интеграции с любым модельным бэкендом.
    """
    dim: int

    async def embed_texts(self, texts: Sequence[str]) -> List[Vector]:
        """
        Возвращает список векторов для списка текстов.
        Размерность всех векторов обязана совпадать с self.dim.
        """
        ...


@dataclass(slots=True)
class Document:
    doc_id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    namespace: str = "default"
    chunk_id: Optional[str] = None
    created_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    updated_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))


@dataclass(slots=True)
class QueryFilter:
    namespace: Optional[str] = None
    # match по эквивалентности meta[key] == value
    equals: Dict[str, Any] = field(default_factory=dict)
    # meta[key] in values
    isin: Dict[str, Sequence[Any]] = field(default_factory=dict)
    # диапазоны для числовых/временных меток: meta[key] >= gte и/или <= lte
    ranges: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class QueryParams:
    query: str
    top_k: int = 8
    threshold: Optional[float] = None  # косинусная близость (0..1); None = без отсечки
    filter: QueryFilter = field(default_factory=QueryFilter)
    mmr_lambda: float = 0.5  # 0..1, выше = больше акцент на релевантность
    mmr_candidates: int = 32  # сколько кандидатов учитывать до MMR
    normalize_vectors: bool = True  # L2-нормализация эмбеддингов при поиске
    namespace: str = "default"


@dataclass(slots=True)
class ScoredDocument:
    doc: Document
    score: float  # косинусная близость (0..1)
    vector: Optional[Vector] = None


# =========================
# Утилиты
# =========================

def _ensure_unit(vecs: List[Vector]) -> List[Vector]:
    """L2-нормализация векторов (на месте не модифицируем)."""
    out: List[Vector] = []
    for v in vecs:
        denom = np.linalg.norm(v)
        out.append(v / denom if denom > 0 else v)
    return out

def _cosine(a: Vector, b: Vector) -> float:
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)

def _hash_key(text: str, dim: int) -> str:
    return hashlib.sha256(f"{dim}:{text}".encode("utf-8")).hexdigest()

def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

# =========================
# Кэш эмбеддингов (SQLite)
# =========================

class EmbeddingCache:
    """
    Простой кэш эмбеддингов на SQLite. Поддерживает многопроцессный доступ (WAL).
    Ключ = SHA256(dim:text). Значение = BLOB (float32 * dim).
    """
    def __init__(self, path: Optional[str], dim: int):
        self.path = path
        self.dim = dim
        self.conn: Optional[sqlite3.Connection] = None
        if path:
            self.conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v BLOB NOT NULL, ts INTEGER NOT NULL)"
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON cache(ts)")

    def get(self, text: str) -> Optional[Vector]:
        if not self.conn:
            return None
        k = _hash_key(text, self.dim)
        cur = self.conn.execute("SELECT v FROM cache WHERE k = ?", (k,))
        row = cur.fetchone()
        if not row:
            return None
        arr = np.frombuffer(row[0], dtype=np.float32)
        if arr.size != self.dim:
            return None
        return arr

    def set(self, text: str, vec: Vector) -> None:
        if not self.conn:
            return
        if vec.dtype != np.float32:
            vec = vec.astype(np.float32, copy=False)
        k = _hash_key(text, self.dim)
        self.conn.execute(
            "INSERT OR REPLACE INTO cache(k, v, ts) VALUES (?, ?, ?)",
            (k, vec.tobytes(order="C"), int(_utcnow().timestamp())),
        )

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None


# =========================
# Абстракция векторного хранилища
# =========================

class VectorStore(ABC):
    @abstractmethod
    async def upsert(self, docs: Sequence[Document], vectors: Sequence[Vector]) -> None: ...

    @abstractmethod
    async def delete(self, doc_ids: Sequence[str], namespace: Optional[str] = None) -> None: ...

    @abstractmethod
    async def query(
        self,
        query_vec: Vector,
        filter: QueryFilter,
        top_k: int,
        candidates: int,
        normalize_vectors: bool,
    ) -> List[Tuple[Document, float, Optional[Vector]]]:
        """
        Возвращает список (doc, score, vec), где score — косинусная близость.
        Реализация может возвращать вектора документов (для MMR), или None, если дорого.
        """
        ...

    @abstractmethod
    async def flush(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...


# =========================
# InMemory реализация (для dev/тестов и как референс)
# =========================

class InMemoryVectorStore(VectorStore):
    def __init__(self, dim: int):
        self.dim = dim
        self._docs: Dict[str, Document] = {}
        self._vecs: Dict[str, Vector] = {}

    async def upsert(self, docs: Sequence[Document], vectors: Sequence[Vector]) -> None:
        assert len(docs) == len(vectors)
        for d, v in zip(docs, vectors):
            if v.shape[0] != self.dim:
                raise ValueError(f"vector dim mismatch: got {v.shape[0]}, expected {self.dim}")
            self._docs[d.doc_id] = dataclasses.replace(d, updated_at=_utcnow())
            self._vecs[d.doc_id] = v.astype(np.float32, copy=False)

    async def delete(self, doc_ids: Sequence[str], namespace: Optional[str] = None) -> None:
        ids = list(doc_ids)
        for i in ids:
            if i in self._docs and (namespace is None or self._docs[i].namespace == namespace):
                self._docs.pop(i, None)
                self._vecs.pop(i, None)

    async def query(
        self,
        query_vec: Vector,
        filter: QueryFilter,
        top_k: int,
        candidates: int,
        normalize_vectors: bool,
    ) -> List[Tuple[Document, float, Optional[Vector]]]:
        # Применяем фильтры
        def _pass(doc: Document) -> bool:
            if filter.namespace and doc.namespace != filter.namespace:
                return False
            for k, v in filter.equals.items():
                if doc.metadata.get(k) != v:
                    return False
            for k, vals in filter.isin.items():
                if doc.metadata.get(k) not in set(vals):
                    return False
            for k, rr in filter.ranges.items():
                val = doc.metadata.get(k)
                gte = rr.get("gte")
                lte = rr.get("lte")
                if gte is not None and (val is None or val < gte):
                    return False
                if lte is not None and (val is None or val > lte):
                    return False
            return True

        items: List[Tuple[Document, float, Optional[Vector]]] = []
        qv = query_vec
        if normalize_vectors:
            qv = _ensure_unit([qv])[0]
        for doc_id, doc in self._docs.items():
            if not _pass(doc):
                continue
            vec = self._vecs.get(doc_id)
            if vec is None:
                continue
            vv = vec
            if normalize_vectors:
                vv = _ensure_unit([vv])[0]
            score = float(np.dot(qv, vv))
            items.append((doc, score, vec))
        items.sort(key=lambda t: t[1], reverse=True)
        return items[: max(top_k, candidates)]

    async def flush(self) -> None:  # in-memory
        return

    async def close(self) -> None:
        self._docs.clear()
        self._vecs.clear()


# =========================
# PostgreSQL/pgvector реализация (optional)
# =========================

class PgVectorStore(VectorStore):
    """
    Требования:
      - PostgreSQL с расширением pgvector (CREATE EXTENSION IF NOT EXISTS vector;)
      - Таблица (если отсутствует — будет создана автоматически):
        CREATE TABLE IF NOT EXISTS memory_items(
            doc_id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            text TEXT NOT NULL,
            metadata JSONB NOT NULL,
            source TEXT NULL,
            chunk_id TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            embedding vector(<dim>) NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_memory_ns ON memory_items(namespace);
        CREATE INDEX IF NOT EXISTS idx_memory_meta_gin ON memory_items USING GIN (metadata);
        -- при необходимости: CREATE INDEX ... ON memory_items USING ivfflat (embedding vector_cosine_ops);

    Параметр use_ivfflat включает ivfflat-индекс при наличии.
    """
    def __init__(self, engine: AsyncEngine, dim: int, table: str = "memory_items", use_ivfflat: bool = False):
        if not _HAVE_SQLALCHEMY:
            raise RuntimeError("SQLAlchemy is required for PgVectorStore")
        self.engine = engine
        self.dim = dim
        self.table = table
        self.use_ivfflat = use_ivfflat

    async def _ensure_schema(self) -> None:
        sql = f"""
        CREATE EXTENSION IF NOT EXISTS vector;
        CREATE TABLE IF NOT EXISTS {self.table}(
            doc_id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            text TEXT NOT NULL,
            metadata JSONB NOT NULL,
            source TEXT NULL,
            chunk_id TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            embedding vector({self.dim}) NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{self.table}_ns ON {self.table}(namespace);
        CREATE INDEX IF NOT EXISTS idx_{self.table}_meta_gin ON {self.table} USING GIN (metadata);
        """
        async with self.engine.begin() as conn:
            await conn.execute(sqla_text(sql))
            if self.use_ivfflat:
                # ivfflat требует анализа данных/кластера; создаём, если нет
                idx_sql = f"CREATE INDEX IF NOT EXISTS idx_{self.table}_ivf ON {self.table} USING ivfflat (embedding vector_cosine_ops);"
                await conn.execute(sqla_text(idx_sql))

    async def upsert(self, docs: Sequence[Document], vectors: Sequence[Vector]) -> None:
        await self._ensure_schema()
        assert len(docs) == len(vectors)
        rows = []
        for d, v in zip(docs, vectors):
            if v.shape[0] != self.dim:
                raise ValueError(f"vector dim mismatch: got {v.shape[0]}, expected {self.dim}")
            if v.dtype != np.float32:
                v = v.astype(np.float32, copy=False)
            rows.append({
                "doc_id": d.doc_id,
                "namespace": d.namespace,
                "text": d.text,
                "metadata": json.dumps(d.metadata, ensure_ascii=False),
                "source": d.source,
                "chunk_id": d.chunk_id,
                "created_at": d.created_at,
                "updated_at": _utcnow(),
                "embedding": list(map(float, v.tolist()))
            })
        sql = f"""
        INSERT INTO {self.table}
        (doc_id, namespace, text, metadata, source, chunk_id, created_at, updated_at, embedding)
        VALUES (:doc_id, :namespace, :text, CAST(:metadata AS JSONB), :source, :chunk_id, :created_at, :updated_at, :embedding)
        ON CONFLICT (doc_id) DO UPDATE SET
          namespace=EXCLUDED.namespace,
          text=EXCLUDED.text,
          metadata=EXCLUDED.metadata,
          source=EXCLUDED.source,
          chunk_id=EXCLUDED.chunk_id,
          updated_at=EXCLUDED.updated_at,
          embedding=EXCLUDED.embedding;
        """
        async with self.engine.begin() as conn:
            await conn.execute(sqla_text(sql), rows)

    async def delete(self, doc_ids: Sequence[str], namespace: Optional[str] = None) -> None:
        await self._ensure_schema()
        if not doc_ids:
            return
        if namespace:
            sql = f"DELETE FROM {self.table} WHERE doc_id = ANY(:ids) AND namespace = :ns;"
            params = {"ids": list(doc_ids), "ns": namespace}
        else:
            sql = f"DELETE FROM {self.table} WHERE doc_id = ANY(:ids);"
            params = {"ids": list(doc_ids)}
        async with self.engine.begin() as conn:
            await conn.execute(sqla_text(sql), params)

    async def query(
        self,
        query_vec: Vector,
        filter: QueryFilter,
        top_k: int,
        candidates: int,
        normalize_vectors: bool,
    ) -> List[Tuple[Document, float, Optional[Vector]]]:
        await self._ensure_schema()
        # Косинусная близость = 1 - cosine_distance (в pgvector)
        where = ["1=1"]
        params: Dict[str, Any] = {"q": list(map(float, query_vec.astype(np.float32)))}
        if filter.namespace:
            where.append("namespace = :ns")
            params["ns"] = filter.namespace
        for k, v in filter.equals.items():
            where.append(f"(metadata ->> :m_eq_k_{k}) = :m_eq_v_{k}")
            params[f"m_eq_k_{k}"] = k
            params[f"m_eq_v_{k}"] = str(v)
        for k, vals in filter.isin.items():
            where.append(f"(metadata ->> :m_in_k_{k}) = ANY(:m_in_v_{k})")
            params[f"m_in_k_{k}"] = k
            params[f"m_in_v_{k}"] = [str(x) for x in vals]
        for k, rr in filter.ranges.items():
            if "gte" in rr:
                where.append(f"( (metadata ->> :m_gte_k_{k})::numeric >= :m_gte_v_{k} )")
                params[f"m_gte_k_{k}"] = k
                params[f"m_gte_v_{k}"] = rr["gte"]
            if "lte" in rr:
                where.append(f"( (metadata ->> :m_lte_k_{k})::numeric <= :m_lte_v_{k} )")
                params[f"m_lte_k_{k}"] = k
                params[f"m_lte_v_{k}"] = rr["lte"]

        # Сначала выбираем кандидатов по расстоянию
        sql = f"""
        SELECT doc_id, namespace, text, metadata, source, chunk_id, created_at, updated_at,
               1 - (embedding <=> :q) AS score
        FROM {self.table}
        WHERE {' AND '.join(where)}
        ORDER BY embedding <=> :q
        LIMIT :lim;
        """
        params["lim"] = max(top_k, candidates)

        async with self.engine.connect() as conn:  # type: AsyncConnection
            res = await conn.execute(sqla_text(sql), params)
            rows = res.fetchall()

        out: List[Tuple[Document, float, Optional[Vector]]] = []
        for r in rows:
            meta = r.metadata if isinstance(r.metadata, dict) else json.loads(r.metadata or "{}")
            out.append((
                Document(
                    doc_id=r.doc_id,
                    text=r.text,
                    metadata=meta,
                    source=r.source,
                    namespace=r.namespace,
                    chunk_id=r.chunk_id,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                ),
                float(r.score),
                None,  # вектор не возвращаем (дорого доставать)
            ))
        return out

    async def flush(self) -> None:
        # Ничего, транзакции управляются на уровне begin()
        return

    async def close(self) -> None:
        if self.engine:
            await self.engine.dispose()


# =========================
# Чанкер текста
# =========================

def simple_semantic_chunk(
    text: str,
    max_tokens: int = 350,
    overlap_tokens: int = 40,
    tokenizer: Optional[Callable[[str], int]] = None,
) -> List[str]:
    """
    Простой чанкер: делит по абзацам/предложениям и склеивает до max_tokens с overlap.
    tokenizer: функция, возвращающая количество «токенов» (грубая оценка: len/4 если не задано).
    """
    if not text.strip():
        return []
    paras = [p.strip() for p in text.replace("\r\n", "\n").split("\n") if p.strip()]
    if not tokenizer:
        tokenizer = lambda s: max(1, len(s) // 4)

    chunks: List[str] = []
    buf: List[str] = []
    buf_tokens = 0

    def flush():
        nonlocal buf, buf_tokens
        if buf:
            chunks.append(" ".join(buf).strip())
            buf = []
            buf_tokens = 0

    for p in paras:
        pt = tokenizer(p)
        if buf_tokens + pt <= max_tokens:
            buf.append(p)
            buf_tokens += pt
        else:
            flush()
            # overlap: берём часть предыдущего чанка как контекст
            if chunks and overlap_tokens > 0:
                last = chunks[-1]
                # грубо отрежем хвост по символам
                overlap = max(1, overlap_tokens * 4)
                p = last[-overlap:] + " " + p
            # если абзац слишком длинный — режем по предложениями
            if tokenizer(p) > max_tokens:
                sentences = [s.strip() for s in p.replace("!", ".").replace("?", ".").split(".") if s.strip()]
                cur = ""
                cur_t = 0
                for s in sentences:
                    st = tokenizer(s)
                    if cur_t + st <= max_tokens:
                        cur += (s + ". ")
                        cur_t += st
                    else:
                        chunks.append(cur.strip())
                        cur = s + ". "
                        cur_t = st
                if cur.strip():
                    chunks.append(cur.strip())
            else:
                buf = [p]
                buf_tokens = tokenizer(p)
    flush()
    # Фильтруем пустые
    return [c for c in chunks if c]


# =========================
# MMR (Maximal Marginal Relevance)
# =========================

def mmr(
    query_vec: Vector,
    candidates: List[Tuple[Document, float, Optional[Vector]]],
    lambda_mult: float = 0.5,
    k: int = 8,
    normalize_vectors: bool = True,
    embed_loader: Optional[Callable[[Document], Optional[Vector]]] = None,
) -> List[Tuple[Document, float]]:
    """
    Реализация MMR: выбирает k документов, балансируя релевантность и разнообразие.
    candidates: (doc, score, vec) — если vec=None, embed_loader(doc) должен вернуть вектор (иначе MMR деградирует).
    Возвращает (doc, mmr_score).
    """
    if not candidates:
        return []
    k = min(k, len(candidates))
    if normalize_vectors:
        qv = _ensure_unit([query_vec])[0]
    else:
        qv = query_vec

    # Подготовим вектора кандидатов
    docs: List[Document] = []
    scores: List[float] = []
    vecs: List[Optional[Vector]] = []
    for d, s, v in candidates:
        docs.append(d)
        scores.append(s)
        if v is None and embed_loader:
            v = embed_loader(d)
        if v is not None and normalize_vectors:
            v = _ensure_unit([v])[0]
        vecs.append(v)

    selected: List[int] = []
    remaining: List[int] = list(range(len(docs)))

    # Инициализация: берем лучший по score
    first = int(np.argmax(np.array(scores)))
    selected.append(first)
    remaining.remove(first)
    result: List[Tuple[Document, float]] = [(docs[first], scores[first])]

    while remaining and len(selected) < k:
        mmr_values: List[Tuple[float, int]] = []
        for idx in remaining:
            rel = scores[idx]
            # вычислим максимальную близость к уже выбранным
            if vecs[idx] is None:
                div = 0.0
            else:
                sim_to_sel = 0.0
                for j in selected:
                    if vecs[j] is None:
                        continue
                    sim_to_sel = max(sim_to_sel, float(np.dot(vecs[idx], vecs[j])))
                div = sim_to_sel
            score = lambda_mult * rel - (1 - lambda_mult) * div
            mmr_values.append((score, idx))
        mmr_values.sort(key=lambda t: t[0], reverse=True)
        best = mmr_values[0][1]
        selected.append(best)
        remaining.remove(best)
        result.append((docs[best], scores[best]))
    return result


# =========================
# Retriever
# =========================

class Retriever:
    """
    Универсальный ретривер памяти:
      - чанкинг текста
      - кэширование эмбеддингов (SQLite)
      - upsert/delete
      - семантический поиск + фильтры по метаданным
      - MMR-переранжирование
    """
    def __init__(
        self,
        embed_model: EmbeddingModelProtocol,
        store: VectorStore,
        *,
        persist_cache_path: Optional[str] = None,
    ):
        self.embed_model = embed_model
        self.store = store
        self.cache = EmbeddingCache(persist_cache_path, dim=embed_model.dim)

    # ---------- Embeddings ----------

    async def _embed(self, texts: Sequence[str]) -> List[Vector]:
        # читаем кэш
        miss_idx: List[int] = []
        vecs: List[Optional[Vector]] = [None] * len(texts)
        for i, t in enumerate(texts):
            v = self.cache.get(t)
            if v is None:
                miss_idx.append(i)
            else:
                vecs[i] = v
        # доэмбеддим промахи
        if miss_idx:
            miss_texts = [texts[i] for i in miss_idx]
            miss_vecs = await self.embed_model.embed_texts(miss_texts)
            if any(v.shape[0] != self.embed_model.dim for v in miss_vecs):
                raise ValueError("Embedding dimension mismatch from provider")
            for i, v in zip(miss_idx, miss_vecs):
                vecs[i] = v.astype(np.float32, copy=False)
                self.cache.set(texts[i], vecs[i])  # persist
        # финальная сборка
        return [v if isinstance(v, np.ndarray) else np.zeros((self.embed_model.dim,), dtype=np.float32) for v in vecs]

    # ---------- Public API ----------

    async def upsert_text(
        self,
        *,
        text: str,
        doc_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
        namespace: str = "default",
        chunk: bool = True,
        chunk_max_tokens: int = 350,
        chunk_overlap_tokens: int = 40,
        tokenizer: Optional[Callable[[str], int]] = None,
    ) -> List[str]:
        """
        Разбивает текст на чанки (если chunk=True), эмбеддит и апсертит.
        Возвращает список doc_id для вставленных чанков.
        """
        chunks = [text] if not chunk else simple_semantic_chunk(
            text, max_tokens=chunk_max_tokens, overlap_tokens=chunk_overlap_tokens, tokenizer=tokenizer
        )
        if not chunks:
            return []

        # Готовим документы
        batch_docs: List[Document] = []
        doc_ids: List[str] = []
        base_id = doc_id or uuid.uuid4().hex
        for idx, ch in enumerate(chunks):
            cid = f"{base_id}:{idx+1:04d}" if chunk else (doc_id or uuid.uuid4().hex)
            d = Document(
                doc_id=cid,
                text=ch,
                metadata=metadata or {},
                source=source,
                namespace=namespace,
                chunk_id=str(idx + 1) if chunk else None,
            )
            batch_docs.append(d)
            doc_ids.append(cid)

        # Эмбеддинги
        vecs = await self._embed([d.text for d in batch_docs])

        # Запись
        await self.store.upsert(batch_docs, vecs)
        return doc_ids

    async def upsert_documents(self, docs: Sequence[Document]) -> None:
        """Апсерт готовых документов (без чанкинга)."""
        if not docs:
            return
        vecs = await self._embed([d.text for d in docs])
        await self.store.upsert(docs, vecs)

    async def delete(self, doc_ids: Sequence[str], namespace: Optional[str] = None) -> None:
        await self.store.delete(doc_ids, namespace=namespace)

    async def query(self, params: QueryParams) -> List[ScoredDocument]:
        # Эмбедд запроса
        qv = (await self._embed([params.query]))[0]
        # Семантические кандидаты
        candidates = await self.store.query(
            query_vec=qv,
            filter=params.filter or QueryFilter(namespace=params.namespace),
            top_k=params.top_k,
            candidates=params.mmr_candidates,
            normalize_vectors=params.normalize_vectors,
        )
        if not candidates:
            return []

        # MMR rerank
        reranked = mmr(
            query_vec=qv,
            candidates=candidates,
            lambda_mult=params.mmr_lambda,
            k=params.top_k,
            normalize_vectors=params.normalize_vectors,
            embed_loader=None,  # для InMemory вектора уже есть; PgVector возвращает None (в этом случае MMR ≈ исходному рангу)
        )
        # Порог
        out: List[ScoredDocument] = []
        for d, s in reranked:
            if params.threshold is not None and s < params.threshold:
                continue
            out.append(ScoredDocument(doc=d, score=s, vector=None))
        return out

    async def close(self) -> None:
        await self.store.close()
        self.cache.close()


# =========================
# Фабрики
# =========================

class _DummyEmbed(EmbeddingModelProtocol):
    """Заглушка для тестов: детерминированный embedding по SHA256."""
    def __init__(self, dim: int = 384):
        self.dim = dim

    async def embed_texts(self, texts: Sequence[str]) -> List[Vector]:
        vecs: List[Vector] = []
        for t in texts:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            rng = np.random.default_rng(int.from_bytes(h[:8], "big", signed=False))
            v = rng.normal(0, 1, size=(self.dim,)).astype(np.float32)
            vecs.append(v)
        return vecs


async def build_inmemory_retriever(dim: int = 384, cache_path: Optional[str] = None) -> Retriever:
    embed = _DummyEmbed(dim=dim)
    store = InMemoryVectorStore(dim=dim)
    return Retriever(embed_model=embed, store=store, persist_cache_path=cache_path)


async def build_pgvector_retriever(
    pg_dsn: str,
    *,
    dim: int = 384,
    table: str = "memory_items",
    use_ivfflat: bool = False,
    cache_path: Optional[str] = None,
    embed_model_factory: Optional[Callable[[int], EmbeddingModelProtocol]] = None,
) -> Retriever:
    if not _HAVE_SQLALCHEMY:
        raise RuntimeError("SQLAlchemy is required for PgVector retriever")
    engine = create_async_engine(pg_dsn, pool_pre_ping=True, pool_size=10, max_overflow=20)
    store = PgVectorStore(engine=engine, dim=dim, table=table, use_ivfflat=use_ivfflat)
    embed = embed_model_factory(dim) if embed_model_factory else _DummyEmbed(dim=dim)
    return Retriever(embed_model=embed, store=store, persist_cache_path=cache_path)


# =========================
# Пример использования (локальный тест)
# =========================

if __name__ == "__main__":  # pragma: no cover
    async def _demo():
        logging.basicConfig(level=logging.INFO)
        r = await build_inmemory_retriever(dim=128)
        await r.upsert_text(text="Пример первый документ про базы данных PostgreSQL.", namespace="docs", source="demo")
        await r.upsert_text(text="Второй пример: векторные базы, pgvector и семантический поиск.", namespace="docs", source="demo")
        await r.upsert_text(text="Третий документ: очереди сообщений Kafka и обработка событий.", namespace="docs", source="demo")

        q = QueryParams(query="Как работать с pgvector и семантическим поиском?", top_k=2, namespace="docs")
        res = await r.query(q)
        for i, sd in enumerate(res, 1):
            print(i, round(sd.score, 4), sd.doc.text[:80])
        await r.close()

    asyncio.run(_demo())
