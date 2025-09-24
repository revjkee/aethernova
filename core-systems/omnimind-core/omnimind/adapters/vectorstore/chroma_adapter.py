# omnimind-core/omnimind/adapters/vectorstore/chroma_adapter.py
# Industrial-grade ChromaDB adapter for Omnimind.
# Copyright (c) 2025.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Iterable, Optional, Protocol, Sequence, Tuple

from pydantic import BaseModel, Field, ConfigDict, field_validator, ValidationError

logger = logging.getLogger("omnimind.vectorstore.chroma")

# ===========
# Embedder API
# ===========

class Embedder(Protocol):
    """
    Унифицированный протокол эмбеддера.
    Может быть синхронным или асинхронным. Принимает список текстов, возвращает список векторов.
    """
    def __call__(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...
    async def aembed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...  # optional async


# ==============
# Error classes
# ==============

class VectorStoreError(Exception):
    pass


class CollectionNotFound(VectorStoreError):
    pass


class CollectionAlreadyExists(VectorStoreError):
    pass


class InvalidEmbeddingDimensions(VectorStoreError):
    pass


# =============
# DTO & Configs
# =============

class ChromaConnection(BaseModel):
    """
    Конфигурация подключения к ChromaDB.
    """
    model_config = ConfigDict(extra="forbid")

    mode: str = Field("memory", description="memory | persistent | http")
    # persistent
    path: Optional[str] = Field(default=None, description="Путь для PersistentClient")
    # http
    host: Optional[str] = Field(default=None)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssl: bool = Field(default=False, description="HTTPS при http-клиенте (если поддерживается)")
    # общие поля
    tenant: Optional[str] = Field(default=None, description="Опциональный неймспейс/тенант (если поддерживается Chroma)")
    database: Optional[str] = Field(default=None, description="Опциональная БД/пространство (если поддерживается)")

    @field_validator("mode")
    @classmethod
    def _mode_ok(cls, v: str) -> str:
        v = v.lower()
        if v not in {"memory", "persistent", "http"}:
            raise ValueError("mode must be one of: memory, persistent, http")
        return v


class ChromaAdapterSettings(BaseModel):
    """
    Параметры адаптера.
    """
    model_config = ConfigDict(extra="forbid")

    default_collection: str = Field(default="default")
    batch_size: int = Field(default=256, ge=1, le=2048)
    max_retries: int = Field(default=3, ge=0, le=10)
    initial_backoff_s: float = Field(default=0.2, ge=0.0, le=10.0)
    # Включить проверку единообразия размерности эмбеддингов на стороне клиента
    validate_dims: bool = Field(default=True)


class VectorItem(BaseModel):
    """
    Элемент для записи в векторное хранилище.
    """
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    document: Optional[str] = Field(default=None, description="Оригинальный текст")
    embedding: Optional[Sequence[float]] = Field(default=None, description="Вектор эмбеддинга")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("embedding")
    @classmethod
    def _finite(cls, v: Optional[Sequence[float]]) -> Optional[Sequence[float]]:
        if v is None:
            return v
        for x in v:
            if not isinstance(x, (int, float)) or math.isnan(x) or math.isinf(x):
                raise ValueError("Embedding must contain only finite numbers")
        return v


class QueryResult(BaseModel):
    """
    Результат поиска — параллельные списки.
    """
    ids: list[list[str]]
    distances: list[list[float]]  # чем меньше — тем ближе (для cosine/l2)
    documents: list[list[Optional[str]]]
    metadatas: list[list[dict[str, Any]]]
    embeddings: Optional[list[list[Sequence[float]]]] = None  # если Chroma вернёт (обычно выключено)


# ==============
# Helper utils
# ==============

def _chunked(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


async def _run_blocking(func, /, *args, **kwargs):
    """
    Запуск блокирующей функции ChromA в отдельном потоке. Сохраняет контекст.
    """
    return await asyncio.to_thread(func, *args, **kwargs)


async def _retry(op_name: str, fn, *args, retries: int, backoff: float, **kwargs):
    """
    Простая retry-обертка для потенциально сетевых операций.
    """
    attempt = 0
    while True:
        try:
            return await fn(*args, **kwargs)
        except Exception as e:
            attempt += 1
            if attempt > retries:
                logger.error("Operation %s failed after %s attempts: %s", op_name, attempt - 1, e)
                raise
            sleep_s = backoff * (2 ** (attempt - 1))
            logger.warning("Operation %s failed (attempt %s/%s): %s. Retrying in %.2fs", op_name, attempt, retries, e, sleep_s)
            await asyncio.sleep(sleep_s)


# =====================
# Chroma adapter class
# =====================

class ChromaAdapter:
    """
    Асинхронный адаптер поверх chromadb.* клиентов (in-memory/persistent/http).
    Внешние вызовы — через asyncio; блокирующие операции Chroma — через to_thread.
    """

    def __init__(
        self,
        conn: ChromaConnection | None = None,
        settings: ChromaAdapterSettings | None = None,
        embedder: Embedder | None = None,
    ) -> None:
        self.conn = conn or ChromaConnection()
        self.settings = settings or ChromaAdapterSettings()
        self.embedder = embedder

        # Клиент chroma создаем лениво, чтобы избежать лишних импортов/исключений
        self._client = None
        self._client_mode = None  # memory|persistent|http

    # -------------
    # Bootstrapping
    # -------------

    def _ensure_client_sync(self):
        """
        Создает клиент Chroma синхронно. Вызывается из рабочего потока.
        """
        if self._client is not None:
            return self._client

        try:
            # Импорты внутри метода, чтобы не ломать процесс, если chromadb не установлен в окружении,
            # пока адаптер не используется.
            import chromadb  # type: ignore
            from chromadb import Client, PersistentClient  # type: ignore
            # HttpClient может отсутствовать в старых версиях. Обработаем это мягко.
            try:
                from chromadb import HttpClient  # type: ignore
            except Exception:  # pragma: no cover
                HttpClient = None  # type: ignore
        except Exception as e:  # pragma: no cover
            raise VectorStoreError(f"chromadb import failed: {e}")

        mode = self.conn.mode
        if mode == "memory":
            self._client = Client()
        elif mode == "persistent":
            if not self.conn.path:
                # Безопасный дефолт — подпапка проекта
                default_path = os.path.abspath("./.chroma")
                self._client = PersistentClient(path=default_path)
            else:
                self._client = PersistentClient(path=self.conn.path)
        elif mode == "http":
            if 'HttpClient' not in locals() or HttpClient is None:
                raise VectorStoreError("HttpClient is not available in this chromadb version")
            host = self.conn.host or "127.0.0.1"
            port = int(self.conn.port or 8000)
            # Некоторые версии поддерживают ssl, некоторые — нет. Пробуем наиболее совместимый вызов.
            try:
                if self.conn.ssl:
                    self._client = HttpClient(host=host, port=port, ssl=True)  # type: ignore[arg-type]
                else:
                    self._client = HttpClient(host=host, port=port)  # type: ignore[arg-type]
            except TypeError:
                # Если сигнатура без ssl — пробуем без него
                self._client = HttpClient(host=host, port=port)  # type: ignore[arg-type]
        else:  # pragma: no cover
            raise VectorStoreError(f"Unknown mode: {mode}")

        self._client_mode = mode
        logger.info("Chroma client initialized (mode=%s)", mode)
        return self._client

    async def _get_client(self):
        return await _run_blocking(self._ensure_client_sync)

    # ---------------
    # Collections API
    # ---------------

    async def list_collections(self) -> list[str]:
        client = await self._get_client()

        def _list():
            cols = client.list_collections()
            # Chroma возвращает объекты Collection — заберем имена
            try:
                return [c.name for c in cols]  # type: ignore[attr-defined]
            except Exception:
                # на случай если вернули строки
                return list(cols)

        return await _retry("list_collections", _run_blocking, _list, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    async def create_collection(self, name: str, *, metadata: Optional[dict[str, Any]] = None, get_or_create: bool = True) -> None:
        client = await self._get_client()

        def _create():
            try:
                # get_or_create=True безопасен для гонок
                client.create_collection(name=name, metadata=metadata or {}, get_or_create=get_or_create)
            except Exception as e:
                msg = str(e)
                if "already exists" in msg.lower():
                    raise CollectionAlreadyExists(msg)
                raise

        await _retry("create_collection", _run_blocking, _create, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    async def drop_collection(self, name: str) -> None:
        client = await self._get_client()

        def _drop():
            try:
                client.delete_collection(name=name)
            except Exception as e:
                # если коллекции нет — считаем идемпотентным успехом
                if "does not exist" in str(e).lower():
                    return
                raise

        await _retry("drop_collection", _run_blocking, _drop, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    async def _get_collection(self, name: Optional[str] = None):
        client = await self._get_client()
        coll_name = name or self.settings.default_collection

        def _get():
            try:
                return client.get_collection(name=coll_name)
            except Exception as e:
                if "does not exist" in str(e).lower():
                    raise CollectionNotFound(f"Collection not found: {coll_name}")
                raise

        return await _retry("get_collection", _run_blocking, _get, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    # -----------
    # Upsert API
    # -----------

    async def upsert(self, items: Sequence[VectorItem], *, collection: Optional[str] = None, strict_dim: bool | None = None) -> int:
        """
        Вставка/обновление элементов. Если embedding=None и задан embedder — он будет вычислен из document.
        Возвращает число вставленных/обновлённых записей.
        """
        if not items:
            return 0

        coll = await self._get_collection(collection)

        # 1) Получить эмбеддинги по необходимости
        docs_to_embed: list[Tuple[int, str]] = []
        for idx, it in enumerate(items):
            if it.embedding is None:
                if it.document is None:
                    raise InvalidEmbeddingDimensions("Item missing both embedding and document")
                docs_to_embed.append((idx, it.document))

        if docs_to_embed:
            if not self.embedder:
                raise VectorStoreError("Embedder is not configured but some items have no embedding")
            texts = [d for _, d in docs_to_embed]
            embeddings = await self._embed(texts)
            for (i, _), vec in zip(docs_to_embed, embeddings):
                items[i].embedding = list(map(float, vec))

        # 2) Проверка размерностей
        if strict_dim is None:
            strict_dim = self.settings.validate_dims
        if strict_dim:
            dims = {len(it.embedding or []) for it in items}
            if len(dims) > 1:
                raise InvalidEmbeddingDimensions(f"Inconsistent embedding dimensions: {sorted(dims)}")

        # 3) Пакетная запись с ретраями
        total = 0
        for batch in _chunked(list(items), self.settings.batch_size):
            ids = [it.id for it in batch]
            embs = [list(map(float, it.embedding or [])) for it in batch]
            docs = [it.document for it in batch]
            metas = [it.metadata for it in batch]

            def _upsert():
                # В новых версиях Chroma есть метод upsert; в старых — только add.
                # Пытаемся использовать upsert, при отсутствии — fallback на add.
                try:
                    return coll.upsert(ids=ids, embeddings=embs, documents=docs, metadatas=metas)  # type: ignore[attr-defined]
                except AttributeError:
                    # В случае add, возможен конфликт при существующем id — придётся удалить/добавить.
                    try:
                        return coll.add(ids=ids, embeddings=embs, documents=docs, metadatas=metas)  # type: ignore[call-arg]
                    except Exception as e:
                        msg = str(e).lower()
                        if "existing" in msg or "already" in msg:
                            # Простой путь: удаляем и добавляем
                            coll.delete(ids=ids)  # type: ignore
                            return coll.add(ids=ids, embeddings=embs, documents=docs, metadatas=metas)  # type: ignore
                        raise

            await _retry("upsert", _run_blocking, _upsert, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)
            total += len(batch)

        return total

    # -----------
    # Delete API
    # -----------

    async def delete(self, *, ids: Optional[Sequence[str]] = None, where: Optional[dict[str, Any]] = None, collection: Optional[str] = None) -> int:
        """
        Удаление по ids или where-фильтру (метаданные). Возвращает число удаленных записей (если Chroma его вернет; иначе оценка).
        """
        coll = await self._get_collection(collection)

        def _delete():
            # Chroma обычно возвращает None. Мы попытаемся оценить число удаленных через get() перед удалением при ids.
            deleted = 0
            if ids:
                try:
                    before = coll.get(ids=list(ids))
                    deleted = len(before["ids"][0]) if isinstance(before.get("ids"), list) else len(list(ids))
                except Exception:
                    deleted = len(list(ids))
                coll.delete(ids=list(ids))
            elif where:
                coll.delete(where=where)  # type: ignore
                deleted = 0
            else:
                raise VectorStoreError("Either ids or where must be provided")
            return deleted

        return await _retry("delete", _run_blocking, _delete, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    # ----------
    # Query API
    # ----------

    async def query(
        self,
        *,
        texts: Optional[Sequence[str]] = None,
        embeddings: Optional[Sequence[Sequence[float]]] = None,
        top_k: int = 5,
        where: Optional[dict[str, Any]] = None,
        where_document: Optional[dict[str, Any]] = None,
        collection: Optional[str] = None,
        include_embeddings: bool = False,
    ) -> QueryResult:
        """
        Поиск ближайших векторов. Если передан texts и сконфигурирован embedder — эмбедим.
        Если embeddings переданы напрямую — они используются как есть.
        """
        if (texts is None and embeddings is None) or (texts and embeddings):
            raise VectorStoreError("Provide either texts or embeddings")

        if texts is not None:
            if not self.embedder:
                raise VectorStoreError("Embedder is not configured but texts were provided")
            embeddings = await self._embed(list(texts))

        if embeddings is None:
            raise VectorStoreError("No embeddings to query with")

        if self.settings.validate_dims:
            dims = {len(e) for e in embeddings}
            if len(dims) > 1:
                raise InvalidEmbeddingDimensions(f"Inconsistent query embedding dimensions: {sorted(dims)}")

        coll = await self._get_collection(collection)

        def _query():
            return coll.query(
                query_embeddings=[list(map(float, e)) for e in embeddings],  # type: ignore[call-arg]
                n_results=int(top_k),
                where=where,
                where_document=where_document,
                include=["distances", "documents", "metadatas"] + (["embeddings"] if include_embeddings else []),
            )

        raw = await _retry("query", _run_blocking, _query, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

        # Нормализуем в единый результат
        ids = raw.get("ids") or []
        distances = raw.get("distances") or [[] for _ in ids]
        documents = raw.get("documents") or [[] for _ in ids]
        metadatas = raw.get("metadatas") or [[] for _ in ids]
        emb_out = raw.get("embeddings") if include_embeddings else None

        return QueryResult(
            ids=ids,
            distances=distances,
            documents=documents,
            metadatas=metadatas,
            embeddings=emb_out,
        )

    # -----------
    # Utilities
    # -----------

    async def count(self, *, collection: Optional[str] = None, where: Optional[dict[str, Any]] = None) -> int:
        """
        Возвращает приблизительное количество записей (через get с пустым ids + where).
        Прямого count в Chroma может не быть — используем workaround.
        """
        coll = await self._get_collection(collection)

        def _count():
            try:
                if where:
                    # Chroma не всегда поддерживает прямой count по where; fallback — query на 1 и взятие total?
                    res = coll.query(query_embeddings=[[0.0]], n_results=1, where=where)  # type: ignore
                    # Если backend вернёт ids без результатов — информации о total может не быть. Тогда вернем 0.
                    return len(res.get("ids", [[]])[0])
                # Без where — используем peek через get() всех ids нецелесообразно; некоторые версии имеют count() в коллекции.
                try:
                    return coll.count()  # type: ignore[attr-defined]
                except Exception:
                    # как fallback попытаемся вытянуть все ids (опасно на больших коллекциях) — не делаем в проде
                    return 0
            except Exception:
                return 0

        return await _retry("count", _run_blocking, _count, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    async def get(self, *, ids: Sequence[str], collection: Optional[str] = None) -> dict[str, Any]:
        """
        Получить записи по id.
        """
        if not ids:
            return {"ids": [[]], "documents": [[]], "metadatas": [[]], "embeddings": [[]]}

        coll = await self._get_collection(collection)

        def _get():
            return coll.get(ids=list(ids))

        return await _retry("get", _run_blocking, _get, retries=self.settings.max_retries, backoff=self.settings.initial_backoff_s)

    async def health_check(self) -> bool:
        """
        Проба готовности: попытка перечислить коллекции.
        """
        try:
            await self.list_collections()
            return True
        except Exception as e:
            logger.warning("Chroma health check failed: %s", e)
            return False

    async def close(self) -> None:
        """
        Явное закрытие клиента. У chromadb обычно явного .close() нет — метод на будущее.
        """
        self._client = None

    # -------------
    # Embed helpers
    # -------------

    async def _embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        """
        Вызов эмбеддера: используем async метод, если доступен; иначе — sync через to_thread.
        """
        if self.embedder is None:
            raise VectorStoreError("Embedder is not configured")

        # Пытаемся вызвать async API
        aembed = getattr(self.embedder, "aembed", None)
        if callable(aembed):
            res = await aembed(texts)  # type: ignore[misc]
            return res

        # Иначе выполняем sync в thread
        def _call():
            return self.embedder(texts)  # type: ignore[misc]

        return await _run_blocking(_call)


# ======================
# Minimal usage example
# ======================

if __name__ == "__main__":  # pragma: no cover
    import asyncio

    class DummyEmbedder:
        def __call__(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
            # Простейший 3-мерный эмбеддинг для демонстрации
            return [[float(len(t)), float(len(t.split())), 1.0] for t in texts]

    async def main():
        adapter = ChromaAdapter(
            conn=ChromaConnection(mode="memory"),
            settings=ChromaAdapterSettings(default_collection="demo", batch_size=64),
            embedder=DummyEmbedder(),
        )
        await adapter.create_collection("demo", get_or_create=True)

        items = [
            VectorItem(id="a", document="hello world", metadata={"lang": "en"}),
            VectorItem(id="b", document="привет мир", metadata={"lang": "ru"}),
            VectorItem(id="c", document="hola mundo", metadata={"lang": "es"}),
        ]
        n = await adapter.upsert(items, collection="demo")
        print("upserted:", n)

        res = await adapter.query(texts=["hello"], top_k=2, collection="demo")
        print("query ids:", res.ids)

        got = await adapter.get(ids=["a", "b"], collection="demo")
        print("get:", got["ids"])

        await adapter.drop_collection("demo")
        await adapter.close()

    asyncio.run(main())
