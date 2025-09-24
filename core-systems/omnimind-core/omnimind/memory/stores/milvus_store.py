# SPDX-License-Identifier: Apache-2.0
"""
MilvusStore — промышленный слой хранения векторайзированной памяти для Omnimind.

Требования:
  - Python 3.10+
  - pymilvus 2.x

Особенности:
  - Явная схема коллекции: id (PK, VARCHAR), vector (FLOAT_VECTOR), text (VARCHAR),
    metadata (JSON), created_at (INT64, unix ms)
  - Индексы: HNSW (по умолчанию) или IVF_FLAT/IVF_SQ8
  - Consistency: Strong по умолчанию (настраивается)
  - Партиции: опциональные
  - Ретраи с экспоненциальной задержкой, таймауты, структурное логирование
  - Безопасное подключение: uri|host:port, user/password или token, secure (TLS)
  - Идемпотентная загрузка (delete-if-exists -> insert)
  - Выгрузка/загрузка коллекции, healthcheck, подсчет, get/delete/search

Примечание: модуль не скрывает ошибок схемы/индекса — их видно в логах.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

try:
    from pymilvus import (
        connections,
        utility,
        FieldSchema,
        CollectionSchema,
        DataType,
        Collection,
    )
    # db API присутствует в новых версиях; используем опционально
    try:
        from pymilvus import db as _db  # type: ignore
    except Exception:  # pragma: no cover
        _db = None  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("pymilvus must be installed to use MilvusStore") from e


Vector = Sequence[float]
RecordID = str


@dataclass
class MilvusConfig:
    # Подключение
    alias: str = "default"
    uri: Optional[str] = None          # например, "http://127.0.0.1:19530" или "https://..."
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None        # альтернатива user/password
    secure: bool = False
    db_name: Optional[str] = None

    # Коллекция
    collection: str = "omnimind_memory"
    dim: int = 1536
    metric_type: str = "COSINE"        # IP | L2 | COSINE
    auto_id: bool = False              # мы используем пользовательские id (VARCHAR PK)
    max_id_length: int = 64
    max_text_length: int = 2048
    consistency_level: str = "Strong"  # Strong | Bounded | Eventually | Session

    # Индексация и поиск
    index_type: str = "HNSW"           # HNSW | IVF_FLAT | IVF_SQ8
    index_params: Mapping[str, Any] = field(default_factory=lambda: {"M": 8, "efConstruction": 64})
    search_params: Mapping[str, Any] = field(default_factory=lambda: {"ef": 64, "nprobe": 16})
    replicas: int = 1

    # Партиции
    create_default_partition: bool = False
    default_partition: str = "p0"

    # Таймауты и ретраи
    timeout: float = 10.0
    retry_attempts: int = 3
    retry_base_delay: float = 0.2

    # Логирование
    log_name: str = "omnimind.milvus"


class MilvusError(RuntimeError):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _backoff(attempt: int, base: float) -> float:
    # Экспоненциальный рост с джиттером
    return min(5.0, base * (2 ** attempt)) + (os.getpid() % 13) * 0.001


class MilvusStore:
    """
    Высокоуровневый интерфейс для работы с Milvus.
    """

    def __init__(self, cfg: MilvusConfig):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg.log_name)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            h.setFormatter(fmt)
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)
        self._collection: Optional[Collection] = None

    # ----------------------- Подключение и инициализация -----------------------

    def connect(self) -> None:
        """
        Установить соединение и выбрать БД (если задана).
        """
        if self.cfg.uri:
            connections.connect(
                alias=self.cfg.alias,
                uri=self.cfg.uri,
                user=self.cfg.user,
                password=self.cfg.password,
                token=self.cfg.token,
                secure=self.cfg.secure,
                timeout=self.cfg.timeout,
            )
        else:
            if not (self.cfg.host and self.cfg.port):
                raise MilvusError("Either uri or host:port must be provided")
            connections.connect(
                alias=self.cfg.alias,
                host=self.cfg.host,
                port=str(self.cfg.port),
                user=self.cfg.user,
                password=self.cfg.password,
                token=self.cfg.token,
                secure=self.cfg.secure,
                timeout=self.cfg.timeout,
            )

        if self.cfg.db_name and _db is not None:
            try:
                if self.cfg.db_name not in (getattr(_db, "list_database")() or []):  # type: ignore
                    getattr(_db, "create_database")(self.cfg.db_name)  # type: ignore
            except Exception:
                # возможно, БД уже существует или API не поддерживается — используем дальше
                pass
            try:
                getattr(_db, "using_database")(self.cfg.db_name)  # type: ignore
            except Exception:
                pass

    def ensure_collection(self) -> None:
        """
        Создать коллекцию/индекс при отсутствии и загрузить в память.
        """
        self._require_connected()
        cfg = self.cfg

        if not utility.has_collection(cfg.collection, using=cfg.alias, timeout=cfg.timeout):
            self.logger.info("Creating collection %s", cfg.collection)
            fields = [
                FieldSchema(
                    name="id",
                    dtype=DataType.VARCHAR,
                    is_primary=True,
                    auto_id=cfg.auto_id,
                    max_length=cfg.max_id_length,
                ),
                FieldSchema(
                    name="vector",
                    dtype=DataType.FLOAT_VECTOR,
                    dim=cfg.dim,
                ),
                FieldSchema(
                    name="text",
                    dtype=DataType.VARCHAR,
                    max_length=cfg.max_text_length,
                ),
                FieldSchema(
                    name="metadata",
                    dtype=DataType.JSON,
                ),
                FieldSchema(
                    name="created_at",
                    dtype=DataType.INT64,
                ),
            ]
            schema = CollectionSchema(
                fields=fields,
                description="Omnimind memory store",
                enable_dynamic_field=False,
            )
            collection = Collection(
                name=cfg.collection,
                schema=schema,
                using=cfg.alias,
                shards_num=2,
                consistency_level=cfg.consistency_level,
            )

            # Индекс
            self._create_index(collection)
        else:
            collection = Collection(name=cfg.collection, using=cfg.alias, consistency_level=cfg.consistency_level)

        # Партиция по умолчанию
        if cfg.create_default_partition:
            try:
                if not utility.has_partition(collection.name, cfg.default_partition, using=cfg.alias):
                    collection.create_partition(cfg.default_partition)
            except Exception as e:
                self.logger.warning("Partition creation skipped: %s", e)

        # Реплики и загрузка
        try:
            collection.load(replica_number=max(1, cfg.replicas), timeout=cfg.timeout)
        except TypeError:
            # если параметр replica_number не поддерживается в текущей версии
            collection.load(timeout=cfg.timeout)

        self._collection = collection

    def _create_index(self, collection: Collection) -> None:
        cfg = self.cfg
        index_params: Mapping[str, Any]
        if cfg.index_type.upper() == "HNSW":
            index_params = {
                "index_type": "HNSW",
                "metric_type": cfg.metric_type,
                "params": {
                    "M": int(cfg.index_params.get("M", 8)),
                    "efConstruction": int(cfg.index_params.get("efConstruction", 64)),
                },
            }
        elif cfg.index_type.upper() in ("IVF_FLAT", "IVF_SQ8"):
            index_params = {
                "index_type": cfg.index_type.upper(),
                "metric_type": cfg.metric_type,
                "params": {
                    "nlist": int(cfg.index_params.get("nlist", 1024)),
                },
            }
        else:
            raise MilvusError(f"Unsupported index_type: {cfg.index_type}")

        self.logger.info("Creating index on %s: %s", collection.name, index_params)
        collection.create_index(field_name="vector", index_params=index_params)

    # ----------------------------- Операции CRUD ------------------------------

    def add(
        self,
        vectors: Sequence[Vector],
        *,
        ids: Optional[Sequence[RecordID]] = None,
        texts: Optional[Sequence[str]] = None,
        metadatas: Optional[Sequence[Mapping[str, Any]]] = None,
        partition: Optional[str] = None,
        upsert: bool = True,
    ) -> List[RecordID]:
        """
        Добавить записи. Если upsert=True, предварительно удаляет записи с теми же id.
        Возвращает список id (сгенерированных или переданных).
        """
        col = self._require_collection()
        n = len(vectors)
        if n == 0:
            return []

        # Валидация входа
        dim = len(vectors[0]) if vectors else self.cfg.dim
        if any(len(v) != dim for v in vectors):
            raise MilvusError("All vectors must have equal dimension")

        if dim != self.cfg.dim:
            raise MilvusError(f"Vector dimension {dim} != configured {self.cfg.dim}")

        ids = list(ids or [])
        if ids and len(ids) != n:
            raise MilvusError("ids length must match vectors length")
        if not ids:
            ids = [self._gen_id(i) for i in range(n)]

        texts = list(texts or [""] * n)
        if len(texts) != n:
            raise MilvusError("texts length must match vectors length")

        metas = list(metadatas or [{} for _ in range(n)])
        if len(metas) != n:
            raise MilvusError("metadatas length must match vectors length")

        now = _now_ms()
        created = [now] * n

        # Upsert: удаляем старые версии
        if upsert:
            self.delete(ids=ids, partition=partition)

        # Вставка с ретраями
        data = [
            ids,
            vectors,
            texts,
            list(metas),
            created,
        ]

        self._with_retries(lambda: col.insert(data=data, partition_name=partition, timeout=self.cfg.timeout))

        # Для немгновенной консистентности можно дождаться
        try:
            col.flush(timeout=self.cfg.timeout)
        except Exception:
            pass

        return ids

    def search(
        self,
        query_vectors: Sequence[Vector],
        *,
        top_k: int = 5,
        expr: Optional[str] = None,
        partition: Optional[str] = None,
        output_fields: Optional[Sequence[str]] = None,
        search_params: Optional[Mapping[str, Any]] = None,
    ) -> List[List[Mapping[str, Any]]]:
        """
        Поиск ближайших соседей. Возвращает лист результатов на каждый запрос.
        Каждый результат — список dict с ключами: id, score, text, metadata, created_at.
        """
        col = self._require_collection()

        if not output_fields:
            output_fields = ["id", "text", "metadata", "created_at"]

        sp = dict(search_params or {})
        # Параметры по типу индекса
        if not sp:
            if self.cfg.index_type.upper() == "HNSW":
                sp = {"metric_type": self.cfg.metric_type, "params": {"ef": int(self.cfg.search_params.get("ef", 64))}}
            else:  # IVF*
                sp = {"metric_type": self.cfg.metric_type, "params": {"nprobe": int(self.cfg.search_params.get("nprobe", 16))}}

        # Обязательно загружена
        try:
            col.load(replica_number=max(1, self.cfg.replicas), timeout=self.cfg.timeout)
        except TypeError:
            col.load(timeout=self.cfg.timeout)
        except Exception:
            pass

        results = self._with_retries(
            lambda: col.search(
                data=list(query_vectors),
                anns_field="vector",
                param=sp,
                limit=top_k,
                expr=expr,
                consistency_level=self.cfg.consistency_level,
                output_fields=list(output_fields),
                partition_names=[partition] if partition else None,
                timeout=self.cfg.timeout,
            )
        )

        out: List[List[Mapping[str, Any]]] = []
        for hits in results:
            arr: List[Mapping[str, Any]] = []
            for hit in hits:
                fields = getattr(hit, "fields", {}) or {}
                arr.append(
                    {
                        "id": str(fields.get("id")),
                        "score": float(hit.distance),
                        "text": fields.get("text"),
                        "metadata": fields.get("metadata"),
                        "created_at": fields.get("created_at"),
                    }
                )
            out.append(arr)
        return out

    def get(
        self,
        ids: Sequence[RecordID],
        *,
        partition: Optional[str] = None,
        output_fields: Optional[Sequence[str]] = None,
    ) -> List[Mapping[str, Any]]:
        """
        Получить записи по ID.
        """
        col = self._require_collection()
        if not output_fields:
            output_fields = ["id", "text", "metadata", "created_at"]
        expr = f'id in [{",".join(f"{json.dumps(i)}" for i in ids)}]'
        res = self._with_retries(
            lambda: col.query(expr=expr, output_fields=list(output_fields), partition_names=[partition] if partition else None, timeout=self.cfg.timeout)
        )
        return list(res or [])

    def delete(
        self,
        ids: Optional[Sequence[RecordID]] = None,
        *,
        expr: Optional[str] = None,
        partition: Optional[str] = None,
    ) -> int:
        """
        Удалить записи по id или выражению expr. Возвращает количество удалённых (если поддерживается).
        """
        col = self._require_collection()
        if not ids and not expr:
            return 0
        if ids and expr:
            raise MilvusError("Provide either ids or expr, not both")
        _expr = expr or f'id in [{",".join(json.dumps(i) for i in ids or [])}]'
        res = self._with_retries(lambda: col.delete(expr=_expr, partition_name=partition, timeout=self.cfg.timeout))
        try:
            return int(res.delete_count)  # type: ignore[attr-defined]
        except Exception:
            return 0

    def count(self) -> int:
        """
        Количество записей в коллекции (приблизительное: num_entities).
        """
        col = self._require_collection()
        col.load(timeout=self.cfg.timeout)
        return int(col.num_entities)

    def drop_collection(self) -> None:
        """
        Полностью удалить коллекцию (опасно).
        """
        self._require_connected()
        if utility.has_collection(self.cfg.collection, using=self.cfg.alias):
            col = Collection(self.cfg.collection, using=self.cfg.alias)
            try:
                col.release()
            except Exception:
                pass
            col.drop()

    # ------------------------------- Сервисное --------------------------------

    def health(self) -> bool:
        """
        Проверка доступности Milvus и коллекции.
        """
        self._require_connected()
        try:
            utility.get_server_version(self.cfg.alias)
            if utility.has_collection(self.cfg.collection, using=self.cfg.alias):
                return True
            return False
        except Exception as e:
            self.logger.warning("Healthcheck failed: %s", e)
            return False

    def close(self) -> None:
        """
        Закрыть соединение.
        """
        try:
            connections.disconnect(self.cfg.alias)
        except Exception:
            pass
        self._collection = None

    # ------------------------------- Внутреннее --------------------------------

    def _gen_id(self, i: int) -> str:
        # детерминированный префикс + монотонность за счёт времени
        return f"mem_{_now_ms()}_{i:06d}"

    def _require_connected(self) -> None:
        # Проверка/ленивое подключение
        try:
            connections.get_connection_addr(self.cfg.alias)
        except Exception:
            self.connect()

    def _require_collection(self) -> Collection:
        if self._collection is None:
            self.ensure_collection()
        assert self._collection is not None
        return self._collection

    def _with_retries(self, fn):
        last_exc = None
        for attempt in range(self.cfg.retry_attempts):
            try:
                t0 = time.perf_counter()
                res = fn()
                dt = (time.perf_counter() - t0) * 1000
                if dt > 500:
                    self.logger.info("Milvus op took %.1f ms", dt)
                return res
            except Exception as e:
                last_exc = e
                delay = _backoff(attempt, self.cfg.retry_base_delay)
                self.logger.warning("Milvus op failed (attempt %d/%d): %s; sleep %.2fs", attempt + 1, self.cfg.retry_attempts, e, delay)
                time.sleep(delay)
        raise MilvusError(f"Milvus operation failed after {self.cfg.retry_attempts} attempts: {last_exc}") from last_exc


# ---------------------------- Пример локальной проверки ----------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    cfg = MilvusConfig(
        uri=os.getenv("MILVUS_URI", None),
        host=os.getenv("MILVUS_HOST", "127.0.0.1"),
        port=int(os.getenv("MILVUS_PORT", "19530")),
        user=os.getenv("MILVUS_USER", None),
        password=os.getenv("MILVUS_PASSWORD", None),
        token=os.getenv("MILVUS_TOKEN", None),
        secure=os.getenv("MILVUS_SECURE", "false").lower() == "true",
        collection=os.getenv("MILVUS_COLLECTION", "omnimind_memory"),
        dim=int(os.getenv("MILVUS_DIM", "1536")),
        metric_type=os.getenv("MILVUS_METRIC", "COSINE"),
        index_type=os.getenv("MILVUS_INDEX", "HNSW"),
        db_name=os.getenv("MILVUS_DB", None),
    )

    store = MilvusStore(cfg)
    store.ensure_collection()

    # Мини-тест
    ids = store.add(
        vectors=[[0.1, 0.2, 0.3] + [0.0] * (cfg.dim - 3), [0.11, 0.21, 0.31] + [0.0] * (cfg.dim - 3)],
        texts=["hello", "world"],
        metadatas=[{"lang": "en"}, {"lang": "en"}],
    )
    print("Inserted:", ids)
    res = store.search(
        query_vectors=[[0.1, 0.2, 0.29] + [0.0] * (cfg.dim - 3)],
        top_k=2,
    )
    print("Search result:", json.dumps(res, ensure_ascii=False, indent=2))
    print("Count:", store.count())
    print("Get:", store.get(ids))
    print("Delete:", store.delete(ids=ids))
    store.close()
