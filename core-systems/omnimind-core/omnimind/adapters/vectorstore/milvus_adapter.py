# omnimind-core/omnimind/adapters/vectorstore/milvus_adapter.py
from __future__ import annotations

import contextlib
import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from pymilvus import (
        connections,
        FieldSchema,
        CollectionSchema,
        DataType,
        Collection,
        utility,
        MilvusException,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("pymilvus is required to use MilvusVectorStore") from e


Vector = Sequence[float]


# ============================ Конфигурация/типы ==============================

@dataclass(frozen=True)
class MilvusConnectConfig:
    alias: str = "default"
    uri: Optional[str] = None          # например, "http://localhost:19530" или "tcp://..."
    host: str = "localhost"
    port: int = 19530
    user: Optional[str] = None
    password: Optional[str] = None
    db_name: Optional[str] = None      # Milvus database (если используется)
    timeout: float = 5.0               # seconds
    reconnect_retries: int = 3
    reconnect_backoff_sec: float = 0.5


@dataclass(frozen=True)
class MilvusIndexConfig:
    metric_type: str = "COSINE"        # "COSINE" | "L2" | "IP"
    index_type: str = "HNSW"           # "HNSW" | "IVF_FLAT" | "IVF_SQ8"
    # Параметры индекса. Для HNSW: {"M": 16, "efConstruction": 200}
    # Для IVF_*: {"nlist": 1024}
    params: Mapping[str, Any] = field(default_factory=lambda: {"M": 16, "efConstruction": 200})
    # Параметры поиска. Для HNSW: {"ef": 128}, для IVF: {"nprobe": 16}
    search_params: Mapping[str, Any] = field(default_factory=lambda: {"ef": 128})


@dataclass(frozen=True)
class MilvusCollectionConfig:
    collection: str
    dim: int
    description: str = "omnimind vector collection"
    shards_num: int = 2
    # Поля
    id_max_length: int = 64
    namespace_max_length: int = 64
    doc_id_max_length: int = 128
    text_max_length: int = 2048  # храните полный текст вовне, здесь — короткие фрагменты
    with_payload_json: bool = False     # включите, только если точно поддерживается вашей версией Milvus
    # Загрузка/реплики
    replicas: int = 1
    consistency_level: str = "Bounded"  # "Strong" | "Bounded" | "Eventually" | "Session"


@dataclass
class UpsertRecord:
    id: str
    vector: Vector
    namespace: str = "default"
    doc_id: Optional[str] = None
    text: Optional[str] = None
    payload: Optional[Mapping[str, Any]] = None  # храните неиндексируемые метаданные


@dataclass
class SearchResult:
    id: str
    score: float
    namespace: str
    doc_id: Optional[str]
    text: Optional[str]
    payload: Optional[Mapping[str, Any]]


class MilvusVectorStoreError(RuntimeError):
    pass


# ================================ Адаптер =====================================

class MilvusVectorStore:
    """
    Промышленный адаптер Milvus: создание/миграции коллекции, индексация, upsert, поиск, удаление.
    """

    def __init__(
        self,
        connect: MilvusConnectConfig,
        collection_cfg: MilvusCollectionConfig,
        index_cfg: MilvusIndexConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._c = connect
        self._cc = collection_cfg
        self._ic = index_cfg
        self._log = logger or logging.getLogger(__name__)
        self._collection: Optional[Collection] = None

    # -------------------------- Подключение/коллекция -------------------------

    def connect(self) -> None:
        """
        Устанавливает соединение (идемпотентно), создаёт/мигрирует коллекцию и индекс при необходимости.
        """
        self._ensure_connection()
        self._ensure_collection()
        self._ensure_index()
        self._load()

    def close(self) -> None:
        """
        Закрывает подключение. В рамках pymilvus достаточно удалить alias или оставить GC.
        """
        with contextlib.suppress(Exception):
            connections.disconnect(self._c.alias)
        self._collection = None

    # ------------------------------- Upsert -----------------------------------

    def upsert(
        self,
        records: Iterable[UpsertRecord],
        *,
        batch_size: int = 512,
        delete_before_insert: bool = True,
        timeout: Optional[float] = None,
    ) -> int:
        """
        Идемпотентный upsert: опционально удаляет по PK, затем вставляет.
        Возвращает количество добавленных записей.
        """
        col = self._require_collection()
        recs = list(records)
        if not recs:
            return 0

        # Валидация и подготовка
        ids, vectors, namespaces, doc_ids, texts, payloads = [], [], [], [], [], []
        for r in recs:
            self._validate_record(r)
            ids.append(r.id)
            vectors.append(list(r.vector))
            namespaces.append(r.namespace)
            doc_ids.append(r.doc_id or "")
            texts.append((r.text or "")[: self._cc.text_max_length])
            payloads.append(dict(r.payload) if (self._cc.with_payload_json and r.payload) else None)

        # Предварительное удаление по PK (безопасно для upsert в любой версии)
        if delete_before_insert:
            self.delete_by_ids(ids, timeout=timeout)

        total = 0
        ts_deadline = _deadline(timeout)
        for start in range(0, len(recs), batch_size):
            end = min(len(recs), start + batch_size)
            fields = {
                "id": ids[start:end],
                "namespace": namespaces[start:end],
                "doc_id": doc_ids[start:end],
                "text": texts[start:end],
                "vector": vectors[start:end],
            }
            if self._cc.with_payload_json:
                fields["payload"] = payloads[start:end]

            try:
                col.insert(fields, timeout=_remaining(ts_deadline))
                total += (end - start)
            except MilvusException as e:
                raise MilvusVectorStoreError(f"insert_failed: {e}") from e

        # Опционально — принудительная загрузка/флаш
        with contextlib.suppress(Exception):
            col.flush(timeout=_remaining(ts_deadline))
        return total

    # ------------------------------- Search -----------------------------------

    def search(
        self,
        query_vectors: Sequence[Vector],
        *,
        top_k: int = 10,
        namespace: Optional[str] = None,
        doc_id: Optional[str] = None,
        ids: Optional[Sequence[str]] = None,
        output_payload: bool = True,
        timeout: Optional[float] = None,
    ) -> List[List[SearchResult]]:
        """
        Поиск ближайших соседей. Фильтры — по namespace/doc_id/ids.
        Возвращает список списков результатов (по каждому запросному вектору).
        """
        if not query_vectors:
            return []
        col = self._require_collection()
        # Строим выражение фильтра
        expr = _build_expr(namespace=namespace, doc_id=doc_id, ids=ids)
        out_fields = ["id", "namespace", "doc_id", "text"]
        if self._cc.with_payload_json and output_payload:
            out_fields.append("payload")

        params = {"metric_type": self._ic.metric_type, "params": dict(self._ic.search_params)}
        try:
            results = col.search(
                data=query_vectors,
                anns_field="vector",
                param=params,
                limit=top_k,
                expr=expr or None,
                output_fields=out_fields,
                consistency_level=self._cc.consistency_level,
                timeout=timeout,
            )
        except MilvusException as e:
            raise MilvusVectorStoreError(f"search_failed: {e}") from e

        out: List[List[SearchResult]] = []
        for batch in results:
            cur: List[SearchResult] = []
            for hit in batch:
                # entity позволяет получить другие поля
                ent = getattr(hit, "entity", None)
                ns = ent.get("namespace") if ent else None
                doc = ent.get("doc_id") if ent else None
                text = ent.get("text") if ent else None
                payload = ent.get("payload") if (ent and self._cc.with_payload_json and output_payload) else None
                cur.append(
                    SearchResult(
                        id=str(getattr(hit, "id", ent.get("id") if ent else "")),
                        score=float(getattr(hit, "distance", 0.0)),
                        namespace=str(ns) if ns is not None else "",
                        doc_id=str(doc) if doc else None,
                        text=str(text) if text else None,
                        payload=payload if isinstance(payload, dict) else None,
                    )
                )
            out.append(cur)
        return out

    # ------------------------------- Query ------------------------------------

    def get_by_ids(
        self,
        ids: Sequence[str],
        *,
        timeout: Optional[float] = None,
        output_payload: bool = True,
    ) -> List[SearchResult]:
        """
        Извлекает записи по ID без поиска (query).
        """
        if not ids:
            return []
        col = self._require_collection()
        expr = _build_expr(ids=ids)
        out_fields = ["id", "namespace", "doc_id", "text"]
        if self._cc.with_payload_json and output_payload:
            out_fields.append("payload")
        try:
            rs = col.query(expr=expr, output_fields=out_fields, timeout=timeout, consistency_level=self._cc.consistency_level)
        except MilvusException as e:
            raise MilvusVectorStoreError(f"query_failed: {e}") from e

        out: List[SearchResult] = []
        for ent in rs or []:
            out.append(
                SearchResult(
                    id=str(ent.get("id", "")),
                    score=0.0,
                    namespace=str(ent.get("namespace", "")),
                    doc_id=str(ent.get("doc_id")) if ent.get("doc_id") else None,
                    text=str(ent.get("text")) if ent.get("text") else None,
                    payload=ent.get("payload") if self._cc.with_payload_json else None,
                )
            )
        return out

    # ------------------------------- Delete -----------------------------------

    def delete_by_ids(self, ids: Sequence[str], *, timeout: Optional[float] = None) -> int:
        """
        Удаляет записи по первичным ключам.
        """
        if not ids:
            return 0
        col = self._require_collection()
        expr = _build_expr(ids=ids)
        try:
            res = col.delete(expr, timeout=timeout)
            return int(res.delete_count) if hasattr(res, "delete_count") else 0
        except MilvusException as e:
            raise MilvusVectorStoreError(f"delete_failed: {e}") from e

    def delete_by_filter(self, *, namespace: Optional[str] = None, doc_id: Optional[str] = None, timeout: Optional[float] = None) -> int:
        """
        Удаляет записи по фильтру (namespace/doc_id).
        """
        col = self._require_collection()
        expr = _build_expr(namespace=namespace, doc_id=doc_id)
        if not expr:
            return 0
        try:
            res = col.delete(expr, timeout=timeout)
            return int(res.delete_count) if hasattr(res, "delete_count") else 0
        except MilvusException as e:
            raise MilvusVectorStoreError(f"delete_failed: {e}") from e

    # ------------------------------- Ops --------------------------------------

    def drop(self) -> None:
        """
        Полностью удаляет коллекцию.
        """
        self._require_connection()
        name = self._cc.collection
        with contextlib.suppress(Exception):
            if utility.has_collection(name, using=self._c.alias):
                utility.drop_collection(name, using=self._c.alias)
        self._collection = None

    def load(self) -> None:
        self._load()

    def release(self) -> None:
        col = self._require_collection()
        with contextlib.suppress(Exception):
            col.release()
        self._log.info("collection_released", extra={"collection": col.name})

    def stats(self) -> Dict[str, Any]:
        col = self._require_collection()
        with contextlib.suppress(Exception):
            return col.get_statistics()
        return {}

    def ping(self) -> bool:
        try:
            self._ensure_connection()
            # Простая операция: перечислить коллекции
            with contextlib.suppress(Exception):
                list(utility.list_collections(using=self._c.alias))
            return True
        except Exception:
            return False

    # ================================ Внутреннее ==============================

    def _validate_record(self, r: UpsertRecord) -> None:
        if not r.id or not isinstance(r.id, str):
            raise MilvusVectorStoreError("record.id must be non-empty string")
        if not r.vector or len(r.vector) != self._cc.dim:
            raise MilvusVectorStoreError(f"record.vector must have dim={self._cc.dim}")
        if any((v is None or (not isinstance(v, (int, float)))) for v in r.vector):
            raise MilvusVectorStoreError("record.vector must be a sequence of numbers")

    def _ensure_connection(self) -> None:
        # Если alias уже существует — не пересоздаём
        try:
            if connections.has_connection(self._c.alias):  # type: ignore[attr-defined]
                return
        except Exception:
            # older pymilvus may not have has_connection; try to use list_collections to test
            with contextlib.suppress(Exception):
                utility.list_collections(using=self._c.alias)
                return

        retries = max(0, self._c.reconnect_retries)
        err: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                if self._c.uri:
                    connections.connect(
                        alias=self._c.alias,
                        uri=self._c.uri,
                        user=self._c.user,
                        password=self._c.password,
                        db_name=self._c.db_name,
                        timeout=self._c.timeout,
                    )
                else:
                    connections.connect(
                        alias=self._c.alias,
                        host=self._c.host,
                        port=str(self._c.port),
                        user=self._c.user,
                        password=self._c.password,
                        db_name=self._c.db_name,
                        timeout=self._c.timeout,
                    )
                self._log.info("milvus_connected", extra={"alias": self._c.alias, "host": self._c.host, "port": self._c.port})
                return
            except Exception as e:
                err = e
                if attempt < retries:
                    time.sleep(self._c.reconnect_backoff_sec * (2 ** attempt))
                else:
                    break
        raise MilvusVectorStoreError(f"connect_failed: {err}") from err

    def _require_connection(self) -> None:
        try:
            self._ensure_connection()
        except Exception as e:
            raise MilvusVectorStoreError(f"connection_required_failed: {e}") from e

    def _ensure_collection(self) -> None:
        self._require_connection()
        name = self._cc.collection
        if not utility.has_collection(name, using=self._c.alias):
            self._create_collection(name)
            return
        # Коллекция существует — сохраним объект
        self._collection = Collection(name=name, using=self._c.alias)
        # Простая проверка схемы по критичным полям
        schema = self._collection.schema
        required_fields = {"id", "namespace", "doc_id", "text", "vector"}
        got = {f.name for f in schema.fields}
        missing = required_fields - got
        if missing:
            raise MilvusVectorStoreError(f"collection_schema_mismatch: missing fields {sorted(missing)}")

    def _create_collection(self, name: str) -> None:
        # Поля коллекции
        id_field = FieldSchema(
            name="id",
            dtype=DataType.VARCHAR,
            is_primary=True,
            auto_id=False,
            max_length=self._cc.id_max_length,
        )
        ns_field = FieldSchema(
            name="namespace",
            dtype=DataType.VARCHAR,
            max_length=self._cc.namespace_max_length,
        )
        doc_field = FieldSchema(
            name="doc_id",
            dtype=DataType.VARCHAR,
            max_length=self._cc.doc_id_max_length,
        )
        text_field = FieldSchema(
            name="text",
            dtype=DataType.VARCHAR,
            max_length=self._cc.text_max_length,
        )
        vec_field = FieldSchema(
            name="vector",
            dtype=DataType.FLOAT_VECTOR,
            dim=self._cc.dim,
        )

        fields = [id_field, ns_field, doc_field, text_field, vec_field]

        # Дополнительное JSON-поле (если явно разрешено конфигом и доступно)
        if self._cc.with_payload_json:
            if hasattr(DataType, "JSON"):
                fields.append(FieldSchema(name="payload", dtype=getattr(DataType, "JSON")))
            else:
                self._log.warning("json_field_not_supported_by_pymilvus; disabling payload")
        
        schema = CollectionSchema(
            fields=fields,
            description=self._cc.description,
            enable_dynamic_field=False,
        )
        try:
            coll = Collection(
                name=name,
                schema=schema,
                using=self._c.alias,
                shards_num=self._cc.shards_num,
            )
        except MilvusException as e:
            raise MilvusVectorStoreError(f"create_collection_failed: {e}") from e
        self._collection = coll
        self._log.info("collection_created", extra={"collection": name, "dim": self._cc.dim})

    def _ensure_index(self) -> None:
        col = self._require_collection()
        # Если индекс уже создан на поле vector — выходим
        try:
            idxes = col.indexes
            if idxes:
                return
        except Exception:
            pass

        index_params = {
            "index_type": self._ic.index_type,
            "metric_type": self._ic.metric_type,
            "params": dict(self._ic.params),
        }
        try:
            col.create_index(field_name="vector", index_params=index_params)
        except MilvusException as e:
            raise MilvusVectorStoreError(f"create_index_failed: {e}") from e
        self._log.info("index_created", extra={"collection": col.name, **index_params})

    def _load(self) -> None:
        col = self._require_collection()
        try:
            col.load(replica_number=self._cc.replicas, _refresh=True)  # type: ignore[call-arg]
        except TypeError:
            # older pymilvus doesn't support _refresh
            col.load(replica_number=self._cc.replicas)
        except MilvusException as e:
            raise MilvusVectorStoreError(f"load_failed: {e}") from e
        self._log.info("collection_loaded", extra={"collection": col.name, "replicas": self._cc.replicas})

    def _require_collection(self) -> Collection:
        if self._collection is None:
            self._ensure_collection()
        assert self._collection is not None
        return self._collection


# ================================ Утилиты =====================================

def _build_expr(*, namespace: Optional[str] = None, doc_id: Optional[str] = None, ids: Optional[Sequence[str]] = None) -> str:
    """
    Конструирует безопасное выражение фильтра Milvus (скалярные поля).
    """
    parts: List[str] = []
    if namespace:
        parts.append(f'namespace == "{_esc(namespace)}"')
    if doc_id:
        parts.append(f'doc_id == "{_esc(doc_id)}"')
    if ids:
        quoted = ",".join(f'"{_esc(i)}"' for i in ids)
        parts.append(f"id in [{quoted}]")
    return " and ".join(parts)


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _deadline(timeout: Optional[float]) -> Optional[float]:
    return (time.monotonic() + timeout) if timeout and timeout > 0 else None


def _remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    rem = deadline - time.monotonic()
    return rem if rem > 0 else 0.001


# ================================ Пример использования ========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    store = MilvusVectorStore(
        connect=MilvusConnectConfig(uri=os.getenv("MILVUS_URI", "http://localhost:19530")),
        collection_cfg=MilvusCollectionConfig(collection="omnimind_vectors", dim=384, with_payload_json=False),
        index_cfg=MilvusIndexConfig(metric_type="COSINE", index_type="HNSW", params={"M": 16, "efConstruction": 200}, search_params={"ef": 128}),
    )
    store.connect()
    store.upsert(
        [
            UpsertRecord(id="a1", namespace="demo", doc_id="doc-1", text="hello", vector=[0.1] * 384),
            UpsertRecord(id="a2", namespace="demo", doc_id="doc-2", text="world", vector=[0.2] * 384),
        ],
        batch_size=128,
    )
    results = store.search([[0.1] * 384], top_k=5, namespace="demo")
    for row in results:
        for r in row:
            print(r)
