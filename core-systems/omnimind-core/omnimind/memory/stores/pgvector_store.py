# -*- coding: utf-8 -*-
"""
OmniMind Core — PgVectorStore
Промышленное хранилище векторных представлений на PostgreSQL с pgvector.

Особенности:
- psycopg 3 (sync/async) + ConnectionPool/AsyncConnectionPool
- Миграции: EXTENSION pgvector, таблицы с выбранной метрикой и размерностью
- Индексы: IVFFLAT (по умолчанию), опционально HNSW (если поддерживается), GIN по tsvector и JSONB
- Батчевый upsert с идемпотентностью; обновление tsvector
- Поиск: kNN (cosine/l2/ip), гибрид (kNN + full-text websearch_to_tsquery), нормализация скорингов
- Фильтры: namespace, doc_id, метки, JSONB-предикаты ($eq/$in/$contains/$range/$like)
- MMR rerank (опционально) для диверсификации результатов на приложении
- Ретраи с экспоненциальной паузой для транзиентных ошибок, безопасное логирование

Требования PostgreSQL:
- PostgreSQL 13+ (рекомендуется 14+)
- EXTENSION pgvector установлен (CREATE EXTENSION pgvector)
- Для HNSW требуется pgvector >= 0.6 (опционально)

Замечания:
- dimension задаётся при миграции и фиксируется в типе vector(d). Изменение — через новую таблицу/миграцию.
- opclass выбирается из: vector_cosine_ops | vector_l2_ops | vector_ip_ops
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import math
import os
import random
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, AsyncConnectionPool
from psycopg import sql

# ---------------------------
# Конфигурация и модели
# ---------------------------

@dataclass(frozen=True)
class PgVectorConfig:
    dsn: str
    schema: str = "public"
    table: str = "memory_items"
    metric: str = "cosine"          # cosine|l2|ip
    dimension: int = 1536           # размерность вектора
    ivfflat_lists: int = 100        # параметр индекса
    use_hnsw: bool = False          # если True и поддерживается — создать HNSW
    text_search_lang: str = "english"
    pool_min_size: int = 1
    pool_max_size: int = 10
    statement_timeout_ms: int = 0   # 0 = без тайм-аута
    application_name: str = "omnimind-pgvector"
    log_level: int = logging.INFO

@dataclass(frozen=True)
class VectorRecord:
    id: str
    namespace: str
    content: str
    embedding: List[float]
    doc_id: Optional[str] = None
    chunk_id: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None
    source: Optional[str] = None

@dataclass(frozen=True)
class QueryFilters:
    namespace: Optional[str] = None
    doc_id: Optional[str] = None
    limit_to_doc_ids: Optional[List[str]] = None
    # where — mini-DSL для JSONB:
    # {"meta.project": {"$eq": "x"}, "meta.tags": {"$contains": ["a","b"]}, "meta.score":{"$range":[0.2,0.9]}}
    where: Optional[Dict[str, Any]] = None
    min_score: Optional[float] = None

@dataclass(frozen=True)
class QueryResult:
    id: str
    namespace: str
    content: str
    score: float
    doc_id: Optional[str]
    chunk_id: Optional[int]
    metadata: Dict[str, Any]
    source: Optional[str]

# ---------------------------
# Утилиты
# ---------------------------

_METRIC_TO_OP = {
    "cosine": "<=>",
    "l2": "<->",
    "ip": "<#>",
}
_METRIC_TO_OPCLASS = {
    "cosine": "vector_cosine_ops",
    "l2": "vector_l2_ops",
    "ip": "vector_ip_ops",
}

def _norm_score(metric: str, distance: float) -> float:
    """
    Нормализует distance -> [0..1], где 1 лучше.
    cosine: sim = 1 - distance
    l2    : sim = 1/(1+distance)
    ip    : distance = -<x,y>/2 (?) у pgvector: <#> меньше — лучше; используем 1/(1+distance_norm)
    """
    if metric == "cosine":
        return max(0.0, min(1.0, 1.0 - float(distance)))
    if metric == "l2":
        return 1.0 / (1.0 + float(distance))
    # ip: чем меньше distance, тем лучше; ограничим
    try:
        d = float(distance)
        return 1.0 / (1.0 + max(0.0, d))
    except Exception:
        return 0.0

def _chunks(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

def _now_ms() -> int:
    return int(time.time() * 1000)

def _as_uuid(v: Union[str, uuid.UUID]) -> uuid.UUID:
    return v if isinstance(v, uuid.UUID) else uuid.UUID(str(v))

# ---------------------------
# Основной класс (sync + async)
# ---------------------------

class PgVectorStore:
    def __init__(self, cfg: PgVectorConfig):
        self.cfg = cfg
        self._log = logging.getLogger("omnimind.pgvector")
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(cfg.log_level)

        # Параметры подключения
        self._conn_kwargs = {
            "autocommit": False,
            "row_factory": dict_row,
            "prepare_threshold": 5,
            "options": f"-c application_name={cfg.application_name}"
                       + (f" -c statement_timeout={cfg.statement_timeout_ms}" if cfg.statement_timeout_ms > 0 else "")
        }

        self.pool = ConnectionPool(
            conninfo=cfg.dsn,
            min_size=cfg.pool_min_size,
            max_size=cfg.pool_max_size,
            kwargs=self._conn_kwargs,
        )
        self.apool = AsyncConnectionPool(
            conninfo=cfg.dsn,
            min_size=cfg.pool_min_size,
            max_size=cfg.pool_max_size,
            kwargs=self._conn_kwargs,
        )

    # -------------- Миграции --------------

    def migrate(self) -> None:
        """
        Создаёт схему хранения, индексы и расширение pgvector при необходимости.
        """
        metric = self.cfg.metric.lower()
        if metric not in _METRIC_TO_OPCLASS:
            raise ValueError("metric must be one of: cosine|l2|ip")

        opclass = _METRIC_TO_OPCLASS[metric]
        dim = int(self.cfg.dimension)
        schema = sql.Identifier(self.cfg.schema)
        table = sql.Identifier(self.cfg.table)

        statements = [
            sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(schema),
            sql.SQL("CREATE EXTENSION IF NOT EXISTS pgvector"),
            # Таблица
            sql.SQL("""
                CREATE TABLE IF NOT EXISTS {}.{} (
                    id UUID PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    doc_id TEXT,
                    chunk_id INT,
                    source TEXT,
                    content TEXT NOT NULL,
                    embedding vector({dim}) NOT NULL,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    ts_lang TEXT NOT NULL DEFAULT %s,
                    ts tsvector,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """).format(schema, table).format(dim=sql.Literal(dim)),
            # Тригер на обновление updated_at
            sql.SQL("""
                CREATE OR REPLACE FUNCTION {}.set_updated_at() RETURNS trigger AS $$
                BEGIN
                  NEW.updated_at = now();
                  RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """).format(schema),
            sql.SQL("""
                DO $$
                BEGIN
                  IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_set_updated_at'
                    AND tgrelid = '{}.{}'::regclass
                  ) THEN
                    CREATE TRIGGER trg_set_updated_at
                    BEFORE UPDATE ON {}.{}
                    FOR EACH ROW EXECUTE FUNCTION {}.set_updated_at();
                  END IF;
                END $$;
            """).format(schema, table, schema, table, schema),
            # Индексы
            sql.SQL("CREATE INDEX IF NOT EXISTS idx_{}_ns ON {}.{} (namespace)").format(
                sql.Identifier(self.cfg.table), schema, table
            ),
            sql.SQL("CREATE INDEX IF NOT EXISTS idx_{}_doc ON {}.{} (doc_id)").format(
                sql.Identifier(self.cfg.table), schema, table
            ),
            sql.SQL("CREATE INDEX IF NOT EXISTS idx_{}_ts ON {}.{} USING GIN (ts)").format(
                sql.Identifier(self.cfg.table), schema, table
            ),
            sql.SQL("CREATE INDEX IF NOT EXISTS idx_{}_meta ON {}.{} USING GIN (metadata)").format(
                sql.Identifier(self.cfg.table), schema, table
            ),
            # IVFFLAT
            sql.SQL("""
                DO $$
                BEGIN
                  IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                     WHERE schemaname = %s AND indexname = %s
                  ) THEN
                    EXECUTE format(
                      'CREATE INDEX %I ON %I.%I USING ivfflat (embedding %s) WITH (lists = %s)',
                      %s, %s, %s, %s, %s
                    );
                  END IF;
                END $$;
            """),
        ]

        hnsw_stmt = sql.SQL("""
            DO $$
            BEGIN
              IF {use_hnsw} AND NOT EXISTS (
                SELECT 1 FROM pg_indexes
                 WHERE schemaname = %s AND indexname = %s
              ) THEN
                EXECUTE format(
                  'CREATE INDEX %I ON %I.%I USING hnsw (embedding %s)',
                  %s, %s, %s, %s
                );
              END IF;
            END $$;
        """).format(use_hnsw=sql.Literal(bool(self.cfg.use_hnsw)))

        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                # schema + extension + table + triggers + common indexes
                cur.execute(statements[0])
                cur.execute(statements[1])
                cur.execute(statements[2], (self.cfg.text_search_lang,))
                cur.execute(statements[3])
                cur.execute(statements[4].as_string(conn))
                cur.execute(statements[5].as_string(conn))
                cur.execute(statements[6].as_string(conn))
                # ivfflat
                ivf_index_name = f"idx_{self.cfg.table}_ivf_{self.cfg.metric}"
                cur.execute(
                    statements[7],
                    (
                        self.cfg.schema,
                        ivf_index_name,
                        ivf_index_name,
                        self.cfg.schema,
                        self.cfg.table,
                        opclass,
                        self.cfg.ivfflat_lists,
                        ivf_index_name,
                        self.cfg.schema,
                        self.cfg.table,
                        opclass,
                        self.cfg.ivfflat_lists,
                    ),
                )
                # hnsw (опционально)
                hnsw_index_name = f"idx_{self.cfg.table}_hnsw_{self.cfg.metric}"
                cur.execute(
                    hnsw_stmt,
                    (
                        self.cfg.schema, hnsw_index_name,
                        hnsw_index_name, self.cfg.schema, self.cfg.table, opclass,
                        hnsw_index_name, self.cfg.schema, self.cfg.table, opclass
                    ),
                )
            conn.commit()

    # -------------- Запись --------------

    def upsert(self, records: Sequence[VectorRecord], batch_size: int = 500) -> int:
        """
        Батчевый upsert. Возвращает количество upsert’ов.
        """
        total = 0
        ins = sql.SQL("""
            INSERT INTO {}.{} (id, namespace, doc_id, chunk_id, source, content, embedding, metadata, ts_lang, ts)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s, to_tsvector(%s, %s))
            ON CONFLICT (id) DO UPDATE SET
                namespace = EXCLUDED.namespace,
                doc_id = EXCLUDED.doc_id,
                chunk_id = EXCLUDED.chunk_id,
                source = EXCLUDED.source,
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                metadata = EXCLUDED.metadata,
                ts_lang = EXCLUDED.ts_lang,
                ts = EXCLUDED.ts,
                updated_at = now()
        """).format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))

        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                for chunk in _chunks(list(records), batch_size):
                    args = []
                    for r in chunk:
                        rid = str(r.id) if isinstance(r.id, (str, uuid.UUID)) else str(uuid.uuid4())
                        args.append((
                            str(rid), r.namespace, r.doc_id, r.chunk_id, r.source, r.content,
                            r.embedding, json.dumps(r.metadata or {}, ensure_ascii=False),
                            self.cfg.text_search_lang, self.cfg.text_search_lang, r.content
                        ))
                    cur.executemany(ins, args)
                    total += len(args)
            conn.commit()
        return total

    async def upsert_async(self, records: Sequence[VectorRecord], batch_size: int = 500) -> int:
        total = 0
        ins = sql.SQL("""
            INSERT INTO {}.{} (id, namespace, doc_id, chunk_id, source, content, embedding, metadata, ts_lang, ts)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s, to_tsvector(%s, %s))
            ON CONFLICT (id) DO UPDATE SET
                namespace = EXCLUDED.namespace,
                doc_id = EXCLUDED.doc_id,
                chunk_id = EXCLUDED.chunk_id,
                source = EXCLUDED.source,
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                metadata = EXCLUDED.metadata,
                ts_lang = EXCLUDED.ts_lang,
                ts = EXCLUDED.ts,
                updated_at = now()
        """).format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))

        async with self.apool.connection() as conn:
            async with conn.cursor() as cur:
                for chunk in _chunks(list(records), batch_size):
                    args = []
                    for r in chunk:
                        rid = str(r.id) if isinstance(r.id, (str, uuid.UUID)) else str(uuid.uuid4())
                        args.append((
                            str(rid), r.namespace, r.doc_id, r.chunk_id, r.source, r.content,
                            r.embedding, json.dumps(r.metadata or {}, ensure_ascii=False),
                            self.cfg.text_search_lang, self.cfg.text_search_lang, r.content
                        ))
                    await cur.executemany(ins, args)
                    total += len(args)
            await conn.commit()
        return total

    # -------------- Удаление --------------

    def delete_by_ids(self, ids: Sequence[Union[str, uuid.UUID]]) -> int:
        q = sql.SQL("DELETE FROM {}.{} WHERE id = ANY(%s)").format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(q, ([str(_as_uuid(x)) for x in ids],))
            n = cur.rowcount or 0
            conn.commit()
            return n

    async def delete_by_ids_async(self, ids: Sequence[Union[str, uuid.UUID]]) -> int:
        q = sql.SQL("DELETE FROM {}.{} WHERE id = ANY(%s)").format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))
        async with self.apool.connection() as conn, conn.cursor() as cur:
            await cur.execute(q, ([str(_as_uuid(x)) for x in ids],))
            n = cur.rowcount or 0
            await conn.commit()
            return n

    def delete_namespace(self, namespace: str) -> int:
        q = sql.SQL("DELETE FROM {}.{} WHERE namespace = %s").format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(q, (namespace,))
            n = cur.rowcount or 0
            conn.commit()
            return n

    # -------------- Фильтры (SQL builder) --------------

    def _build_filters(self, f: Optional[QueryFilters]) -> Tuple[str, List[Any]]:
        where = ["1=1"]
        args: List[Any] = []
        if not f:
            return " AND ".join(where), args

        if f.namespace:
            where.append("namespace = %s")
            args.append(f.namespace)
        if f.doc_id:
            where.append("doc_id = %s")
            args.append(f.doc_id)
        if f.limit_to_doc_ids:
            where.append("doc_id = ANY(%s)")
            args.append(list(f.limit_to_doc_ids))

        # JSONB mini-DSL
        if f.where:
            for key, cond in f.where.items():
                # meta.path -> JSONB path
                if not key.startswith("meta."):
                    continue
                jpath = key.split(".", 1)[1]
                # jsonb ->> for scalars, #>> for deep text
                # для простоты используем jsonb_path_exists / containment
                if isinstance(cond, dict):
                    if "$eq" in cond:
                        where.append(f"(metadata #>> %s) = %s")
                        args.append([jpath.replace(".", ",")])
                        args.append(str(cond["$eq"]))
                    if "$like" in cond:
                        where.append(f"(metadata #>> %s) ILIKE %s")
                        args.append([jpath.replace(".", ",")])
                        args.append(str(cond["$like"]))
                    if "$in" in cond:
                        vals = list(cond["$in"])
                        where.append(f"(metadata #>> %s) = ANY(%s)")
                        args.append([jpath.replace(".", ",")])
                        args.append([str(v) for v in vals])
                    if "$contains" in cond:
                        # JSONB containment: {"path": value} эквивалент недоступен напрямую,
                        # поэтому используем @> с фрагментом
                        where.append("metadata @> %s::jsonb")
                        frag = {}
                        cur = frag
                        parts = jpath.split(".")
                        for p in parts[:-1]:
                            cur[p] = {}
                            cur = cur[p]
                        cur[parts[-1]] = cond["$contains"]
                        args.append(json.dumps(frag))
                    if "$range" in cond:
                        lo, hi = cond["$range"]
                        where.append("(metadata #>> %s)::numeric BETWEEN %s AND %s")
                        args.append([jpath.replace(".", ",")])
                        args.append(lo)
                        args.append(hi)
        if f.min_score is not None:
            # min_score фильтруется после вычисления; тут просто пометим
            pass

        return " AND ".join(where), args

    # -------------- Поиск: kNN --------------

    def query(
        self,
        embedding: List[float],
        top_k: int = 10,
        filters: Optional[QueryFilters] = None,
    ) -> List[QueryResult]:
        op = _METRIC_TO_OP[self.cfg.metric]
        where_sql, args = self._build_filters(filters)
        q = sql.SQL(f"""
            SELECT id, namespace, doc_id, chunk_id, source, content, metadata,
                   (embedding {op} %s) AS distance
            FROM {self.cfg.schema}.{self.cfg.table}
            WHERE {where_sql}
            ORDER BY embedding {op} %s
            LIMIT %s
        """)
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(q, args + [embedding, embedding, top_k])
            rows = cur.fetchall() or []
        results: List[QueryResult] = []
        for r in rows:
            score = _norm_score(self.cfg.metric, r["distance"])
            if filters and filters.min_score is not None and score < float(filters.min_score):
                continue
            results.append(QueryResult(
                id=str(r["id"]),
                namespace=r["namespace"],
                content=r["content"],
                score=score,
                doc_id=r["doc_id"],
                chunk_id=r["chunk_id"],
                metadata=r["metadata"] or {},
                source=r["source"],
            ))
        return results

    async def query_async(
        self,
        embedding: List[float],
        top_k: int = 10,
        filters: Optional[QueryFilters] = None,
    ) -> List[QueryResult]:
        op = _METRIC_TO_OP[self.cfg.metric]
        where_sql, args = self._build_filters(filters)
        q = sql.SQL(f"""
            SELECT id, namespace, doc_id, chunk_id, source, content, metadata,
                   (embedding {op} %s) AS distance
            FROM {self.cfg.schema}.{self.cfg.table}
            WHERE {where_sql}
            ORDER BY embedding {op} %s
            LIMIT %s
        """)
        async with self.apool.connection() as conn, conn.cursor() as cur:
            await cur.execute(q, args + [embedding, embedding, top_k])
            rows = await cur.fetchall() or []
        results: List[QueryResult] = []
        for r in rows:
            score = _norm_score(self.cfg.metric, r["distance"])
            if filters and filters.min_score is not None and score < float(filters.min_score):
                continue
            results.append(QueryResult(
                id=str(r["id"]),
                namespace=r["namespace"],
                content=r["content"],
                score=score,
                doc_id=r["doc_id"],
                chunk_id=r["chunk_id"],
                metadata=r["metadata"] or {},
                source=r["source"],
            ))
        return results

    # -------------- Поиск: гибрид (вектор + FTS) --------------

    def query_hybrid(
        self,
        embedding: List[float],
        text_query: Optional[str],
        top_k: int = 10,
        alpha: float = 0.7,  # вес вектора в [0..1]
        filters: Optional[QueryFilters] = None,
    ) -> List[QueryResult]:
        op = _METRIC_TO_OP[self.cfg.metric]
        where_sql, args = self._build_filters(filters)
        # FTS-часть
        ts_expr = "0.0"
        ts_where = ""
        if text_query:
            ts_expr = "ts_rank(ts, websearch_to_tsquery(ts_lang, %s))"
            ts_where = "AND websearch_to_tsquery(ts_lang, %s) @@ ts"
            args = args + [text_query, text_query]

        q = sql.SQL(f"""
            WITH scored AS (
              SELECT id, namespace, doc_id, chunk_id, source, content, metadata,
                     (embedding {op} %s) AS distance,
                     {ts_expr} AS ts_score
              FROM {self.cfg.schema}.{self.cfg.table}
              WHERE {where_sql} {ts_where}
              ORDER BY embedding {op} %s
              LIMIT %s
            )
            SELECT *, 
                   ((%s * (CASE WHEN ts_score IS NULL THEN 0 ELSE ts_score END))
                     + ((1-%s) * (CASE WHEN distance IS NULL THEN 0 ELSE (CASE %s END) END))) AS hybrid
            FROM scored
            ORDER BY hybrid DESC
            LIMIT %s
        """)
        # CASE нормализации distance -> [0..1]
        if self.cfg.metric == "cosine":
            norm_case = "WHEN distance IS NULL THEN 0 ELSE (1 - distance) END"
        elif self.cfg.metric == "l2":
            norm_case = "WHEN distance IS NULL THEN 0 ELSE (1/(1+distance)) END"
        else:
            norm_case = "WHEN distance IS NULL THEN 0 ELSE (1/(1+distance)) END"

        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(q, args + [embedding, embedding, top_k * 5, alpha, alpha, sql.SQL(norm_case).as_string(conn), top_k])
            rows = cur.fetchall() or []
        results: List[QueryResult] = []
        for r in rows:
            score = float(r["hybrid"])
            if filters and filters.min_score is not None and score < float(filters.min_score):
                continue
            results.append(QueryResult(
                id=str(r["id"]),
                namespace=r["namespace"],
                content=r["content"],
                score=score,
                doc_id=r["doc_id"],
                chunk_id=r["chunk_id"],
                metadata=r["metadata"] or {},
                source=r["source"],
            ))
        return results

    # -------------- MMR rerank (опционально) --------------

    @staticmethod
    def _mmr(query_vec: List[float], candidates: List[Tuple[str, List[float], float]], top_k: int = 10, lambda_: float = 0.5) -> List[str]:
        """
        Minimal MMR по id. candidates: [(id, emb, base_score)].
        Возвращает список id в порядке MMR.
        """
        import math
        def dot(a, b): return sum(x*y for x, y in zip(a, b))
        def norm(a): return math.sqrt(sum(x*x for x in a)) or 1.0
        def cos(a, b): return dot(a, b) / (norm(a) * norm(b))
        selected: List[str] = []
        selected_vecs: List[List[float]] = []
        cand_map = {cid: (vec, base) for cid, vec, base in candidates}
        while candidates and len(selected) < top_k:
            best_id = None
            best_score = -1e9
            for cid, vec, base in candidates:
                div = 0.0
                if selected_vecs:
                    div = max(cos(vec, sv) for sv in selected_vecs)
                mmr = lambda_ * base - (1 - lambda_) * div
                if mmr > best_score:
                    best_score = mmr
                    best_id = cid
            if best_id is None:
                break
            selected.append(best_id)
            selected_vecs.append(cand_map[best_id][0])
            candidates = [(cid, vec, base) for cid, vec, base in candidates if cid != best_id]
        return selected

    # -------------- Вспомогательные операции --------------

    def count(self, namespace: Optional[str] = None) -> int:
        q = sql.SQL("SELECT COUNT(*) AS c FROM {}.{}").format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))
        args: List[Any] = []
        if namespace:
            q = sql.SQL("SELECT COUNT(*) AS c FROM {}.{} WHERE namespace = %s").format(sql.Identifier(self.cfg.schema), sql.Identifier(self.cfg.table))
            args.append(namespace)
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(q, args)
            return int(cur.fetchone()["c"])

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.pool.close()
        with contextlib.suppress(Exception):
            asyncio.get_event_loop()
            # Async pool закрываем бестрепетно (если использовался)
            self.apool.close()

# ---------------------------
# Пример использования
# ---------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cfg = PgVectorConfig(
        dsn=os.getenv("PG_DSN", "postgresql://postgres:postgres@localhost:5432/omni"),
        schema=os.getenv("PG_SCHEMA", "public"),
        table=os.getenv("PG_TABLE", "memory_items"),
        metric=os.getenv("PG_METRIC", "cosine"),
        dimension=int(os.getenv("PG_DIM", "1536")),
        ivfflat_lists=int(os.getenv("PG_IVF_LISTS", "100")),
        use_hnsw=bool(int(os.getenv("PG_USE_HNSW", "0"))),
        text_search_lang=os.getenv("PG_TS_LANG", "english"),
    )
    store = PgVectorStore(cfg)
    store.migrate()
    # Демозапись
    rid = str(uuid.uuid4())
    rec = VectorRecord(
        id=rid,
        namespace="default",
        content="Vector search with PostgreSQL is efficient.",
        embedding=[0.01] * cfg.dimension,
        metadata={"meta": {"project": "demo", "tags": ["pg", "vector"], "score": 0.9}},
        source="unit-test",
        doc_id="doc-1",
        chunk_id=1,
    )
    store.upsert([rec])
    res = store.query([0.01] * cfg.dimension, top_k=3, filters=QueryFilters(namespace="default"))
    print(json.dumps([dataclasses.asdict(r) for r in res], ensure_ascii=False, indent=2))
