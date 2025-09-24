# mythos-core/mythos/graph/indexer.py
"""
Асинхронный промышленный индексатор графа для Mythos Core.

Возможности:
- Абстракция бэкенда GraphBackend (upsert узлов/рёбер, удаление, ensure_schema, health).
- Реализация для Neo4j (async) и "сухой" бэкенд DryRun для тестов/CI.
- Валидация входных сущностей по JSON Schema Draft 2020-12 (если установлен jsonschema).
- Идемпотентность: отпечаток (sha256) содержимого -> пропуск неизменённых узлов/рёбер.
- Параллелизм и батчинг с ограничением concurrency и размерами партий.
- Ретраи с экспоненциальной паузой для временных ошибок.
- Метрики Prometheus (best-effort), структурное логирование.
- Создание индексов/констрейнтов (Neo4j) по (kind,id) и для рёбер (label:REL).

Контракты:
- "Сущность" соответствует schemas/jsonschema/v1/entity.schema.json (id, kind, attributes, ...).
- "Связь" имеет поля: from{id,kind}, to{id,kind}, type (строка RELATION_TYPE), props (опционально).

Зависимости (опционально):
- neo4j>=5 (для Neo4jBackend)
- jsonschema>=4 (для валидации)
- prometheus_client (для метрик)

Автор: platform@mythos.local
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterable, Awaitable, Dict, Iterable, List, Optional, Sequence, Tuple

# Опциональные библиотеки (no-op при отсутствии)
try:
    from jsonschema import Draft202012Validator  # type: ignore
except Exception:
    Draft202012Validator = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:
    Counter = Histogram = Gauge = None  # type: ignore

try:
    from neo4j import AsyncGraphDatabase  # type: ignore
except Exception:
    AsyncGraphDatabase = None  # type: ignore

# -------------------- Логирование --------------------

LOG = logging.getLogger("mythos.graph.indexer")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)

# -------------------- Метрики --------------------

_METRICS_ENABLED = Counter is not None and Histogram is not None and Gauge is not None

if _METRICS_ENABLED:
    M_ENTITIES = Counter(
        "mythos_graph_entities_total", "Количество обработанных сущностей", ["result"]
    )
    M_EDGES = Counter(
        "mythos_graph_edges_total", "Количество обработанных связей", ["result"]
    )
    M_LAT = Histogram(
        "mythos_graph_batch_seconds", "Длительность обработки батча, сек", buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]
    )
    M_INFLIGHT = Gauge(
        "mythos_graph_inflight", "Число одновременно обрабатываемых батчей"
    )
else:
    class _No:
        def labels(self, *args, **kwargs): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    M_ENTITIES = M_EDGES = M_LAT = M_INFLIGHT = _No()

# -------------------- Валидация --------------------

def load_entity_validator(schema_path: Optional[Path] = None):
    """
    Загружает JSON Schema валидатор сущности. Если jsonschema недоступна или файл отсутствует,
    возвращает функцию-стаб, которая ничего не делает.
    """
    if Draft202012Validator is None:
        LOG.warning("jsonschema не установлен: валидация отключена")
        return lambda _entity: None

    candidate_paths: List[Path] = []
    if schema_path:
        candidate_paths.append(schema_path)
    # стандартное расположение
    candidate_paths.append(Path(__file__).resolve().parents[2] / "schemas" / "jsonschema" / "v1" / "entity.schema.json")

    schema = None
    for p in candidate_paths:
        try:
            if p.exists():
                schema = json.loads(p.read_text(encoding="utf-8"))
                break
        except Exception as e:
            LOG.error("Ошибка чтения схемы %s: %s", p, e)

    if not schema:
        LOG.warning("Схема сущности не найдена: валидация отключена")
        return lambda _entity: None

    validator = Draft202012Validator(schema)

    def _validate(entity: Dict[str, Any]) -> None:
        errors = sorted(validator.iter_errors(entity), key=lambda e: e.path)
        if errors:
            msg = "; ".join([f"{list(e.path)}: {e.message}" for e in errors][:5])
            raise ValueError(f"Entity schema validation failed: {msg}")

    return _validate

# -------------------- Абстракции --------------------

@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    props: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""  # sha256

@dataclass(frozen=True)
class Edge:
    src_id: str
    src_kind: str
    dst_id: str
    dst_kind: str
    rel_type: str
    props: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""  # sha256

class GraphBackend:
    """
    Интерфейс бэкенда графа.
    Реализации должны быть асинхронно-безопасны и поддерживать батчевую запись.
    """

    async def ensure_schema(self) -> None:
        raise NotImplementedError

    async def upsert_nodes(self, nodes: Sequence[Node]) -> Tuple[int, int]:
        """
        Возвращает кортеж (inserted_or_updated, skipped_by_fingerprint)
        """
        raise NotImplementedError

    async def upsert_edges(self, edges: Sequence[Edge]) -> Tuple[int, int]:
        raise NotImplementedError

    async def delete_nodes(self, ids_kinds: Sequence[Tuple[str, str]]) -> int:
        raise NotImplementedError

    async def delete_edges(self, edges: Sequence[Tuple[str, str, str, str, str]]) -> int:
        """
        Удаление рёбер по (src_id, src_kind, dst_id, dst_kind, rel_type)
        """
        raise NotImplementedError

    async def health(self) -> bool:
        raise NotImplementedError

    async def close(self) -> None:
        pass

# -------------------- Реализация: DryRun --------------------

class DryRunBackend(GraphBackend):
    """
    Бэкенд, который ничего не пишет, а логирует операции. Удобен для тестов/CI.
    """

    async def ensure_schema(self) -> None:
        LOG.info("[dryrun] ensure_schema")

    async def upsert_nodes(self, nodes: Sequence[Node]) -> Tuple[int, int]:
        LOG.info("[dryrun] upsert_nodes: %d", len(nodes))
        return len(nodes), 0

    async def upsert_edges(self, edges: Sequence[Edge]) -> Tuple[int, int]:
        LOG.info("[dryrun] upsert_edges: %d", len(edges))
        return len(edges), 0

    async def delete_nodes(self, ids_kinds: Sequence[Tuple[str, str]]) -> int:
        LOG.info("[dryrun] delete_nodes: %d", len(ids_kinds))
        return len(ids_kinds)

    async def delete_edges(self, edges: Sequence[Tuple[str, str, str, str, str]]) -> int:
        LOG.info("[dryrun] delete_edges: %d", len(edges))
        return len(edges)

    async def health(self) -> bool:
        return True

# -------------------- Реализация: Neo4j --------------------

class Neo4jBackend(GraphBackend):
    """
    Async Neo4j backend. Требует neo4j>=5.
    Хранит отпечаток узла/ребра в свойстве `fingerprint`, метки: :Kind для узлов, тип отношения REL_TYPE в верхнем регистре.
    """

    def __init__(self, uri: str, user: str, password: str, database: Optional[str] = None, **driver_kwargs: Any) -> None:
        if AsyncGraphDatabase is None:
            raise RuntimeError("neo4j драйвер не установлен")
        self._driver = AsyncGraphDatabase.driver(uri, auth=(user, password), **driver_kwargs)
        self._db = database

    async def close(self) -> None:
        await self._driver.close()

    async def _run(self, cypher: str, params: Dict[str, Any]) -> Any:
        async with self._driver.session(database=self._db) as session:
            return await session.run(cypher, params)

    async def ensure_schema(self) -> None:
        cyphers = [
            # Узлы: уникальность по (kind,id)
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:__ANY__) REQUIRE (n.id) IS UNIQUE",  # placeholder
        ]
        # Neo4j не поддерживает динамические метки в DDL; создадим generic constraint через apoc не будем — вместо этого используем индекс по id
        cyphers = [
            "CREATE INDEX IF NOT EXISTS FOR (n) ON (n.id)",
            "CREATE INDEX IF NOT EXISTS FOR (n) ON (n.kind)",
            "CREATE INDEX IF NOT EXISTS FOR ()-[r]-() ON (r.id)",
        ]
        async with self._driver.session(database=self._db) as session:
            for c in cyphers:
                try:
                    await session.run(c)
                except Exception as e:
                    LOG.warning("ensure_schema warning: %s -> %s", c, e)

    async def upsert_nodes(self, nodes: Sequence[Node]) -> Tuple[int, int]:
        if not nodes:
            return 0, 0
        query = """
        UNWIND $items AS it
        CALL {
          WITH it
          MERGE (n:`%s` {id: it.id})
          ON CREATE SET n.kind = it.kind, n.created_at = timestamp(), n.fingerprint = it.fp, n += it.props
          ON MATCH  SET n.kind = it.kind,
                      n.updated_at = timestamp(),
                      n += CASE WHEN n.fingerprint <> it.fp THEN it.props ELSE {} END,
                      n.fingerprint = CASE WHEN n.fingerprint <> it.fp THEN it.fp ELSE n.fingerprint END
          RETURN CASE WHEN n.fingerprint = it.fp THEN 1 ELSE 0 END AS skipped
        }
        RETURN reduce(s=0, x IN collect(skipped) | s + x) AS skipped_count, count(*) AS total
        """ % (nodes[0].kind)  # батч по единому kind; оркестратор гарантирует группировку
        params = {
            "items": [{"id": n.id, "kind": n.kind, "props": n.props, "fp": n.fingerprint} for n in nodes]
        }
        async with self._driver.session(database=self._db) as session:
            rec = await (await session.run(query, params)).single()
            skipped = int(rec["skipped_count"]) if rec else 0
            total = int(rec["total"]) if rec else len(nodes)
            return total - skipped, skipped

    async def upsert_edges(self, edges: Sequence[Edge]) -> Tuple[int, int]:
        if not edges:
            return 0, 0
        e0 = edges[0]
        rel = e0.rel_type.upper()
        query = """
        UNWIND $items AS it
        MERGE (a:`%s` {id: it.aid})
        MERGE (b:`%s` {id: it.bid})
        MERGE (a)-[r:%s {id: it.rid}]->(b)
        ON CREATE SET r.created_at = timestamp(), r.fingerprint = it.fp, r += it.props
        ON MATCH  SET r.updated_at = timestamp(),
                    r += CASE WHEN r.fingerprint <> it.fp THEN it.props ELSE {} END,
                    r.fingerprint = CASE WHEN r.fingerprint <> it.fp THEN it.fp ELSE r.fingerprint END
        RETURN CASE WHEN r.fingerprint = it.fp THEN 1 ELSE 0 END AS skipped
        """ % (e0.src_kind, e0.dst_kind, rel)
        params = {
            "items": [{
                "aid": e.src_id, "bid": e.dst_id, "rid": _edge_id(e), "props": e.props, "fp": e.fingerprint
            } for e in edges]
        }
        async with self._driver.session(database=self._db) as session:
            result = await session.run(query, params)
            skipped = 0
            async for rec in result:
                skipped += int(rec["skipped"])
            total = len(edges)
            return total - skipped, skipped

    async def delete_nodes(self, ids_kinds: Sequence[Tuple[str, str]]) -> int:
        if not ids_kinds:
            return 0
        # Группируем по kind
        total = 0
        async with self._driver.session(database=self._db) as session:
            kinds: Dict[str, List[str]] = {}
            for _id, kind in ids_kinds:
                kinds.setdefault(kind, []).append(_id)
            for kind, ids in kinds.items():
                q = f"""
                UNWIND $ids AS idv
                MATCH (n:`{kind}` {{id: idv}})
                DETACH DELETE n
                """
                await session.run(q, {"ids": ids})
                total += len(ids)
        return total

    async def delete_edges(self, edges: Sequence[Tuple[str, str, str, str, str]]) -> int:
        if not edges:
            return 0
        # edges: (src_id, src_kind, dst_id, dst_kind, rel_type)
        total = 0
        async with self._driver.session(database=self._db) as session:
            # удаляем по rid, чтобы не строить сложные матчи
            rids = [_edge_id(Edge(a, ak, b, bk, rel)) for a, ak, b, bk, rel in edges]
            q = """
            UNWIND $ids AS rid
            MATCH ()-[r {id: rid}]-()
            DELETE r
            """
            await session.run(q, {"ids": rids})
            total = len(rids)
        return total

    async def health(self) -> bool:
        try:
            async with self._driver.session(database=self._db) as session:
                rec = await (await session.run("RETURN 1 as ok")).single()
                return bool(rec and rec["ok"] == 1)
        except Exception as e:
            LOG.error("Neo4j health failed: %s", e)
            return False

# -------------------- Вспомогательные функции --------------------

def _fingerprint(obj: Any) -> str:
    """Детерминированный sha256 отпечаток для идемпотентности."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _edge_id(e: Edge) -> str:
    """Детерминированный идентификатор ребра."""
    base = f"{e.src_kind}:{e.src_id}->{e.rel_type.upper()}->{e.dst_kind}:{e.dst_id}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]

def entity_to_node(entity: Dict[str, Any]) -> Node:
    node_props = dict(entity)
    # Приводим к компактным пропсам
    node_props.pop("id", None)
    node_props.pop("kind", None)
    fp = _fingerprint({"kind": entity.get("kind"), "attributes": entity.get("attributes"), "metadata": entity.get("metadata")})
    return Node(id=str(entity["id"]), kind=str(entity["kind"]), props=node_props, fingerprint=fp)

def relation_to_edge(rel: Dict[str, Any]) -> Edge:
    """
    Ожидаемый формат:
    {
      "from": {"id": "...", "kind": "..."},
      "to":   {"id": "...", "kind": "..."},
      "type": "REL_TYPE",
      "props": {...}  # опционально
    }
    """
    props = dict(rel.get("props") or {})
    fp = _fingerprint({"type": rel["type"], "props": props})
    return Edge(
        src_id=str(rel["from"]["id"]),
        src_kind=str(rel["from"]["kind"]),
        dst_id=str(rel["to"]["id"]),
        dst_kind=str(rel["to"]["kind"]),
        rel_type=str(rel["type"]),
        props=props,
        fingerprint=fp,
    )

# -------------------- Ретраи --------------------

class RetryPolicy:
    def __init__(self, *, attempts: int = 5, base_delay: float = 0.1, max_delay: float = 2.0, jitter: float = 0.1) -> None:
        self.attempts = attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

    async def run(self, fn, *args, **kwargs):
        last_exc = None
        for i in range(self.attempts):
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                last_exc = e
                delay = min(self.max_delay, self.base_delay * (2 ** i)) * (1 + (self.jitter * (2 * (os.urandom(1)[0] / 255) - 1)))
                LOG.warning("retry %d/%d after error: %s (sleep %.3fs)", i + 1, self.attempts, e, delay)
                await asyncio.sleep(delay)
        assert last_exc is not None
        raise last_exc

# -------------------- Индексатор --------------------

@dataclass
class IndexerConfig:
    batch_size_nodes: int = 500
    batch_size_edges: int = 1000
    concurrency: int = 4
    validate: bool = True
    create_schema_on_start: bool = True
    stop_on_validation_error: bool = True

class AsyncGraphIndexer:
    """
    Высокоуровневый асинхронный индексатор. Управляет батчингом, параллелизмом, ретраями и валидацией.
    """

    def __init__(self, backend: GraphBackend, config: Optional[IndexerConfig] = None, schema_path: Optional[Path] = None) -> None:
        self._backend = backend
        self._cfg = config or IndexerConfig()
        self._retry = RetryPolicy()
        self._validate_entity = load_entity_validator(schema_path) if self._cfg.validate else (lambda _e: None)

    async def start(self) -> None:
        if self._cfg.create_schema_on_start:
            await self._retry.run(self._backend.ensure_schema)
        ok = await self._backend.health()
        if not ok:
            raise RuntimeError("backend health check failed")

    async def close(self) -> None:
        await self._backend.close()

    async def index_entities(self, entities: AsyncIterable[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Индексация сущностей. Возвращает (upserted, skipped).
        """
        up, sk = 0, 0
        async for batch in _abatch(entities, self._cfg.batch_size_nodes):
            nodes: List[Node] = []
            for e in batch:
                if self._cfg.validate:
                    try:
                        self._validate_entity(e)
                    except Exception as ve:
                        LOG.error("validation failed for id=%s kind=%s: %s", e.get("id"), e.get("kind"), ve)
                        if self._cfg.stop_on_validation_error:
                            raise
                        else:
                            continue
                nodes.append(entity_to_node(e))

            # Группируем по kind для оптимизации Neo4j MERGE (одна метка в запросе)
            for kind, group in _group_by(nodes, key=lambda n: n.kind).items():
                t0 = time.perf_counter()
                M_INFLIGHT.set(1)
                try:
                    inserted, skipped = await self._retry.run(self._backend.upsert_nodes, group)
                finally:
                    M_INFLIGHT.set(0)
                    M_LAT.observe(time.perf_counter() - t0)
                up += inserted
                sk += skipped
                M_ENTITIES.labels(result="upserted").inc(inserted)
                M_ENTITIES.labels(result="skipped").inc(skipped)
        return up, sk

    async def index_relations(self, relations: AsyncIterable[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Индексация связей. Возвращает (upserted, skipped).
        """
        up, sk = 0, 0
        async for batch in _abatch(relations, self._cfg.batch_size_edges):
            edges = [relation_to_edge(r) for r in batch]
            # Группируем по (src_kind, dst_kind, rel_type), чтобы уменьшить число шаблонов
            for key, group in _group_by(edges, key=lambda e: (e.src_kind, e.dst_kind, e.rel_type.upper())).items():
                t0 = time.perf_counter()
                M_INFLIGHT.set(1)
                try:
                    inserted, skipped = await self._retry.run(self._backend.upsert_edges, group)
                finally:
                    M_INFLIGHT.set(0)
                    M_LAT.observe(time.perf_counter() - t0)
                up += inserted
                sk += skipped
                M_EDGES.labels(result="upserted").inc(inserted)
                M_EDGES.labels(result="skipped").inc(skipped)
        return up, sk

# -------------------- Утилиты батчинга --------------------

async def _abatch(source: AsyncIterable[Any], size: int) -> AsyncIterable[List[Any]]:
    buf: List[Any] = []
    async for item in source:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf

def _group_by(items: Iterable[Any], key) -> Dict[Any, List[Any]]:
    out: Dict[Any, List[Any]] = {}
    for it in items:
        k = key(it)
        out.setdefault(k, []).append(it)
    return out

# -------------------- Пример использования --------------------
# Эти функции иллюстрируют, как можно прокачивать data-стримы в индексатор.

async def example_stream_entities(rows: Iterable[Dict[str, Any]]) -> AsyncIterable[Dict[str, Any]]:
    for r in rows:
        yield r
        await asyncio.sleep(0)

async def example_main() -> None:
    """
    Пример: загрузка NDJSON со списком сущностей и связей и индексация в Neo4j или DryRun.
    Переменные окружения:
      GRAPH_BACKEND=neo4j|dryrun
      NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DB
    """
    backend_name = os.getenv("GRAPH_BACKEND", "dryrun").lower()
    if backend_name == "neo4j":
        if AsyncGraphDatabase is None:
            raise RuntimeError("neo4j driver is not installed")
        backend = Neo4jBackend(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "neo4j"),
            database=os.getenv("NEO4J_DB") or None,
        )
    else:
        backend = DryRunBackend()

    indexer = AsyncGraphIndexer(backend, IndexerConfig())
    await indexer.start()

    # Примерные данные
    entities = [
        {"id": "u1", "kind": "user", "version": 1, "status": "active", "created_at": "2025-01-01T00:00:00Z",
         "attributes": {"username": "alice", "email": "alice@example.com"}},
        {"id": "c1", "kind": "content", "version": 1, "status": "active", "created_at": "2025-01-01T00:00:00Z",
         "attributes": {"title": "Hello", "locale": "en"}}
    ]
    relations = [
        {"from": {"id": "u1", "kind": "user"}, "to": {"id": "c1", "kind": "content"}, "type": "AUTHORED", "props": {"since": 2025}}
    ]

    up_nodes, sk_nodes = await indexer.index_entities(example_stream_entities(entities))
    LOG.info("entities: upserted=%d skipped=%d", up_nodes, sk_nodes)

    async def rel_stream():
        for r in relations:
            yield r
            await asyncio.sleep(0)

    up_edges, sk_edges = await indexer.index_relations(rel_stream())
    LOG.info("edges: upserted=%d skipped=%d", up_edges, sk_edges)

    await indexer.close()

if __name__ == "__main__":
    # Позволяет запускать модуль напрямую для ручной проверки.
    asyncio.run(example_main())
