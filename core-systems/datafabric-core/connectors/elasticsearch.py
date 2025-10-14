# datafabric-core/datafabric/connectors/elasticsearch.py
"""
Промышленный коннектор Elasticsearch (8.x) для DataFabric.

Особенности:
- Конфигурация через pydantic (TLS/verify, Basic/Auth via API‑Key, cloud_id).
- Sync и Async клиенты (elasticsearch>=8).
- Ретраи c экспоненциальным бэкоффом и джиттером на транзиентные ошибки (429/5xx/сетевые).
- Таймауты на запросы, отдельные per‑request settings (routing, refresh, pipeline и т.п.).
- Высокоуровневые операции: index/update/delete/get/mget/search/msearch/count.
- Bulk/async_bulk с контролем размера батчей, backpressure и авто‑ретраями.
- Поиск с PIT (point‑in‑time)/search_after/scroll (fallback).
- Управление схемой: index‑template, ILM‑policy, алиасы, rollover.
- Метрики Prometheus (ops/errors/latency/throughput), OpenTelemetry‑спаны (опционально).
- Health‑check и graceful close.

Зависимости:
- elasticsearch>=8.12
- pydantic>=2

Опционально:
- prometheus-client
- opentelemetry-sdk (+ exporter)
"""

from __future__ import annotations

import os
import time
import ssl
import random
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required") from ex

# Elasticsearch client (sync/async)
try:
    from elasticsearch import Elasticsearch, AsyncElasticsearch, ApiError  # type: ignore
    from elastic_transport import ConnectionError as ESConnectionError  # type: ignore
    from elasticsearch.helpers import bulk as es_bulk, async_bulk as es_async_bulk  # type: ignore
    _ES_OK = True
except Exception as ex:  # pragma: no cover
    _ES_OK = False
    ApiError = Exception  # type: ignore
    ESConnectionError = Exception  # type: ignore

# Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    Counter = Histogram = None  # type: ignore

# OpenTelemetry (опционально)
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None


# =========================
# Конфигурация
# =========================

class ESAuthMode(str):
    BASIC = "basic"
    APIKEY = "api_key"
    NONE = "none"

class ESConfig(BaseModel):
    # Подключение
    hosts: List[str] = Field(default_factory=lambda: ["https://localhost:9200"])
    cloud_id: Optional[str] = Field(default=None, description="Elastic Cloud cloud_id (альтернатива hosts)")
    # Аутентификация
    auth_mode: str = Field(default=ESAuthMode.BASIC)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    api_key_id: Optional[str] = Field(default=None)
    api_key: Optional[str] = Field(default=None)

    # TLS
    verify_certs: bool = Field(default=True)
    ca_certs: Optional[str] = Field(default=None, description="Путь к CA bundle/CRT")
    client_cert: Optional[str] = Field(default=None)
    client_key: Optional[str] = Field(default=None)

    # Таймауты/ретраи
    request_timeout: float = Field(default=30.0)
    max_retries: int = Field(default=5)
    base_backoff_s: float = Field(default=0.2)
    max_backoff_s: float = Field(default=4.0)

    # Bulk
    bulk_batch_size: int = Field(default=1000)
    bulk_max_bytes: int = Field(default=5 * 1024 * 1024)  # 5 MiB
    bulk_concurrency: int = Field(default=2)  # для async_bulk

    # Метки
    default_index: Optional[str] = Field(default=None)
    client_name: str = Field(default="datafabric-es")

    @field_validator("auth_mode")
    @classmethod
    def _chk_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in (ESAuthMode.BASIC, ESAuthMode.APIKEY, ESAuthMode.NONE):
            raise ValueError("auth_mode must be basic|api_key|none")
        return v

    @classmethod
    def from_env(cls) -> "ESConfig":
        return cls(
            hosts=[h.strip() for h in os.getenv("ES_HOSTS", "https://localhost:9200").split(",") if h.strip()],
            cloud_id=os.getenv("ES_CLOUD_ID"),
            auth_mode=os.getenv("ES_AUTH_MODE", ESAuthMode.BASIC),
            username=os.getenv("ES_USER"),
            password=os.getenv("ES_PASS"),
            api_key_id=os.getenv("ES_API_KEY_ID"),
            api_key=os.getenv("ES_API_KEY"),
            verify_certs=os.getenv("ES_VERIFY", "true").lower() == "true",
            ca_certs=os.getenv("ES_CA_CERTS"),
            client_cert=os.getenv("ES_CLIENT_CERT"),
            client_key=os.getenv("ES_CLIENT_KEY"),
            request_timeout=float(os.getenv("ES_TIMEOUT", "30")),
            max_retries=int(os.getenv("ES_MAX_RETRIES", "5")),
            base_backoff_s=float(os.getenv("ES_BASE_BACKOFF", "0.2")),
            max_backoff_s=float(os.getenv("ES_MAX_BACKOFF", "4.0")),
            bulk_batch_size=int(os.getenv("ES_BULK_BATCH", "1000")),
            bulk_max_bytes=int(os.getenv("ES_BULK_MAX_BYTES", str(5 * 1024 * 1024))),
            bulk_concurrency=int(os.getenv("ES_BULK_CONCURRENCY", "2")),
            default_index=os.getenv("ES_DEFAULT_INDEX"),
            client_name=os.getenv("ES_CLIENT_NAME", "datafabric-es"),
        )


# =========================
# Метрики
# =========================

def _build_metrics(ns: str = "datafabric_es") -> Dict[str, Any]:
    if not _PROM:
        return {}
    labels = ("op",)
    return {
        "ops": Counter(f"{ns}_ops_total", "Операции ES", labels),
        "errors": Counter(f"{ns}_errors_total", "Ошибки ES", labels),
        "latency": Histogram(f"{ns}_latency_seconds", "Латентность операций ES", labels),
        "bulk_docs": Counter(f"{ns}_bulk_docs_total", "Обработано документов в bulk"),
        "bulk_failed": Counter(f"{ns}_bulk_failed_total", "Проваленных документов в bulk"),
        "search_hits": Counter(f"{ns}_search_hits_total", "Считано документов search"),
    }


# =========================
# Ретраи/бэкофф
# =========================

def _should_retry(exc: Exception) -> bool:
    if isinstance(exc, (ESConnectionError, TimeoutError, OSError)):
        return True
    if isinstance(exc, ApiError):
        # Retry на HTTP 429 и 5xx
        try:
            status = getattr(exc, "status", None) or getattr(exc, "meta", None).status  # type: ignore
        except Exception:
            status = None
        if status is not None and (status == 429 or 500 <= int(status) < 600):
            return True
        # строки на случай оберток
        text = str(exc).lower()
        for key in ("timeout", "temporar", "unavailable", "connection", "reset", "too many"):
            if key in text:
                return True
    return False

def _backoff(attempt: int, base: float, cap: float) -> float:
    t = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(0, t)


# =========================
# Коннектор
# =========================

@dataclass
class ESConnector:
    config: ESConfig
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("datafabric.connectors.elasticsearch"))

    _es: Optional[Elasticsearch] = field(init=False, default=None)
    _aes: Optional[AsyncElasticsearch] = field(init=False, default=None)
    _metrics: Dict[str, Any] = field(init=False, default_factory=dict)
    _closed: bool = field(init=False, default=True)

    def __post_init__(self) -> None:
        if not _ES_OK:
            raise RuntimeError("elasticsearch>=8 is not installed")
        self.logger.setLevel(logging.INFO)
        self._metrics = _build_metrics()
        self._es = self._build_client(async_mode=False)
        self._closed = False

    def _build_client(self, async_mode: bool) -> Union[Elasticsearch, AsyncElasticsearch]:
        common_kwargs: Dict[str, Any] = {
            "request_timeout": self.config.request_timeout,
            "retry_on_status": [429, 502, 503, 504],
            "max_retries": 0,  # управляем ретраями сами
            "headers": {"x-datafabric-client": self.config.client_name},
            "verify_certs": self.config.verify_certs,
        }
        if self.config.ca_certs:
            common_kwargs["ca_certs"] = self.config.ca_certs
        if self.config.client_cert and self.config.client_key:
            common_kwargs["client_cert"] = self.config.client_cert
            common_kwargs["client_key"] = self.config.client_key

        # Аутентификация
        if self.config.auth_mode == ESAuthMode.BASIC and self.config.username:
            common_kwargs["basic_auth"] = (self.config.username, self.config.password or "")
        elif self.config.auth_mode == ESAuthMode.APIKEY and self.config.api_key:
            # формат "id:api_key" или просто base64 key
            if self.config.api_key_id:
                common_kwargs["api_key"] = (self.config.api_key_id, self.config.api_key)
            else:
                common_kwargs["api_key"] = self.config.api_key

        if self.config.cloud_id:
            if async_mode:
                return AsyncElasticsearch(cloud_id=self.config.cloud_id, **common_kwargs)
            return Elasticsearch(cloud_id=self.config.cloud_id, **common_kwargs)
        else:
            if async_mode:
                return AsyncElasticsearch(hosts=self.config.hosts, **common_kwargs)
            return Elasticsearch(hosts=self.config.hosts, **common_kwargs)

    # ---------- lifecycle ----------

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._es:
                self._es.close()
        except Exception:
            pass
        self._closed = True

    async def aopen(self) -> None:
        if self._aes:
            return
        self._aes = self._build_client(async_mode=True)  # type: ignore

    async def aclose(self) -> None:
        if self._aes:
            try:
                await self._aes.close()  # type: ignore
            except Exception:
                pass
            self._aes = None

    # ---------- metric/timed wrappers ----------

    def _time(self, op: str, fn, *args, **kwargs):
        t0 = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"es.{op}"):
                    return fn(*args, **kwargs)
            return fn(*args, **kwargs)
        except Exception as ex:
            if self._metrics:
                try:
                    self._metrics["errors"].labels(op).inc()
                except Exception:
                    pass
            raise
        finally:
            if self._metrics:
                try:
                    self._metrics["ops"].labels(op).inc()
                    self._metrics["latency"].labels(op).observe(time.perf_counter() - t0)
                except Exception:
                    pass

    async def _atime(self, op: str, fn, *args, **kwargs):
        t0 = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span(f"es.{op}"):
                    return await fn(*args, **kwargs)
            return await fn(*args, **kwargs)
        except Exception as ex:
            if self._metrics:
                try:
                    self._metrics["errors"].labels(op).inc()
                except Exception:
                    pass
            raise
        finally:
            if self._metrics:
                try:
                    self._metrics["ops"].labels(op).inc()
                    self._metrics["latency"].labels(op).observe(time.perf_counter() - t0)
                except Exception:
                    pass

    def _retrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return self._time(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _should_retry(ex):
                    self.logger.error("es_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_backoff_s, self.config.max_backoff_s)
                self.logger.warning("es_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                time.sleep(sleep_for)

    async def _aretrying(self, op: str, fn, *args, **kwargs):
        attempts = 0
        while True:
            try:
                return await self._atime(op, fn, *args, **kwargs)
            except Exception as ex:
                attempts += 1
                if attempts > self.config.max_retries or not _should_retry(ex):
                    self.logger.error("es_op_failed", extra={"op": op, "attempts": attempts, "error": str(ex)})
                    raise
                sleep_for = _backoff(attempts, self.config.base_backoff_s, self.config.max_backoff_s)
                self.logger.warning("es_op_retry", extra={"op": op, "attempt": attempts, "sleep": sleep_for})
                await __import__("asyncio").sleep(sleep_for)

    # ---------- базовые операции (sync) ----------

    def ping(self) -> bool:
        def _do():
            return bool(self._es.ping())  # type: ignore
        return self._retrying("ping", _do)

    def get(self, index: str, id: str, *, realtime: bool = True, _source: Union[bool, List[str]] = True) -> Dict[str, Any]:
        def _do():
            return self._es.get(index=index, id=id, realtime=realtime, _source=_source)  # type: ignore
        return self._retrying("get", _do)

    def index(self, index: str, doc: Dict[str, Any], *, id: Optional[str] = None,
              refresh: Optional[str] = None, pipeline: Optional[str] = None, routing: Optional[str] = None) -> Dict[str, Any]:
        def _do():
            return self._es.index(index=index, id=id, document=doc, refresh=refresh, pipeline=pipeline, routing=routing)  # type: ignore
        return self._retrying("index", _do)

    def update(self, index: str, id: str, doc: Dict[str, Any], *, refresh: Optional[str] = None) -> Dict[str, Any]:
        def _do():
            return self._es.update(index=index, id=id, doc={"doc": doc}, refresh=refresh)  # type: ignore
        return self._retrying("update", _do)

    def delete(self, index: str, id: str, *, refresh: Optional[str] = None) -> Dict[str, Any]:
        def _do():
            return self._es.delete(index=index, id=id, refresh=refresh)  # type: ignore
        return self._retrying("delete", _do)

    def search(self, index: Union[str, List[str]], query: Dict[str, Any], *,
               size: int = 10, from_: int = 0, sort: Optional[List[str]] = None,
               track_total_hits: Union[bool, int] = True, _source: Union[bool, List[str]] = True) -> Dict[str, Any]:
        def _do():
            return self._es.search(index=index, query=query, size=size, from_=from_, sort=sort,
                                   track_total_hits=track_total_hits, _source=_source)  # type: ignore
        res = self._retrying("search", _do)
        if self._metrics:
            try:
                self._metrics["search_hits"].inc(res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else len(res["hits"]["hits"]))
            except Exception:
                pass
        return res

    def mget(self, index: str, ids: Sequence[str], _source: Union[bool, List[str]] = True) -> Dict[str, Any]:
        def _do():
            return self._es.mget(index=index, ids=list(ids), _source=_source)  # type: ignore
        return self._retrying("mget", _do)

    def count(self, index: Union[str, List[str]], query: Optional[Dict[str, Any]] = None) -> int:
        def _do():
            return int(self._es.count(index=index, query=query or {"match_all": {}})["count"])  # type: ignore
        return self._retrying("count", _do)

    # ---------- bulk (sync) ----------

    def bulk(self, actions: Iterable[Dict[str, Any]], *, stats: bool = True, refresh: Optional[str] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """
        actions: итерируемый поток { "_op_type": "index|update|delete", "_index": "...", "_id": "...", "doc"/"_source": {...} }
        """
        def _do():
            ok, errors = es_bulk(self._es, actions, chunk_size=self.config.bulk_batch_size, request_timeout=self.config.request_timeout, refresh=refresh)  # type: ignore
            return ok, errors
        ok, errors = self._retrying("bulk", _do)
        if self._metrics:
            try:
                self._metrics["bulk_docs"].inc(int(ok))
                self._metrics["bulk_failed"].inc(len(errors))
            except Exception:
                pass
        return ok, errors

    # ---------- async API ----------

    async def aping(self) -> bool:
        await self.aopen()
        async def _do():
            return bool(await self._aes.ping())  # type: ignore
        return await self._aretrying("ping", _do)

    async def aget(self, index: str, id: str, **kwargs) -> Dict[str, Any]:
        await self.aopen()
        async def _do():
            return await self._aes.get(index=index, id=id, **kwargs)  # type: ignore
        return await self._aretrying("get", _do)

    async def aindex(self, index: str, doc: Dict[str, Any], *, id: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        await self.aopen()
        async def _do():
            return await self._aes.index(index=index, id=id, document=doc, **kwargs)  # type: ignore
        return await self._aretrying("index", _do)

    async def aupdate(self, index: str, id: str, doc: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        await self.aopen()
        async def _do():
            return await self._aes.update(index=index, id=id, doc={"doc": doc}, **kwargs)  # type: ignore
        return await self._aretrying("update", _do)

    async def adelete(self, index: str, id: str, **kwargs) -> Dict[str, Any]:
        await self.aopen()
        async def _do():
            return await self._aes.delete(index=index, id=id, **kwargs)  # type: ignore
        return await self._aretrying("delete", _do)

    async def asearch(self, index: Union[str, List[str]], query: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        await self.aopen()
        async def _do():
            return await self._aes.search(index=index, query=query, **kwargs)  # type: ignore
        res = await self._aretrying("search", _do)
        if self._metrics:
            try:
                self._metrics["search_hits"].inc(res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else len(res["hits"]["hits"]))
            except Exception:
                pass
        return res

    async def abulk(self, actions: Iterable[Dict[str, Any]], *, refresh: Optional[str] = None) -> Tuple[int, List[Dict[str, Any]]]:
        await self.aopen()
        async def _do():
            return await es_async_bulk(self._aes, actions, chunk_size=self.config.bulk_batch_size,
                                       request_timeout=self.config.request_timeout, refresh=refresh,
                                       max_concurrency=self.config.bulk_concurrency)  # type: ignore
        ok, errors = await self._aretrying("bulk", _do)
        if self._metrics:
            try:
                self._metrics["bulk_docs"].inc(int(ok))
                self._metrics["bulk_failed"].inc(len(errors))
            except Exception:
                pass
        return ok, errors

    # ---------- PIT / search_after / scroll ----------

    def open_pit(self, index: Union[str, List[str]], keep_alive: str = "1m") -> str:
        def _do():
            return self._es.open_point_in_time(index=index, keep_alive=keep_alive)["id"]  # type: ignore
        return self._retrying("open_pit", _do)

    def close_pit(self, pit_id: str) -> bool:
        def _do():
            return bool(self._es.close_point_in_time(body={"id": pit_id})["succeeded"])  # type: ignore
        return self._retrying("close_pit", _do)

    def scan_pit(self, index: Union[str, List[str]], query: Dict[str, Any], *, page_size: int = 1000,
                 keep_alive: str = "1m", sort: Optional[List[Dict[str, str]]] = None,
                 _source: Union[bool, List[str]] = True) -> Iterable[Dict[str, Any]]:
        pit = self.open_pit(index, keep_alive=keep_alive)
        try:
            search_after = None
            while True:
                def _do():
                    return self._es.search(
                        size=page_size,
                        query=query,
                        sort=sort or [{"_shard_doc": "asc"}],
                        search_after=search_after,
                        pit={"id": pit, "keep_alive": keep_alive},
                        _source=_source,
                        track_total_hits=False,
                    )
                res = self._retrying("search_pit", _do)
                hits = res["hits"]["hits"]
                if not hits:
                    break
                for h in hits:
                    yield h
                search_after = hits[-1]["sort"]
        finally:
            with suppress(Exception):
                self.close_pit(pit)

    def scroll(self, index: Union[str, List[str]], query: Dict[str, Any], *, page_size: int = 1000, keep_alive: str = "1m") -> Iterable[Dict[str, Any]]:
        def _init():
            return self._es.search(index=index, query=query, scroll=keep_alive, size=page_size)  # type: ignore
        res = self._retrying("scroll_init", _init)
        scroll_id = res.get("_scroll_id")
        try:
            while True:
                hits = res["hits"]["hits"]
                if not hits:
                    break
                for h in hits:
                    yield h
                def _next():
                    return self._es.scroll(scroll_id=scroll_id, scroll=keep_alive)  # type: ignore
                res = self._retrying("scroll_next", _next)
                scroll_id = res.get("_scroll_id")
        finally:
            if scroll_id:
                with suppress(Exception):
                    self._es.clear_scroll(scroll_id=scroll_id)  # type: ignore

    # ---------- Индекс/схемы/ILM ----------

    def ensure_template(self, name: str, template_body: Dict[str, Any]) -> None:
        """
        Идемпотентно создаёт/обновляет index template (component или обычный).
        """
        def _get():
            return self._es.indices.get_index_template(name=name, ignore=404)  # type: ignore
        exists = False
        try:
            res = self._retrying("get_index_template", _get)
            exists = bool(res and res.get("index_templates"))
        except Exception:
            exists = False

        def _put():
            return self._es.indices.put_index_template(name=name, template=template_body.get("template") or template_body, **{k: v for k, v in template_body.items() if k != "template"})  # type: ignore
        self._retrying("put_index_template", _put)

    def ensure_ilm_policy(self, name: str, policy_body: Dict[str, Any]) -> None:
        def _put():
            return self._es.ilm.put_lifecycle(policy=name, policy=policy_body)  # type: ignore
        self._retrying("put_ilm_policy", _put)

    def ensure_index_with_alias(self, index_alias: str, settings: Optional[Dict[str, Any]] = None,
                                mappings: Optional[Dict[str, Any]] = None, ilm_policy: Optional[str] = None) -> None:
        """
        Создаёт write‑алиас с физическим индексом <alias>-000001 и подключённой ILM‑политикой.
        """
        alias = index_alias
        first_index = f"{alias}-000001"

        def _exists():
            return self._es.indices.exists_alias(name=alias)  # type: ignore
        if self._retrying("alias_exists", _exists):
            return

        body = {"aliases": {alias: {"is_write_index": True}}}
        if settings:
            body["settings"] = settings
        if mappings:
            body["mappings"] = mappings
        if ilm_policy:
            body.setdefault("settings", {}).setdefault("index", {}).setdefault("lifecycle", {})["name"] = ilm_policy

        def _create():
            return self._es.indices.create(index=first_index, **body)  # type: ignore
        self._retrying("create_index", _create)

    def rollover(self, alias: str, conditions: Dict[str, Any]) -> Dict[str, Any]:
        def _do():
            return self._es.indices.rollover(alias=alias, conditions=conditions)  # type: ignore
        return self._retrying("rollover", _do)

    def add_alias(self, index: str, alias: str, is_write: bool = False) -> None:
        def _do():
            return self._es.indices.update_aliases(actions=[{"add": {"index": index, "alias": alias, "is_write_index": is_write}}])  # type: ignore
        self._retrying("update_aliases", _do)

    def index_exists(self, index: str) -> bool:
        def _do():
            return bool(self._es.indices.exists(index=index))  # type: ignore
        return self._retrying("index_exists", _do)

    def delete_index(self, index: str, ignore_missing: bool = True) -> None:
        def _do():
            return self._es.indices.delete(index=index, ignore=[404] if ignore_missing else None)  # type: ignore
        self._retrying("delete_index", _do)

    # ---------- Health ----------

    def health(self) -> Dict[str, Any]:
        ok = False
        err = None
        try:
            ok = self.ping()
        except Exception as ex:
            err = str(ex)
        return {"ok": ok, "error": err}

    # ---------- Utils ----------

    def default_index_or(self, idx: Optional[str]) -> str:
        if idx:
            return idx
        if not self.config.default_index:
            raise ValueError("index is required and ESConfig.default_index is not set")
        return self.config.default_index


# =========================
# Вспомогательное
# =========================

from contextlib import suppress  # noqa: E402


# =========================
# Самопроверка
# =========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    try:
        cfg = ESConfig.from_env()
        es = ESConnector(cfg)
        print("Ping:", es.ping())
        print("Health:", es.health())
    except ValidationError as e:
        print("Invalid config:", e)
