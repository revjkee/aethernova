# datafabric-core/datafabric/ingest/sources/http_ingest.py
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import math
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)

import httpx
from pydantic import BaseModel, Field, HttpUrl, PositiveInt, ValidationError, root_validator, validator

# ======================================================================================
# Конфигурация источника
# ======================================================================================

PaginationMode = Literal["none", "page", "cursor", "link"]
AuthMode = Literal["none", "header", "bearer", "basic"]
BodyEncoding = Literal["json", "form", "none"]
InputFormat = Literal["json_array", "json_lines", "csv"]  # где искать записи
HashStrategy = Literal["record", "payload"]

class RetryPolicy(BaseModel):
    max_retries: int = Field(6, ge=0, le=12)
    base_delay_ms: int = Field(250, ge=10, le=5000)
    max_delay_ms: int = Field(15_000, ge=500, le=120_000)
    retry_on_status: List[int] = Field(default_factory=lambda: [408, 425, 429, 500, 502, 503, 504])
    retry_on_network: bool = True
    @validator("retry_on_status", pre=True)
    def _norm_statuses(cls, v):
        return sorted(set(int(x) for x in v or []))

class CircuitBreakerSettings(BaseModel):
    failure_threshold: int = Field(10, ge=1)
    cooldown_seconds: int = Field(30, ge=1)
    half_open_max_attempts: int = Field(3, ge=1)

class RateLimitSettings(BaseModel):
    # Token bucket
    tokens_per_second: float = Field(5.0, gt=0)
    burst: PositiveInt = 20

class CursorConfig(BaseModel):
    # Конфиг для cursor‑пагинации
    cursor_field: str = Field(..., description="Ключ курсора в ответе (data.next_cursor)")
    path_to_cursor: List[str] = Field(default_factory=list, description="Путь до курсора в JSON (например ['data','next'])")
    request_param: str = "cursor"

class PageConfig(BaseModel):
    page_param: str = "page"
    page_start: int = 1
    limit_param: Optional[str] = "limit"
    per_page: Optional[int] = Field(100, gt=0, le=10_000)
    max_pages: Optional[int] = Field(None, ge=1)

class LinkHeaderConfig(BaseModel):
    rel: str = Field("next", description='rel для выборки, по умолчанию rel="next"')

class IncrementalConfig(BaseModel):
    # Инкрементальность: ETag/Last-Modified и/или пользовательское поле маркера
    enable_etag: bool = True
    enable_last_modified: bool = True
    since_param: Optional[str] = None
    since_state_key: Optional[str] = None  # ключ в состоянии, если используем кастомный since

class ExtractionConfig(BaseModel):
    input_format: InputFormat = "json_array"
    # Путь до массива записей (для JSON). Пустой — весь корень.
    json_records_path: List[str] = Field(default_factory=list)
    # Для CSV
    csv_has_header: bool = True
    csv_delimiter: str = ","
    # Валидация записей
    schema: Optional[type[BaseModel]] = None
    # Поле/ключ для стабильного идентификатора записи (опционально)
    record_id_field: Optional[str] = None
    # Хэш‑стратегия дедупликации
    hash_strategy: HashStrategy = "record"

class AuthConfig(BaseModel):
    mode: AuthMode = "none"
    header_name: str = "Authorization"
    header_value: Optional[str] = None   # для mode=header
    bearer_token: Optional[str] = None   # для mode=bearer
    basic_username: Optional[str] = None # для mode=basic
    basic_password: Optional[str] = None # для mode=basic

    def apply(self, headers: Dict[str, str]) -> None:
        if self.mode == "header" and self.header_value:
            headers[self.header_name] = self.header_value
        elif self.mode == "bearer" and self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.mode == "basic" and self.basic_username is not None and self.basic_password is not None:
            import base64
            token = base64.b64encode(f"{self.basic_username}:{self.basic_password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"

class HTTPSourceConfig(BaseModel):
    name: str = "http_source"
    base_url: HttpUrl
    method: Literal["GET", "POST"] = "GET"
    route: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    body_encoding: BodyEncoding = "json"

    timeout_seconds: float = Field(30.0, gt=0, le=120.0)
    connect_timeout_seconds: float = Field(10.0, gt=0, le=60.0)

    pagination: PaginationMode = "none"
    page: Optional[PageConfig] = None
    cursor: Optional[CursorConfig] = None
    link: Optional[LinkHeaderConfig] = None

    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    circuit_breaker: CircuitBreakerSettings = Field(default_factory=CircuitBreakerSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    incremental: IncrementalConfig = Field(default_factory=IncrementalConfig)
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)
    request_concurrency: PositiveInt = 1

    @root_validator
    def _validate_pagination(cls, values):
        mode = values.get("pagination")
        if mode == "page" and not values.get("page"):
            raise ValueError("pagination=page requires 'page' config")
        if mode == "cursor" and not values.get("cursor"):
            raise ValueError("pagination=cursor requires 'cursor' config")
        if mode == "link" and not values.get("link"):
            raise ValueError("pagination=link requires 'link' config")
        return values

# ======================================================================================
# Состояние/чекпойнты
# ======================================================================================

class StateStore(Protocol):
    async def get(self, key: str) -> Optional[str]: ...
    async def set(self, key: str, value: str) -> None: ...

class InMemoryStateStore:
    def __init__(self) -> None:
        self._data: Dict[str, str] = {}
        self._lock = asyncio.Lock()
    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            return self._data.get(key)
    async def set(self, key: str, value: str) -> None:
        async with self._lock:
            self._data[key] = value

# ======================================================================================
# Rate limiter (token bucket)
# ======================================================================================

class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = max(0.1, rate)
        self.capacity = max(1, burst)
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delta = now - self.updated
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

# ======================================================================================
# Circuit breaker
# ======================================================================================

class CircuitBreaker:
    def __init__(self, settings: CircuitBreakerSettings):
        self.s = settings
        self.failures = 0
        self.state: Literal["closed", "open", "half_open"] = "closed"
        self.opened_at = 0.0
        self.half_open_attempts = 0

    def on_success(self):
        self.failures = 0
        self.state = "closed"
        self.half_open_attempts = 0

    def on_failure(self):
        self.failures += 1
        if self.state == "closed" and self.failures >= self.s.failure_threshold:
            self.state = "open"
            self.opened_at = time.monotonic()
        elif self.state == "half_open":
            # возврат в open
            self.state = "open"
            self.opened_at = time.monotonic()
            self.half_open_attempts = 0

    def can_pass(self) -> bool:
        now = time.monotonic()
        if self.state == "open":
            if now - self.opened_at >= self.s.cooldown_seconds:
                self.state = "half_open"
                self.half_open_attempts = 0
            else:
                return False
        if self.state == "half_open":
            if self.half_open_attempts >= self.s.half_open_max_attempts:
                return False
            self.half_open_attempts += 1
        return True

# ======================================================================================
# Утилиты
# ======================================================================================

def _jitter_backoff(attempt: int, base_ms: int, max_ms: int) -> float:
    exp = min(max_ms, base_ms * (2 ** attempt))
    return (random.random() * (exp - base_ms)) / 1000.0 + base_ms / 1000.0

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _extract_from_path(obj: Any, path: List[str]) -> Any:
    cur = obj
    for p in path or []:
        if not isinstance(cur, Mapping) or p not in cur:
            return None
        cur = cur[p]
    return cur

def _to_records_from_json(parsed: Any, path: List[str]) -> List[Dict[str, Any]]:
    node = _extract_from_path(parsed, path) if path else parsed
    if isinstance(node, list):
        return [x for x in node if isinstance(x, Mapping)]
    if isinstance(node, Mapping):
        # попытка найти массив в одном из полей
        for v in node.values():
            if isinstance(v, list) and all(isinstance(i, Mapping) for i in v):
                return v  # type: ignore
    return []

def _parse_ndjson(raw: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, Mapping):
                out.append(obj)  # type: ignore
        except Exception:
            continue
    return out

def _parse_csv(raw: bytes, delimiter: str = ",", header: bool = True) -> List[Dict[str, Any]]:
    text = raw.decode("utf-8", errors="replace")
    buf = io.StringIO(text)
    if header:
        reader = csv.DictReader(buf, delimiter=delimiter)
        return [dict(row) for row in reader]  # type: ignore
    else:
        reader = csv.reader(buf, delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return []
        # auto headers: col_0..col_n
        headers = [f"col_{i}" for i in range(len(rows[0]))]
        out = []
        for r in rows:
            out.append({h: (r[i] if i < len(r) else None) for i, h in enumerate(headers)})
        return out

# ======================================================================================
# Метрики и логи‑хуки (минимальные интерфейсы)
# ======================================================================================

class MetricsSink(Protocol):
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None: ...
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class NullMetrics:
    async def incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        return
    async def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        return

# ======================================================================================
# Основной инжестор
# ======================================================================================

@dataclass
class IngestRecord:
    source: str
    record: Dict[str, Any]
    record_id: Optional[str]
    content_hash: str
    fetched_at: float
    raw_page: Optional[bytes] = None

class HTTPIngestor:
    def __init__(
        self,
        cfg: HTTPSourceConfig,
        state: StateStore | None = None,
        metrics: MetricsSink | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.cfg = cfg
        self.state = state or InMemoryStateStore()
        self.metrics = metrics or NullMetrics()
        self._client = client
        self._bucket = TokenBucket(cfg.rate_limit.tokens_per_second, cfg.rate_limit.burst)
        self._cb = CircuitBreaker(cfg.circuit_breaker)

    async def _client_ctx(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        timeout = httpx.Timeout(
            timeout=self.cfg.timeout_seconds,
            connect=self.cfg.connect_timeout_seconds,
        )
        self._client = httpx.AsyncClient(base_url=str(self.cfg.base_url), timeout=timeout, http2=True)
        return self._client

    async def _request_once(
        self, url: str, headers: Dict[str, str], params: Dict[str, Any], body: Optional[Dict[str, Any]]
    ) -> httpx.Response:
        await self._bucket.acquire()
        client = await self._client_ctx()
        if self.cfg.method == "GET":
            return await client.get(url, headers=headers, params=params)
        else:
            if self.cfg.body_encoding == "json":
                return await client.post(url, headers=headers, params=params, json=body)
            elif self.cfg.body_encoding == "form":
                return await client.post(url, headers=headers, params=params, data=body)
            else:
                return await client.post(url, headers=headers, params=params)

    async def _request_with_retry(
        self, url: str, headers: Dict[str, str], params: Dict[str, Any], body: Optional[Dict[str, Any]]
    ) -> httpx.Response:
        attempt = 0
        while True:
            if not self._cb.can_pass():
                raise RuntimeError("circuit_open")
            t0 = time.monotonic()
            try:
                resp = await self._request_once(url, headers, params, body)
                await self.metrics.observe("http_ingest.rtt_ms", (time.monotonic() - t0) * 1000.0, {"source": self.cfg.name})
            except (httpx.TransportError, httpx.TimeoutException):
                if not self.cfg.retry.retry_on_network or attempt >= self.cfg.retry.max_retries:
                    self._cb.on_failure()
                    raise
                self._cb.on_failure()
                delay = _jitter_backoff(attempt, self.cfg.retry.base_delay_ms, self.cfg.retry.max_delay_ms)
                await asyncio.sleep(delay)
                attempt += 1
                continue

            if resp.status_code >= 200 and resp.status_code < 300:
                self._cb.on_success()
                return resp

            if resp.status_code in self.cfg.retry.retry_on_status and attempt < self.cfg.retry.max_retries:
                self._cb.on_failure()
                # Respect Retry-After when possible
                ra = resp.headers.get("Retry-After")
                if ra:
                    try:
                        delay = float(ra)
                    except Exception:
                        delay = _jitter_backoff(attempt, self.cfg.retry.base_delay_ms, self.cfg.retry.max_delay_ms)
                else:
                    delay = _jitter_backoff(attempt, self.cfg.retry.base_delay_ms, self.cfg.retry.max_delay_ms)
                await asyncio.sleep(delay)
                attempt += 1
                continue

            # окончательная ошибка
            self._cb.on_failure()
            return resp

    def _build_headers(self, etag: Optional[str], last_modified: Optional[str]) -> Dict[str, str]:
        h = dict(self.cfg.headers)
        # Auth
        AuthConfig(**{}).apply(h)  # no-op to keep type checker happy
        # применяем реальный auth
        # создаем из входного конфига, т.к. он может быть неполным для автокомплита
        # но здесь cfg.headers уже есть
        # Если у вас отдельный AuthConfig, добавьте его в HTTPSourceConfig и вызовите .apply(h)
        if hasattr(self.cfg, "auth") and isinstance(getattr(self.cfg, "auth"), AuthConfig):
            getattr(self.cfg, "auth").apply(h)  # type: ignore

        if self.cfg.incremental.enable_etag and etag:
            h["If-None-Match"] = etag
        if self.cfg.incremental.enable_last_modified and last_modified:
            h["If-Modified-Since"] = last_modified
        return h

    def _build_params(self, base: Dict[str, Any]) -> Dict[str, Any]:
        p = dict(self.cfg.query_params)
        p.update(base)
        return p

    # ------------------------------ Парсинг страницы ------------------------------

    def _extract_records(self, content: bytes, content_type: str) -> List[Dict[str, Any]]:
        fmt = self.cfg.extraction.input_format
        if fmt == "json_array":
            try:
                parsed = json.loads(content)
            except Exception:
                return []
            path = self.cfg.extraction.json_records_path
            return _to_records_from_json(parsed, path)
        elif fmt == "json_lines":
            return _parse_ndjson(content)
        elif fmt == "csv":
            return _parse_csv(content, delimiter=self.cfg.extraction.csv_delimiter, header=self.cfg.extraction.csv_has_header)
        return []

    def _validate_and_prepare(
        self, recs: List[Dict[str, Any]], raw_payload_hash: str
    ) -> List[Tuple[Dict[str, Any], Optional[str], str]]:
        out: List[Tuple[Dict[str, Any], Optional[str], str]] = []
        schema = self.cfg.extraction.schema
        rid_field = self.cfg.extraction.record_id_field
        hmode = self.cfg.extraction.hash_strategy

        for r in recs:
            record = r
            if schema:
                try:
                    model = schema.parse_obj(r)  # type: ignore
                    record = model.dict()
                except ValidationError:
                    continue
            record_id = str(record.get(rid_field)) if rid_field and record.get(rid_field) is not None else None
            if hmode == "record":
                h = _sha256_bytes(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            else:
                h = raw_payload_hash
            out.append((record, record_id, h))
        return out

    # ------------------------------ Пагинация ------------------------------

    def _next_from_link(self, resp: httpx.Response) -> Optional[str]:
        link = resp.headers.get("Link") or resp.headers.get("link")
        if not link:
            return None
        # примитивный парсер Link
        # <url>; rel="next", <url2>; rel="prev"
        parts = [p.strip() for p in link.split(",")]
        for p in parts:
            if 'rel="' + (self.cfg.link.rel if self.cfg.link else "next") + '"' in p:
                start = p.find("<")
                end = p.find(">")
                if 0 <= start < end:
                    return p[start + 1 : end]
        return None

    def _next_from_cursor(self, payload: Any) -> Optional[str]:
        if not self.cfg.cursor:
            return None
        node = _extract_from_path(payload, self.cfg.cursor.path_to_cursor)
        if not node:
            # Падаем назад на прямое поле
            node = payload.get(self.cfg.cursor.cursor_field) if isinstance(payload, Mapping) else None
        if node and isinstance(node, (str, int)):
            return str(node)
        return None

    # ------------------------------ Публичный API ------------------------------

    async def ingest(self) -> AsyncGenerator[IngestRecord, None]:
        """
        Асинхронный генератор записей.
        """
        etag_key = f"{self.cfg.name}:etag"
        lm_key = f"{self.cfg.name}:last_modified"
        since_key = self.cfg.incremental.since_state_key or f"{self.cfg.name}:since"

        etag = await self.state.get(etag_key) if self.cfg.incremental.enable_etag else None
        last_mod = await self.state.get(lm_key) if self.cfg.incremental.enable_last_modified else None
        since_val = await self.state.get(since_key) if self.cfg.incremental.since_param else None

        # Базовые параметры
        params: Dict[str, Any] = {}
        if self.cfg.pagination == "page" and self.cfg.page:
            params[self.cfg.page.page_param] = self.cfg.page.page_start
            if self.cfg.page.limit_param and self.cfg.page.per_page:
                params[self.cfg.page.limit_param] = self.cfg.page.per_page
        if self.cfg.incremental.since_param and since_val:
            params[self.cfg.incremental.since_param] = since_val

        url = self.cfg.route
        page_count = 0

        while True:
            headers = self._build_headers(etag, last_mod)
            body = self.cfg.body

            resp = await self._request_with_retry(url, headers, self._build_params(params), body)
            status = resp.status_code

            if status == 304:
                # Нет изменений
                return

            if status < 200 or status >= 300:
                # Ошибка страницы — прекращаем; retry уже был применён
                return

            raw = resp.content
            raw_hash = _sha256_bytes(raw)
            ctype = resp.headers.get("Content-Type", "application/octet-stream").split(";")[0].strip().lower()

            # Сохранить ETag/Last-Modified
            new_etag = resp.headers.get("ETag")
            if new_etag and self.cfg.incremental.enable_etag:
                await self.state.set(etag_key, new_etag)
                etag = new_etag

            new_lm = resp.headers.get("Last-Modified")
            if new_lm and self.cfg.incremental.enable_last_modified:
                await self.state.set(lm_key, new_lm)
                last_mod = new_lm

            # Парсим
            parsed_json: Any = None
            records: List[Dict[str, Any]] = []

            if ctype in ("application/json", "application/vnd.api+json", "text/json"):
                try:
                    parsed_json = resp.json()
                except Exception:
                    parsed_json = None

            if self.cfg.extraction.input_format == "json_array":
                if parsed_json is None:
                    try:
                        parsed_json = json.loads(raw)
                    except Exception:
                        parsed_json = None
                records = _to_records_from_json(parsed_json, self.cfg.extraction.json_records_path) if parsed_json is not None else []
            elif self.cfg.extraction.input_format == "json_lines":
                records = _parse_ndjson(raw)
            elif self.cfg.extraction.input_format == "csv":
                records = _parse_csv(raw, delimiter=self.cfg.extraction.csv_delimiter, header=self.cfg.extraction.csv_has_header)

            prepped = self._validate_and_prepare(records, raw_hash)
            fetched_at = time.time()

            # Эмитим записи
            for record, record_id, ch in prepped:
                yield IngestRecord(
                    source=self.cfg.name,
                    record=record,
                    record_id=record_id,
                    content_hash=ch,
                    fetched_at=fetched_at,
                )

            # Пагинация
            next_url: Optional[str] = None
            if self.cfg.pagination == "none":
                return
            elif self.cfg.pagination == "page" and self.cfg.page:
                page_count += 1
                if self.cfg.page.max_pages and page_count >= self.cfg.page.max_pages:
                    return
                # Если данных нет — прекращаем
                if not records:
                    return
                params[self.cfg.page.page_param] = int(params[self.cfg.page.page_param]) + 1
                next_url = self.cfg.route
            elif self.cfg.pagination == "cursor":
                # cursor через тело ответа
                if parsed_json is None:
                    try:
                        parsed_json = json.loads(raw)
                    except Exception:
                        parsed_json = None
                cursor = self._next_from_cursor(parsed_json or {})
                if not cursor:
                    return
                params[self.cfg.cursor.request_param] = cursor  # type: ignore
                next_url = self.cfg.route
            elif self.cfg.pagination == "link":
                n = self._next_from_link(resp)
                if not n:
                    return
                # link может быть абсолютным URL
                next_url = n

            url = next_url or self.cfg.route

# ======================================================================================
# Пример схемы записи (опционально подключайте свою)
# ======================================================================================

class ExampleRecord(BaseModel):
    id: Union[int, str]
    name: Optional[str]
    value: Optional[float]

# ======================================================================================
# Фабрика и удобная функция
# ======================================================================================

async def run_ingest(
    cfg: HTTPSourceConfig,
    state: Optional[StateStore] = None,
    metrics: Optional[MetricsSink] = None,
) -> List[IngestRecord]:
    """
    Утилита для единичного запуска с возвратом всех записей (для тестов/отладки).
    В продакшен‑пайплайне используйте HTTPIngestor.ingest() и обрабатывайте потоково.
    """
    ing = HTTPIngestor(cfg, state=state, metrics=metrics)
    out: List[IngestRecord] = []
    async for rec in ing.ingest():
        out.append(rec)
    return out

# ======================================================================================
# Мини‑самотест (локальный запуск): python http_ingest.py
# ======================================================================================

if __name__ == "__main__":
    async def _demo():
        cfg = HTTPSourceConfig(
            name="demo_json",
            base_url="https://jsonplaceholder.typicode.com",
            route="/posts",
            pagination="page",
            page=PageConfig(page_param="_page", page_start=1, limit_param="_limit", per_page=50, max_pages=2),
            extraction=ExtractionConfig(
                input_format="json_array",
                json_records_path=[],  # корень — массив объектов
                schema=ExampleRecord,
                record_id_field="id",
                hash_strategy="record",
            ),
            retry=RetryPolicy(max_retries=3, base_delay_ms=200, max_delay_ms=2000),
            rate_limit=RateLimitSettings(tokens_per_second=5, burst=10),
        )
        rs = await run_ingest(cfg)
        print(f"Fetched records: {len(rs)}")
        # показаем 1 пример
        if rs:
            print(rs[0].record)

    asyncio.run(_demo())
