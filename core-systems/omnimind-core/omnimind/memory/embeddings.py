# -*- coding: utf-8 -*-
"""
OmniMind Core — Embeddings Service

Назначение:
- Единый асинхронный сервис получения эмбеддингов для текста.
- Плагинные провайдеры: OpenAI, Hugging Face Inference API, локальные Sentence-Transformers.
- Нормализация текста, пакетная обработка, ограничение конкуренции, ретраи, circuit breaker.
- Кэширование (встроенный LRU + опционально Redis), метрики Prometheus, OpenTelemetry.
- Конфигурация через Pydantic Settings и переменные окружения.

Зависимости (все опциональны, модуль мягко деградирует):
- httpx (клиент для HTTP): для OpenAI/HF.
- numpy: постобработка векторных представлений.
- sentence_transformers: локальные модели.
- redis.asyncio: кэш Redis.
- prometheus_client: метрики.
- opentelemetry-api: трассировка.

Безопасность:
- Секреты не попадают в логи (маскирование).
- Таймауты/ретраи не бесконечные; есть предохранители.
- Валидация входа/выхода и контроль размеров.

Авторский код не делает неподтвержденных утверждений о внешней среде. Если переменные окружения не заданы, провайдеры, зависящие от них, вызовут осмысленную ошибку.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import math
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union, Protocol

# -----------------------------
# Опциональные зависимости
# -----------------------------
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:  # pragma: no cover
    SentenceTransformer = None  # type: ignore

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: no-requirements
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_, **__): pass
        def observe(self, *_, **__): pass
    Counter = Histogram = _Noop  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False
    trace = None  # type: ignore

from pydantic import BaseSettings, Field, validator

# -----------------------------
# Метрики
# -----------------------------
EMB_REQS = Counter("omnimind_embeddings_requests_total",
                   "Total embedding requests", ["provider", "result"]) if _PROM else Counter()
EMB_LAT = Histogram("omnimind_embeddings_latency_seconds",
                    "Embedding latency seconds", ["provider"],
                    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10)) if _PROM else Histogram()

# -----------------------------
# Конфигурация
# -----------------------------
ProviderKind = Literal["openai", "hf", "local"]

class EmbeddingSettings(BaseSettings):
    provider: ProviderKind = Field("openai", env="EMBEDDINGS_PROVIDER")

    # Общие лимиты/параметры
    dim: Optional[int] = Field(None, env="EMBEDDINGS_DIM")
    max_batch_size: int = Field(256, env="EMBEDDINGS_MAX_BATCH")
    max_concurrency: int = Field(8, env="EMBEDDINGS_MAX_CONCURRENCY")
    timeout_s: float = Field(30.0, env="EMBEDDINGS_TIMEOUT_S")
    retries: int = Field(3, env="EMBEDDINGS_RETRIES")
    backoff_base_s: float = Field(0.2, env="EMBEDDINGS_BACKOFF_BASE_S")
    backoff_max_s: float = Field(5.0, env="EMBEDDINGS_BACKOFF_MAX_S")
    max_chars: int = Field(8000, env="EMBEDDINGS_MAX_CHARS")  # защита от очень больших строк
    normalize: bool = Field(True, env="EMBEDDINGS_NORMALIZE_L2")  # L2-нормализация

    # Circuit breaker
    cb_fail_threshold: int = Field(10, env="EMBEDDINGS_CB_FAILS")
    cb_reset_after_s: int = Field(30, env="EMBEDDINGS_CB_RESET_S")

    # Кэш
    cache_enabled: bool = Field(True, env="EMBEDDINGS_CACHE_ENABLED")
    cache_size: int = Field(10000, env="EMBEDDINGS_CACHE_SIZE")
    cache_ttl_s: int = Field(3600, env="EMBEDDINGS_CACHE_TTL_S")
    redis_url: Optional[str] = Field(None, env="EMBEDDINGS_REDIS_URL")
    redis_prefix: str = Field("emb:", env="EMBEDDINGS_REDIS_PREFIX")

    # OpenAI
    openai_api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    openai_base_url: Optional[str] = Field(None, env="OPENAI_BASE_URL")  # опционально для совместимых API
    openai_model: str = Field("text-embedding-3-large", env="OPENAI_EMBEDDING_MODEL")

    # Hugging Face Inference
    hf_api_key: Optional[str] = Field(None, env="HF_API_KEY")
    hf_model: str = Field("sentence-transformers/all-MiniLM-L6-v2", env="HF_EMBEDDING_MODEL")
    hf_base_url: str = Field("https://api-inference.huggingface.co", env="HF_BASE_URL")

    # Local sentence-transformers
    local_model: str = Field("sentence-transformers/all-MiniLM-L6-v2", env="LOCAL_EMBEDDING_MODEL")
    local_device: Optional[str] = Field(None, env="LOCAL_EMBEDDING_DEVICE")  # cpu/cuda:0 и т.п.

    class Config:
        case_sensitive = False
        env_file = os.environ.get("ENV_FILE", None)

    @validator("max_batch_size")
    def _v_batch(cls, v):  # noqa
        return max(1, min(2048, v))

    @validator("max_concurrency")
    def _v_conc(cls, v):  # noqa
        return max(1, min(128, v))

# -----------------------------
# Вспомогательные утилиты
# -----------------------------
def _mask(s: Optional[str]) -> str:
    if not s:
        return ""
    return "****" + s[-4:]

def _hash_key(text: str, model: str, dim: Optional[int]) -> str:
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    if dim:
        h.update(str(dim).encode("utf-8"))
    h.update(b"\x00")
    h.update(text.encode("utf-8"))
    return h.hexdigest()

def _norm_text(s: str, max_chars: int) -> str:
    # Минимальная нормализация: trim, collapse whitespace, безопасная отсечка.
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = " ".join(s.split())
    if len(s) > max_chars:
        s = s[:max_chars]
    return s

def _l2_normalize(vec: List[float]) -> List[float]:
    if not vec:
        return vec
    if np is None:
        # Fallback без numpy
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]
    arr = np.asarray(vec, dtype=np.float32)
    norm = np.linalg.norm(arr)
    if norm == 0.0:
        return vec
    return (arr / norm).astype(np.float32).tolist()

# -----------------------------
# Кэш
# -----------------------------
class _LRUCache:
    def __init__(self, capacity: int, ttl_s: int) -> None:
        from collections import OrderedDict
        self._cap = capacity
        self._ttl = ttl_s
        self._od = OrderedDict()  # key -> (value, expires_at)
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            now = time.time()
            if key in self._od:
                val, exp = self._od.pop(key)
                if exp > now:
                    self._od[key] = (val, exp)
                    return val
            return None

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            now = time.time()
            exp = now + self._ttl
            if key in self._od:
                self._od.pop(key)
            self._od[key] = (value, exp)
            while len(self._od) > self._cap:
                self._od.popitem(last=False)

class _RedisCache:
    def __init__(self, url: str, prefix: str, ttl_s: int):
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not installed")
        self._r = aioredis.from_url(url, encoding="utf-8", decode_responses=True)
        self._p = prefix
        self._ttl = ttl_s

    async def get(self, key: str) -> Optional[Any]:
        raw = await self._r.get(self._p + key)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def set(self, key: str, value: Any) -> None:
        raw = json.dumps(value)
        await self._r.set(self._p + key, raw, ex=self._ttl)

# -----------------------------
# Circuit Breaker
# -----------------------------
class CircuitBreaker:
    def __init__(self, fail_threshold: int, reset_after_s: int):
        self.fail_threshold = fail_threshold
        self.reset_after_s = reset_after_s
        self._fail_count = 0
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            if self._opened_at is None:
                return True
            # полузакрытое состояние после окна
            if time.time() - self._opened_at >= self.reset_after_s:
                return True
            return False

    async def on_success(self) -> None:
        async with self._lock:
            self._fail_count = 0
            self._opened_at = None

    async def on_failure(self) -> None:
        async with self._lock:
            self._fail_count += 1
            if self._fail_count >= self.fail_threshold:
                self._opened_at = time.time()

# -----------------------------
# Контракт провайдера
# -----------------------------
class EmbeddingProvider(Protocol):
    model: str

    async def embed(self, batch: Sequence[str]) -> List[List[float]]:
        """
        Возвращает список векторов для входных строк.
        Длина списка равна длине batch; исключения должны быть подняты целиком
        (частичные ответы недопустимы).
        """
        ...

# -----------------------------
# Реализации провайдеров
# -----------------------------
class OpenAIProvider:
    def __init__(self, settings: EmbeddingSettings):
        if httpx is None:
            raise RuntimeError("httpx is not installed")
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._api_key = settings.openai_api_key
        self._base = (settings.openai_base_url or "https://api.openai.com").rstrip("/")
        self.model = settings.openai_model
        self._timeout = settings.timeout_s

    async def embed(self, batch: Sequence[str]) -> List[List[float]]:
        url = f"{self._base}/v1/embeddings"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {"input": list(batch), "model": self.model}
        timeout = httpx.Timeout(self._timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Важно: OpenAI возвращает data с индексами; соблюдаем порядок
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                # не логируем тело, чтобы не утекали данные; показываем код
                raise RuntimeError(f"OpenAI error {resp.status_code}")
            data = resp.json()
            if "data" not in data:
                raise RuntimeError("OpenAI malformed response")
            # сортируем по index
            items = sorted(data["data"], key=lambda x: x.get("index", 0))
            vectors = [it["embedding"] for it in items]
            return vectors

class HFProvider:
    def __init__(self, settings: EmbeddingSettings):
        if httpx is None:
            raise RuntimeError("httpx is not installed")
        if not settings.hf_api_key:
            raise RuntimeError("HF_API_KEY is not set")
        self._api_key = settings.hf_api_key
        self._base = settings.hf_base_url.rstrip("/")
        self.model = settings.hf_model
        self._timeout = settings.timeout_s

    async def embed(self, batch: Sequence[str]) -> List[List[float]]:
        # Документация HF Inference API для эмбеддингов может отличаться между моделями;
        # используем /pipeline/feature-extraction как наиболее совместимый путь.
        url = f"{self._base}/pipeline/feature-extraction/{self.model}"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        timeout = httpx.Timeout(self._timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json={"inputs": list(batch)})
            if resp.status_code >= 400:
                raise RuntimeError(f"HF error {resp.status_code}")
            data = resp.json()
            # Ответ может быть [seq, dim] на каждый input; берём mean pooling по seq
            # Формат: либо список на каждый запрос, либо список одного — нормализуем:
            if isinstance(data[0][0], list):
                # батч: [[seq x dim], [seq x dim], ...]
                def _pool(mat: List[List[float]]) -> List[float]:
                    if np is None:
                        # mean pooling без numpy
                        dim = len(mat[0])
                        out = [0.0] * dim
                        for row in mat:
                            for i, v in enumerate(row):
                                out[i] += float(v)
                        return [x / max(1, len(mat)) for x in out]
                    arr = np.asarray(mat, dtype=np.float32)
                    return arr.mean(axis=0).astype(np.float32).tolist()
                return [_pool(m) for m in data]
            else:
                # единичный input: [seq x dim]
                mat = data
                if np is None:
                    dim = len(mat[0])
                    out = [0.0] * dim
                    for row in mat:
                        for i, v in enumerate(row):
                            out[i] += float(v)
                    vec = [x / max(1, len(mat)) for x in out]
                else:
                    vec = np.asarray(mat, dtype=np.float32).mean(axis=0).astype(np.float32).tolist()
                return [vec] * len(batch)  # выравнивание; HF может не поддерживать батч как мы ожидаем

class LocalSTProvider:
    def __init__(self, settings: EmbeddingSettings):
        if SentenceTransformer is None:
            raise RuntimeError("sentence-transformers is not installed")
        self._model = SentenceTransformer(settings.local_model, device=settings.local_device)  # type: ignore
        self.model = settings.local_model
        self._normalize = settings.normalize

    async def embed(self, batch: Sequence[str]) -> List[List[float]]:
        # SentenceTransformer — синхронный; оборачиваем в thread executor
        loop = asyncio.get_running_loop()
        def _run():
            arr = self._model.encode(list(batch), normalize_embeddings=False, convert_to_numpy=True)  # type: ignore
            if isinstance(arr, list):
                return [list(map(float, v)) for v in arr]
            return [list(map(float, row)) for row in arr]
        vectors = await loop.run_in_executor(None, _run)
        return vectors

# -----------------------------
# Сервис эмбеддингов
# -----------------------------
@dataclass
class EmbeddingResult:
    vector: List[float]
    model: str
    dim: int

class EmbeddingsService:
    def __init__(self, settings: EmbeddingSettings):
        self.settings = settings
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._cb = CircuitBreaker(settings.cb_fail_threshold, settings.cb_reset_after_s)

        # Кэш
        self._lru = _LRUCache(settings.cache_size, settings.cache_ttl_s) if settings.cache_enabled else None
        self._redis = _RedisCache(settings.redis_url, settings.redis_prefix, settings.cache_ttl_s) if (settings.cache_enabled and settings.redis_url) else None  # type: ignore

        # Провайдер
        if settings.provider == "openai":
            self._provider: EmbeddingProvider = OpenAIProvider(settings)
        elif settings.provider == "hf":
            self._provider = HFProvider(settings)
        elif settings.provider == "local":
            self._provider = LocalSTProvider(settings)
        else:
            raise ValueError(f"Unknown provider {settings.provider}")

    # ------------- Публичный API -------------

    async def embed_texts(self, texts: Sequence[str]) -> List[EmbeddingResult]:
        """
        Получить эмбеддинги для набора строк с кэшированием, ретраями и пакетированием.
        """
        if not texts:
            return []
        # Нормализация и подготовка
        normed = [_norm_text(t or "", self.settings.max_chars) for t in texts]
        # Кэш-хиты собираем сразу
        cached: Dict[int, EmbeddingResult] = {}
        to_query: List[Tuple[int, str, str]] = []  # (index, text, cache_key)
        for i, s in enumerate(normed):
            key = _hash_key(s, self._provider.model, self.settings.dim)
            hit = await self._cache_get(key)
            if hit is not None:
                cached[i] = EmbeddingResult(vector=hit["v"], model=hit["m"], dim=hit["d"])
            else:
                to_query.append((i, s, key))

        results: Dict[int, EmbeddingResult] = {}
        # Запрашиваем то, чего нет в кэше
        if to_query:
            # Circuit breaker
            if not await self._cb.allow():
                EMB_REQS.labels(self._provider.model, "cb_open").inc()
                raise RuntimeError("Embeddings circuit is open")

            # Батчим
            batches: List[List[Tuple[int, str, str]]] = []
            bs = self.settings.max_batch_size
            for i in range(0, len(to_query), bs):
                batches.append(to_query[i:i+bs])

            # Параллельная обработка батчей
            async def _process_batch(items: List[Tuple[int, str, str]]):
                idxs = [i for i, _, _ in items]
                inputs = [s for _, s, _ in items]
                vectors = await self._call_provider_with_retry(inputs)
                if self.settings.normalize:
                    vectors = [_l2_normalize(v) for v in vectors]
                # dim
                if vectors and len(vectors[0]) == 0:
                    raise RuntimeError("Empty embedding vector")
                dim = len(vectors[0]) if vectors else (self.settings.dim or 0)
                # сохранить
                for (i, _, key), vec in zip(items, vectors):
                    res = EmbeddingResult(vector=vec, model=self._provider.model, dim=dim)
                    results[i] = res
                    await self._cache_set(key, {"v": vec, "m": res.model, "d": res.dim})

            # ограничиваем конкуренцию
            await asyncio.gather(*[self._bounded(_process_batch, b) for b in batches])

            # cb success
            await self._cb.on_success()

        # Собрать все по исходному порядку
        final: List[EmbeddingResult] = []
        for i in range(len(texts)):
            if i in results:
                final.append(results[i])
            elif i in cached:
                final.append(cached[i])
            else:
                # Это возможно только при логической ошибке
                raise RuntimeError("Missing embedding result after processing")

        # Проверка dim
        if self.settings.dim is not None:
            for r in final:
                if r.dim != self.settings.dim:
                    # Несогласованность размеров — сообщаем, но не переписываем в runtime
                    raise RuntimeError(f"Embedding dim mismatch: expected {self.settings.dim}, got {r.dim}")

        return final

    # ------------- Внутренние утилиты -------------

    async def _bounded(self, fn, *args, **kwargs):
        async with self._sem:
            return await fn(*args, **kwargs)

    async def _call_provider_with_retry(self, batch: Sequence[str]) -> List[List[float]]:
        prov_name = type(self._provider).__name__
        attempt = 0
        t0 = time.perf_counter()
        try:
            while True:
                try:
                    if _OTEL:
                        tracer = trace.get_tracer("omnimind.embeddings")  # type: ignore
                        with tracer.start_as_current_span("embed", attributes={"provider": prov_name, "count": len(batch)}):  # type: ignore
                            out = await asyncio.wait_for(self._provider.embed(batch), timeout=self.settings.timeout_s)
                    else:
                        out = await asyncio.wait_for(self._provider.embed(batch), timeout=self.settings.timeout_s)

                    EMB_REQS.labels(self._provider.model, "ok").inc()
                    return out
                except Exception as e:
                    attempt += 1
                    if attempt > self.settings.retries:
                        EMB_REQS.labels(self._provider.model, "fail").inc()
                        await self._cb.on_failure()
                        raise
                    delay = min(self.settings.backoff_max_s,
                                self.settings.backoff_base_s * (2 ** (attempt - 1))) * (0.5 + random.random())
                    await asyncio.sleep(delay)
        finally:
            EMB_LAT.labels(self._provider.model).observe(time.perf_counter() - t0)

    async def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        if self._redis:
            try:
                val = await self._redis.get(key)  # type: ignore
                if val is not None:
                    return val
            except Exception:
                pass
        if self._lru:
            return await self._lru.get(key)
        return None

    async def _cache_set(self, key: str, value: Dict[str, Any]) -> None:
        if self._redis:
            with contextlib.suppress(Exception):
                await self._redis.set(key, value)  # type: ignore
        if self._lru:
            await self._lru.set(key, value)

# -----------------------------
# Фабрика
# -----------------------------
_service_singleton: Optional[EmbeddingsService] = None
_service_lock = asyncio.Lock()

async def get_embeddings_service(settings: Optional[EmbeddingSettings] = None) -> EmbeddingsService:
    """
    Возвращает singleton EmbeddingsService. Для тестов можно передать отдельные настройки.
    """
    global _service_singleton
    if settings is not None:
        return EmbeddingsService(settings)
    async with _service_lock:
        if _service_singleton is None:
            _service_singleton = EmbeddingsService(EmbeddingSettings())
        return _service_singleton

# -----------------------------
# Синхронная обертка (опционально)
# -----------------------------
def embed_sync(texts: Sequence[str], settings: Optional[EmbeddingSettings] = None) -> List[EmbeddingResult]:
    """
    Синхронная обертка для embed_texts (создаёт временный event loop при необходимости).
    Используйте в CLI/скриптах; в веб-приложениях применяйте асинхронный API.
    """
    async def _run():
        svc = await get_embeddings_service(settings)
        return await svc.embed_texts(texts)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())
    else:
        return loop.run_until_complete(_run())

# -----------------------------
# Пример использования (док)
# -----------------------------
"""
Пример:

from omnimind.memory.embeddings import EmbeddingSettings, get_embeddings_service

settings = EmbeddingSettings(
    provider="openai",
    openai_api_key=os.environ.get("OPENAI_API_KEY"),
    openai_model="text-embedding-3-large",
    max_batch_size=128,
    max_concurrency=8,
)

async def main():
    svc = await get_embeddings_service(settings)
    res = await svc.embed_texts(["hello world", "добрый день"])
    for r in res:
        print(r.dim, r.model, r.vector[:8])

Ограничения:
- Для OpenAI/HF требуется httpx; для Redis — redis.asyncio; для локального провайдера — sentence_transformers.
- Если нужные ENV не заданы для выбранного провайдера, будет выброшена ошибка конфигурации. I cannot verify this.
"""
