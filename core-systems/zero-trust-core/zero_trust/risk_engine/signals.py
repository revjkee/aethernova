# zero-trust-core/zero_trust/risk_engine/signals.py
from __future__ import annotations

import abc
import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, Iterable, List, Mapping, Optional, Tuple

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - httpx optional
    httpx = None  # type: ignore

try:
    from redis import asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover - redis optional
    aioredis = None  # type: ignore

from pydantic import BaseModel, Field, PositiveInt, ValidationError, root_validator

logger = logging.getLogger("zt.risk.signals")


# =========================
# Errors / Enums
# =========================

class SignalError(Exception):
    pass

class ProviderUnavailable(SignalError):
    pass

class StalePolicy(str, Enum):
    fail = "fail"
    warn = "warn"
    ignore = "ignore"

class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class FetchStatus(str, Enum):
    ok = "ok"
    stale = "stale"
    missing = "missing"
    error = "error"


# =========================
# Utilities
# =========================

def utc_now_s() -> int:
    return int(time.time())

def _jptr(data: Any, path: str, default: Any = None) -> Any:
    """
    Очень легкий json-pointer/dot-path: 'a.b[0].c' и 'a.b.0.c' поддерживаются.
    """
    if path in ("", ".", "/"):
        return data
    cur = data
    for token in re.split(r"[./]", path.strip(".")):
        if token == "":
            continue
        if isinstance(cur, Mapping):
            if token.endswith("]"):
                # key like key[0]
                m = re.match(r"([^\[]+)\[(\d+)\]$", token)
                if m:
                    k, idx = m.group(1), int(m.group(2))
                    cur = cur.get(k, [])
                    if isinstance(cur, (list, tuple)) and 0 <= idx < len(cur):
                        cur = cur[idx]
                        continue
                    return default
            cur = cur.get(token, default)
        elif isinstance(cur, (list, tuple)):
            try:
                i = int(token)
                cur = cur[i]
            except Exception:
                return default
        else:
            return default
    return cur

def flatten_dot(data: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None, depth: int = 0, max_depth: int = 12) -> Dict[str, Any]:
    if out is None:
        out = {}
    if depth > max_depth:
        return out
    if isinstance(data, Mapping):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten_dot(v, key, out, depth + 1, max_depth)
    elif isinstance(data, (list, tuple)):
        for i, v in enumerate(data):
            key = f"{prefix}.{i}" if prefix else str(i)
            flatten_dot(v, key, out, depth + 1, max_depth)
    else:
        out[prefix] = data
    return out

def redact_pii(data: Any, fields: Iterable[str] = ("email", "ssn", "pan", "password", "authorization", "cookie")) -> Any:
    """
    Редакция PII по полям (dot‑ключам) и базовым паттернам.
    """
    if not isinstance(data, (dict, list, tuple)):
        return data
    flat = flatten_dot(data)
    # простые маски
    email_re = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
    pan_re = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    redacted = dict(flat)
    for k, v in flat.items():
        if any(f in k.lower() for f in fields):
            redacted[k] = "***"
            continue
        if isinstance(v, str):
            if email_re.search(v):
                redacted[k] = email_re.sub("***", v)
            elif pan_re.search(v):
                redacted[k] = pan_re.sub("***", v)
    # собрать обратно неглубоко (для логов оставим плоский вид)
    return redacted


# =========================
# Cache Abstraction
# =========================

class CacheStore(abc.ABC):
    @abc.abstractmethod
    async def get(self, key: str) -> Optional[Tuple[int, bytes]]: ...
    @abc.abstractmethod
    async def set(self, key: str, value: bytes, ttl_s: int) -> None: ...
    @abc.abstractmethod
    async def invalidate(self, key: str) -> None: ...

class MemoryCache(CacheStore):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[int, bytes]] = {}

    async def get(self, key: str) -> Optional[Tuple[int, bytes]]:
        item = self._data.get(key)
        if not item:
            return None
        exp, blob = item
        if utc_now_s() >= exp:
            self._data.pop(key, None)
            return None
        return item

    async def set(self, key: str, value: bytes, ttl_s: int) -> None:
        self._data[key] = (utc_now_s() + max(1, ttl_s), value)

    async def invalidate(self, key: str) -> None:
        self._data.pop(key, None)

class RedisCache(CacheStore):  # pragma: no cover - requires redis
    def __init__(self, redis_url: str) -> None:
        if not aioredis:
            raise ProviderUnavailable("redis package not installed")
        self.r = aioredis.from_url(redis_url, encoding=None, decode_responses=False)

    async def get(self, key: str) -> Optional[Tuple[int, bytes]]:
        p = self.r.pipeline()
        p.get(key)
        p.ttl(key)
        res = await p.execute()
        blob, ttl = res[0], res[1]
        if blob is None or ttl is None or ttl < 0:
            return None
        return (utc_now_s() + int(ttl), blob)

    async def set(self, key: str, value: bytes, ttl_s: int) -> None:
        await self.r.set(key, value, ex=ttl_s)

    async def invalidate(self, key: str) -> None:
        await self.r.delete(key)


# =========================
# RateLimiter & CircuitBreaker
# =========================

class TokenBucket:
    def __init__(self, rate_per_s: float, burst: int) -> None:
        self.rate = rate_per_s
        self.capacity = burst
        self.tokens = burst
        self.timestamp = time.perf_counter()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.perf_counter()
            delta = now - self.timestamp
            self.timestamp = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens < 1:
                # sleep до пополнения 1 токена
                need = (1 - self.tokens) / self.rate
                await asyncio.sleep(need)
                self.tokens = 0
            else:
                self.tokens -= 1

class CircuitBreakerState(str, Enum):
    closed = "closed"
    open = "open"
    half_open = "half_open"

class CircuitBreaker:
    def __init__(self, failures: int = 5, reset_timeout_s: int = 30) -> None:
        self.failures = failures
        self.reset_timeout_s = reset_timeout_s
        self.count = 0
        self.state = CircuitBreakerState.closed
        self.opened_at = 0.0
        self._lock = asyncio.Lock()

    async def before(self) -> None:
        async with self._lock:
            if self.state == CircuitBreakerState.open:
                if time.time() - self.opened_at >= self.reset_timeout_s:
                    self.state = CircuitBreakerState.half_open
                else:
                    raise ProviderUnavailable("circuit open")

    async def success(self) -> None:
        async with self._lock:
            self.count = 0
            self.state = CircuitBreakerState.closed

    async def failure(self) -> None:
        async with self._lock:
            self.count += 1
            if self.count >= self.failures:
                self.state = CircuitBreakerState.open
                self.opened_at = time.time()


# =========================
# Signal Spec / Result
# =========================

class SignalSpec(BaseModel):
    id: str = Field(..., description="Уникальный идентификатор сигнала, напр. mdm.device")
    provider: str = Field(..., description="Идентификатор провайдера (в реестре)")
    required: bool = True
    max_age_s: PositiveInt = Field(300, description="Максимальная свежесть данных")
    stale_policy: StalePolicy = Field(StalePolicy.fail)
    required_keys: List[str] = Field(default_factory=list, description="Dot‑ключи, которые обязаны присутствовать")
    map: Dict[str, str] = Field(default_factory=dict, description="Карта dot‑ключ -> dot‑ключ в нормализованном выходе")
    redact: bool = True

class SignalFetchResult(BaseModel):
    spec_id: str
    status: FetchStatus
    age_s: Optional[int] = None
    error: Optional[str] = None
    data: Optional[Dict[str, Any]] = None  # уже нормализованный и, при необходимости, отредактированный


# =========================
# Provider Abstraction
# =========================

class SignalProvider(abc.ABC):
    """
    Абстракция источника сигналов. Провайдер может кешировать внутри себя.
    """
    def __init__(self, name: str) -> None:
        self.name = name

    @abc.abstractmethod
    async def fetch(self, entity: Mapping[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Возвращает пару: данные (dict) и timestamp unix seconds когда были получены/актуальны.
        Должен поднимать ProviderUnavailable при временной недоступности.
        """
        raise NotImplementedError


# =========================
# HTTP JSON Provider
# =========================

class HttpJsonProvider(SignalProvider):
    """
    Гибкий HTTP JSON провайдер. Поддерживает:
      - GET/POST
      - шаблоны URL/заголовков с ${var} из entity
      - retry с экспоненциальной задержкой + jitter
      - rate limit (token bucket)
      - circuit breaker
      - кэш (Memory/Redis) по ключу <name>:<hash>
    """
    def __init__(
        self,
        name: str,
        *,
        url_template: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body_template: Optional[str] = None,
        timeout_s: float = 2.5,
        retry: int = 2,
        backoff_base_s: float = 0.2,
        backoff_factor: float = 2.0,
        rate_per_s: float = 10.0,
        burst: int = 20,
        cache: Optional[CacheStore] = None,
        cache_ttl_s: int = 60,
    ) -> None:
        super().__init__(name)
        if httpx is None:
            raise ProviderUnavailable("httpx package not installed")
        self.url_template = url_template
        self.method = method.upper()
        self.headers = headers or {}
        self.body_template = body_template
        self.timeout_s = timeout_s
        self.retry = max(0, retry)
        self.backoff_base_s = backoff_base_s
        self.backoff_factor = backoff_factor
        self.rate = TokenBucket(rate_per_s=rate_per_s, burst=burst)
        self.cb = CircuitBreaker()
        self.cache = cache or MemoryCache()
        self.cache_ttl_s = cache_ttl_s

    def _render(self, template: str, entity: Mapping[str, Any]) -> str:
        # ${a.b.c}
        def sub(m):
            key = m.group(1)
            val = _jptr(entity, key, "")
            return str(val if val is not None else "")
        return re.sub(r"\$\{([^}]+)\}", sub, template)

    def _cache_key(self, url: str, method: str, body: Optional[bytes]) -> str:
        import hashlib
        h = hashlib.sha256()
        h.update(method.encode())
        h.update(url.encode())
        if body:
            h.update(body)
        return f"sig:httpjson:{self.name}:{h.hexdigest()[:16]}"

    async def fetch(self, entity: Mapping[str, Any]) -> Tuple[Dict[str, Any], int]:
        await self.cb.before()
        url = self._render(self.url_template, entity)
        hdrs = {k: self._render(v, entity) for k, v in self.headers.items()}
        body = self._render(self.body_template, entity).encode("utf-8") if self.body_template else None

        # cache lookup
        ckey = self._cache_key(url, self.method, body)
        cached = await self.cache.get(ckey)
        if cached:
            exp, blob = cached
            try:
                payload = json.loads(blob)
                # приблизительная оценка времени получения: exp - ttl
                now = utc_now_s()
                age_s = max(0, now - (exp - self.cache_ttl_s))
                return payload, now - age_s
            except Exception:
                await self.cache.invalidate(ckey)

        await self.rate.acquire()
        delay = self.backoff_base_s
        last_exc: Optional[Exception] = None
        for attempt in range(self.retry + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                    if self.method == "GET":
                        r = await client.get(url, headers=hdrs)
                    elif self.method == "POST":
                        r = await client.post(url, headers=hdrs, content=body)
                    else:
                        raise ProviderUnavailable(f"unsupported method {self.method}")
                    r.raise_for_status()
                    data = r.json()
                    ts = int(time.time())
                    blob = json.dumps(data, separators=(",", ":")).encode("utf-8")
                    await self.cache.set(ckey, blob, self.cache_ttl_s)
                    await self.cb.success()
                    return data, ts
            except Exception as e:
                last_exc = e
                await self.cb.failure()
                if attempt >= self.retry:
                    break
                # экспоненциальный backoff с jitter
                jitter = delay * 0.25
                await asyncio.sleep(delay + (jitter * (2 * (os.urandom(1)[0] / 255.0 - 0.5))))
                delay *= self.backoff_factor

        raise ProviderUnavailable(f"http fetch failed: {last_exc}")


# =========================
# Registry
# =========================

class ProviderRegistry:
    def __init__(self) -> None:
        self._p: Dict[str, SignalProvider] = {}

    def register(self, provider: SignalProvider) -> None:
        if provider.name in self._p:
            raise ValueError(f"provider {provider.name} already registered")
        self._p[provider.name] = provider

    def get(self, name: str) -> SignalProvider:
        if name not in self._p:
            raise KeyError(f"provider {name} not registered")
        return self._p[name]

# Глобальный реестр по умолчанию (можно заменить в рантайме)
default_registry = ProviderRegistry()


# =========================
# Aggregation / Validation
# =========================

def _normalize_map(data: Mapping[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
    # Если mapping пуст — возвращаем плоскую версию
    if not mapping:
        return flatten_dot(data)
    out: Dict[str, Any] = {}
    for dst, src in mapping.items():
        out[dst] = _jptr(data, src, None)
    return out

def _validate_required_keys(payload: Mapping[str, Any], required_keys: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for k in required_keys:
        if _jptr(payload, k, None) is None:
            missing.append(k)
    return missing

async def gather_signals(
    specs: Iterable[SignalSpec],
    entity: Mapping[str, Any],
    registry: ProviderRegistry = default_registry,
) -> Tuple[Dict[str, Dict[str, Any]], List[SignalFetchResult]]:
    """
    Возвращает:
      - normalized: словарь spec.id -> нормализованные данные (dot‑keys или map)
      - results: список статусов по каждому сигналу
    """
    normalized: Dict[str, Dict[str, Any]] = {}
    results: List[SignalFetchResult] = []

    async def _one(spec: SignalSpec) -> None:
        try:
            provider = registry.get(spec.provider)
        except KeyError as e:
            results.append(SignalFetchResult(spec_id=spec.id, status=FetchStatus.error, error=str(e)))
            return

        try:
            raw, ts = await provider.fetch(entity)
        except ProviderUnavailable as e:
            status = FetchStatus.error if spec.required else FetchStatus.missing
            results.append(SignalFetchResult(spec_id=spec.id, status=status, error=str(e)))
            return
        except Exception as e:
            results.append(SignalFetchResult(spec_id=spec.id, status=FetchStatus.error, error=f"unexpected: {e}"))
            return

        age = max(0, utc_now_s() - ts)
        # нормализация
        mapped = _normalize_map(raw, spec.map)
        # проверка обязательных ключей
        missing = _validate_required_keys(mapped, spec.required_keys)
        if missing:
            results.append(SignalFetchResult(
                spec_id=spec.id,
                status=FetchStatus.error if spec.required else FetchStatus.missing,
                error=f"missing keys: {','.join(missing)}",
                age_s=age,
                data=None if spec.redact else mapped,
            ))
            return

        # свежесть
        if age > spec.max_age_s:
            status = FetchStatus.stale
            if spec.stale_policy == StalePolicy.fail or spec.required:
                # при fail/required обозначим как stale, но потребитель решит, что делать
                pass
        else:
            status = FetchStatus.ok

        safe_payload = redact_pii(mapped) if spec.redact else mapped
        normalized[spec.id] = mapped
        results.append(SignalFetchResult(spec_id=spec.id, status=status, age_s=age, data=safe_payload))

    await asyncio.gather(*[_one(s) for s in specs])
    return normalized, results


# =========================
# Example wiring helpers
# =========================

def default_cache() -> CacheStore:
    redis_url = os.getenv("ZTC_REDIS_URL")
    if redis_url and aioredis:
        try:
            return RedisCache(redis_url)
        except Exception as e:  # pragma: no cover
            logger.warning("redis unavailable, using memory: %s", e)
    return MemoryCache()

def register_default_http_providers() -> None:
    """
    Регистрирует типичные HTTP‑провайдеры: MDM, EDR, Geo.
    Значения токенов берутся из переменных окружения.
    """
    cache = default_cache()
    # MDM
    mdm_token = os.getenv("ZTC_MDM_TOKEN", "")
    if os.getenv("ZTC_MDM_URL"):
        default_registry.register(HttpJsonProvider(
            name="mdm",
            url_template=os.environ["ZTC_MDM_URL"].rstrip("/") + "/api/v1/devices/${device.id}",
            method="GET",
            headers={"Authorization": f"Bearer {mdm_token}"} if mdm_token else {},
            cache=cache,
            cache_ttl_s=60,
            timeout_s=2.5,
            retry=2,
        ))
    # EDR
    edr_token = os.getenv("ZTC_EDR_TOKEN", "")
    if os.getenv("ZTC_EDR_URL"):
        default_registry.register(HttpJsonProvider(
            name="edr",
            url_template=os.environ["ZTC_EDR_URL"].rstrip("/") + "/api/v2/telemetry?device=${device.id}&window=5m",
            method="GET",
            headers={"Authorization": f"Bearer {edr_token}"} if edr_token else {},
            cache=cache,
            cache_ttl_s=30,
            timeout_s=2.0,
            retry=2,
        ))
    # GEO
    if os.getenv("ZTC_GEO_URL"):
        default_registry.register(HttpJsonProvider(
            name="geo",
            url_template=os.environ["ZTC_GEO_URL"].rstrip("/") + "/last-login?subject=${subject}",
            method="GET",
            cache=cache,
            cache_ttl_s=120,
            timeout_s=1.5,
            retry=1,
        ))


# =========================
# Self‑test (optional)
# =========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    async def main():
        # Регистрация провайдеров (пример; замените на реальные URL’ы в окружении)
        try:
            register_default_http_providers()
        except ProviderUnavailable:
            logger.warning("http providers not registered (httpx not installed)")

        # Определим спецификации для агрегатора
        specs = [
            SignalSpec(
                id="mdm.device",
                provider="mdm",
                required=True,
                max_age_s=600,
                required_keys=["os.name", "encryption.enabled"],
                map={
                    "os.name": "os.name",
                    "os.version": "os.version",
                    "encryption.enabled": "encryption.enabled",
                    "secure_boot": "secure_boot",
                    "serial": "serial",
                },
            ),
            SignalSpec(
                id="edr.status",
                provider="edr",
                required=True,
                max_age_s=180,
                required_keys=["agent.healthy", "threat.level"],
                map={"agent.healthy": "agent.healthy", "threat.level": "threat.level"},
            ),
            SignalSpec(
                id="geo.last_login",
                provider="geo",
                required=False,
                max_age_s=900,
                map={"impossible_travel": "impossible_travel", "country": "country", "city": "city"},
            ),
        ]
        # Сущность (контекст)
        entity = {"subject": "user@example.com", "device": {"id": "ABC-123"}}

        normalized, results = await gather_signals(specs, entity)
        print("Normalized:", json.dumps(normalized, indent=2))
        print("Results:", json.dumps([r.dict() for r in results], indent=2))

    asyncio.run(main())
