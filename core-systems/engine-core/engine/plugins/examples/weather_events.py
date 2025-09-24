# engine-core/engine/plugins/examples/weather_events.py
# Industrial-grade example plugin that produces weather events from pluggable providers.
# Features:
# - Typed config via Pydantic with environment overrides
# - Async IO using aiohttp
# - Rate limiting (token bucket) + exponential backoff with jitter
# - Circuit breaker with half-open probing
# - Structured logging
# - Event queue with backpressure
# - Health/metrics snapshot
# - Clean shutdown and resource management
# - Provider isolation (strategy pattern), default: Open-Meteo
# - Minimal external contracts: a Plugin class with {init|ainit|aclose} as expected by your loader

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import random
import time
from dataclasses import dataclass, asdict
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

try:
    import aiohttp
except ImportError as e:  # pragma: no cover
    raise RuntimeError("weather_events plugin requires 'aiohttp'") from e

try:
    from pydantic import BaseModel, Field, PositiveInt, conint, confloat, validator
except ImportError as e:  # pragma: no cover
    raise RuntimeError("weather_events plugin requires 'pydantic'") from e


# ----------------------------
# Logging (structured)
# ----------------------------
LOG = logging.getLogger("engine.plugins.weather")
if not LOG.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s","mod":"%(name)s"}'
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(os.environ.get("WEATHER_PLUGIN_LOG_LEVEL", "INFO").upper())


# ----------------------------
# Data models
# ----------------------------
@dataclass(frozen=True)
class WeatherSnapshot:
    provider: str
    latitude: float
    longitude: float
    temperature_c: Optional[float]
    wind_speed_ms: Optional[float]
    precipitation_mm: Optional[float]
    condition: Optional[str]
    fetched_at_unix: int


@dataclass(frozen=True)
class WeatherEvent:
    """Event emitted by the plugin."""
    type: str  # e.g., "weather.update"
    snapshot: WeatherSnapshot
    correlation_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "type": self.type,
                "snapshot": asdict(self.snapshot),
                "correlation_id": self.correlation_id,
            },
            ensure_ascii=False,
        )


# ----------------------------
# Provider contract (strategy)
# ----------------------------
class WeatherProvider(Protocol):
    name: str

    async def fetch(self, lat: float, lon: float, session: aiohttp.ClientSession) -> WeatherSnapshot:
        ...


# ----------------------------
# Rate limiter (token bucket)
# ----------------------------
class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self.rate = rate_per_sec
        self.capacity = capacity
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last)
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            # need to wait
            deficit = tokens - self._tokens
            wait_s = deficit / self.rate if self.rate > 0 else 0.1
        await asyncio.sleep(wait_s)
        # try once more recursively to avoid duplicating logic
        await self.acquire(tokens)


# ----------------------------
# Circuit breaker
# ----------------------------
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout_s: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout_s = reset_timeout_s
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._state = "CLOSED"  # CLOSED -> OPEN -> HALF_OPEN
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            if self._state == "CLOSED":
                return True
            if self._state == "OPEN":
                # allow probing after timeout
                assert self._opened_at is not None
                if time.monotonic() - self._opened_at >= self.reset_timeout_s:
                    self._state = "HALF_OPEN"
                    return True
                return False
            if self._state == "HALF_OPEN":
                # allow single probe
                return True
            return False

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._opened_at = None
            self._state = "CLOSED"

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = "OPEN"
                self._opened_at = time.monotonic()

    @property
    def state(self) -> str:
        return self._state


# ----------------------------
# Backoff with jitter
# ----------------------------
def backoff_delay(attempt: int, base: float = 0.5, cap: float = 10.0) -> float:
    # Exponential backoff with decorrelated jitter
    exp = min(cap, base * (2 ** attempt))
    return random.uniform(base, exp)


# ----------------------------
# Config
# ----------------------------
class Location(BaseModel):
    lat: confloat(ge=-90.0, le=90.0) = Field(..., description="Latitude")
    lon: confloat(ge=-180.0, le=180.0) = Field(..., description="Longitude")
    correlation_id: Optional[str] = Field(None, description="Optional correlation id for tracing")


class ProviderConfig(BaseModel):
    name: str = Field("open-meteo", description="Provider name")
    base_url: str = Field(
        "https://api.open-meteo.com/v1/forecast",
        description="Base URL for the provider",
    )
    timeout_s: confloat(gt=0, le=60) = 10.0
    # allowlist for security
    allowed_domains: List[str] = Field(default_factory=lambda: ["api.open-meteo.com"])


class QueueConfig(BaseModel):
    max_events: PositiveInt = 1000


class LimitsConfig(BaseModel):
    rate_per_sec: confloat(gt=0, le=50) = 5.0
    burst: conint(ge=1, le=200) = 20


class BreakerConfig(BaseModel):
    failure_threshold: conint(ge=1, le=50) = 5
    reset_timeout_s: confloat(gt=1, le=600) = 30.0


class PollingConfig(BaseModel):
    interval_s: confloat(gt=0.5, le=3600) = 30.0
    parallelism: conint(ge=1, le=64) = 4


class WeatherPluginConfig(BaseModel):
    locations: List[Location] = Field(default_factory=list)
    provider: ProviderConfig = ProviderConfig()
    queue: QueueConfig = QueueConfig()
    limits: LimitsConfig = LimitsConfig()
    breaker: BreakerConfig = BreakerConfig()
    polling: PollingConfig = PollingConfig()
    metrics_namespace: str = "engine.weather"

    @validator("locations")
    def ensure_locations(cls, v: List[Location]) -> List[Location]:
        if not v:
            # provide a sensible default (Stockholm) if nothing set
            return [Location(lat=59.3293, lon=18.0686, correlation_id="default")]
        return v


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# ----------------------------
# Provider implementation (Open-Meteo)
# ----------------------------
class OpenMeteoProvider:
    name = "open-meteo"

    def __init__(self, cfg: ProviderConfig) -> None:
        self.cfg = cfg

    def _check_domain(self, url: str) -> None:
        # rudimentary safety: require hostname in allowlist
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        if not any(host.endswith(d) for d in self.cfg.allowed_domains):
            raise ValueError(f"Domain not allowed: {host}")

    async def fetch(self, lat: float, lon: float, session: aiohttp.ClientSession) -> WeatherSnapshot:
        params = {
            "latitude": f"{lat:.4f}",
            "longitude": f"{lon:.4f}",
            "current_weather": "true",
            "hourly": "precipitation",
        }
        url = self.cfg.base_url
        self._check_domain(url)
        async with session.get(url, params=params, timeout=self.cfg.timeout_s) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            data = await resp.json()

        # Parse fields defensively
        cw = data.get("current_weather") or {}
        temp = cw.get("temperature")
        wind = cw.get("windspeed")
        condition = str(cw.get("weathercode")) if cw.get("weathercode") is not None else None

        prec_mm: Optional[float] = None
        try:
            # take first hourly value if available
            hourly = data.get("hourly") or {}
            prec = hourly.get("precipitation") or []
            if prec:
                prec_mm = float(prec[0])
        except Exception:
            prec_mm = None

        return WeatherSnapshot(
            provider=self.name,
            latitude=lat,
            longitude=lon,
            temperature_c=float(temp) if temp is not None else None,
            wind_speed_ms=float(wind) / 3.6 if wind is not None else None,  # km/h -> m/s
            precipitation_mm=prec_mm,
            condition=condition,
            fetched_at_unix=int(time.time()),
        )


# ----------------------------
# Metrics (lightweight)
# ----------------------------
@dataclass
class Metrics:
    requests_total: int = 0
    failures_total: int = 0
    events_emitted: int = 0
    last_fetch_latency_ms: Optional[float] = None

    def snapshot(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------
# Plugin main
# ----------------------------
class Plugin:
    """Engine plugin that periodically fetches weather data and emits events."""

    def __init__(self, config_schema: Optional[str] = None, capabilities: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None) -> None:
        self._config_schema_path = config_schema
        self._capabilities = capabilities or []
        self._env = env or {}
        self._cfg: WeatherPluginConfig = self._load_config(self._env)

        self._session: Optional[aiohttp.ClientSession] = None
        self._queue: asyncio.Queue[WeatherEvent] = asyncio.Queue(maxsize=self._cfg.queue.max_events)
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task] = []
        self._bucket = TokenBucket(rate_per_sec=self._cfg.limits.rate_per_sec, capacity=self._cfg.limits.burst)
        self._breaker = CircuitBreaker(
            failure_threshold=self._cfg.breaker.failure_threshold,
            reset_timeout_s=self._cfg.breaker.reset_timeout_s,
        )
        self._metrics = Metrics()
        self._provider: WeatherProvider = OpenMeteoProvider(self._cfg.provider)

    # ------------- lifecycle -------------
    def init(self) -> None:
        # Optional sync initialization hook
        LOG.debug("weather plugin init (sync)")

    async def ainit(self) -> None:
        LOG.info("weather plugin starting")
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._cfg.provider.timeout_s + 5),
            raise_for_status=False,
            trust_env=_env_bool("WEATHER_PLUGIN_TRUST_ENV", False),
        )
        # launch polling workers
        for i in range(self._cfg.polling.parallelism):
            task = asyncio.create_task(self._poll_worker(worker_id=i), name=f"weather-poll-{i}")
            self._tasks.append(task)
        LOG.info("weather plugin started with %d workers", len(self._tasks))

    async def aclose(self) -> None:
        LOG.info("weather plugin stopping")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        if self._session:
            await self._session.close()
        # drain queue to avoid blocking close in host
        with contextlib.suppress(asyncio.QueueEmpty):
            while True:
                self._queue.get_nowait()
                self._queue.task_done()
        LOG.info("weather plugin stopped")

    # ------------- config -------------
    def _load_config(self, env: Dict[str, str]) -> WeatherPluginConfig:
        # Environment overrides (optional)
        # Example: WEATHER_LOCATIONS="59.3293,18.0686;55.7558,37.6173"
        locs: List[Location] = []
        s = env.get("WEATHER_LOCATIONS") or os.environ.get("WEATHER_LOCATIONS")
        if s:
            for chunk in s.split(";"):
                p = chunk.split(",")
                if len(p) >= 2:
                    lat = float(p[0].strip())
                    lon = float(p[1].strip())
                    cid = p[2].strip() if len(p) >= 3 else None
                    locs.append(Location(lat=lat, lon=lon, correlation_id=cid))

        interval = float(env.get("WEATHER_INTERVAL_S", os.environ.get("WEATHER_INTERVAL_S", 30.0)))
        rate = float(env.get("WEATHER_RATE_PER_SEC", os.environ.get("WEATHER_RATE_PER_SEC", 5.0)))
        burst = int(env.get("WEATHER_BURST", os.environ.get("WEATHER_BURST", 20)))

        cfg = WeatherPluginConfig(
            locations=locs or [],
            polling=PollingConfig(interval_s=interval),
            limits=LimitsConfig(rate_per_sec=rate, burst=burst),
        )
        LOG.debug("weather config loaded: %s", cfg.json())
        return cfg

    # ------------- public API -------------
    async def get_event(self) -> WeatherEvent:
        """Blocking await for next event (for simple consumers)."""
        return await self._queue.get()

    def subscribe(self) -> AsyncIterator[WeatherEvent]:
        """Async iterator interface for consumers."""
        queue = self._queue

        async def gen() -> AsyncIterator[WeatherEvent]:
            while not self._stop.is_set():
                ev = await queue.get()
                try:
                    yield ev
                finally:
                    queue.task_done()

        return gen()

    def health(self) -> Dict[str, Any]:
        return {
            "status": "degraded" if self._breaker.state != "CLOSED" else "ok",
            "breaker_state": self._breaker.state,
            "queue_size": self._queue.qsize() if self._queue else None,
            "metrics": self._metrics.snapshot(),
            "capabilities": self._capabilities,
        }

    # ------------- internals -------------
    async def _poll_worker(self, worker_id: int) -> None:
        assert self._session is not None
        session = self._session
        attempt_map: Dict[Tuple[float, float], int] = {}
        # simple round-robin over locations
        idx = worker_id % max(1, len(self._cfg.locations))
        while not self._stop.is_set():
            loc = self._cfg.locations[idx % len(self._cfg.locations)]
            idx += self._cfg.polling.parallelism  # deinterleave workers

            # circuit breaker gate
            allowed = await self._breaker.allow()
            if not allowed:
                await asyncio.sleep(0.25)
                continue

            # rate limit
            await self._bucket.acquire(1.0)
            start = time.perf_counter()
            try:
                snapshot = await self._provider.fetch(loc.lat, loc.lon, session)
                self._metrics.requests_total += 1
                self._metrics.last_fetch_latency_ms = (time.perf_counter() - start) * 1000.0
                await self._breaker.record_success()
                # emit event
                ev = WeatherEvent(
                    type="weather.update",
                    snapshot=snapshot,
                    correlation_id=loc.correlation_id,
                )
                await self._emit(ev)
                self._metrics.events_emitted += 1
                # reset backoff for this location
                attempt_map[(loc.lat, loc.lon)] = 0
            except Exception as e:
                self._metrics.failures_total += 1
                await self._breaker.record_failure()
                n = attempt_map.get((loc.lat, loc.lon), 0) + 1
                attempt_map[(loc.lat, loc.lon)] = n
                delay = backoff_delay(n, base=0.5, cap=10.0)
                LOG.warning(
                    'fetch failed {"err":"%s","lat":%.4f,"lon":%.4f,"attempt":%d,"delay":%.2f,"breaker":"%s"}',
                    str(e),
                    loc.lat,
                    loc.lon,
                    n,
                    delay,
                    self._breaker.state,
                )
                await asyncio.sleep(delay)

            # main pacing
            await asyncio.sleep(self._cfg.polling.interval_s)

    async def _emit(self, ev: WeatherEvent) -> None:
        # apply backpressure: wait if queue is full
        try:
            await self._queue.put(ev)
            LOG.debug('event queued {"type":"%s","cid":"%s"}', ev.type, ev.correlation_id)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # pragma: no cover
            LOG.error('failed to queue event {"err":"%s"}', str(e))
