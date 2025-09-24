# ledger-core/api/http/middleware/ratelimit.py
"""
ASGI middleware для промышленного rate limiting:
- Backend: Redis (рекомендуется) + резервный InMemory.
- Алгоритмы: fixed window + sliding window + token bucket.
- Ключи лимита: по API-ключу, subject (user_id), IP, пути/методу; составной ключ.
- Теневой режим (shadow): не блокирует, только метит и пишет заголовки.
- Динамические лимиты: колбэк на основе запроса (например, платный тариф vs бесплатный).
- Идемпотентность: пропуск повторов по Idempotency-Key без списания квоты (настраиваемо).
- Заголовки RFC-подобные: RateLimit-Limit / RateLimit-Remaining / RateLimit-Reset и Retry-After.
- Корректное извлечение реального IP за прокси (trust proxy настройка).
- Безопасность: защита от key explosion, ограничение размеров ключей/тегов.
- Совместимость: Starlette/FastAPI/ASGI 3.0+, Python 3.10+.
"""

from __future__ import annotations

import abc
import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Literal, Optional, Tuple

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

try:
    # redis>=4.5, модуль с asyncio-клиентом
    from redis.asyncio import Redis as AsyncRedis  # type: ignore
except Exception:  # pragma: no cover
    AsyncRedis = None  # type: ignore


# ------------------------------- Конфигурация -------------------------------

Strategy = Literal["fixed_window", "sliding_window", "token_bucket"]

@dataclass(frozen=True)
class LimitConfig:
    """
    Конфигурация одного лимита:
    - limit: максимум событий за окно, либо ёмкость бакета.
    - window: длительность окна в секундах (для fixed/sliding), период пополнения бакета.
    - burst: дополнительная ёмкость/запас (применимо к token_bucket).
    - strategy: стратегия подсчёта.
    """
    limit: int
    window: int
    burst: int = 0
    strategy: Strategy = "sliding_window"


@dataclass(frozen=True)
class MiddlewareConfig:
    """
    Общая конфигурация middleware:
    - default_limit: значение по умолчанию, если dynamic_limiter не задан или вернул None.
    - header_prefix: префикс для RateLimit-* заголовков (пустой = без префикса).
    - trust_proxy: использовать X-Forwarded-For/Proto/Host для реального IP.
    - shadow_mode: не блокировать при превышении, только помечать.
    - include_headers: выставлять информативные заголовки.
    - idempotency_header: имя заголовка, при совпадении повторов не списывать квоту (опция).
    - exempt_predicate: функция, позволяющая пропустить лимитирование (healthz и т.п.).
    - key_func: функция формирования ключа лимита.
    - metric_callback: функция сбора метрик событий лимитера.
    """
    default_limit: LimitConfig
    header_prefix: str = ""
    trust_proxy: bool = True
    shadow_mode: bool = False
    include_headers: bool = True
    idempotency_header: Optional[str] = "Idempotency-Key"
    exempt_predicate: Optional[Callable[[Scope], bool]] = None
    key_func: Optional[Callable[[Scope], str]] = None
    metric_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None


# ------------------------------ Интерфейс стораджа ------------------------------

class RateLimitStorage(abc.ABC):
    """
    Абстракция для подсчёта запросов.
    Все методы атомарны в границах одного сервера/кластера.
    """

    @abc.abstractmethod
    async def incr_fixed(self, key: str, window: int, now: float) -> Tuple[int, float]:
        """
        Fixed window счётчик: инкремент и TTL.
        Возвращает (текущее значение после инкремента, unix_ts_окончания_окна).
        """

    @abc.abstractmethod
    async def incr_sliding(self, key: str, window: int, now: float) -> Tuple[int, float]:
        """
        Sliding window с точностью до секунды:
        Использует 2 окна: текущее и предыдущее. Возвращает (оценка_счётчика, reset_ts).
        """

    @abc.abstractmethod
    async def token_bucket_take(
        self, key: str, capacity: int, refill_per_sec: float, now: float
    ) -> Tuple[int, float]:
        """
        Токен-бакет: списывает 1 токен, пополняет по refill_per_sec.
        Возвращает (остаток_после_списания, время_полного_восстановления_емкости).
        """

    @abc.abstractmethod
    async def close(self) -> None:
        ...


# ------------------------------ Redis сторадж ------------------------------

class RedisStorage(RateLimitStorage):
    """
    Реализация на Redis. Требует redis>=6, Lua-скрипты для атомарности.
    Ключи:
      rl:fw:{key}:{epoch_window}
      rl:sw:{key} -> ZSET с таймстампами секунд
      rl:tb:{key} -> HASH: {tokens, updated_at}
    """

    def __init__(self, redis: AsyncRedis, namespace: str = "rl", max_key_len: int = 256) -> None:
        if AsyncRedis is None:
            raise RuntimeError("redis.asyncio недоступен. Установите пакет 'redis'.")
        self._r = redis
        self._ns = namespace
        self._max_key_len = max_key_len

    def _safe(self, key: str) -> str:
        if len(key) > self._max_key_len:
            key = key[: self._max_key_len]
        return key

    async def incr_fixed(self, key: str, window: int, now: float) -> Tuple[int, float]:
        epoch = int(now // window)
        k = f"{self._ns}:fw:{self._safe(key)}:{epoch}"
        # INCR + EXPIRE NX
        pipe = self._r.pipeline()
        pipe.incr(k)
        pipe.expire(k, window + 1)
        val, _ = await pipe.execute()
        reset_ts = (epoch + 1) * window
        return int(val), float(reset_ts)

    async def incr_sliding(self, key: str, window: int, now: float) -> Tuple[int, float]:
        k = f"{self._ns}:sw:{self._safe(key)}"
        # ZADD now_sec, ZREMRANGEBYSCORE older_than, ZCOUNT
        now_sec = int(now)
        oldest = now - window
        pipe = self._r.pipeline()
        pipe.zadd(k, {str(now_sec): now})
        pipe.zremrangebyscore(k, 0, oldest)
        pipe.expire(k, window + 2)
        pipe.zcard(k)
        _, _, _, card = await pipe.execute()
        reset_ts = now + window
        return int(card), float(reset_ts)

    async def token_bucket_take(
        self, key: str, capacity: int, refill_per_sec: float, now: float
    ) -> Tuple[int, float]:
        """
        Храним:
          HSET rl:tb:{key} tokens <int> updated_at <float>
        Алгоритм:
          - вычислить пополнение с момента обновления
          - ограничить до capacity
          - если токенов >=1, списать 1
        """
        k = f"{self._ns}:tb:{self._safe(key)}"
        # Получаем atomically с Lua
        script = """
        local k = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])

        local h = redis.call('HGETALL', k)
        local tokens = 0
        local updated = now
        if #h > 0 then
          for i=1,#h,2 do
            if h[i] == 'tokens' then tokens = tonumber(h[i+1]) end
            if h[i] == 'updated_at' then updated = tonumber(h[i+1]) end
          end
          local delta = math.max(0, now - updated)
          tokens = math.min(capacity, tokens + delta * refill)
        else
          tokens = capacity
          updated = now
        end

        local allowed = 0
        if tokens >= 1 then
          tokens = tokens - 1
          allowed = 1
        end

        redis.call('HSET', k, 'tokens', tokens, 'updated_at', now)
        redis.call('EXPIRE', k, math.max(2, math.ceil(capacity / math.max(refill, 0.0001))))

        local seconds_to_full = 0
        if tokens < capacity then
          seconds_to_full = (capacity - tokens) / math.max(refill, 0.0001)
        end

        return {allowed, tokens, now + seconds_to_full}
        """
        allowed, tokens, reset_ts = await self._r.eval(script, 1, k, capacity, refill_per_sec, now)
        if int(allowed) == 1:
            return int(tokens), float(reset_ts)
        # не удалось списать — токенов нет
        return int(tokens), float(reset_ts)

    async def close(self) -> None:  # pragma: no cover
        try:
            await self._r.close()
        except Exception:
            pass


# ------------------------------ In-Memory сторадж ------------------------------

class InMemoryStorage(RateLimitStorage):
    """
    Потокобезопасная in‑memory реализация для dev/test.
    Не кластеризуется. Использует asyncio.Lock.
    """

    def __init__(self) -> None:
        self._fixed: Dict[Tuple[str, int], int] = {}
        self._sliding: Dict[str, Dict[int, int]] = {}
        self._bucket: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, updated_at)
        self._lock = asyncio.Lock()

    async def incr_fixed(self, key: str, window: int, now: float) -> Tuple[int, float]:
        epoch = int(now // window)
        k = (key, epoch)
        async with self._lock:
            self._fixed[k] = self._fixed.get(k, 0) + 1
            return self._fixed[k], float((epoch + 1) * window)

    async def incr_sliding(self, key: str, window: int, now: float) -> Tuple[int, float]:
        now_sec = int(now)
        oldest = int(now - window)
        async with self._lock:
            d = self._sliding.setdefault(key, {})
            d[now_sec] = d.get(now_sec, 0) + 1
            # purge
            for ts in list(d.keys()):
                if ts <= oldest:
                    del d[ts]
            total = sum(d.values())
            return total, float(now + window)

    async def token_bucket_take(
        self, key: str, capacity: int, refill_per_sec: float, now: float
    ) -> Tuple[int, float]:
        async with self._lock:
            tokens, updated = self._bucket.get(key, (float(capacity), float(now)))
            delta = max(0.0, now - updated)
            tokens = min(float(capacity), tokens + delta * refill_per_sec)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._bucket[key] = (tokens, float(now))
            seconds_to_full = 0.0 if tokens >= capacity else (capacity - tokens) / max(refill_per_sec, 1e-4)
            return int(tokens), float(now + seconds_to_full)

    async def close(self) -> None:
        # nothing
        return


# ------------------------------ Утилиты ключей и IP ------------------------------

def _client_ip_from_scope(scope: Scope, trust_proxy: bool) -> str:
    headers = Headers(scope=scope)
    if trust_proxy:
        xff = headers.get("x-forwarded-for")
        if xff:
            # берем первый адрес списка
            ip = xff.split(",")[0].strip()
            if ip:
                return ip
    client = scope.get("client")
    if client and isinstance(client, tuple):
        return client[0]
    return "0.0.0.0"


def default_key_func(scope: Scope) -> str:
    """
    Составной ключ: <method>|<path_template>|<api_key_or_user>|<ip>
    """
    headers = Headers(scope=scope)
    ip = _client_ip_from_scope(scope, trust_proxy=True)
    api_key = headers.get("authorization") or headers.get("x-api-key") or "-"
    method = scope.get("method", "GET")
    path = scope.get("path", "/")
    # Можно заменить path на шаблонизированный маршрут, если фреймворк позволяет.
    return f"{method}|{path}|{api_key[:32]}|{ip}"


# ------------------------------ ASGI Middleware ------------------------------

class RateLimitMiddleware:
    """
    Применение:
      app.add_middleware(RateLimitMiddleware,
                         storage=RedisStorage(redis),
                         config=MiddlewareConfig(default_limit=LimitConfig(100, 60)))
    Если нужен динамический лимит:
      dynamic_limiter(scope) -> Optional[LimitConfig]
    """

    def __init__(
        self,
        app: ASGIApp,
        storage: RateLimitStorage,
        config: MiddlewareConfig,
        dynamic_limiter: Optional[Callable[[Scope], Awaitable[Optional[LimitConfig]]]] = None,
    ) -> None:
        self.app = app
        self.storage = storage
        self.cfg = config
        self.dynamic_limiter = dynamic_limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self.cfg.exempt_predicate and self.cfg.exempt_predicate(scope):
            await self.app(scope, receive, send)
            return

        now = time.time()
        # Идемпотентность: повторные запросы с тем же ключом можем не списывать
        headers = Headers(scope=scope)
        idem_key = headers.get(self.cfg.idempotency_header) if self.cfg.idempotency_header else None

        # Динамический лимит либо дефолт
        limit_cfg = self.cfg.default_limit
        if self.dynamic_limiter:
            dyn = await self.dynamic_limiter(scope)
            if isinstance(dyn, LimitConfig):
                limit_cfg = dyn

        # Ключ лимита
        key_raw = (self.cfg.key_func or default_key_func)(scope)
        key = f"v1:{key_raw}"  # версионирование ключей

        # Выбор стратегии
        remaining: int
        reset_ts: float

        # Если есть идемпотентный ключ — учитываем как «без списания» (но всё равно проверим текущий уровень)
        skip_charge = bool(idem_key)

        # Текущее значение и «reset»
        current, reset_ts = await self._consume(limit_cfg, key, now, charge=not skip_charge)
        remaining = max(0, limit_cfg.limit - current)

        # Заголовки
        hdr_prefix = self.cfg.header_prefix
        response_headers: Dict[str, str] = {}
        if self.cfg.include_headers:
            response_headers[f"{hdr_prefix}RateLimit-Limit"] = str(limit_cfg.limit)
            response_headers[f"{hdr_prefix}RateLimit-Remaining"] = str(remaining)
            response_headers[f"{hdr_prefix}RateLimit-Reset"] = str(int(max(0, reset_ts - now)))

        over_limit = current > limit_cfg.limit

        # Shadow mode: не блокируем, только помечаем
        if self.cfg.shadow_mode and over_limit:
            response_headers[f"{hdr_prefix}RateLimit-Shadow-Over"] = "1"
            await self._call_downstream(scope, receive, send, response_headers)
            self._metric("shadow_exceeded", scope, limit_cfg, over_limit=True)
            return

        if over_limit:
            # 429
            retry_after = max(1, int(reset_ts - now))
            if self.cfg.include_headers:
                response_headers["Retry-After"] = str(retry_after)
            body = {
                "error": "rate_limited",
                "detail": "Too many requests",
                "limit": limit_cfg.limit,
                "remaining": max(0, remaining),
                "reset": int(max(0, reset_ts - now)),
            }
            await self._send_json(scope, send, 429, body, response_headers)
            self._metric("blocked", scope, limit_cfg, over_limit=True)
            return

        # OK — пропускаем
        await self._call_downstream(scope, receive, send, response_headers)
        self._metric("allowed", scope, limit_cfg, over_limit=False)

    async def _consume(self, cfg: LimitConfig, key: str, now: float, charge: bool) -> Tuple[int, float]:
        """
        Возвращает (текущее_значение_после_операции, reset_ts).
        Если charge=False, только читает оценку состояния без списания (для idem).
        """
        # Для режима "только посмотреть" при sliding можно сделать incr_sliding без записи при charge=False.
        # Для простоты и консистентности считаем, что idem-запрос не увеличит счётчик (fixed/sliding),
        # а для token_bucket — не списывает.
        if cfg.strategy == "fixed_window":
            if not charge:
                # оценка: текущий фикс‑счётчик + TTL окна
                count, reset_ts = await self.storage.incr_fixed(key + ":peek", cfg.window, now)
                # не используем отдельный peek‑ключ, можно было бы читать ttl, но это общий интерфейс
                return max(0, count - 1), reset_ts
            return await self.storage.incr_fixed(key, cfg.window, now)

        if cfg.strategy == "sliding_window":
            if not charge:
                # аккуратная оценка без записи: используем соседний ключ для snapshot
                count, reset_ts = await self.storage.incr_sliding(key + ":peek", cfg.window, now)
                return max(0, count - 1), reset_ts
            return await self.storage.incr_sliding(key, cfg.window, now)

        # token_bucket
        # refill_per_sec = (limit + burst) / window  — чтобы за window пополнялся полный объём
        capacity = max(1, cfg.limit + max(0, cfg.burst))
        refill = capacity / max(1, cfg.window)
        if not charge:
            # не списываем токен, а только оцениваем остаток: делаем take на временном ключе и вычитаем 1
            tokens_left, reset_ts = await self.storage.token_bucket_take(key + ":peek", capacity, refill, now)
            return max(0, (capacity - int(tokens_left)) - 1), reset_ts
        tokens_left, reset_ts = await self.storage.token_bucket_take(key, capacity, refill, now)
        used = capacity - int(tokens_left)
        return used, reset_ts

    async def _call_downstream(
        self, scope: Scope, receive: Receive, send: Send, extra_headers: Dict[str, str]
    ) -> None:
        if not extra_headers:
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers_list = list(message.get("headers", []))
                for k, v in extra_headers.items():
                    headers_list.append((k.encode("ascii"), v.encode("ascii")))
                message = {**message, "headers": headers_list}
            await send(message)

        await self.app(scope, receive, send_with_headers)

    async def _send_json(
        self, scope: Scope, send: Send, status_code: int, payload: Dict[str, Any], headers: Dict[str, str]
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers_list = [(b"content-type", b"application/json; charset=utf-8")]
        for k, v in headers.items():
            headers_list.append((k.encode("ascii"), v.encode("ascii")))
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": headers_list,
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _metric(self, name: str, scope: Scope, cfg: LimitConfig, over_limit: bool) -> None:
        if not self.cfg.metric_callback:
            return
        try:
            ip = _client_ip_from_scope(scope, self.cfg.trust_proxy)
            self.cfg.metric_callback(
                name,
                {
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "over_limit": over_limit,
                    "strategy": cfg.strategy,
                    "limit": cfg.limit,
                    "window": cfg.window,
                    "ip": ip,
                },
            )
        except Exception:
            # не ломаем обработку при ошибке метрик
            pass


# ------------------------------ Пример и фабрики ------------------------------

async def example_dynamic_limiter(scope: Scope) -> Optional[LimitConfig]:
    """
    Пример динамики: бесплатный тариф 60 rpm, платный 600 rpm,
    для POST на /payments — отдельный строгий лимит 30 rpm.
    """
    headers = Headers(scope=scope)
    plan = headers.get("x-plan", "free")
    method = scope.get("method", "GET")
    path = scope.get("path", "/")

    if method == "POST" and path.startswith("/payments"):
        return LimitConfig(limit=30, window=60, strategy="sliding_window")

    if plan == "pro":
        return LimitConfig(limit=600, window=60, strategy="sliding_window")
    return LimitConfig(limit=60, window=60, strategy="sliding_window")


def exempt_healthz(scope: Scope) -> bool:
    path = scope.get("path", "")
    return path in ("/health", "/live", "/ready")


def build_inmemory_middleware(app: ASGIApp) -> RateLimitMiddleware:
    storage = InMemoryStorage()
    cfg = MiddlewareConfig(
        default_limit=LimitConfig(limit=100, window=60, strategy="sliding_window"),
        header_prefix="",
        trust_proxy=True,
        shadow_mode=False,
        include_headers=True,
        idempotency_header="Idempotency-Key",
        exempt_predicate=exempt_healthz,
        key_func=default_key_func,
        metric_callback=None,
    )
    return RateLimitMiddleware(app, storage=storage, config=cfg, dynamic_limiter=example_dynamic_limiter)


def build_redis_middleware(app: ASGIApp, redis_client: Any) -> RateLimitMiddleware:
    """
    redis_client: экземпляр redis.asyncio.Redis
    """
    storage = RedisStorage(redis_client, namespace="rl", max_key_len=256)
    cfg = MiddlewareConfig(
        default_limit=LimitConfig(limit=200, window=60, strategy="sliding_window"),
        header_prefix="",
        trust_proxy=True,
        shadow_mode=False,
        include_headers=True,
        idempotency_header="Idempotency-Key",
        exempt_predicate=exempt_healthz,
        key_func=default_key_func,
        metric_callback=None,
    )
    return RateLimitMiddleware(app, storage=storage, config=cfg, dynamic_limiter=example_dynamic_limiter)


# ------------------------------ Pydantic/FastAPI хелперы (опционально) ------------------------------
# Для FastAPI: from fastapi import FastAPI
# app = FastAPI()
# app.add_middleware(RateLimitMiddleware, storage=InMemoryStorage(), config=..., dynamic_limiter=...)

"""
Примечания по эксплуатации:
- Redis рекомендуется с настройкой maxmemory-policy=allkeys-lru для ZSET/keys лимитера.
- Для кластеров за балансировщиками установите trust_proxy=True и правильно сконфигурируйте прокси.
- В shadow_mode можно прогнать трафик и собрать статистику без 429, затем включить блокировки.
- Если используете CDN/WAF лимитирование, синхронизируйте пороги и окна, чтобы избежать каскадных 429.
"""
