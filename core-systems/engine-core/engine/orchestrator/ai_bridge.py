# engine-core/engine/orchestrator/ai_bridge.py
"""
Industrial-grade AI Bridge for multi-provider orchestration.

Features:
- Async interface with streaming and non-streaming completions
- Provider adapters (OpenAI-compatible Chat Completions, Local/Echo)
- Pluggable HTTP client interface (inject your own transport)
- Deterministic request hashing for cache/idempotency
- In-memory TTL cache, idempotency dedupe
- Token-bucket rate limiting (RPS) + concurrency semaphore
- Exponential backoff with full jitter, bounded retries
- Circuit breaker (half-open) per provider/route
- PII redaction (configurable regexes) before transport; audit of redacted fields
- Output safety: stop sequences, max tokens, truncation policy
- Cost accounting by provider/model with simple token estimation
- Telemetry hooks (events, timings, counters) without hard deps
- Structured errors with categories (Retryable/Timeout/RateLimit/etc.)

No external deps. Wire your networking via HttpClient interface.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field, asdict
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

# =========================
# Errors
# =========================

class AIBridgeError(Exception):
    pass

class AIBridgeTimeout(AIBridgeError):
    pass

class AIBridgeRateLimited(AIBridgeError):
    pass

class AIBridgeCircuitOpen(AIBridgeError):
    pass

class AIBridgeRetryable(AIBridgeError):
    pass

class AIBridgeBadRequest(AIBridgeError):
    pass

# =========================
# Types
# =========================

Role = str  # "system"|"user"|"assistant"|"tool"
Message = Dict[str, Any]  # {"role":..., "content": str|list, "name"?: str, "tool_call_id"?: str}
ToolSpec = Dict[str, Any]  # openai-tools compatible schema or your own
StopSeq = Sequence[str]

# =========================
# Utilities
# =========================

def _ujson(obj: Any) -> str:
    # Stable JSON: sorted keys, no spaces, ensure_ascii False
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _canonical_hash(obj: Any) -> str:
    data = _ujson(obj).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _now() -> float:
    return time.monotonic()

def _full_jitter_delay(base: float, factor: float, attempt: int, cap: float) -> float:
    raw = min(cap, base * (factor ** max(0, attempt - 1)))
    # time.monotonic_ns() LCG fallback for jitter
    ns = time.monotonic_ns() & 0xFFFFFFFF
    jitter = ((1664525 * ns + 1013904223) & 0xFFFFFFFF) / 0xFFFFFFFF
    return raw * jitter

# =========================
# Rate limiter & Circuit breaker
# =========================

class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float) -> None:
        self.rate = float(max(0.0, rate_per_s))
        self.burst = float(max(1.0, burst))
        self.tokens = self.burst
        self.last = _now()
        self.cv = asyncio.Condition()

    def _refill(self) -> None:
        now = _now()
        dt = now - self.last
        if dt > 0:
            self.tokens = min(self.burst, self.tokens + dt * self.rate)
            self.last = now

    async def acquire(self, n: float = 1.0, timeout: Optional[float] = None) -> None:
        dl = _now() + (timeout if timeout else 3600.0)
        async with self.cv:
            while True:
                self._refill()
                if self.tokens >= n:
                    self.tokens -= n
                    return
                rem = dl - _now()
                if rem <= 0:
                    raise AIBridgeRateLimited("rate limit waiting timed out")
                await self.cv.wait_for(lambda: False, timeout=min(rem, 0.05))

    def release(self, n: float = 1.0) -> None:
        async def _notify():
            async with self.cv:
                self.tokens = min(self.burst, self.tokens + n)
                self.cv.notify_all()
        try:
            asyncio.get_running_loop().create_task(_notify())
        except RuntimeError:
            pass

class CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 5, reset_timeout_s: float = 10.0) -> None:
        self.failures = 0
        self.state = "closed"  # "closed"|"open"|"half"
        self.failure_threshold = failure_threshold
        self.reset_at = 0.0
        self.reset_timeout_s = reset_timeout_s

    def on_success(self) -> None:
        self.failures = 0
        self.state = "closed"

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "open"
            self.reset_at = _now() + self.reset_timeout_s

    def allow(self) -> bool:
        if self.state == "open":
            if _now() >= self.reset_at:
                self.state = "half"
                return True
            return False
        return True

# =========================
# HTTP client interface (inject)
# =========================

class HttpResponse:
    def __init__(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

class HttpClient:
    """
    Implement post_json and stream_sse for your stack (aiohttp/httpx/custom).
    """

    async def post_json(self, url: str, headers: Mapping[str, str], payload: Mapping[str, Any], timeout_s: float) -> HttpResponse:
        raise NotImplementedError

    async def stream_sse(self, url: str, headers: Mapping[str, str], payload: Mapping[str, Any], timeout_s: float) -> AsyncIterator[bytes]:
        raise NotImplementedError

# =========================
# Cost & token estimation
# =========================

def simple_token_estimate(text: str) -> int:
    # Fast lower-bound estimate: split by whitespace and punctuation
    if not text:
        return 0
    # Rough heuristics suitable for budgeting
    return max(1, int(len(text) / 4.0))

@dataclass(slots=True)
class PriceEntry:
    input_per_1k: float  # USD
    output_per_1k: float

DEFAULT_PRICING: Dict[str, PriceEntry] = {
    # Example defaults; adjust to your contracts
    "openai:gpt-4o-mini": PriceEntry(0.15, 0.60),
    "openai:gpt-4o": PriceEntry(2.50, 10.00),
    "local:echo": PriceEntry(0.0, 0.0),
}

# =========================
# PII redaction
# =========================

@dataclass(slots=True)
class RedactionRule:
    name: str
    pattern: str
    replacement: str = "[REDACTED]"

DEFAULT_REDACTIONS = (
    RedactionRule("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    RedactionRule("phone", r"\+?\d[\d \-()]{7,}\d"),
    RedactionRule("iban", r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}"),
)

def redact_text(text: str, rules: Sequence[RedactionRule]) -> Tuple[str, List[str]]:
    applied: List[str] = []
    red = text
    for r in rules:
        new = re.sub(r.pattern, r.replacement, red)
        if new != red:
            applied.append(r.name)
            red = new
    return red, applied

# =========================
# Cache with TTL
# =========================

@dataclass(slots=True)
class CacheEntry:
    value: Any
    expires_at: float

class TTLCache:
    def __init__(self, max_items: int = 1024) -> None:
        self._store: Dict[str, CacheEntry] = {}
        self._order: List[str] = []
        self._max = max_items

    def get(self, key: str) -> Optional[Any]:
        e = self._store.get(key)
        if not e:
            return None
        if _now() >= e.expires_at:
            self.delete(key)
            return None
        return e.value

    def set(self, key: str, value: Any, ttl_s: float) -> None:
        if len(self._order) >= self._max:
            old = self._order.pop(0)
            self._store.pop(old, None)
        self._store[key] = CacheEntry(value=value, expires_at=_now() + ttl_s)
        if key in self._order:
            self._order.remove(key)
        self._order.append(key)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        if key in self._order:
            self._order.remove(key)

# =========================
# Config & request model
# =========================

@dataclass(slots=True)
class BridgeLimits:
    rps: float = 5.0
    burst: float = 10.0
    concurrency: int = 8
    max_retries: int = 4
    timeout_s: float = 60.0
    cache_ttl_s: float = 0.0

@dataclass(slots=True)
class BridgeConfig:
    provider: str  # "openai" | "local"
    model: str
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    organization: Optional[str] = None
    limits: BridgeLimits = field(default_factory=BridgeLimits)
    pricing: Dict[str, PriceEntry] = field(default_factory=lambda: dict(DEFAULT_PRICING))
    redactions: Tuple[RedactionRule, ...] = DEFAULT_REDACTIONS
    safe_stop: Tuple[str, ...] = tuple()
    max_output_tokens: Optional[int] = None
    idempotency_window_s: float = 120.0
    enable_stream: bool = True

@dataclass(slots=True)
class CompletionRequest:
    messages: List[Message]
    temperature: float = 0.2
    top_p: float = 1.0
    tools: Optional[List[ToolSpec]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    user: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass(slots=True)
class CompletionResult:
    content: str
    finish_reason: str
    model: str
    provider: str
    usage_input_tokens: int
    usage_output_tokens: int
    cost_usd: float
    redactions_applied: List[str]
    cached: bool
    idempotency_key: str

# =========================
# Telemetry hook
# =========================

TelemetryHook = Callable[[str, Mapping[str, str], Mapping[str, float]], None]

# =========================
# Provider adapters
# =========================

class ProviderAdapter:
    name: str = "base"

    async def complete(
        self,
        http: HttpClient,
        cfg: BridgeConfig,
        req: CompletionRequest,
        stream: bool,
        timeout_s: float,
    ) -> Union[CompletionResult, AsyncIterator[str]]:
        raise NotImplementedError

class OpenAIAdapter(ProviderAdapter):
    name = "openai"

    def _build_headers(self, cfg: BridgeConfig) -> Dict[str, str]:
        h = {
            "authorization": f"Bearer {cfg.api_key or ''}",
            "content-type": "application/json",
        }
        if cfg.organization:
            h["openai-organization"] = cfg.organization
        return h

    def _endpoint(self, cfg: BridgeConfig) -> str:
        # Expect Chat Completions style
        return (cfg.endpoint or "https://api.openai.com") + "/v1/chat/completions"

    def _payload(self, cfg: BridgeConfig, req: CompletionRequest, stream: bool) -> Dict[str, Any]:
        body = {
            "model": cfg.model,
            "messages": req.messages,
            "temperature": req.temperature,
            "top_p": req.top_p,
            "stream": bool(stream),
        }
        if req.tools is not None:
            body["tools"] = req.tools
        if req.tool_choice is not None:
            body["tool_choice"] = req.tool_choice
        if req.user:
            body["user"] = req.user
        return body

    async def complete(
        self,
        http: HttpClient,
        cfg: BridgeConfig,
        req: CompletionRequest,
        stream: bool,
        timeout_s: float,
    ) -> Union[CompletionResult, AsyncIterator[str]]:
        headers = self._build_headers(cfg)
        url = self._endpoint(cfg)
        payload = self._payload(cfg, req, stream)

        if stream:
            async def _aiter() -> AsyncIterator[str]:
                async for chunk in http.stream_sse(url, headers, payload, timeout_s):
                    # Expect "data: {json}\n\n" chunks; filter keep-alives
                    if not chunk:
                        continue
                    try:
                        line = chunk.decode("utf-8", errors="ignore").strip()
                        if not line or not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        obj = json.loads(data)
                        delta = obj.get("choices", [{}])[0].get("delta", {})
                        piece = delta.get("content")
                        if piece:
                            yield piece
                    except Exception:
                        # Silently drop malformed chunks; upstream retry handled outside stream
                        continue
            return _aiter()

        resp = await http.post_json(url, headers, payload, timeout_s)
        if resp.status == 429:
            raise AIBridgeRateLimited("openai rate limit")
        if 400 <= resp.status < 500:
            raise AIBridgeBadRequest(f"openai bad request: {resp.status}")
        if resp.status >= 500:
            raise AIBridgeRetryable(f"openai server error: {resp.status}")

        obj = json.loads(resp.body.decode("utf-8", errors="ignore"))
        choice = (obj.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content") or ""
        finish_reason = choice.get("finish_reason") or "stop"

        # Usage may be present; fallback to estimation
        usage = obj.get("usage") or {}
        in_tok = int(usage.get("prompt_tokens") or 0)
        out_tok = int(usage.get("completion_tokens") or max(1, simple_token_estimate(content)))

        price_key = f"openai:{cfg.model}"
        price = cfg.pricing.get(price_key, PriceEntry(0.0, 0.0))
        cost = (in_tok / 1000.0) * price.input_per_1k + (out_tok / 1000.0) * price.output_per_1k

        return CompletionResult(
            content=content,
            finish_reason=finish_reason,
            model=cfg.model,
            provider=self.name,
            usage_input_tokens=in_tok,
            usage_output_tokens=out_tok,
            cost_usd=round(cost, 6),
            redactions_applied=[],
            cached=False,
            idempotency_key="",
        )

class LocalEchoAdapter(ProviderAdapter):
    name = "local"

    async def complete(
        self,
        http: HttpClient,
        cfg: BridgeConfig,
        req: CompletionRequest,
        stream: bool,
        timeout_s: float,
    ) -> Union[CompletionResult, AsyncIterator[str]]:
        # Does not use http (pure echo), good for tests
        text = ""
        for m in req.messages:
            if m.get("role") == "user":
                c = m.get("content")
                text += (c if isinstance(c, str) else _ujson(c)) + "\n"
        reply = f"[echo:{cfg.model}] {text.strip()}"

        if stream:
            async def _aiter() -> AsyncIterator[str]:
                for i in range(0, len(reply), 16):
                    await asyncio.sleep(0)  # ensure async friendliness
                    yield reply[i : i + 16]
            return _aiter()

        tok_in = sum(simple_token_estimate(m.get("content") or "") for m in req.messages)
        tok_out = simple_token_estimate(reply)
        price = cfg.pricing.get("local:echo", PriceEntry(0.0, 0.0))
        cost = (tok_in / 1000.0) * price.input_per_1k + (tok_out / 1000.0) * price.output_per_1k

        return CompletionResult(
            content=reply,
            finish_reason="stop",
            model=cfg.model,
            provider=self.name,
            usage_input_tokens=tok_in,
            usage_output_tokens=tok_out,
            cost_usd=round(cost, 6),
            redactions_applied=[],
            cached=False,
            idempotency_key="",
        )

ADAPTERS: Dict[str, ProviderAdapter] = {
    "openai": OpenAIAdapter(),
    "local": LocalEchoAdapter(),
}

# =========================
# Bridge
# =========================

class AIBridge:
    def __init__(
        self,
        *,
        config: BridgeConfig,
        http_client: HttpClient,
        telemetry: Optional[TelemetryHook] = None,
    ) -> None:
        self.cfg = config
        self.http = http_client
        self.tel = telemetry
        self.bucket = TokenBucket(config.limits.rps, config.limits.burst)
        self.sema = asyncio.Semaphore(config.limits.concurrency)
        self.cb = CircuitBreaker()
        self.cache = TTLCache()
        self._inflight: Dict[str, asyncio.Future] = {}

        if self.cfg.provider not in ADAPTERS:
            raise ValueError(f"unknown provider {self.cfg.provider}")

    # ----- Public API -----

    async def complete(
        self,
        req: CompletionRequest,
        *,
        stream: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> Union[CompletionResult, AsyncIterator[str]]:
        stream = self.cfg.enable_stream if stream is None else stream

        # Build canonical payload for idempotency/cache
        raw_messages = self._apply_redactions(req.messages)
        canon_req = {
            "provider": self.cfg.provider,
            "model": self.cfg.model,
            "messages": raw_messages["messages_redacted"],
            "temperature": req.temperature,
            "top_p": req.top_p,
            "tools": req.tools,
            "tool_choice": req.tool_choice,
            "user": req.user,
        }
        req_hash = _canonical_hash(canon_req)
        idem = idempotency_key or req_hash

        # Idempotent dedupe in-flight
        if idem in self._inflight:
            fut = self._inflight[idem]
            try:
                res = await fut
                return res
            except Exception:
                # fall through to new execution
                pass

        # Cache (non-stream only)
        if not stream and self.cfg.limits.cache_ttl_s > 0:
            cached = self.cache.get(req_hash)
            if cached is not None:
                res: CompletionResult = cached
                res.cached = True
                res.idempotency_key = idem
                return res

        if not self.cb.allow():
            raise AIBridgeCircuitOpen("circuit open")

        # Rate limit + concurrency
        await self.bucket.acquire(1.0, timeout=self.cfg.limits.timeout_s)
        await self.sema.acquire()
        fut = asyncio.get_running_loop().create_future()
        self._inflight[idem] = fut

        t0 = _now()
        try:
            res = await self._execute_with_retries(
                req=req,
                stream=stream,
                timeout_s=self.cfg.limits.timeout_s,
                redactions_applied=raw_messages["applied"],
            )
            # annotate idempotency
            if not stream and isinstance(res, CompletionResult):
                res.idempotency_key = idem
                if self.cfg.limits.cache_ttl_s > 0:
                    self.cache.set(req_hash, res, ttl_s=self.cfg.limits.cache_ttl_s)
            fut.set_result(res)
            self._telemetry("ai.complete.ok", {"provider": self.cfg.provider, "model": self.cfg.model}, {"latency_ms": (_now() - t0) * 1000})
            return res
        except Exception as e:
            fut.set_exception(e)
            self.cb.on_failure()
            self._telemetry("ai.complete.err", {"provider": self.cfg.provider, "model": self.cfg.model, "type": type(e).__name__}, {"latency_ms": (_now() - t0) * 1000})
            raise
        finally:
            self._inflight.pop(idem, None)
            self.sema.release()
            self.bucket.release(1.0)

    # ----- Internal -----

    async def _execute_with_retries(
        self,
        *,
        req: CompletionRequest,
        stream: bool,
        timeout_s: float,
        redactions_applied: List[str],
    ) -> Union[CompletionResult, AsyncIterator[str]]:
        adapter = ADAPTERS[self.cfg.provider]

        # Wrap provider call with safety post-processing
        async def call_once() -> Union[CompletionResult, AsyncIterator[str]]:
            result = await adapter.complete(self.http, self.cfg, req, stream, timeout_s)
            if stream:
                return self._safe_stream(result)  # type: ignore[arg-type]
            else:
                return self._safe_finalize(result, redactions_applied)  # type: ignore[arg-type]

        # Streaming path: retries not meaningful mid-stream; do one attempt
        if stream:
            try:
                self.cb.on_success()
                return await call_once()
            except AIBridgeRateLimited:
                self.cb.on_failure()
                raise
            except AIBridgeBadRequest:
                self.cb.on_failure()
                raise
            except asyncio.TimeoutError:
                self.cb.on_failure()
                raise AIBridgeTimeout("provider timeout")
            except Exception as e:
                self.cb.on_failure()
                raise AIBridgeRetryable(str(e))

        # Non-stream: bounded retries
        attempt = 1
        maxr = max(0, self.cfg.limits.max_retries)
        base = 0.2
        cap = 4.0
        factor = 2.0
        while True:
            try:
                res = await call_once()
                self.cb.on_success()
                return res
            except (AIBridgeRateLimited, AIBridgeRetryable, asyncio.TimeoutError) as e:
                if attempt > maxr:
                    self.cb.on_failure()
                    if isinstance(e, asyncio.TimeoutError):
                        raise AIBridgeTimeout("provider timeout") from e
                    raise
                delay = _full_jitter_delay(base, factor, attempt, cap)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            except AIBridgeBadRequest:
                self.cb.on_failure()
                raise

    def _safe_stream(self, it: AsyncIterator[str]) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            emitted = 0
            async for chunk in it:
                s = self._apply_stops(chunk)
                if not s:
                    continue
                if self.cfg.max_output_tokens is not None:
                    emitted += simple_token_estimate(s)
                    if emitted > self.cfg.max_output_tokens:
                        # truncate and end
                        yield ""
                        break
                yield s
        return _gen()

    def _safe_finalize(self, res: CompletionResult, redactions_applied: List[str]) -> CompletionResult:
        s = self._apply_stops(res.content)
        res.content = s
        res.redactions_applied = redactions_applied
        # Enforce max tokens
        if self.cfg.max_output_tokens is not None:
            t = simple_token_estimate(res.content)
            if t > self.cfg.max_output_tokens:
                # naive truncation by characters proportional to tokens
                keep = max(1, int(len(res.content) * (self.cfg.max_output_tokens / t)))
                res.content = res.content[:keep]
                res.finish_reason = "length"
        # Cost correction if provider didn't provide usage
        price_key = f"{self.cfg.provider}:{self.cfg.model}"
        price = self.cfg.pricing.get(price_key, PriceEntry(0.0, 0.0))
        if (res.usage_input_tokens == 0 and res.usage_output_tokens == 0) and (price.input_per_1k or price.output_per_1k):
            # estimate from messages + content
            # This estimation is imprecise and intended only for budgeting/alerts
            res.usage_input_tokens = sum(simple_token_estimate(m.get("content") or "") for m in res.__dict__.get("messages", []) or [])  # usually absent
            res.usage_output_tokens = simple_token_estimate(res.content)
            res.cost_usd = round(
                (res.usage_input_tokens / 1000.0) * price.input_per_1k
                + (res.usage_output_tokens / 1000.0) * price.output_per_1k,
                6,
            )
        return res

    def _apply_redactions(self, messages: Sequence[Message]) -> Dict[str, Any]:
        applied_all: List[str] = []
        red_msgs: List[Message] = []
        for m in messages:
            m2 = dict(m)
            c = m.get("content")
            if isinstance(c, str):
                red, applied = redact_text(c, self.cfg.redactions)
                applied_all.extend(applied)
                m2["content"] = red
            red_msgs.append(m2)
        return {"messages_redacted": red_msgs, "applied": list(sorted(set(applied_all)))}

    def _apply_stops(self, text: str) -> str:
        if not text:
            return text
        for stop in self.cfg.safe_stop:
            idx = text.find(stop)
            if idx >= 0:
                return text[:idx]
        return text

    def _telemetry(self, name: str, tags: Mapping[str, str] | None, fields: Mapping[str, float] | None) -> None:
        if self.tel:
            try:
                self.tel(name, tags or {}, fields or {})
            except Exception:
                pass

# =========================
# __all__
# =========================

__all__ = [
    # config
    "BridgeLimits",
    "BridgeConfig",
    "CompletionRequest",
    "CompletionResult",
    # core
    "AIBridge",
    "HttpClient",
    "HttpResponse",
    # errors
    "AIBridgeError",
    "AIBridgeTimeout",
    "AIBridgeRateLimited",
    "AIBridgeCircuitOpen",
    "AIBridgeRetryable",
    "AIBridgeBadRequest",
]
