# path: omnimind-core/omnimind/adapters/llm/openai_adapter.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

###############################################################################
# Optional OpenAI imports with graceful fallback
###############################################################################

try:
    # OpenAI Python SDK (>= v1.x)
    from openai import OpenAI, AsyncOpenAI
    from openai._exceptions import (
        APIConnectionError,
        APIError,
        RateLimitError,
        APITimeoutError,
        BadRequestError,
        AuthenticationError,
        PermissionDeniedError,
        UnprocessableEntityError,
        ConflictError,
    )
except Exception:  # pragma: no cover
    OpenAI = object  # type: ignore[assignment]
    AsyncOpenAI = object  # type: ignore[assignment]

    class _E(Exception):  # pragma: no cover
        pass
    APIConnectionError = APIError = RateLimitError = APITimeoutError = BadRequestError = _E  # type: ignore
    AuthenticationError = PermissionDeniedError = UnprocessableEntityError = ConflictError = _E  # type: ignore


###############################################################################
# Public data structures
###############################################################################

Role = Literal["system", "user", "assistant", "tool", "developer"]

@dataclass
class ChatMessage:
    role: Role
    content: Union[str, List[Dict[str, Any]]]
    name: Optional[str] = None
    tool_call_id: Optional[str] = None

@dataclass
class ToolSpec:
    type: Literal["function"]
    function: Dict[str, Any]  # {"name": str, "description": str, "parameters": JSON schema}

@dataclass
class JsonResponseSpec:
    mode: Literal["json_object", "json_schema"] = "json_object"
    schema_name: Optional[str] = None
    json_schema: Optional[Dict[str, Any]] = None

@dataclass
class AdapterConfig:
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None           # e.g. Azure endpoint or custom gateway
    organization: Optional[str] = None
    project: Optional[str] = None
    # Azure OpenAI specifics (optional):
    azure_api_version: Optional[str] = None  # ?api-version=
    # Networking:
    request_timeout_s: float = 60.0
    connect_timeout_s: float = 10.0
    # Reliability:
    max_retries: int = 5
    initial_backoff_s: float = 0.2
    max_backoff_s: float = 8.0
    jitter: float = 0.2  # 0..1
    # Rate-limiting:
    rate_limit_rps: Optional[float] = None
    # Logging:
    logger_name: str = "omnimind.llm.openai"
    # Telemetry hooks:
    #   on_request(payload), on_stream_delta(delta), on_response(resp), on_error(exc, attempt)
    observer: Optional["Observer"] = None

class Observer:
    def on_request(self, payload: Dict[str, Any]) -> None: ...
    def on_stream_delta(self, delta: Dict[str, Any]) -> None: ...
    def on_response(self, response: Dict[str, Any]) -> None: ...
    def on_error(self, exc: BaseException, attempt: int) -> None: ...

@dataclass
class ChatResult:
    model: str
    role: Role
    text: str
    finish_reason: Optional[str]
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    usage: Dict[str, int] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    # For JSON mode:
    json: Optional[Any] = None
    # Provider latency
    latency_ms: Optional[int] = None

###############################################################################
# Utilities
###############################################################################

class TokenBucket:
    """Simple token bucket limiter for RPS control."""
    def __init__(self, rate_per_sec: float) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = max(self.rate, 1.0)
        self.tokens = self.capacity
        self.timestamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self, cost: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.timestamp
                self.timestamp = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= cost:
                    self.tokens -= cost
                    return
                # sleep enough to accumulate required tokens
                missing = cost - self.tokens
                await asyncio.sleep(missing / self.rate)

def _safe_json_loads(s: str) -> Optional[Any]:
    try:
        return json.loads(s)
    except Exception:
        return None

def _build_response_format(spec: Optional[JsonResponseSpec]) -> Optional[Dict[str, Any]]:
    if not spec:
        return None
    if spec.mode == "json_object":
        return {"type": "json_object"}
    if spec.mode == "json_schema" and spec.json_schema and spec.schema_name:
        return {
            "type": "json_schema",
            "json_schema": {
                "name": spec.schema_name,
                "schema": spec.json_schema,
            },
        }
    return None

def _env_default(key: str, fallback: Optional[str] = None) -> Optional[str]:
    val = os.getenv(key)
    return val if val else fallback

def _make_base_url(cfg: AdapterConfig) -> Optional[str]:
    if cfg.base_url and cfg.azure_api_version and "?" not in cfg.base_url:
        # Allow auto-append api-version for Azure if not present
        return f"{cfg.base_url.rstrip('/')}?api-version={cfg.azure_api_version}"
    return cfg.base_url

def _jittered(base: float, jitter: float) -> float:
    if jitter <= 0:
        return base
    d = base * jitter
    return random.uniform(max(0, base - d), base + d)

def _merge_usage(a: Dict[str, int], b: Optional[Dict[str, int]]) -> Dict[str, int]:
    if not b:
        return a
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + int(v)
    return out

###############################################################################
# OpenAI Adapter
###############################################################################

class OpenAIAdapter:
    """
    Production-grade adapter for OpenAI / Azure OpenAI chat completions.

    - Supports sync and async clients.
    - Retries with exponential backoff for transient errors.
    - Optional token-bucket RPS limiter.
    - Streaming with delta aggregation and tool-calls emission.
    - JSON mode and JSON Schema structured outputs.
    - Observability hooks and detailed logging.
    """

    def __init__(self, cfg: AdapterConfig) -> None:
        self.cfg = cfg
        self.log = logging.getLogger(cfg.logger_name)
        self.api_key = cfg.api_key or _env_default("OPENAI_API_KEY")
        self.base_url = _make_base_url(cfg) or _env_default("OPENAI_BASE_URL")
        self.org = cfg.organization or _env_default("OPENAI_ORG")
        self.project = cfg.project or _env_default("OPENAI_PROJECT")
        self.rps = TokenBucket(cfg.rate_limit_rps) if cfg.rate_limit_rps else None
        self._observer = cfg.observer

        # Initialize clients
        self._client = self._make_client()
        self._aclient = self._make_async_client()

    def _make_client(self):
        if OpenAI is object:  # pragma: no cover
            raise RuntimeError("OpenAI SDK is not installed")
        return OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            organization=self.org,
            project=self.project,
            timeout=self.cfg.request_timeout_s,
            max_retries=0,  # retries are handled here
        )

    def _make_async_client(self):
        if AsyncOpenAI is object:  # pragma: no cover
            return None
        return AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            organization=self.org,
            project=self.project,
            timeout=self.cfg.request_timeout_s,
            max_retries=0,  # retries are handled here
        )

    ###########################################################################
    # Public API
    ###########################################################################

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Optional[Sequence[ToolSpec]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        top_p: Optional[float] = None,
        seed: Optional[int] = None,
        response_format: Optional[JsonResponseSpec] = None,
        user: Optional[str] = None,
        stream: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Union[ChatResult, Iterable[Dict[str, Any]]]:
        """
        Synchronous interface. For stream=True returns an iterator of events:
        {"type": "delta"|"tool_call"|"end"|"error", ...}
        """
        if stream:
            # Wrap async generator into blocking iterator
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            agen = self.async_chat(
                messages,
                tools=tools,
                tool_choice=tool_choice,
                temperature=temperature,
                max_tokens=max_tokens,
                top_p=top_p,
                seed=seed,
                response_format=response_format,
                user=user,
                stream=True,
                extra=extra,
            )
            return _AsyncIteratorSyncWrapper(loop, agen)

        # Non-streaming path
        return asyncio.run(self.async_chat(
            messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            seed=seed,
            response_format=response_format,
            user=user,
            stream=False,
            extra=extra,
        ))

    async def async_chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Optional[Sequence[ToolSpec]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        top_p: Optional[float] = None,
        seed: Optional[int] = None,
        response_format: Optional[JsonResponseSpec] = None,
        user: Optional[str] = None,
        stream: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Union[ChatResult, AsyncGenerator[Dict[str, Any], None]]:
        payload = self._build_payload(
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            seed=seed,
            response_format=response_format,
            user=user,
            stream=stream,
            extra=extra or {},
        )

        if self._observer:
            try:
                self._observer.on_request(dict(payload))
            except Exception:
                pass

        if stream:
            return self._stream_call(payload)
        else:
            return await self._call_with_retries(payload)

    ###########################################################################
    # Internals
    ###########################################################################

    def _build_payload(
        self,
        *,
        messages: Sequence[ChatMessage],
        tools: Optional[Sequence[ToolSpec]],
        tool_choice: Optional[Union[str, Dict[str, Any]]],
        temperature: Optional[float],
        max_tokens: Optional[int],
        top_p: Optional[float],
        seed: Optional[int],
        response_format: Optional[JsonResponseSpec],
        user: Optional[str],
        stream: bool,
        extra: Dict[str, Any],
    ) -> Dict[str, Any]:
        msgs = []
        for m in messages:
            item: Dict[str, Any] = {"role": m.role, "content": m.content}
            if m.name:
                item["name"] = m.name
            if m.tool_call_id:
                item["tool_call_id"] = m.tool_call_id
            msgs.append(item)

        payload: Dict[str, Any] = {
            "model": self.cfg.model,
            "messages": msgs,
            "stream": stream,
        }
        if tools:
            payload["tools"] = [dict(t) for t in tools]
        if tool_choice:
            payload["tool_choice"] = tool_choice
        if temperature is not None:
            payload["temperature"] = float(temperature)
        if max_tokens is not None:
            payload["max_tokens"] = int(max_tokens)
        if top_p is not None:
            payload["top_p"] = float(top_p)
        if seed is not None:
            payload["seed"] = int(seed)
        if user:
            payload["user"] = user
        rf = _build_response_format(response_format)
        if rf:
            payload["response_format"] = rf

        # allow passing any additional vendor keys
        payload.update(extra or {})
        return payload

    async def _call_with_retries(self, payload: Dict[str, Any]) -> ChatResult:
        attempt = 0
        last_exc: Optional[BaseException] = None
        t_start = time.monotonic()

        while attempt <= self.cfg.max_retries:
            if self.rps:
                await self.rps.take()

            try:
                # Async client preferred when available
                if self._aclient is not None:
                    resp = await self._aclient.chat.completions.create(**payload)  # type: ignore[attr-defined]
                else:  # pragma: no cover
                    resp = self._client.chat.completions.create(**payload)  # type: ignore[attr-defined]

                latency_ms = int((time.monotonic() - t_start) * 1000)
                result = self._to_result(resp, latency_ms)
                if self._observer:
                    try:
                        self._observer.on_response(result.raw)
                    except Exception:
                        pass
                return result

            except (RateLimitError, APITimeoutError, APIConnectionError, APIError) as e:
                last_exc = e
                transient = isinstance(e, (RateLimitError, APITimeoutError, APIConnectionError)) or (
                    isinstance(e, APIError) and getattr(e, "status_code", 500) >= 500
                )
                self._emit_error(e, attempt)
                if not transient or attempt >= self.cfg.max_retries:
                    raise
                await asyncio.sleep(_jittered(min(self.cfg.initial_backoff_s * (2 ** attempt), self.cfg.max_backoff_s), self.cfg.jitter))
                attempt += 1
                continue
            except (AuthenticationError, PermissionDeniedError, BadRequestError, UnprocessableEntityError, ConflictError) as e:
                self._emit_error(e, attempt)
                raise
            except Exception as e:  # Unknown
                self._emit_error(e, attempt)
                raise

        assert last_exc is not None
        raise last_exc

    def _to_result(self, resp: Any, latency_ms: Optional[int]) -> ChatResult:
        # The OpenAI SDK returns an object with .choices[0].message
        ch = resp.choices[0]
        msg = ch.message
        text = (msg.content or "") if isinstance(msg.content, str) else (msg.content or "")
        tool_calls = getattr(msg, "tool_calls", None) or []
        usage = {
            "prompt_tokens": getattr(resp, "usage", {}).get("prompt_tokens", 0) if getattr(resp, "usage", None) else 0,
            "completion_tokens": getattr(resp, "usage", {}).get("completion_tokens", 0) if getattr(resp, "usage", None) else 0,
            "total_tokens": getattr(resp, "usage", {}).get("total_tokens", 0) if getattr(resp, "usage", None) else 0,
        }
        raw = resp.model_dump() if hasattr(resp, "model_dump") else getattr(resp, "to_dict_recursive", lambda: dict(resp))()
        jr = None
        if isinstance(text, str):
            jr = _safe_json_loads(text)

        return ChatResult(
            model=getattr(resp, "model", self.cfg.model),
            role=getattr(msg, "role", "assistant"),
            text=text or "",
            finish_reason=getattr(ch, "finish_reason", None),
            tool_calls=[tc.model_dump() if hasattr(tc, "model_dump") else dict(tc) for tc in tool_calls],
            usage=usage,
            raw=raw,
            json=jr,
            latency_ms=latency_ms,
        )

    async def _stream_call(self, payload: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        attempt = 0
        while attempt <= self.cfg.max_retries:
            if self.rps:
                await self.rps.take()

            try:
                if self._aclient is None:  # pragma: no cover
                    # Streaming requires async client; fall back to sync—wrap as async
                    stream = self._client.chat.completions.create(stream=True, **payload)  # type: ignore[attr-defined]
                    async for evt in _sync_stream_to_async(stream):
                        yield evt
                    return

                start = time.monotonic()
                stream = await self._aclient.chat.completions.create(stream=True, **payload)  # type: ignore[attr-defined]

                full_text: List[str] = []
                tool_calls: Dict[int, Dict[str, Any]] = {}
                usage: Dict[str, int] = {}

                async for chunk in stream:
                    # Each chunk has .choices[0].delta
                    ch = chunk.choices[0]
                    delta = getattr(ch, "delta", None)
                    if delta and getattr(delta, "content", None):
                        part = delta.content or ""
                        full_text.append(part)
                        evt = {"type": "delta", "content": part}
                        if self._observer:
                            try: self._observer.on_stream_delta(evt)
                            except Exception: pass
                        yield evt

                    # Tool calls streaming (if any)
                    if delta and getattr(delta, "tool_calls", None):
                        for tc in delta.tool_calls:
                            idx = int(getattr(tc, "index", 0))
                            obj = tool_calls.setdefault(idx, {"id": None, "function": {"name": "", "arguments": ""}})
                            if getattr(tc, "id", None):
                                obj["id"] = tc.id
                            if getattr(tc, "function", None):
                                fn = tc.function
                                if getattr(fn, "name", None):
                                    obj["function"]["name"] = fn.name
                                if getattr(fn, "arguments", None):
                                    # Arguments may arrive in chunks
                                    obj["function"]["arguments"] += fn.arguments
                            yield {"type": "tool_call", "index": idx, "partial": obj}

                latency_ms = int((time.monotonic() - start) * 1000)
                # The stream often ends with a final chunk that includes usage; if not, usage stays empty.
                # Emit final event with aggregation:
                final_text = "".join(full_text)
                end_evt = {
                    "type": "end",
                    "text": final_text,
                    "tool_calls": list(tool_calls.values()),
                    "usage": usage,
                    "latency_ms": latency_ms,
                }
                if self._observer:
                    try: self._observer.on_response(end_evt)
                    except Exception: pass
                yield end_evt
                return

            except (RateLimitError, APITimeoutError, APIConnectionError, APIError) as e:
                transient = isinstance(e, (RateLimitError, APITimeoutError, APIConnectionError)) or (
                    isinstance(e, APIError) and getattr(e, "status_code", 500) >= 500
                )
                self._emit_error(e, attempt)
                if not transient or attempt >= self.cfg.max_retries:
                    yield {"type": "error", "error": repr(e)}
                    return
                await asyncio.sleep(_jittered(min(self.cfg.initial_backoff_s * (2 ** attempt), self.cfg.max_backoff_s), self.cfg.jitter))
                attempt += 1
                continue
            except Exception as e:
                self._emit_error(e, attempt)
                yield {"type": "error", "error": repr(e)}
                return

    def _emit_error(self, exc: BaseException, attempt: int) -> None:
        self.log.warning("OpenAI call failed (attempt %s/%s): %r", attempt + 1, self.cfg.max_retries + 1, exc)
        if self._observer:
            try:
                self._observer.on_error(exc, attempt)
            except Exception:
                pass


###############################################################################
# Helpers: sync<->async bridges
###############################################################################

class _AsyncIteratorSyncWrapper:
    """
    Wrap an async generator into a blocking iterator with a private event loop.
    """
    def __init__(self, loop: asyncio.AbstractEventLoop, agen: AsyncGenerator[Dict[str, Any], None]) -> None:
        self.loop = loop
        self.agen = agen
        self._ait = agen.__aiter__()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return self.loop.run_until_complete(self._ait.__anext__())
        except StopAsyncIteration:
            self.loop.run_until_complete(self._aclose())
            self.loop.close()
            raise

    async def _aclose(self):
        try:
            await self.agen.aclose()
        except Exception:
            pass


async def _sync_stream_to_async(sync_stream) -> AsyncGenerator[Dict[str, Any], None]:  # pragma: no cover
    """
    Best-effort bridge if only sync client is available.
    """
    loop = asyncio.get_running_loop()
    it = iter(sync_stream)
    while True:
        item = await loop.run_in_executor(None, _next_or_none, it)
        if item is None:
            break
        # Convert to our event shape as needed by caller; here we pass through raw chunks.
        yield {"type": "chunk", "raw": item}

def _next_or_none(it):
    try:
        return next(it)
    except StopIteration:
        return None


###############################################################################
# Example usage (commented)
###############################################################################
# from omnimind.adapters.llm.openai_adapter import (
#     OpenAIAdapter, AdapterConfig, ChatMessage, ToolSpec, JsonResponseSpec
# )
#
# cfg = AdapterConfig(
#     model="gpt-4o-mini",
#     api_key=os.getenv("OPENAI_API_KEY"),
#     base_url=os.getenv("OPENAI_BASE_URL"),  # for Azure: "https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions"
#     azure_api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
#     request_timeout_s=60.0,
#     max_retries=5,
#     rate_limit_rps=5.0,
# )
# adapter = OpenAIAdapter(cfg)
#
# # Non-streaming:
# res = asyncio.run(adapter.async_chat([
#     ChatMessage(role="system", content="You are a helpful assistant."),
#     ChatMessage(role="user", content="Say hello in one word."),
# ]))
# print(res.text, res.usage)
#
# # Streaming:
# async def demo():
#     async for evt in await adapter.async_chat(
#         [ChatMessage(role="user", content="Stream ABC")],
#         stream=True
#     ):
#         if evt["type"] == "delta":
#             print(evt["content"], end="", flush=True)
# asyncio.run(demo())
