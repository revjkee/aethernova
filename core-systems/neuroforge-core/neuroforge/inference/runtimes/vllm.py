# file: neuroforge-core/neuroforge/inference/runtimes/vllm.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    httpx = None  # type: ignore

logger = logging.getLogger(__name__)

# =============================================================================
# Конфигурации и модели
# =============================================================================

@dataclass
class RetryConfig:
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 3000
    multiplier: float = 2.0
    jitter: float = 0.25  # 25% джиттер

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_time_seconds: int = 30

@dataclass
class VLLMRuntimeConfig:
    base_url: str = "http://localhost:8000"  # vLLM OpenAI-compatible сервер
    api_key: Optional[str] = None            # если включена проверка ключа на сервере
    model: str = "model"                     # имя модели, зарегистрированной в vLLM
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 3.0
    max_concurrency: int = 32
    retry: RetryConfig = field(default_factory=RetryConfig)
    cb: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    # Безопасность/ограничения
    max_input_chars: int = 20000
    max_output_tokens: int = 1024
    redact_secrets: bool = True

@dataclass
class SamplingParams:
    temperature: float = 0.2
    top_p: float = 0.95
    max_tokens: Optional[int] = None
    stop: Optional[List[str]] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    seed: Optional[int] = None

@dataclass
class ChatMessage:
    role: str
    content: str

@dataclass
class Usage:
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

@dataclass
class ChatResponse:
    model: str
    content: str
    finish_reason: str
    usage: Usage
    latency_ms: float
    raw: Dict[str, Any] = field(default_factory=dict)

# =============================================================================
# Исключения
# =============================================================================

class InferenceError(Exception): ...
class InferenceTimeout(InferenceError): ...
class InferenceOverloaded(InferenceError): ...
class InferenceUnavailable(InferenceError): ...
class InferenceBadRequest(InferenceError): ...

# =============================================================================
# Утилиты: валидаторы, редактирование, троттлинг
# =============================================================================

def _truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    return s[:limit]

_SECRET_HINTS = ("api_key", "authorization", "password", "secret", "token", "set-cookie")

def _redact(s: str) -> str:
    # Простейшая редактирующая функция, убирающая явные ключи/токены из входа
    lower = s.lower()
    for hint in _SECRET_HINTS:
        if hint in lower:
            s = s.replace(hint, "[REDACTED]")
    return s

def _validate_messages(messages: Sequence[ChatMessage], max_chars: int, redact: bool) -> List[Dict[str, str]]:
    if not messages:
        raise InferenceBadRequest("messages is empty")
    out: List[Dict[str, str]] = []
    total = 0
    for m in messages:
        if m.role not in ("system", "user", "assistant", "tool"):
            raise InferenceBadRequest(f"unsupported role: {m.role}")
        content = m.content or ""
        if redact:
            content = _redact(content)
        content = _truncate(content, max_chars)
        total += len(content)
        out.append({"role": m.role, "content": content})
    if total > max_chars * len(messages):
        raise InferenceBadRequest("input too large")
    return out

def _jittered_backoff(attempt: int, cfg: RetryConfig) -> float:
    delay = min(cfg.max_delay_ms / 1000.0, (cfg.base_delay_ms / 1000.0) * (cfg.multiplier ** (attempt - 1)))
    if cfg.jitter > 0:
        delta = delay * cfg.jitter
        delay = random.uniform(max(0.0, delay - delta), delay + delta)
    return delay

# =============================================================================
# Простой circuit breaker
# =============================================================================

class _CircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig) -> None:
        self.cfg = cfg
        self.failures = 0
        self.open_until = 0.0

    def on_success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.cfg.failure_threshold:
            self.open_until = time.time() + self.cfg.recovery_time_seconds

    def allow(self) -> bool:
        if self.open_until == 0.0:
            return True
        if time.time() >= self.open_until:
            # полуприкрытое состояние — позволяем одну попытку
            self.failures = max(0, self.cfg.failure_threshold - 1)
            self.open_until = 0.0
            return True
        return False

# =============================================================================
# Протокол интерфейса рантайма
# =============================================================================

class LLMRuntime:
    async def aclose(self) -> None: ...
    async def chat(
        self,
        messages: Sequence[ChatMessage],
        params: Optional[SamplingParams] = None,
        *,
        stream: bool = False,
        extra_headers: Optional[Mapping[str, str]] = None,
        request_id: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Union[ChatResponse, AsyncGenerator[str, None]]:
        ...

# =============================================================================
# HTTP-реализация поверх vLLM OpenAI-совместимого API
# =============================================================================

class VLLMHTTPRuntime(LLMRuntime):
    def __init__(self, cfg: VLLMRuntimeConfig) -> None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for VLLMHTTPRuntime")
        self.cfg = cfg
        limits = httpx.Limits(max_connections=cfg.max_concurrency, max_keepalive_connections=min(10, cfg.max_concurrency))
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout_seconds, connect=cfg.connect_timeout_seconds),
            limits=limits,
            headers=self._default_headers(),
        )
        self._sema = asyncio.Semaphore(cfg.max_concurrency)
        self._cb = _CircuitBreaker(cfg.cb)

    def _default_headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        return h

    async def aclose(self) -> None:
        await self._client.aclose()

    async def chat(
        self,
        messages: Sequence[ChatMessage],
        params: Optional[SamplingParams] = None,
        *,
        stream: bool = False,
        extra_headers: Optional[Mapping[str, str]] = None,
        request_id: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Union[ChatResponse, AsyncGenerator[str, None]]:
        if not self._cb.allow():
            raise InferenceUnavailable("circuit open")
        payload_msgs = _validate_messages(messages, self.cfg.max_input_chars, self.cfg.redact_secrets)
        p = params or SamplingParams()
        max_tokens = p.max_tokens or self.cfg.max_output_tokens

        payload: Dict[str, Any] = {
            "model": self.cfg.model,
            "messages": payload_msgs,
            "temperature": p.temperature,
            "top_p": p.top_p,
            "max_tokens": max_tokens,
            "stream": stream,
        }
        if p.stop:
            # vLLM ожидает либо строку, либо список строк
            # убираем дубликаты
            payload["stop"] = list(dict.fromkeys(p.stop))
        if p.presence_penalty is not None:
            payload["presence_penalty"] = p.presence_penalty
        if p.frequency_penalty is not None:
            payload["frequency_penalty"] = p.frequency_penalty
        if p.seed is not None:
            payload["seed"] = p.seed
        if user:
            payload["user"] = user

        headers = dict(extra_headers or {})
        if request_id:
            headers["X-Request-Id"] = request_id

        # Ретраи при 429/5xx, таймауты — на уровне клиента
        attempt = 0
        try:
            async with self._sema:
                while True:
                    attempt += 1
                    try:
                        if stream:
                            return self._stream_chat(payload, headers)
                        else:
                            t0 = time.perf_counter()
                            r = await self._client.post("/v1/chat/completions", headers=headers, json=payload)
                            if r.status_code == 408:
                                raise InferenceTimeout("request timeout")
                            if r.status_code in (429, 500, 502, 503, 504):
                                raise InferenceOverloaded(f"http {r.status_code}")
                            if r.status_code >= 400:
                                raise InferenceBadRequest(f"http {r.status_code}: {r.text[:256]}")
                            data = r.json()
                            self._cb.on_success()
                            latency_ms = (time.perf_counter() - t0) * 1000.0
                            return _to_chat_response(data, latency_ms)
                    except (httpx.ReadTimeout, httpx.ConnectTimeout):
                        err = InferenceTimeout("timeout")
                    except (httpx.RemoteProtocolError, httpx.ReadError):
                        err = InferenceOverloaded("transport error")
                    except InferenceOverloaded as e:
                        err = e
                    except InferenceBadRequest as e:
                        self._cb.on_failure()
                        raise e
                    except Exception as e:
                        err = InferenceError(str(e))

                    self._cb.on_failure()
                    if attempt >= max(1, self.cfg.retry.max_attempts):
                        raise err
                    await asyncio.sleep(_jittered_backoff(attempt, self.cfg.retry))
        except InferenceBadRequest:
            raise
        except InferenceTimeout:
            raise
        except InferenceOverloaded:
            raise
        except Exception as e:
            # аккуратная деградация
            raise InferenceUnavailable(str(e))

    async def _stream_chat(self, payload: Dict[str, Any], headers: Mapping[str, str]) -> AsyncGenerator[str, None]:
        # Возвращаем куски текста без обрамления — только дельты content
        # Клиент верхнего уровня сам агрегирует при необходимости
        t0 = time.perf_counter()
        try:
            r = await self._client.stream("POST", "/v1/chat/completions", headers=headers, json=payload)
        except Exception as e:
            self._cb.on_failure()
            raise InferenceUnavailable(str(e))
        if r.status_code >= 400:
            text = await r.aread()
            self._cb.on_failure()
            if r.status_code in (429, 500, 502, 503, 504):
                raise InferenceOverloaded(f"http {r.status_code}")
            raise InferenceBadRequest(f"http {r.status_code}: {text[:256].decode('utf-8', 'ignore')}")

        async with r:
            async for line in r.aiter_lines():
                if not line:
                    continue
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                        # OpenAI-совместимый формат: choices[0].delta.content
                        ch = obj.get("choices", [{}])[0]
                        delta = ch.get("delta", {})
                        if "content" in delta and delta["content"] is not None:
                            yield str(delta["content"])
                    except Exception:
                        # пропускаем битые чанки
                        continue
        self._cb.on_success()
        _ = (time.perf_counter() - t0) * 1000.0

# =============================================================================
# Опциональный локальный Python-бэкенд через vLLM (если установлен)
# =============================================================================

class VLLMPythonRuntime(LLMRuntime):
    """
    Простая обёртка вокруг локальной библиотеки vLLM.
    Выполняет генерацию в отдельном потоке, чтобы не блокировать event-loop.
    """
    def __init__(self, model: str, cfg: Optional[VLLMRuntimeConfig] = None) -> None:
        self.cfg = cfg or VLLMRuntimeConfig()
        self.model_name = model
        try:
            from vllm import LLM, SamplingParams as _SP  # type: ignore
            self._LLM = LLM
            self._SP = _SP
        except Exception as e:  # pragma: no cover
            raise RuntimeError("vllm is not installed") from e
        # Ленивая инициализация из event-loop по первому вызову
        self._llm = None  # type: ignore

    async def aclose(self) -> None:
        # vLLM не требует явного закрытия
        return None

    async def _ensure_llm(self) -> None:
        if self._llm is None:
            # прогреем модель в отдельном потоке
            def _init() -> Any:
                return self._LLM(self.model_name)
            import anyio.to_thread  # type: ignore
            self._llm = await anyio.to_thread.run_sync(_init)

    async def chat(
        self,
        messages: Sequence[ChatMessage],
        params: Optional[SamplingParams] = None,
        *,
        stream: bool = False,
        extra_headers: Optional[Mapping[str, str]] = None,
        request_id: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Union[ChatResponse, AsyncGenerator[str, None]]:
        if stream:
            raise InferenceBadRequest("streaming not supported in python mode")
        await self._ensure_llm()
        payload_msgs = _validate_messages(messages, self.cfg.max_input_chars, self.cfg.redact_secrets)
        prompt = _render_chat_to_prompt(payload_msgs)
        p = params or SamplingParams()
        max_tokens = p.max_tokens or self.cfg.max_output_tokens

        def _run() -> Tuple[Dict[str, Any], float]:
            t0 = time.perf_counter()
            sp = self._SP(
                max_tokens=max_tokens,
                temperature=p.temperature,
                top_p=p.top_p,
                stop=p.stop or None,
                seed=p.seed,
            )
            outs = self._llm.generate([prompt], sp)  # type: ignore
            text = outs[0].outputs[0].text if outs and outs[0].outputs else ""
            latency_ms = (time.perf_counter() - t0) * 1000.0
            data = {
                "id": "local-vllm",
                "object": "chat.completion",
                "model": self.cfg.model or self.model_name,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": text},
                    }
                ],
                "usage": {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None},
            }
            return data, latency_ms

        import anyio.to_thread  # type: ignore
        data, latency_ms = await anyio.to_thread.run_sync(_run)
        return _to_chat_response(data, latency_ms)

# =============================================================================
# Преобразования форматов
# =============================================================================

def _to_chat_response(data: Mapping[str, Any], latency_ms: float) -> ChatResponse:
    try:
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content") or ""
        finish = choice.get("finish_reason") or "stop"
        usage = data.get("usage") or {}
        return ChatResponse(
            model=str(data.get("model") or ""),
            content=str(content),
            finish_reason=str(finish),
            usage=Usage(
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens"),
            ),
            latency_ms=float(latency_ms),
            raw=dict(data),
        )
    except Exception as e:
        raise InferenceError(f"malformed response: {e}")

def _render_chat_to_prompt(messages: List[Dict[str, str]]) -> str:
    # Нейтральный преобразователь чата в простой prompt для локального режима.
    # Для конкретных моделей лучше использовать системные шаблоны.
    lines: List[str] = []
    for m in messages:
        role = m["role"]
        if role == "system":
            lines.append(f"[system]\n{m['content']}\n")
        elif role == "user":
            lines.append(f"[user]\n{m['content']}\n")
        elif role == "assistant":
            lines.append(f"[assistant]\n{m['content']}\n")
        else:
            lines.append(f"[{role}]\n{m['content']}\n")
    lines.append("[assistant]\n")
    return "\n".join(lines)

# =============================================================================
# Публичное API модуля
# =============================================================================

__all__ = [
    "VLLMRuntimeConfig",
    "SamplingParams",
    "ChatMessage",
    "ChatResponse",
    "Usage",
    "LLMRuntime",
    "VLLMHTTPRuntime",
    "VLLMPythonRuntime",
    # исключения
    "InferenceError",
    "InferenceTimeout",
    "InferenceOverloaded",
    "InferenceUnavailable",
    "InferenceBadRequest",
]
