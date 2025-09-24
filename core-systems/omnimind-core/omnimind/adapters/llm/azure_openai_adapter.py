# SPDX-License-Identifier: Apache-2.0
"""
Azure OpenAI Adapter (industrial grade)

Особенности:
- Чёткая конфигурация без жёстко зашитых версий (api_version обязателен)
- Синхронный HTTP-клиент (httpx) с ретраями и бэк-оффом
- Chat Completions: обычный и потоковый (SSE)
- Поддержка tools/tool_choice (совместимо со схемой OpenAI)
- Embeddings
- Структурные исключения и безопасное логирование
- Корреляция запросов (correlation_id) и user/idempotency
- Безопасная обработка ошибок/таймаутов, маскирование ключей

Зависимости:
  - Python 3.10+
  - httpx>=0.24 (не импортируем ничего лишнего)

Примечания:
  - Не фиксируем конкретные версии API и схемы; всё задаётся конфигом.
  - Маршруты соответствуют общедоступному формату Azure OpenAI.
  - Потоковый режим использует SSE (data: <json> ... [DONE]).
  - В проекте предусмотрите управление секретами вне кода.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, Iterable, List, Literal, Mapping, Optional, Tuple, Union

try:
    import httpx
except Exception as e:  # pragma: no cover
    raise RuntimeError("httpx is required for AzureOpenAIAdapter") from e


Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class AzureOpenAIConfig:
    # Базовые настройки подключения
    endpoint: str                           # https://<resource>.openai.azure.com
    api_version: str                        # напр. "2024-xx-xx" (обязательно)
    api_key: Optional[str] = None           # заголовок: "api-key: <key>"
    bearer_token: Optional[str] = None      # заголовок: "Authorization: Bearer <token>" (AAD)
    organization: Optional[str] = None      # опционально (заголовок "OpenAI-Organization")
    # Развёртывания (deployment names)
    chat_deployment: str = "gpt-deploy"
    embeddings_deployment: str = "embeddings-deploy"
    # Сетевые настройки
    timeout: float = 30.0
    connect_timeout: float = 10.0
    max_retries: int = 4
    backoff_base: float = 0.25
    backoff_max: float = 5.0
    proxy: Optional[str] = None
    # Идентификация/телеметрия
    user: Optional[str] = None
    client_id: str = "omnimind-core"
    correlation_id: Optional[str] = None
    # Логирование
    logger_name: str = "omnimind.adapters.azure_openai"
    log_payloads: bool = False  # В проде оставляйте False
    # Доп. заголовки
    extra_headers: Mapping[str, str] = field(default_factory=dict)

    def headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"{self.client_id}/1.0",
        }
        if self.api_key:
            h["api-key"] = self.api_key
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if self.organization:
            h["OpenAI-Organization"] = self.organization
        if self.user:
            h["OpenAI-User"] = self.user
        if self.correlation_id:
            h["X-Correlation-Id"] = self.correlation_id
        h.update(dict(self.extra_headers or {}))
        return h

    def httpx_params(self) -> Dict[str, Any]:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        proxies = self.proxy if self.proxy else None
        return {
            "timeout": httpx.Timeout(self.timeout, connect=self.connect_timeout),
            "limits": limits,
            "proxies": proxies,
            "transport": httpx.HTTPTransport(retries=0),  # ретраи делаем сами
        }


@dataclass
class ChatMessage:
    role: Role
    content: Optional[str] = None
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    # Сообщения инструментов (ответы инструментов)
    # content обязателен для role="tool"


@dataclass
class ToolSpec:
    type: Literal["function"]
    function: Dict[str, Any]  # {"name": str, "description": str, "parameters": {...}}


@dataclass
class ChatResult:
    content: Optional[str]
    role: Role
    finish_reason: Optional[str]
    tool_calls: Optional[List[Dict[str, Any]]]  # [{"id","type","function":{"name","arguments"}}]
    usage: Optional[Dict[str, int]]             # prompt_tokens, completion_tokens, total_tokens
    content_filter: Optional[Dict[str, Any]]    # azure content filter block
    raw: Dict[str, Any]                         # полный ответ


@dataclass
class ChatChunk:
    delta: Optional[str]
    role: Optional[Role]
    finish_reason: Optional[str]
    tool_calls_delta: Optional[List[Dict[str, Any]]]
    raw: Dict[str, Any]


@dataclass
class EmbeddingResult:
    embeddings: List[List[float]]
    usage: Optional[Dict[str, int]]
    raw: Dict[str, Any]


class AzureOpenAIError(RuntimeError):
    def __init__(self, message: str, *, status: Optional[int] = None, code: Optional[str] = None, raw: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.raw = raw


class AzureOpenAIAdapter:
    """
    Промышленный адаптер к Azure OpenAI (REST).
    """

    def __init__(self, cfg: AzureOpenAIConfig):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg.logger_name)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            handler.setFormatter(fmt)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        self._client = httpx.Client(**cfg.httpx_params())

    # ------------------------------- Public API -------------------------------

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    # Chat Completions (non-stream)
    def chat(
        self,
        messages: List[ChatMessage],
        *,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[ToolSpec]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        stop: Optional[Union[str, List[str]]] = None,
        response_format: Optional[Dict[str, Any]] = None,
        seed: Optional[int] = None,
        user: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> ChatResult:
        """
        Выполнить чат-запрос и вернуть финальный ответ.
        """
        payload = self._build_chat_payload(
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            tools=tools,
            tool_choice=tool_choice,
            stop=stop,
            response_format=response_format,
            seed=seed,
            user=user,
            stream=False,
            extra=extra,
        )
        url = self._chat_url()
        resp = self._request("POST", url, json=payload)
        data = self._parse_json(resp)
        return self._to_chat_result(data)

    # Chat Completions (stream)
    def chat_stream(
        self,
        messages: List[ChatMessage],
        *,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[ToolSpec]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        stop: Optional[Union[str, List[str]]] = None,
        response_format: Optional[Dict[str, Any]] = None,
        seed: Optional[int] = None,
        user: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Generator[ChatChunk, None, None]:
        """
        Потоковый чат-ответ (SSE). Возвращает генератор ChatChunk.
        """
        payload = self._build_chat_payload(
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            tools=tools,
            tool_choice=tool_choice,
            stop=stop,
            response_format=response_format,
            seed=seed,
            user=user,
            stream=True,
            extra=extra,
        )
        url = self._chat_url()
        # Stream SSE
        with self._request_stream("POST", url, json=payload) as r:
            for line in r.iter_lines():
                if not line:
                    continue
                if isinstance(line, bytes):
                    try:
                        line = line.decode("utf-8")
                    except Exception:
                        continue
                if not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    data = json.loads(data_str)
                except Exception:
                    continue
                choice = (data.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                yield ChatChunk(
                    delta=delta.get("content"),
                    role=delta.get("role"),
                    finish_reason=choice.get("finish_reason"),
                    tool_calls_delta=delta.get("tool_calls"),
                    raw=data,
                )

    # Embeddings
    def embeddings(
        self,
        inputs: Union[str, List[str]],
        *,
        deployment: Optional[str] = None,
        dimensions: Optional[int] = None,
        user: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> EmbeddingResult:
        payload: Dict[str, Any] = {"input": inputs}
        if dimensions is not None:
            payload["dimensions"] = int(dimensions)
        if user or self.cfg.user:
            payload["user"] = user or self.cfg.user
        if extra:
            payload.update(extra)
        url = self._emb_url(deployment=deployment)
        resp = self._request("POST", url, json=payload)
        data = self._parse_json(resp)
        vectors = [item["embedding"] for item in (data.get("data") or [])]
        usage = data.get("usage")
        return EmbeddingResult(embeddings=vectors, usage=usage, raw=data)

    # ------------------------------- Builders ---------------------------------

    def _build_chat_payload(
        self,
        *,
        messages: List[ChatMessage],
        stream: bool,
        temperature: Optional[float],
        top_p: Optional[float],
        max_tokens: Optional[int],
        tools: Optional[List[ToolSpec]],
        tool_choice: Optional[Union[str, Dict[str, Any]]],
        stop: Optional[Union[str, List[str]]],
        response_format: Optional[Dict[str, Any]],
        seed: Optional[int],
        user: Optional[str],
        extra: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        m: List[Dict[str, Any]] = []
        for msg in messages:
            item: Dict[str, Any] = {"role": msg.role}
            if msg.name:
                item["name"] = msg.name
            if msg.role == "tool":
                # tool сообщения должны иметь content и tool_call_id
                item["tool_call_id"] = msg.tool_call_id
            if msg.content is not None:
                item["content"] = msg.content
            m.append(item)

        payload: Dict[str, Any] = {
            "messages": m,
            "stream": bool(stream),
        }
        if temperature is not None:
            payload["temperature"] = float(temperature)
        if top_p is not None:
            payload["top_p"] = float(top_p)
        if max_tokens is not None:
            payload["max_tokens"] = int(max_tokens)
        if tools:
            payload["tools"] = [dict(t) for t in tools]  # type: ignore[arg-type]
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if stop is not None:
            payload["stop"] = stop
        if response_format is not None:
            payload["response_format"] = response_format
        if seed is not None:
            payload["seed"] = int(seed)
        if user or self.cfg.user:
            payload["user"] = user or self.cfg.user
        if extra:
            payload.update(extra)
        return payload

    # ------------------------------- URLs -------------------------------------

    def _chat_url(self) -> str:
        # /openai/deployments/{deployment}/chat/completions?api-version=...
        base = self.cfg.endpoint.rstrip("/")
        return f"{base}/openai/deployments/{self.cfg.chat_deployment}/chat/completions?api-version={self.cfg.api_version}"

    def _emb_url(self, *, deployment: Optional[str]) -> str:
        base = self.cfg.endpoint.rstrip("/")
        dep = deployment or self.cfg.embeddings_deployment
        return f"{base}/openai/deployments/{dep}/embeddings?api-version={self.cfg.api_version}"

    # ------------------------------ HTTP layer --------------------------------

    def _request(self, method: str, url: str, *, json: Optional[Mapping[str, Any]] = None) -> httpx.Response:
        # Ретрай на 429/5xx, экспоненциальный бэк-офф с джиттером
        last_exc: Optional[Exception] = None
        for attempt in range(self.cfg.max_retries + 1):
            try:
                if self.cfg.log_payloads:
                    self.logger.info("HTTP %s %s payload=%s", method, url, self._scrub(json))
                resp = self._client.request(method, url, headers=self.cfg.headers(), json=json)
                if resp.status_code >= 200 and resp.status_code < 300:
                    return resp
                if resp.status_code in (408, 409, 429) or 500 <= resp.status_code < 600:
                    # Подлежащие ретраю коды
                    self._log_http_error(resp, attempt)
                else:
                    # Неретраимые ошибки
                    self._raise_http_error(resp)
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as e:
                last_exc = e
                self.logger.warning("HTTP error (attempt %d/%d): %s", attempt + 1, self.cfg.max_retries, e)
            # backoff
            if attempt < self.cfg.max_retries:
                delay = self._backoff_delay(attempt)
                time.sleep(delay)
        if last_exc:
            raise AzureOpenAIError(f"request failed after retries: {last_exc}") from last_exc
        raise AzureOpenAIError("request failed (exhausted retries)")

    def _request_stream(self, method: str, url: str, *, json: Optional[Mapping[str, Any]] = None) -> httpx.Response:
        # Возвращаем Response, который должен закрываться контекстным менеджером
        last_exc: Optional[Exception] = None
        for attempt in range(self.cfg.max_retries + 1):
            try:
                if self.cfg.log_payloads:
                    self.logger.info("HTTP(stream) %s %s payload=%s", method, url, self._scrub(json))
                r = self._client.build_request(method, url, headers=self.cfg.headers(), json=json)
                resp = self._client.send(r, stream=True)
                if 200 <= resp.status_code < 300:
                    return resp
                if resp.status_code in (408, 409, 429) or 500 <= resp.status_code < 600:
                    self._log_http_error(resp, attempt)
                    resp.close()
                else:
                    self._raise_http_error(resp)
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as e:
                last_exc = e
                self.logger.warning("HTTP(stream) error (attempt %d/%d): %s", attempt + 1, self.cfg.max_retries, e)
            if attempt < self.cfg.max_retries:
                delay = self._backoff_delay(attempt)
                time.sleep(delay)
        if last_exc:
            raise AzureOpenAIError(f"stream request failed after retries: {last_exc}") from last_exc
        raise AzureOpenAIError("stream request failed (exhausted retries)")

    def _parse_json(self, resp: httpx.Response) -> Dict[str, Any]:
        try:
            return resp.json()
        except Exception as e:
            raise AzureOpenAIError("invalid json in response", status=resp.status_code) from e

    def _raise_http_error(self, resp: httpx.Response) -> None:
        try:
            data = resp.json()
            message = data.get("error", {}).get("message") or data.get("message") or resp.text
            code = data.get("error", {}).get("code") or data.get("code")
        except Exception:
            message = resp.text
            code = None
        raise AzureOpenAIError(message=message, status=resp.status_code, code=code, raw=resp.text)

    def _log_http_error(self, resp: httpx.Response, attempt: int) -> None:
        try:
            payload = resp.json()
        except Exception:
            payload = {"text": resp.text[:400]}
        self.logger.warning(
            "HTTP %s -> %s (attempt %d/%d) error=%s",
            resp.request.method if resp.request else "POST",
            resp.status_code,
            attempt + 1,
            self.cfg.max_retries,
            self._scrub(payload),
        )

    def _backoff_delay(self, attempt: int) -> float:
        # Экспоненциальный бэк-офф + джиттер
        base = min(self.cfg.backoff_max, self.cfg.backoff_base * (2 ** attempt))
        return round(base * (0.7 + 0.6 * random.random()), 3)

    @staticmethod
    def _scrub(obj: Any) -> Any:
        # Маскировка ключей/токенов в логах
        try:
            s = json.dumps(obj)
            s = s.replace(os.environ.get("AZURE_OPENAI_API_KEY", "*****"), "***")
            return s
        except Exception:
            return obj

    # ------------------------------ Translators -------------------------------

    @staticmethod
    def _to_chat_result(data: Dict[str, Any]) -> ChatResult:
        choices = data.get("choices") or [{}]
        choice = choices[0] or {}
        msg = choice.get("message") or {}
        usage = data.get("usage")
        cfr = (choice.get("content_filter_results") or {}) or (data.get("content_filter_results") or {})
        return ChatResult(
            content=msg.get("content"),
            role=msg.get("role") or "assistant",
            finish_reason=choice.get("finish_reason"),
            tool_calls=msg.get("tool_calls"),
            usage=usage,
            content_filter=cfr,
            raw=data,
        )
