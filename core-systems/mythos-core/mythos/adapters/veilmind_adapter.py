# -*- coding: utf-8 -*-
"""
mythos-core/mythos/adapters/veilmind_adapter.py

Промышленный адаптер к VeilMind-провайдеру LLM (спецификация API не подтверждена).
Адаптер спроектирован как настраиваемый слой поверх универсального HTTP-клиента stdlib.

Возможности:
- Безопасный HTTP (TLS) на stdlib (http.client, ssl)
- Таймауты: connect/read; ретраи с экспоненциальным бэкофом и джиттером
- Токен-бакет rate-limit + семафор на max_concurrency
- Circuit Breaker (half-open пробные запросы)
- Идемпотентность: заголовок Idempotency-Key
- Корреляция: X-Request-ID (возвращается из ответов), пользовательские context headers
- Поддержка обычного и потокового (SSE/NDJSON) вывода
- Строгие структурированные исключения по классам ошибок
- Настраиваемые эндпойнты и трансформеры полезной нагрузки/ответов без привязки к не подтверждённой спецификации

ВАЖНО: Названия путей/полей по умолчанию — «разумные догадки», но не подтверждённые официальной документацией VeilMind.
Перед использованием в проде задайте их явно в VeilMindConfig.endpoints и VeilMindConfig.mappers. I cannot verify this.

Лицензия: proprietary (Aethernova / Mythos Core)
"""
from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import json
import os
import random
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, Iterable, Iterator, List, Mapping, Optional, Tuple, Union

__all__ = [
    "VeilMindConfig",
    "VeilMindAdapter",
    "VeilMindError",
    "VeilMindAuthError",
    "VeilMindRateLimitError",
    "VeilMindTimeout",
    "VeilMindServerError",
    "VeilMindAPIError",
    "VeilMindBadResponse",
]

# =========================
# Ошибки
# =========================

class VeilMindError(Exception):
    """Базовая ошибка адаптера."""
    def __init__(self, message: str, *, status: Optional[int] = None, request_id: Optional[str] = None, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.request_id = request_id
        self.payload = payload

class VeilMindAuthError(VeilMindError):
    """401/403"""

class VeilMindRateLimitError(VeilMindError):
    """429"""

class VeilMindTimeout(VeilMindError):
    """Таймаут соединения/чтения."""

class VeilMindServerError(VeilMindError):
    """5xx"""

class VeilMindAPIError(VeilMindError):
    """4xx прочие"""

class VeilMindBadResponse(VeilMindError):
    """Неконсистентный JSON/поля."""

# =========================
# Конфиг
# =========================

@dataclass
class Endpoint:
    path: str
    method: str = "POST"

@dataclass
class Endpoints:
    generate: Endpoint = Endpoint(path="/v1/chat/completions", method="POST")
    stream_generate: Endpoint = Endpoint(path="/v1/chat/completions", method="POST")  # c ?stream=1 или stream=true
    embeddings: Endpoint = Endpoint(path="/v1/embeddings", method="POST")
    moderate: Endpoint = Endpoint(path="/v1/moderations", method="POST")
    health: Endpoint = Endpoint(path="/v1/health", method="GET")

# Преобразователи: dict -> dict для запроса и dict -> нормализованный dict для ответа
Mapper = Callable[[Mapping[str, Any]], Mapping[str, Any]]
ResponseMapper = Callable[[Mapping[str, Any]], Mapping[str, Any]]

def _identity(x: Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(x)

@dataclass
class Mappers:
    request_generate: Mapper = _identity
    response_generate: ResponseMapper = _identity
    request_embeddings: Mapper = _identity
    response_embeddings: ResponseMapper = _identity
    request_moderate: Mapper = _identity
    response_moderate: ResponseMapper = _identity

@dataclass
class VeilMindConfig:
    base_url: str = os.getenv("VEILMIND_BASE_URL", "https://api.veilmind.example")  # I cannot verify this.
    api_key: Optional[str] = os.getenv("VEILMIND_API_KEY") or None
    organization: Optional[str] = os.getenv("VEILMIND_ORG") or None

    # сетевые настройки
    connect_timeout: float = float(os.getenv("VEILMIND_CONNECT_TIMEOUT", "5"))
    read_timeout: float = float(os.getenv("VEILMIND_READ_TIMEOUT", "60"))
    max_retries: int = int(os.getenv("VEILMIND_MAX_RETRIES", "3"))
    backoff_base: float = float(os.getenv("VEILMIND_BACKOFF_BASE", "0.25"))
    backoff_cap: float = float(os.getenv("VEILMIND_BACKOFF_CAP", "4.0"))
    jitter: bool = True

    # лимиты
    rate_limit_per_sec: float = float(os.getenv("VEILMIND_RATE", "10"))
    max_concurrency: int = int(os.getenv("VEILMIND_MAX_CONCURRENCY", "16"))

    # TLS / proxy
    verify_tls: bool = os.getenv("VEILMIND_VERIFY_TLS", "1") in ("1", "true", "yes")
    ca_file: Optional[str] = os.getenv("VEILMIND_CA_FILE") or None
    http_proxy: Optional[str] = os.getenv("HTTP_PROXY") or None
    https_proxy: Optional[str] = os.getenv("HTTPS_PROXY") or None

    # опции протокола стриминга
    stream_query_param: str = "stream"
    stream_param_value: str = "true"  # добавляется как ?stream=true
    stream_mode: str = "auto"  # "sse" | "ndjson" | "auto"

    # заголовки
    user_agent: str = "mythos-core/veilmind-adapter"
    x_request_id_header: str = "X-Request-ID"
    idempotency_key_header: str = "Idempotency-Key"

    # настраиваемые эндпойнты и мапперы
    endpoints: Endpoints = field(default_factory=Endpoints)
    mappers: Mappers = field(default_factory=Mappers)

# =========================
# Служебные утилиты
# =========================

def _url_join(base: str, path: str) -> str:
    if base.endswith("/"):
        base = base[:-1]
    if not path.startswith("/"):
        path = "/" + path
    return base + path

def _sleep_backoff(attempt: int, cfg: VeilMindConfig) -> None:
    # экспонента с джиттером
    d = min(cfg.backoff_cap, cfg.backoff_base * (2 ** max(0, attempt - 1)))
    if cfg.jitter:
        d *= (0.5 + random.random())
    time.sleep(max(0.05, d))

def _gen_request_id() -> str:
    return uuid.uuid4().hex

def _gen_idempotency_key(payload: Mapping[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

def _parse_retry_after(headers: Mapping[str, str]) -> Optional[float]:
    v = headers.get("retry-after") or headers.get("Retry-After")
    if not v:
        return None
    try:
        return float(v)
    except Exception:
        return None

# =========================
# Rate limiter, Circuit breaker
# =========================

class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: Optional[float] = None):
        self.rate = max(0.01, rate_per_sec)
        self.capacity = capacity or self.rate
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            # ожидание недостающих токенов
            wait = (1.0 - self.tokens) / self.rate
        time.sleep(max(0.0, wait))

class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: float = 30.0, half_open_attempts: int = 1) -> None:
        self.threshold = threshold
        self.cooldown = cooldown
        self.half_open_attempts = half_open_attempts
        self.fail_count = 0
        self.opened_at = 0.0
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            if self.fail_count < self.threshold:
                return True
            # Открыт
            since = time.monotonic() - self.opened_at
            if since >= self.cooldown:
                # half-open окно
                self.fail_count = self.threshold - self.half_open_attempts
                return True
            return False

    def on_success(self) -> None:
        with self.lock:
            self.fail_count = 0
            self.opened_at = 0.0

    def on_failure(self) -> None:
        with self.lock:
            self.fail_count += 1
            if self.fail_count >= self.threshold:
                self.opened_at = time.monotonic()

# =========================
# Низкоуровневый HTTP-клиент stdlib
# =========================

class _HttpClient:
    def __init__(self, cfg: VeilMindConfig) -> None:
        self.cfg = cfg
        self.bucket = TokenBucket(cfg.rate_limit_per_sec, capacity=cfg.rate_limit_per_sec * 2)
        self.cb = CircuitBreaker()
        self.sem = threading.Semaphore(cfg.max_concurrency)

        # SSL контекст
        self.ssl_ctx = ssl.create_default_context(cafile=cfg.ca_file) if cfg.verify_tls else ssl._create_unverified_context()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Optional[bytes],
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        stream: bool = False,
        retries: Optional[int] = None,
    ) -> Tuple[int, Dict[str, str], Union[bytes, Iterator[bytes]]]:
        """
        Выполняет HTTP-запрос с ретраями и rate-limit. Возвращает (status, headers, body|iterator).
        При stream=True возвращается итератор байтовых чанков (raw).
        """
        rt = read_timeout if read_timeout is not None else self.cfg.read_timeout
        ct = connect_timeout if connect_timeout is not None else self.cfg.connect_timeout
        max_retries = self.cfg.max_retries if retries is None else retries

        # Простейший парсер url (без зависимостей)
        scheme, host, port, path, qs = self._parse_url(url)
        if qs:
            path = f"{path}?{qs}"

        attempt = 0
        last_exc: Optional[Exception] = None

        while True:
            attempt += 1
            if not self.cb.allow():
                raise VeilMindError("circuit_open")

            self.bucket.acquire()
            with self.sem:
                try:
                    conn = self._open_conn(scheme, host, port, timeout=ct)
                    # для чтения таймаут выставим на сокете
                    if hasattr(conn, "sock") and conn.sock:
                        conn.sock.settimeout(rt)

                    conn.request(method.upper(), path, body=body, headers=dict(headers))
                    resp = conn.getresponse()
                    status = resp.status
                    resp_headers = {k: v for k, v in resp.getheaders()}

                    # Стриминг: возвращаем итератор
                    if stream:
                        def _iter() -> Iterator[bytes]:
                            try:
                                while True:
                                    chunk = resp.read(8192)
                                    if not chunk:
                                        break
                                    yield chunk
                            finally:
                                with contextlib.suppress(Exception):
                                    resp.close()
                                    conn.close()
                        if 200 <= status < 300:
                            self.cb.on_success()
                            return status, resp_headers, _iter()
                        else:
                            # читаем всё, чтобы получить тело ошибки
                            data = resp.read()
                            self._raise_for_status(status, resp_headers, data)
                    else:
                        data = resp.read()
                        if 200 <= status < 300:
                            self.cb.on_success()
                            return status, resp_headers, data
                        else:
                            self._raise_for_status(status, resp_headers, data)
                except (socket.timeout, TimeoutError) as e:
                    last_exc = e
                    self.cb.on_failure()
                    if attempt > max_retries:
                        raise VeilMindTimeout("timeout") from e
                    _sleep_backoff(attempt, self.cfg)
                    continue
                except (ConnectionError, OSError, http.client.HTTPException) as e:
                    last_exc = e
                    self.cb.on_failure()
                    if attempt > max_retries:
                        raise VeilMindError("connection_error") from e
                    _sleep_backoff(attempt, self.cfg)
                    continue
                finally:
                    with contextlib.suppress(Exception):
                        conn.close()

    def _open_conn(self, scheme: str, host: str, port: int, timeout: float):
        if scheme == "https":
            return http.client.HTTPSConnection(host, port=port, context=self.ssl_ctx, timeout=timeout)
        return http.client.HTTPConnection(host, port=port, timeout=timeout)

    @staticmethod
    def _parse_url(url: str) -> Tuple[str, str, int, str, str]:
        # очень простой парсер (без IPv6)
        if "://" not in url:
            raise ValueError("bad url")
        scheme, rest = url.split("://", 1)
        if "/" in rest:
            hostport, path = rest.split("/", 1)
            path = "/" + path
        else:
            hostport, path = rest, "/"
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        else:
            host = hostport
            port = 443 if scheme == "https" else 80
        if "?" in path:
            path, qs = path.split("?", 1)
        else:
            qs = ""
        return scheme, host, port, path, qs

    def _raise_for_status(self, status: int, headers: Mapping[str, str], data: bytes) -> None:
        rid = headers.get("x-request-id") or headers.get("X-Request-ID")
        text = data.decode("utf-8", errors="ignore")
        payload: Any = None
        with contextlib.suppress(Exception):
            payload = json.loads(text) if text else None

        if status in (401, 403):
            raise VeilMindAuthError("unauthorized", status=status, request_id=rid, payload=payload)
        if status == 429:
            raise VeilMindRateLimitError("rate_limited", status=status, request_id=rid, payload=payload)
        if 500 <= status < 600:
            raise VeilMindServerError("server_error", status=status, request_id=rid, payload=payload)
        raise VeilMindAPIError(f"api_error_{status}", status=status, request_id=rid, payload=payload)

# =========================
# Потоковый парсер (SSE/NDJSON)
# =========================

class _StreamParser:
    def __init__(self, mode: str = "auto") -> None:
        self.mode = mode

    def parse(self, chunks: Iterable[bytes]) -> Iterator[Dict[str, Any]]:
        if self.mode == "ndjson":
            yield from self._iter_ndjson(chunks)
            return
        if self.mode == "sse":
            yield from self._iter_sse(chunks)
            return
        # auto: пробуем угадать
        # читаем немного буфера
        buf = io.BytesIO()
        for chunk in chunks:
            buf.write(chunk)
            if buf.tell() >= 2048:
                break
        data = buf.getvalue()
        # эвристика: строки начинаются с "data:" => SSE
        head = data.decode("utf-8", errors="ignore")
        if "data:" in head or "event:" in head:
            # заново спарсим — отдадим и уже прочитанные байты + оставшиеся
            tail_iter = _chain_bytes([data], chunks)
            yield from self._iter_sse(tail_iter)
        else:
            tail_iter = _chain_bytes([data], chunks)
            yield from self._iter_ndjson(tail_iter)

    def _iter_ndjson(self, chunks: Iterable[bytes]) -> Iterator[Dict[str, Any]]:
        buf = b""
        for chunk in chunks:
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(Exception):
                    obj = json.loads(line.decode("utf-8", errors="ignore"))
                    yield obj
        # хвост
        line = buf.strip()
        if line:
            with contextlib.suppress(Exception):
                yield json.loads(line.decode("utf-8", errors="ignore"))

    def _iter_sse(self, chunks: Iterable[bytes]) -> Iterator[Dict[str, Any]]:
        # очень простой SSE: собираем блоки между пустыми строками, выдёргиваем data:
        buf = ""
        for chunk in chunks:
            buf += chunk.decode("utf-8", errors="ignore")
            while "\n\n" in buf:
                block, buf = buf.split("\n\n", 1)
                data_lines = []
                for ln in block.splitlines():
                    if ln.startswith("data:"):
                        data_lines.append(ln[5:].lstrip())
                if not data_lines:
                    continue
                data = "\n".join(data_lines).strip()
                with contextlib.suppress(Exception):
                    obj = json.loads(data)
                    yield obj

def _chain_bytes(head: Iterable[bytes], tail: Iterable[bytes]) -> Iterable[bytes]:
    for x in head:
        yield x
    for x in tail:
        yield x

# =========================
# Публичный адаптер
# =========================

class VeilMindAdapter:
    """
    Высокоуровневый клиент VeilMind c безопасными дефолтами.
    Перед реальным использованием задайте фактические эндпойнты и маппинг полей в конфиге. I cannot verify this.
    """
    def __init__(self, cfg: Optional[VeilMindConfig] = None) -> None:
        self.cfg = cfg or VeilMindConfig()
        if not self.cfg.api_key:
            # Разрешаем работу без ключа для тестов/health
            pass
        self.http = _HttpClient(self.cfg)

    # ----------- Вспомогательное -----------

    def _headers(self, extra: Optional[Mapping[str, str]] = None, *, idempotency_key: Optional[str] = None) -> Dict[str, str]:
        h = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "application/json",
        }
        if self.cfg.api_key:
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        if self.cfg.organization:
            h["X-Organization"] = self.cfg.organization
        # request id — на уровне приложения (сервер может переписать)
        h[self.cfg.x_request_id_header] = _gen_request_id()
        if idempotency_key:
            h[self.cfg.idempotency_key_header] = idempotency_key
        if extra:
            h.update(extra)
        return h

    def _build_url(self, ep: Endpoint, *, streaming: bool = False) -> str:
        url = _url_join(self.cfg.base_url, ep.path)
        if streaming:
            sep = "?" if "?" not in url else "&"
            url = f"{url}{sep}{self.cfg.stream_query_param}={self.cfg.stream_param_value}"
        return url

    # ----------- Методы API -----------

    def healthcheck(self, extra_headers: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
        ep = self.cfg.endpoints.health
        url = self._build_url(ep)
        st, hdrs, data = self.http.request(ep.method, url, headers=self._headers(extra_headers), body=None)
        txt = data.decode("utf-8", errors="ignore")
        with contextlib.suppress(Exception):
            return json.loads(txt)
        return {"ok": st == 200, "raw": txt}

    def generate(
        self,
        *,
        model: str,
        messages: List[Mapping[str, Any]],
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Mapping[str, Any]]] = None,
        tool_choice: Optional[Union[str, Mapping[str, Any]]] = None,
        user: Optional[str] = None,
        extra_params: Optional[Mapping[str, Any]] = None,
        idempotent: bool = True,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Синхронная генерация (не потоковая). Возвращает нормализованный словарь:
        {
          "text": str,
          "finish_reason": str|None,
          "tool_calls": [ ... ],
          "usage": {"prompt_tokens":..., "completion_tokens":..., "total_tokens":...},
          "raw": <оригинальный ответ провайдера>
        }
        """
        ep = self.cfg.endpoints.generate
        url = self._build_url(ep, streaming=False)

        payload = {
            "model": model,
            "messages": messages,
        }
        if temperature is not None:
            payload["temperature"] = float(temperature)
        if top_p is not None:
            payload["top_p"] = float(top_p)
        if max_tokens is not None:
            payload["max_tokens"] = int(max_tokens)
        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if user:
            payload["user"] = user
        if extra_params:
            payload.update(dict(extra_params))

        # трансформер запроса (под ваш фактический API)
        payload = self.cfg.mappers.request_generate(payload)

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = self._headers(extra_headers, idempotency_key=_gen_idempotency_key(payload) if idempotent else None)
        st, hdrs, data = self.http.request(ep.method, url, headers=headers, body=body)

        txt = data.decode("utf-8", errors="ignore")
        try:
            obj = json.loads(txt) if txt else {}
        except Exception as e:
            raise VeilMindBadResponse("bad_json", status=st, request_id=hdrs.get(self.cfg.x_request_id_header), payload=txt) from e

        # нормализация ответа
        norm = self.cfg.mappers.response_generate(obj)
        # best-effort дефолтная нормализация
        result = _normalize_completion(norm or obj)
        result["raw"] = obj
        result["request_id"] = hdrs.get(self.cfg.x_request_id_header)
        return result

    def stream_generate(
        self,
        *,
        model: str,
        messages: List[Mapping[str, Any]],
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Mapping[str, Any]]] = None,
        tool_choice: Optional[Union[str, Mapping[str, Any]]] = None,
        user: Optional[str] = None,
        extra_params: Optional[Mapping[str, Any]] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Потоковая генерация: итератор событий.
        События:
          {"type":"delta","text":"...", "tool_calls":[...]} — прирост текста/инструментов
          {"type":"end","finish_reason":"stop","usage":{...}}
          {"type":"error","error":"message"}
        """
        ep = self.cfg.endpoints.stream_generate
        url = self._build_url(ep, streaming=True)

        payload = {
            "model": model,
            "messages": messages,
            self.cfg.stream_query_param: True,  # многие API принимают параметр также в теле
        }
        if temperature is not None:
            payload["temperature"] = float(temperature)
        if top_p is not None:
            payload["top_p"] = float(top_p)
        if max_tokens is not None:
            payload["max_tokens"] = int(max_tokens)
        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if user:
            payload["user"] = user
        if extra_params:
            payload.update(dict(extra_params))

        payload = self.cfg.mappers.request_generate(payload)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = self._headers(extra_headers, idempotency_key=_gen_idempotency_key(payload))

        st, hdrs, it = self.http.request(ep.method, url, headers=headers, body=body, stream=True)
        if not isinstance(it, (Iterator, Iterable)):
            raise VeilMindBadResponse("stream_expected", status=st)

        parser = _StreamParser(self.cfg.stream_mode)
        acc_usage: Dict[str, int] = {}
        try:
            for obj in parser.parse(it):  # provider-specific чанки (SSE/NDJSON JSON-объекты)
                mapped = self.cfg.mappers.response_generate(obj)  # нормализуем каждую порцию
                ev = _normalize_stream_chunk(mapped or obj)
                if ev is None:
                    continue
                if ev.get("type") == "usage":
                    # копим usage в end
                    for k, v in ev.get("usage", {}).items():
                        acc_usage[k] = acc_usage.get(k, 0) + int(v)
                    continue
                if ev.get("type") == "delta":
                    yield ev
                if ev.get("type") == "end":
                    if acc_usage and "usage" not in ev:
                        ev["usage"] = dict(acc_usage)
                    ev["request_id"] = hdrs.get(self.cfg.x_request_id_header)
                    yield ev
        except VeilMindError:
            raise
        except Exception as e:
            yield {"type": "error", "error": str(e)}

    def embeddings(
        self,
        *,
        model: str,
        inputs: Union[str, List[str]],
        extra_params: Optional[Mapping[str, Any]] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ep = self.cfg.endpoints.embeddings
        url = self._build_url(ep)
        payload = {"model": model, "input": inputs}
        if extra_params:
            payload.update(dict(extra_params))
        payload = self.cfg.mappers.request_embeddings(payload)

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        st, hdrs, data = self.http.request(ep.method, url, headers=self._headers(extra_headers), body=body)
        txt = data.decode("utf-8", errors="ignore")
        try:
            obj = json.loads(txt) if txt else {}
        except Exception as e:
            raise VeilMindBadResponse("bad_json", status=st, payload=txt) from e

        norm = self.cfg.mappers.response_embeddings(obj) or obj
        vecs = _normalize_embeddings(norm)
        return {"vectors": vecs, "raw": obj, "request_id": hdrs.get(self.cfg.x_request_id_header)}

    def moderate(
        self,
        *,
        model: Optional[str],
        text: str,
        extra_params: Optional[Mapping[str, Any]] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ep = self.cfg.endpoints.moderate
        url = self._build_url(ep)
        payload = {"model": model, "input": text}
        if extra_params:
            payload.update(dict(extra_params))
        payload = self.cfg.mappers.request_moderate(payload)

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        st, hdrs, data = self.http.request(ep.method, url, headers=self._headers(extra_headers), body=body)
        txt = data.decode("utf-8", errors="ignore")
        try:
            obj = json.loads(txt) if txt else {}
        except Exception as e:
            raise VeilMindBadResponse("bad_json", status=st, payload=txt) from e

        norm = self.cfg.mappers.response_moderate(obj) or obj
        result = _normalize_moderation(norm)
        result["raw"] = obj
        result["request_id"] = hdrs.get(self.cfg.x_request_id_header)
        return result


# =========================
# Нормализация ответов (best-effort)
# =========================

def _normalize_completion(obj: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Пробуем вытащить текст/инструменты/usage из «похоже на OpenAI-совместимый» объекта,
    но не полагаемся на структуру. I cannot verify this.
    """
    text = ""
    tool_calls: List[Dict[str, Any]] = []
    finish_reason: Optional[str] = None
    usage = {}

    # candidates: obj["choices"][0]["message"]["content"]
    with contextlib.suppress(Exception):
        ch0 = (obj.get("choices") or [])[0]
        msg = ch0.get("message") or {}
        text = msg.get("content") or ""
        finish_reason = ch0.get("finish_reason")

        # tool calls
        tc = msg.get("tool_calls") or []
        if isinstance(tc, list):
            for t in tc:
                tool_calls.append({
                    "id": t.get("id"),
                    "name": t.get("function", {}).get("name") or t.get("name"),
                    "arguments": t.get("function", {}).get("arguments") or t.get("arguments"),
                    "type": t.get("type", "function"),
                })

    # часто usage на верхнем уровне
    with contextlib.suppress(Exception):
        u = obj.get("usage") or {}
        usage = {
            "prompt_tokens": u.get("prompt_tokens"),
            "completion_tokens": u.get("completion_tokens"),
            "total_tokens": u.get("total_tokens"),
        }

    return {
        "text": text,
        "finish_reason": finish_reason,
        "tool_calls": tool_calls,
        "usage": usage,
    }

def _normalize_stream_chunk(obj: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Пытаемся нормализовать потоковые чанки (аналог «delta»).
    Возвращаем одно из:
    - {"type":"delta","text": "...", "tool_calls":[...]}
    - {"type":"end","finish_reason":"stop","usage": {...}}
    - {"type":"usage","usage": {...}}  # для промежуточных usage
    - None — если чанк не несёт полезной нагрузки
    I cannot verify this.
    """
    # Кандидаты для текста
    with contextlib.suppress(Exception):
        if "choices" in obj:
            ch0 = (obj.get("choices") or [])[0]
            delta = ch0.get("delta") or {}
            if "content" in delta:
                return {"type": "delta", "text": delta.get("content") or "", "tool_calls": []}
            # tool_calls в delta
            tcs = delta.get("tool_calls") or []
            if tcs:
                norm_tcs: List[Dict[str, Any]] = []
                for t in tcs:
                    norm_tcs.append({
                        "id": t.get("id"),
                        "name": (t.get("function") or {}).get("name"),
                        "arguments": (t.get("function") or {}).get("arguments"),
                        "type": t.get("type", "function"),
                    })
                return {"type": "delta", "text": "", "tool_calls": norm_tcs}
            if ch0.get("finish_reason"):
                return {"type": "end", "finish_reason": ch0.get("finish_reason")}
    # Попробуем usage
    with contextlib.suppress(Exception):
        if "usage" in obj:
            return {"type": "usage", "usage": obj.get("usage") or {}}
    return None

def _normalize_embeddings(obj: Mapping[str, Any]) -> List[List[float]]:
    with contextlib.suppress(Exception):
        data = obj.get("data")
        out: List[List[float]] = []
        if isinstance(data, list):
            for item in data:
                emb = item.get("embedding")
                if isinstance(emb, list):
                    out.append([float(x) for x in emb])
        return out
    return []

def _normalize_moderation(obj: Mapping[str, Any]) -> Dict[str, Any]:
    # Нормализуем под простую схему: blocked + categories с вероятностями/флагами
    result = {"blocked": False, "categories": {}, "scores": {}}
    with contextlib.suppress(Exception):
        res = (obj.get("results") or [obj])[0]
        cats = res.get("categories") or {}
        scores = res.get("category_scores") or res.get("scores") or {}
        blocked = bool(res.get("blocked") or res.get("flagged") or False)
        result["categories"] = cats
        result["scores"] = scores
        result["blocked"] = blocked
    return result

# =========================
# Пример настройки мапперов (документация)
# =========================
"""
Пример: задать маппер, если реальное API VeilMind использует другие поля:

def req_map_gen(p):
    # переименуем messages -> input, tools -> functions и т.п.
    q = dict(p)
    q["input"] = q.pop("messages")
    if "tools" in q:
        q["functions"] = q.pop("tools")
    return q

def resp_map_gen(obj):
    # вернуть OpenAI-подобную структуру, чтобы _normalize_completion её понял
    return obj

cfg = VeilMindConfig(
    base_url="https://api.veilmind.example",
    mappers=Mappers(
        request_generate=req_map_gen,
        response_generate=resp_map_gen,
    )
)
client = VeilMindAdapter(cfg)
resp = client.generate(model="vm-large", messages=[{"role":"user","content":"Привет"}])
print(resp["text"])
"""
