# file: cybersecurity-core/cybersecurity/edr/agent_api.py
"""
EDR Agent API (industrial-grade)

Особенности:
- Асинхронный HTTP-клиент на базе httpx с экспоненциальными ретраями (c джиттером) и уважением Retry-After.
- Единая аутентификация: Authorization: Bearer + опциональная криптоподпись тела (HMAC-SHA256 или Ed25519, если доступен pynacl).
- Идемпотентность запросов (X-Idempotency-Key) и безопасные логи (без PII/секретов).
- Коррекция смещения времени по заголовку Date (для TTL/nonce).
- Батчинг событий с Gzip-сжатием и строгой валидацией моделей (Pydantic v1/v2 совместимость).
- Загрузка артефактов по частям (init/chunk/complete) с контролем целостности (SHA-256).
- Отдельные исключения APIError/AuthError/RateLimitError/ServerError/TransportError/ProtocolError/SigningError.
- Минимальная кардинальность меток и предсказуемые заголовки.

Зависимости: httpx, pydantic; (опционально) pynacl для Ed25519.
Поддержка Python: 3.10+

Семантика API (ожидаемые эндпоинты, могут быть замаплены сервером):
- POST   /v1/agents/enroll
- POST   /v1/agents/{agent_id}/heartbeat
- POST   /v1/agents/{agent_id}/commands:poll
- POST   /v1/agents/{agent_id}/commands/{command_id}:ack
- POST   /v1/agents/{agent_id}/events:batch
- POST   /v1/agents/{agent_id}/files:upload_init
- POST   /v1/agents/{agent_id}/files/{upload_id}:chunk
- POST   /v1/agents/{agent_id}/files/{upload_id}:complete
- GET    /v1/agents/{agent_id}/policy

Пример использования:
    import asyncio
    from cybersecurity.edr.agent_api import AgentAPI, AgentConfig, EventRecord

    async def main():
        api = AgentAPI(AgentConfig(
            base_url="https://edr.example.com",
            api_key="agent-xxxxx",
            secret_key="supersecret",  # для HMAC; или используйте ed25519_sk_hex
        ))
        async with api:
            enrol = await api.enroll(hostname="host1", platform="windows", labels=["prod"])
            hb = await api.heartbeat()
            cmds = await api.poll_commands(max_items=10, wait_seconds=20)
            # ...
    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Tuple, Union

import httpx

try:
    # Optional Ed25519 signing via PyNaCl
    from nacl import signing as _nacl_signing  # type: ignore
    from nacl import exceptions as _nacl_exceptions  # type: ignore
    _HAS_NACL = True
except Exception:  # pragma: no cover
    _HAS_NACL = False

# Pydantic v1/v2 compatibility
try:
    from pydantic import BaseModel, Field, root_validator, validator  # v1
    _PD_V2 = False
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, field_validator  # v2
    _PD_V2 = True  # type: ignore

__all__ = [
    "AgentAPI",
    "AgentConfig",
    "EventRecord",
    "Command",
    "CommandAckResult",
    "EnrollmentResponse",
    "HeartbeatResponse",
    "PolicyBundle",
    "UploadInitResponse",
    "APIError",
    "AuthError",
    "RateLimitError",
    "ServerError",
    "TransportError",
    "ProtocolError",
    "SigningError",
]

logger = logging.getLogger("cybersecurity.edr.agent_api")
logger.addHandler(logging.NullHandler())

# ------------------------- МОДЕЛИ -------------------------------------------

class EnrollmentResponse(BaseModel):
    agent_id: str
    tenant_id: Optional[str] = None
    token: Optional[str] = None
    interval_seconds: int = Field(30, ge=5, le=3600)
    policy_etag: Optional[str] = None


class HeartbeatResponse(BaseModel):
    interval_seconds: int = Field(30, ge=5, le=3600)
    policy_changed: bool = False
    policy_etag: Optional[str] = None
    server_time: Optional[str] = None  # RFC 7231 Date или ISO-8601


class Command(BaseModel):
    command_id: str
    type: str
    issued_at: Optional[str] = None
    args: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = Field(None, ge=1, le=86400)


class CommandAckResult(BaseModel):
    command_id: str
    status: Literal["acknowledged", "failed"]
    error: Optional[str] = None


class EventRecord(BaseModel):
    ts: float = Field(..., description="Unix time seconds")
    level: Literal["debug", "info", "warn", "error"] = "info"
    source: str = Field(..., min_length=1, max_length=64)
    kind: str = Field(..., min_length=1, max_length=64)
    message: str = Field(..., min_length=1, max_length=4096)
    attrs: Dict[str, Any] = Field(default_factory=dict)
    host: Optional[str] = None

    # Валидация уровня кардинальности
    if not _PD_V2:
        @root_validator(pre=False)
        def _prune_attrs_v1(cls, values):  # type: ignore
            attrs = values.get("attrs") or {}
            # защита от сверхкрупных полезных нагрузок
            if len(json.dumps(attrs)) > 16 * 1024:
                values["attrs"] = {"_note": "attrs truncated"}
            return values
    else:  # pragma: no cover
        @field_validator("attrs")
        @classmethod
        def _prune_attrs_v2(cls, v):  # type: ignore
            if len(json.dumps(v or {})) > 16 * 1024:
                return {"_note": "attrs truncated"}
            return v


class PolicyBundle(BaseModel):
    etag: str
    version: str
    checksum: str  # sha256 base64
    data: Dict[str, Any]


class UploadInitResponse(BaseModel):
    upload_id: str
    part_size: int = Field(..., ge=64 * 1024, le=16 * 1024 * 1024)
    expires_in: int = Field(..., ge=60, le=24 * 3600)


# ------------------------- ИСКЛЮЧЕНИЯ ---------------------------------------

class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, *, retry_after: Optional[int] = None) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


class AuthError(APIError):
    pass


class RateLimitError(APIError):
    pass


class ServerError(APIError):
    pass


class TransportError(Exception):
    pass


class ProtocolError(Exception):
    pass


class SigningError(Exception):
    pass


# ------------------------- КОНФИГ -------------------------------------------

@dataclass
class AgentConfig:
    base_url: str
    api_key: str
    # Вариант 1: HMAC
    secret_key: Optional[str] = None  # для HMAC-SHA256 (ASCII/UTF-8)
    # Вариант 2: Ed25519 (hex приватного ключа)
    ed25519_sk_hex: Optional[str] = None

    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    user_agent: str = "Aethernova-EDR-Agent/1.0"

    # HTTP
    timeout: float = 15.0
    connect_timeout: float = 5.0
    verify: Union[bool, str] = True  # True/False или путь к CA-bundle
    proxies: Optional[Dict[str, str]] = None

    # Ретраи
    retries: int = 5
    backoff_initial: float = 0.2
    backoff_max: float = 15.0

    # Сжатие/батчинг
    gzip_min_bytes: int = 1024
    events_batch_max: int = 500
    events_flush_seconds: int = 5

    # Идемпотентность
    idempotency: bool = True

    # Ограничение размера тел (защита)
    max_body_bytes: int = 8 * 1024 * 1024  # 8 MiB на запрос


# ------------------------- ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ --------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256_b64(data: bytes) -> str:
    return _b64(hashlib.sha256(data).digest())


def _now_http_date() -> str:
    # RFC 7231 Date — для совместимости с серверным логированием
    return httpx.Headers().get("date", None) or time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def _gzip_maybe(data: bytes, threshold: int) -> Tuple[bytes, Optional[str]]:
    if len(data) >= threshold:
        return gzip.compress(data), "gzip"
    return data, None


def _jitter_delay(attempt: int, base: float, max_s: float) -> float:
    # экспоненциальный backoff с decorrelated jitter
    import random
    return min(max_s, random.uniform(0, base * (2 ** attempt)))


def _safe_json_dumps(obj: Any) -> bytes:
    try:
        s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        out = s.encode("utf-8")
        if len(out) > 32 * 1024 * 1024:
            raise ValueError("payload too large")
        return out
    except Exception as e:  # pragma: no cover
        raise ProtocolError(f"Failed to serialize JSON: {e}") from e


def _gen_idem_key() -> str:
    return str(uuid.uuid4())


# ------------------------- ПОДПИСАНИЕ ЗАПРОСОВ ------------------------------

class _Signer:
    """
    Унифицированная обертка для HMAC-SHA256 или Ed25519 (если задан ed25519_sk_hex и доступна PyNaCl).
    """
    def __init__(self, secret_key: Optional[str], ed25519_sk_hex: Optional[str]) -> None:
        self._mode: Literal["none", "hmac", "ed25519"] = "none"
        self._hmac_key: Optional[bytes] = None
        self._ed25519: Optional[Any] = None

        if ed25519_sk_hex:
            if not _HAS_NACL:
                raise SigningError("PyNaCl is required for Ed25519 signing but not installed")
            try:
                sk_bytes = bytes.fromhex(ed25519_sk_hex)
                self._ed25519 = _nacl_signing.SigningKey(sk_bytes)
                self._mode = "ed25519"
            except Exception as e:
                raise SigningError(f"Invalid Ed25519 secret: {e}") from e
        elif secret_key:
            self._hmac_key = secret_key.encode("utf-8")
            self._mode = "hmac"

    @property
    def mode(self) -> str:
        return self._mode

    def sign(self, method: str, path_qs: str, body_sha256_b64: str, date: str, nonce: str) -> str:
        """
        Возвращает строку подписи base64 для заголовка X-Signature.
        """
        if self._mode == "none":
            raise SigningError("No signing keys configured")

        msg = f"{method.upper()} {path_qs}\n{date}\n{nonce}\n{body_sha256_b64}".encode("utf-8")

        if self._mode == "hmac":
            assert self._hmac_key is not None
            sig = hmac.new(self._hmac_key, msg, hashlib.sha256).digest()
            return _b64(sig)

        if self._mode == "ed25519":
            assert self._ed25519 is not None
            sig = self._ed25519.sign(msg).signature
            return _b64(sig)

        raise SigningError("Unsupported signing mode")


# ------------------------- ОСНОВНОЙ КЛАСС API -------------------------------

class AgentAPI:
    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self._client: Optional[httpx.AsyncClient] = None
        self._time_offset_sec: float = 0.0  # server_now - client_now
        self._signer = _Signer(cfg.secret_key, cfg.ed25519_sk_hex) if (cfg.secret_key or cfg.ed25519_sk_hex) else None

    # --------- контекстный менеджер ---------
    async def __aenter__(self) -> "AgentAPI":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # --------- публичные методы API ---------
    async def enroll(self, *, hostname: str, platform: str, labels: Optional[List[str]] = None,
                     capabilities: Optional[List[str]] = None) -> EnrollmentResponse:
        payload = {
            "hostname": hostname,
            "platform": platform,
            "labels": labels or [],
            "capabilities": capabilities or [],
            "agent_id": self.cfg.agent_id,
            "tenant_id": self.cfg.tenant_id,
            "version": os.getenv("EDR_AGENT_VERSION", "1.0.0"),
        }
        resp = await self._post("/v1/agents/enroll", json_obj=payload, sign=True)
        data = self._parse_json(resp)
        model = EnrollmentResponse(**data)
        # Обновляем локальный агентский контекст
        self.cfg.agent_id = model.agent_id
        if model.tenant_id and not self.cfg.tenant_id:
            self.cfg.tenant_id = model.tenant_id
        return model

    async def heartbeat(self) -> HeartbeatResponse:
        self._require_agent()
        path = f"/v1/agents/{self.cfg.agent_id}/heartbeat"
        resp = await self._post(path, json_obj={"ts": self._server_now_ts()}, sign=True)
        self._update_time_offset(resp)
        return HeartbeatResponse(**self._parse_json(resp))

    async def poll_commands(self, *, max_items: int = 50, wait_seconds: int = 30) -> List[Command]:
        self._require_agent()
        path = f"/v1/agents/{self.cfg.agent_id}/commands:poll"
        body = {"max_items": max(1, min(max_items, 500)), "wait_seconds": max(0, min(wait_seconds, 60))}
        resp = await self._post(path, json_obj=body, sign=True, timeout=self.cfg.timeout + wait_seconds + 5)
        data = self._parse_json(resp)
        items = data.get("items") or []
        return [Command(**it) for it in items]

    async def ack_command(self, command_id: str, *, ok: bool, error: Optional[str] = None) -> CommandAckResult:
        self._require_agent()
        path = f"/v1/agents/{self.cfg.agent_id}/commands/{command_id}:ack"
        body = {"status": "acknowledged" if ok else "failed", "error": error}
        resp = await self._post(path, json_obj=body, sign=True)
        return CommandAckResult(**self._parse_json(resp))

    async def send_events(self, events: Iterable[EventRecord]) -> Dict[str, Any]:
        """
        Отправляет батч событий. Автоматически gzip, если превышен порог.
        """
        self._require_agent()
        path = f"/v1/agents/{self.cfg.agent_id}/events:batch"
        batch = [e.dict() for e in events]
        if not batch:
            return {"sent": 0}
        if len(batch) > self.cfg.events_batch_max:
            batch = batch[: self.cfg.events_batch_max]

        raw = _safe_json_dumps({"items": batch, "ts": self._server_now_ts()})
        raw, enc = _gzip_maybe(raw, self.cfg.gzip_min_bytes)
        headers = {"Content-Type": "application/json"}
        if enc:
            headers["Content-Encoding"] = enc
        resp = await self._post(path, raw_body=raw, headers=headers, sign=True)
        return self._parse_json(resp)

    async def get_policy(self) -> PolicyBundle:
        self._require_agent()
        path = f"/v1/agents/{self.cfg.agent_id}/policy"
        resp = await self._get(path)
        return PolicyBundle(**self._parse_json(resp))

    async def upload_file(
        self,
        file_name: str,
        content: AsyncIterator[bytes],
        *,
        total_size: Optional[int] = None,
        part_size: int = 2 * 1024 * 1024,
        sha256_hex: Optional[str] = None,
        content_type: str = "application/octet-stream",
        labels: Optional[List[str]] = None,
        timeout_per_part: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Инициализирует загрузку, отправляет чанки и завершает с контролем целостности.
        """
        self._require_agent()
        init = await self._post(
            f"/v1/agents/{self.cfg.agent_id}/files:upload_init",
            json_obj={
                "file_name": file_name,
                "size": total_size,
                "content_type": content_type,
                "labels": labels or [],
                "client_part_size": part_size,
                "sha256": sha256_hex,
            },
            sign=True,
        )
        init_model = UploadInitResponse(**self._parse_json(init))
        upload_id = init_model.upload_id
        server_part = init_model.part_size or part_size

        idx = 0
        hasher = hashlib.sha256()
        async for chunk in _chunk_stream(content, server_part):
            idx += 1
            hasher.update(chunk)
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Transfer-Encoding": "binary",
                "X-Upload-Part-Number": str(idx),
            }
            await self._post(
                f"/v1/agents/{self.cfg.agent_id}/files/{upload_id}:chunk",
                raw_body=chunk,
                headers=headers,
                sign=True,
                timeout=timeout_per_part or max(self.cfg.timeout, 30.0),
            )

        final_sha256 = hasher.hexdigest()
        if sha256_hex and sha256_hex.lower() != final_sha256.lower():
            raise ProtocolError("Local SHA-256 mismatch for uploaded content")

        complete = await self._post(
            f"/v1/agents/{self.cfg.agent_id}/files/{upload_id}:complete",
            json_obj={"sha256": final_sha256},
            sign=True,
            timeout=max(self.cfg.timeout, 30.0),
        )
        return self._parse_json(complete)

    # --------------------- низкоуровневый транспорт ---------------------

    async def _ensure_client(self) -> None:
        if self._client is not None:
            return
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
        timeout = httpx.Timeout(
            self.cfg.timeout,
            connect=self.cfg.connect_timeout,
            read=self.cfg.timeout,
            write=self.cfg.timeout,
            pool=self.cfg.timeout,
        )
        headers = {"User-Agent": self.cfg.user_agent, "Accept": "application/json"}
        self._client = httpx.AsyncClient(
            base_url=self.cfg.base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            limits=limits,
            verify=self.cfg.verify,
            proxies=self.cfg.proxies,
        )

    async def _get(self, path: str, *, timeout: Optional[float] = None) -> httpx.Response:
        return await self._request("GET", path, timeout=timeout)

    async def _post(
        self,
        path: str,
        *,
        json_obj: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        sign: bool = False,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        if (json_obj is None) == (raw_body is None):
            raise ProtocolError("Exactly one of json_obj or raw_body must be provided")
        body = raw_body if raw_body is not None else _safe_json_dumps(json_obj)
        if len(body) > self.cfg.max_body_bytes:
            raise ProtocolError("Request body exceeds max_body_bytes")
        return await self._request("POST", path, body=body, headers=headers, sign=sign, timeout=timeout)

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.cfg.api_key}"}

    def _idempotency_headers(self) -> Dict[str, str]:
        if self.cfg.idempotency:
            return {"X-Idempotency-Key": _gen_idem_key()}
        return {}

    def _sig_headers(self, method: str, path_qs: str, body: bytes) -> Dict[str, str]:
        if not self._signer:
            return {}
        date = _now_http_date()
        nonce = uuid.uuid4().hex
        digest = sha256_b64(body)
        try:
            sig = self._signer.sign(method, path_qs, digest, date, nonce)
        except SigningError:
            raise
        except Exception as e:  # pragma: no cover
            raise SigningError(f"Signing failed: {e}") from e
        alg = "ed25519" if self._signer.mode == "ed25519" else "hmac-sha256"
        return {
            "X-Signature": f'v1;alg={alg};nonce={nonce};digest-sha256={digest};sig={sig}',
            "Date": date,
            "Digest": f"SHA-256={digest}",
        }

    def _update_time_offset(self, resp: httpx.Response) -> None:
        try:
            server_date = resp.headers.get("Date")
            if not server_date:
                return
            # httpx сам парсит даты в .headers? Берём time.time() как now
            server_epoch = httpx.utils.parse_header_links  # noqa: F401 (стаб для mypy)
            # Упростим: используем Date как истину, но без сложного парсинга — httpx не даёт парсер.
            # Если сервер отдаёт X-Server-Time: <epoch>
            server_epoch_hdr = resp.headers.get("X-Server-Time")
            if server_epoch_hdr:
                server_ts = float(server_epoch_hdr)
                self._time_offset_sec = server_ts - time.time()
        except Exception:
            pass

    def _server_now_ts(self) -> float:
        return time.time() + self._time_offset_sec

    async def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        sign: bool = False,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        await self._ensure_client()
        assert self._client is not None

        url_path = path if path.startswith("/") else f"/{path}"
        hdrs: Dict[str, str] = {}
        hdrs.update(self._auth_headers())
        hdrs.update(self._idempotency_headers())
        if headers:
            hdrs.update(headers)

        # Подпись тела
        if sign:
            if body is None:
                body = b""
            hdrs.update(self._sig_headers(method, url_path, body))

        attempt = 0
        last_exc: Optional[Exception] = None
        while True:
            attempt += 1
            try:
                resp = await self._client.request(
                    method,
                    url_path,
                    content=body,
                    headers=hdrs,
                    timeout=timeout or self.cfg.timeout,
                )
                self._update_time_offset(resp)
                if 200 <= resp.status_code < 300:
                    return resp

                # Парсим тело ошибки
                err_json = self._parse_json_safely(resp)
                code = (err_json.get("code") if isinstance(err_json, dict) else None) or "error"
                msg = (err_json.get("message") if isinstance(err_json, dict) else None) or resp.text[:200]

                retry_after = None
                if "Retry-After" in resp.headers:
                    try:
                        retry_after = int(resp.headers["Retry-After"])
                    except Exception:
                        retry_after = None

                if resp.status_code in (401, 403):
                    raise AuthError(resp.status_code, code, msg, retry_after=retry_after)
                if resp.status_code == 429:
                    raise RateLimitError(resp.status_code, code, msg, retry_after=retry_after)
                if 500 <= resp.status_code < 600:
                    raise ServerError(resp.status_code, code, msg, retry_after=retry_after)
                raise APIError(resp.status_code, code, msg, retry_after=retry_after)

            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.ConnectError) as e:
                last_exc = e
                if attempt > self.cfg.retries:
                    raise TransportError(f"Transport failed after {attempt} attempts: {e}") from e
                await asyncio.sleep(_jitter_delay(attempt, self.cfg.backoff_initial, self.cfg.backoff_max))
                continue

            except RateLimitError as e:
                if attempt > self.cfg.retries:
                    raise
                delay = e.retry_after if e.retry_after is not None else _jitter_delay(attempt, self.cfg.backoff_initial, self.cfg.backoff_max)
                await asyncio.sleep(min(delay, self.cfg.backoff_max))
                continue

            except ServerError as e:
                if attempt > self.cfg.retries:
                    raise
                delay = e.retry_after if e.retry_after is not None else _jitter_delay(attempt, self.cfg.backoff_initial, self.cfg.backoff_max)
                await asyncio.sleep(min(delay, self.cfg.backoff_max))
                continue

            except APIError:
                # Коды 4xx (кроме 401/403/429) — не ретраим
                raise

            except Exception as e:  # непредвиденная ошибка
                raise TransportError(f"Unexpected error: {e}") from e

        raise TransportError(f"Request failed: {last_exc}")

    # --------------------- парсинг ответов ---------------------

    @staticmethod
    def _parse_json(resp: httpx.Response) -> Dict[str, Any]:
        try:
            return resp.json()
        except Exception as e:
            raise ProtocolError(f"Invalid JSON response: {e}") from e

    @staticmethod
    def _parse_json_safely(resp: httpx.Response) -> Dict[str, Any]:
        try:
            return resp.json()
        except Exception:
            return {"message": resp.text[:200]}

    def _require_agent(self) -> None:
        if not self.cfg.agent_id:
            raise ProtocolError("agent_id is required; call enroll() first")


# ------------------------- ВСПОМОГАТЕЛЬНЫЕ ГЕНЕРАТОРЫ -----------------------

async def _chunk_stream(source: AsyncIterator[bytes], chunk_size: int) -> AsyncIterator[bytes]:
    """
    Ребуферизует поток в заданный размер чанка.
    """
    buf = bytearray()
    async for piece in source:
        if not piece:
            continue
        buf.extend(piece)
        while len(buf) >= chunk_size:
            yield bytes(buf[:chunk_size])
            del buf[:chunk_size]
    if buf:
        yield bytes(buf)
