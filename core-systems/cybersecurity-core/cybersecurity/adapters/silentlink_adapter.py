# cybersecurity-core/cybersecurity/adapters/silentlink_adapter.py
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

import httpx
from pydantic import BaseModel, Field, HttpUrl, PositiveInt, validator

__all__ = [
    "SilentLinkError",
    "SilentLinkAuthError",
    "SilentLinkPermissionError",
    "SilentLinkNotFoundError",
    "SilentLinkRateLimitError",
    "SilentLinkServerError",
    "SilentLinkSettings",
    "SilentLinkAdapter",
    "SilentLinkWebhookVerifier",
    "RetryConfig",
    "Money",
    "Balance",
    "Product",
    "Order",
    "ESimActivation",
    "SmsMessage",
    "InboxPage",
]

logger = logging.getLogger(__name__)


# =============================== Errors ======================================

class SilentLinkError(Exception):
    """Generic adapter error."""


class SilentLinkAuthError(SilentLinkError):
    """401 Unauthorized."""


class SilentLinkPermissionError(SilentLinkError):
    """403 Forbidden."""


class SilentLinkNotFoundError(SilentLinkError):
    """404 Not Found."""


class SilentLinkRateLimitError(SilentLinkError):
    """429 Too Many Requests."""


class SilentLinkServerError(SilentLinkError):
    """5xx server errors."""


# =============================== Models ======================================

class RetryConfig(BaseModel):
    max_retries: int = 4
    backoff_factor: float = 0.6
    jitter: float = 0.2
    retry_on_status: Tuple[int, ...] = (429, 500, 502, 503, 504)


class AuthMode(str):
    BEARER = "bearer"           # Authorization: Bearer <api_key>
    HMAC = "hmac"               # X-Api-Key + X-Api-Signature (настраиваемые имена)


class Money(BaseModel):
    amount: float
    currency: str

    @validator("currency")
    def _cur(cls, v: str) -> str:
        return v.upper()


class Balance(BaseModel):
    available: Money
    hold: Optional[Money] = None
    updated_at: Optional[int] = None  # epoch seconds


class Product(BaseModel):
    id: str
    name: str
    category: Literal["esim", "number", "bundle", "other"] = "esim"
    country: Optional[str] = None
    region: Optional[str] = None
    data_limit_mb: Optional[int] = None
    validity_days: Optional[int] = None
    price: Money
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Order(BaseModel):
    id: str
    status: Literal[
        "new", "pending", "processing", "active", "delivered", "failed", "canceled", "refunded"
    ] = "pending"
    product_id: str
    iccid: Optional[str] = None
    activation_code: Optional[str] = None
    qr_svg: Optional[str] = None
    msisdn: Optional[str] = None
    expires_at: Optional[int] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class ESimActivation(BaseModel):
    iccid: str
    activation_code: Optional[str] = None
    smdp_address: Optional[str] = None
    profile_state: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class SmsMessage(BaseModel):
    id: str
    to: str
    from_: str = Field(alias="from")
    body: str
    created_at: int
    raw: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        allow_population_by_field_name = True


class InboxPage(BaseModel):
    items: List[SmsMessage]
    next_token: Optional[str] = None


class ApiPaths(BaseModel):
    """
    Все пути настраиваются, чтобы адаптер не зависел от конкретной схемы провайдера.
    """
    balance: str = "/v1/balance"
    products: str = "/v1/products"
    orders: str = "/v1/orders"
    order_by_id: str = "/v1/orders/{order_id}"
    activate_esim: str = "/v1/esim/{order_id}/activate"
    inbox: str = "/v1/resources/{resource_id}/inbox"
    release_resource: str = "/v1/resources/{resource_id}/release"


class SilentLinkSettings(BaseModel):
    """
    Конфигурация адаптера. Все имена заголовков и пути — переопределяемые.
    """
    base_url: HttpUrl
    api_key: str
    api_secret: Optional[str] = None          # для HMAC
    auth_mode: Literal["bearer", "hmac"] = "bearer"
    timeout_seconds: float = 30.0
    retry: RetryConfig = RetryConfig()
    verify_ssl: Union[bool, str] = True
    proxies: Optional[Dict[str, str]] = None
    user_agent: str = "Aethernova-SilentLinkAdapter/1.0"
    idempotency_header: str = "Idempotency-Key"
    hmac_headers: Dict[str, str] = Field(
        default_factory=lambda: {
            "key": "X-Api-Key",
            "signature": "X-Api-Signature",
            "timestamp": "X-Api-Timestamp",
        }
    )
    webhook_signature_header: str = "X-Webhook-Signature"
    webhook_timestamp_header: str = "X-Webhook-Timestamp"
    webhook_secret: Optional[str] = None
    api_paths: ApiPaths = ApiPaths()

    @validator("user_agent")
    def _ua(cls, v: str) -> str:
        return v.strip() or "Aethernova-SilentLinkAdapter/1.0"


# =============================== Core Adapter =================================

@dataclass
class _ReqContext:
    method: str
    path: str
    url: str
    attempt: int
    correlation_id: str


class SilentLinkAdapter:
    """
    Промышленный асинхронный адаптер к API провайдера SilentLink-подобного класса.
    Все провайдер-специфичные детали выносятся в конфиг.
    """

    def __init__(self, settings: SilentLinkSettings) -> None:
        self.s = settings
        self._client: Optional[httpx.AsyncClient] = None

    # ---------- lifecycle ----------

    async def __aenter__(self) -> "SilentLinkAdapter":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _ensure_client(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=str(self.s.base_url),
                timeout=self.s.timeout_seconds,
                verify=self.s.verify_ssl,
                proxies=self.s.proxies,
                headers={"User-Agent": self.s.user_agent, "Accept": "application/json"},
                http2=True,
            )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---------- auth/sign ----------

    def _auth_headers(self, body: Optional[bytes] = None) -> Dict[str, str]:
        if self.s.auth_mode == "bearer":
            return {"Authorization": f"Bearer {self.s.api_key}"}
        # hmac
        ts = str(int(time.time()))
        body_b = body or b""
        msg = ts.encode("ascii") + b"." + body_b
        if not self.s.api_secret:
            raise SilentLinkAuthError("HMAC mode requires api_secret")
        sig = hmac.new(self.s.api_secret.encode("utf-8"), msg, sha256).hexdigest()
        return {
            self.s.hmac_headers["key"]: self.s.api_key,
            self.s.hmac_headers["signature"]: sig,
            self.s.hmac_headers["timestamp"]: ts,
        }

    # ---------- request core ----------

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        expected: Tuple[int, ...] = (200,),
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> httpx.Response:
        await self._ensure_client()
        assert self._client is not None

        # prepare
        url = path
        body_bytes = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8") if json_body is not None else None
        headers = self._auth_headers(body=body_bytes)
        if idempotency_key:
            headers[self.s.idempotency_header] = idempotency_key

        attempt = 0
        last_exc: Optional[Exception] = None
        corr = correlation_id or str(uuid.uuid4())

        while True:
            attempt += 1
            ctx = _ReqContext(method=method, path=path, url=str(self.s.base_url) + path, attempt=attempt, correlation_id=corr)
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    content=body_bytes if body_bytes is not None else None,
                )
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_exc = e
                if attempt <= self.s.retry.max_retries:
                    await asyncio.sleep(self._sleep_for(attempt))
                    continue
                raise SilentLinkError(f"Connection error: {e}") from e

            self._audit_http(ctx, resp)

            # success
            if resp.status_code in expected:
                return resp

            # auth/permission
            if resp.status_code == 401:
                raise SilentLinkAuthError(self._error_text(resp))
            if resp.status_code == 403:
                raise SilentLinkPermissionError(self._error_text(resp))
            if resp.status_code == 404:
                raise SilentLinkNotFoundError(self._error_text(resp))

            # rate limit / server errors with retry
            if resp.status_code == 429 or resp.status_code in self.s.retry.retry_on_status:
                if attempt <= self.s.retry.max_retries:
                    delay = self._retry_after(resp) or self._sleep_for(attempt)
                    await asyncio.sleep(delay)
                    continue
                if resp.status_code == 429:
                    raise SilentLinkRateLimitError(self._error_text(resp))
                raise SilentLinkServerError(self._error_text(resp))

            # other 4xx
            if 400 <= resp.status_code < 500:
                raise SilentLinkError(self._error_text(resp))

            # other 5xx
            if 500 <= resp.status_code < 600:
                if attempt <= self.s.retry.max_retries:
                    await asyncio.sleep(self._sleep_for(attempt))
                    continue
                raise SilentLinkServerError(self._error_text(resp))

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        try:
            data = resp.json()
            msg = data.get("error") or data.get("message") or data
            return f"{resp.status_code} {msg}"
        except Exception:
            return f"{resp.status_code} {resp.text}"

    @staticmethod
    def _retry_after(resp: httpx.Response) -> Optional[float]:
        ra = resp.headers.get("Retry-After")
        if not ra:
            return None
        try:
            return max(0.0, float(ra))
        except ValueError:
            return None

    def _sleep_for(self, attempt: int) -> float:
        base = self.s.retry.backoff_factor * (2 ** (attempt - 1))
        # jitter вокруг базы, чтобы избежать синхронизации клиентов
        return base + (self.s.retry.jitter * (0.5 - (time.time() % 1)))

    @staticmethod
    def _audit_http(ctx: _ReqContext, resp: httpx.Response) -> None:
        try:
            record = {
                "event": "silentlink_http",
                "ts": int(time.time()),
                "correlation_id": ctx.correlation_id,
                "method": ctx.method,
                "url": ctx.url,
                "status": resp.status_code,
                "attempt": ctx.attempt,
                "rate_limit": {
                    "limit": resp.headers.get("ratelimit-limit"),
                    "remaining": resp.headers.get("ratelimit-remaining"),
                    "reset": resp.headers.get("ratelimit-reset"),
                },
            }
            logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            logger.exception("Failed to audit HTTP event")

    # ========================= High-level operations ==========================

    async def get_balance(self, *, correlation_id: Optional[str] = None) -> Balance:
        resp = await self._request("GET", self.s.api_paths.balance, correlation_id=correlation_id)
        data = resp.json() or {}
        return self._parse_balance(data)

    async def list_products(
        self,
        *,
        category: Optional[str] = None,
        country: Optional[str] = None,
        region: Optional[str] = None,
        limit: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ) -> List[Product]:
        params: Dict[str, Any] = {}
        if category:
            params["category"] = category
        if country:
            params["country"] = country
        if region:
            params["region"] = region
        if limit:
            params["limit"] = int(limit)
        resp = await self._request("GET", self.s.api_paths.products, params=params, correlation_id=correlation_id)
        data = resp.json() or {}
        items = data.get("items") or data.get("products") or data
        return [self._parse_product(x) for x in items]

    async def create_order(
        self,
        product_id: str,
        *,
        quantity: int = 1,
        options: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Order:
        body: Dict[str, Any] = {"product_id": product_id, "quantity": int(quantity)}
        if options:
            body["options"] = options
        idemp = idempotency_key or str(uuid.uuid4())
        resp = await self._request(
            "POST",
            self.s.api_paths.orders,
            json_body=body,
            expected=(200, 201, 202),
            idempotency_key=idemp,
            correlation_id=correlation_id,
        )
        return self._parse_order(resp.json() or {})

    async def get_order(self, order_id: str, *, correlation_id: Optional[str] = None) -> Order:
        path = self.s.api_paths.order_by_id.format(order_id=order_id)
        resp = await self._request("GET", path, correlation_id=correlation_id)
        return self._parse_order(resp.json() or {})

    async def activate_esim(
        self,
        order_id: str,
        *,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> ESimActivation:
        path = self.s.api_paths.activate_esim.format(order_id=order_id)
        resp = await self._request(
            "POST",
            path,
            json_body={},
            expected=(200, 202),
            idempotency_key=idempotency_key or str(uuid.uuid4()),
            correlation_id=correlation_id,
        )
        return self._parse_activation(resp.json() or {})

    async def get_inbox(
        self,
        resource_id: str,
        *,
        page_token: Optional[str] = None,
        limit: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ) -> InboxPage:
        params: Dict[str, Any] = {}
        if page_token:
            params["page_token"] = page_token
        if limit:
            params["limit"] = int(limit)
        path = self.s.api_paths.inbox.format(resource_id=resource_id)
        resp = await self._request("GET", path, params=params, correlation_id=correlation_id)
        data = resp.json() or {}
        items = data.get("items") or data.get("messages") or []
        next_token = data.get("next_token") or data.get("next")
        return InboxPage(items=[self._parse_sms(x) for x in items], next_token=next_token)

    async def wait_for_sms(
        self,
        resource_id: str,
        *,
        predicate: Optional[callable] = None,
        timeout_seconds: int = 120,
        poll_interval: float = 2.0,
        correlation_id: Optional[str] = None,
    ) -> SmsMessage:
        """
        Ожидание первого SMS, удовлетворяющего predicate(message)->bool.
        Если predicate не задан, вернётся первое новое сообщение.
        """
        end = time.time() + timeout_seconds
        seen: set[str] = set()
        while True:
            page = await self.get_inbox(resource_id, correlation_id=correlation_id)
            for msg in page.items:
                if msg.id in seen:
                    continue
                seen.add(msg.id)
                if predicate is None or predicate(msg):
                    return msg
            if time.time() >= end:
                raise SilentLinkError("Timeout waiting for SMS")
            await asyncio.sleep(poll_interval)

    async def release_resource(self, resource_id: str, *, correlation_id: Optional[str] = None) -> bool:
        path = self.s.api_paths.release_resource.format(resource_id=resource_id)
        resp = await self._request("POST", path, json_body={}, expected=(200, 204), correlation_id=correlation_id)
        return resp.status_code in (200, 204)

    # =============================== Parsers ==================================

    @staticmethod
    def _parse_money(obj: Any) -> Money:
        if isinstance(obj, dict) and "amount" in obj and "currency" in obj:
            return Money(amount=float(obj["amount"]), currency=str(obj["currency"]))
        # допустим плоский формат
        return Money(amount=float(obj or 0.0), currency="USD")

    def _parse_balance(self, data: Dict[str, Any]) -> Balance:
        # поддержка разных форматов провайдера
        if "available" in data and isinstance(data["available"], dict):
            return Balance(
                available=self._parse_money(data["available"]),
                hold=self._parse_money(data["hold"]) if data.get("hold") is not None else None,
                updated_at=data.get("updated_at") or data.get("ts"),
            )
        if "balance" in data:
            return Balance(available=self._parse_money(data["balance"]))
        return Balance(available=self._parse_money(data))

    def _parse_product(self, obj: Dict[str, Any]) -> Product:
        price = obj.get("price") if isinstance(obj.get("price"), dict) else {"amount": obj.get("price"), "currency": obj.get("currency", "USD")}
        return Product(
            id=str(obj.get("id") or obj.get("product_id")),
            name=str(obj.get("name") or obj.get("title") or "product"),
            category=obj.get("category") or "esim",
            country=obj.get("country"),
            region=obj.get("region"),
            data_limit_mb=obj.get("data_limit_mb") or obj.get("data_mb") or obj.get("size_mb"),
            validity_days=obj.get("validity_days") or obj.get("validity") or obj.get("days"),
            price=self._parse_money(price),
            metadata={k: v for k, v in obj.items() if k not in {"id", "product_id", "name", "title", "price", "currency", "country", "region", "data_limit_mb", "data_mb", "size_mb", "validity_days", "validity", "days"}},
        )

    @staticmethod
    def _parse_order(obj: Dict[str, Any]) -> Order:
        return Order(
            id=str(obj.get("id") or obj.get("order_id")),
            status=str(obj.get("status") or "pending"),
            product_id=str(obj.get("product_id") or obj.get("product") or ""),
            iccid=obj.get("iccid"),
            activation_code=obj.get("activation_code") or obj.get("lpa") or obj.get("lpa_code"),
            qr_svg=obj.get("qr_svg") or obj.get("qr") or obj.get("qr_image"),
            msisdn=obj.get("msisdn") or obj.get("phone") or obj.get("number"),
            expires_at=obj.get("expires_at"),
            created_at=obj.get("created_at"),
            updated_at=obj.get("updated_at"),
            raw=obj,
        )

    @staticmethod
    def _parse_activation(obj: Dict[str, Any]) -> ESimActivation:
        return ESimActivation(
            iccid=str(obj.get("iccid") or obj.get("eid") or obj.get("sim_id") or ""),
            activation_code=obj.get("activation_code") or obj.get("lpa") or obj.get("lpa_code"),
            smdp_address=obj.get("smdp") or obj.get("smdp_address"),
            profile_state=obj.get("state") or obj.get("profile_state"),
            raw=obj,
        )

    @staticmethod
    def _parse_sms(obj: Dict[str, Any]) -> SmsMessage:
        return SmsMessage(
            id=str(obj.get("id") or obj.get("msg_id") or obj.get("message_id") or obj.get("uuid")),
            to=str(obj.get("to") or obj.get("recipient") or ""),
            from_=str(obj.get("from") or obj.get("sender") or ""),
            body=str(obj.get("body") or obj.get("text") or ""),
            created_at=int(obj.get("created_at") or obj.get("ts") or obj.get("timestamp") or int(time.time())),
            raw=obj,
        )


# =============================== Webhook verify ===============================

class SilentLinkWebhookVerifier:
    """
    Валидация вебхуков с HMAC-подписью. Формат сообщения:
        signature = HMAC_SHA256(webhook_secret, timestamp + "." + body)
    Заголовки берутся из настроек.
    """

    def __init__(self, settings: SilentLinkSettings) -> None:
        self.s = settings
        if not self.s.webhook_secret:
            logger.warning("webhook_secret is not set; webhook verification will fail")

    def verify_webhook(self, headers: Dict[str, str], body_bytes: bytes, *, tolerance_seconds: int = 300) -> bool:
        ts = headers.get(self.s.webhook_timestamp_header)
        sig = headers.get(self.s.webhook_signature_header)
        if not ts or not sig or not self.s.webhook_secret:
            return False
        # Защита от повторов и отложенных запросов
        try:
            ts_i = int(ts)
        except ValueError:
            return False
        now = int(time.time())
        if abs(now - ts_i) > tolerance_seconds:
            return False

        msg = f"{ts}.{body_bytes.decode('utf-8', errors='ignore')}".encode("utf-8")
        calc = hmac.new(self.s.webhook_secret.encode("utf-8"), msg, sha256).hexdigest()
        return hmac.compare_digest(calc, sig)


# =============================== Usage example ===============================
# Пример (для документации проекта, не исполняется при импорте):
#
# async def main():
#     settings = SilentLinkSettings(
#         base_url="https://api.example.com",
#         api_key=os.environ["SL_API_KEY"],
#         api_secret=os.getenv("SL_API_SECRET"),   # для HMAC
#         auth_mode="bearer",                      # или "hmac"
#     )
#     async with SilentLinkAdapter(settings) as sl:
#         bal = await sl.get_balance()
#         products = await sl.list_products(country="US")
#         order = await sl.create_order(products[0].id, idempotency_key="order-123")
#         order = await sl.get_order(order.id)
#         if order.status in ("active", "delivered"):
#             act = await sl.activate_esim(order.id)
#         inbox = await sl.get_inbox(resource_id=order.msisdn or "")
#         # ожидать sms с конкретным кодом:
#         msg = await sl.wait_for_sms(order.msisdn or "", predicate=lambda m: "code" in m.body.lower())
#         await sl.release_resource(order.msisdn or "")
#
# Вебхук:
# def handle_webhook(headers: Dict[str, str], body: bytes):
#     verifier = SilentLinkWebhookVerifier(settings)
#     if not verifier.verify_webhook(headers, body):
#         raise HTTPException(status_code=400, detail="invalid signature")
#     event = json.loads(body.decode("utf-8"))
#     # ... обработка события ...
