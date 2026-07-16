# agent_mash/tests/mocks/payment_mock.py
"""
Industrial payment mock for integration and service tests.

Unverified parts (must be adapted to your project):
- Your real payment provider API shapes (fields, statuses)
- Your signature header names and signing scheme
- Your id formats and currency/amount rules
- Your import paths and dependency injection hooks

Because I cannot verify these specifics, this module provides:
- A deterministic, in-memory payment gateway with realistic flows
- Optional HMAC signature generation/verification for webhook testing
- Async and sync compatible interfaces
- Idempotency keys
- Event journal for assertions

No external network, no real provider calls.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import hmac
import hashlib
import json
import secrets
import threading
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Optional, Protocol


# -----------------------------
# Domain types
# -----------------------------

class PaymentStatus(str, enum.Enum):
    PENDING = "pending"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"


class PaymentErrorCode(str, enum.Enum):
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    ALREADY_FINAL = "already_final"
    AMOUNT_EXCEEDS = "amount_exceeds"
    SIGNATURE_INVALID = "signature_invalid"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"


@dataclasses.dataclass(frozen=True, slots=True)
class PaymentError(Exception):
    code: PaymentErrorCode
    message: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message} ({self.details})"


@dataclasses.dataclass(slots=True)
class PaymentIntent:
    """
    Provider-neutral payment intent model.
    """
    id: str
    amount: int
    currency: str
    status: PaymentStatus
    created_at: _dt.datetime
    description: str = ""
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    customer_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    provider_ref: Optional[str] = None
    confirmed_at: Optional[_dt.datetime] = None
    canceled_at: Optional[_dt.datetime] = None
    failure_reason: Optional[str] = None
    refunded_amount: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "amount": self.amount,
            "currency": self.currency,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "description": self.description,
            "metadata": self.metadata,
            "customer_id": self.customer_id,
            "idempotency_key": self.idempotency_key,
            "provider_ref": self.provider_ref,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "canceled_at": self.canceled_at.isoformat() if self.canceled_at else None,
            "failure_reason": self.failure_reason,
            "refunded_amount": self.refunded_amount,
        }


@dataclasses.dataclass(slots=True)
class Refund:
    id: str
    payment_id: str
    amount: int
    currency: str
    created_at: _dt.datetime
    reason: str = ""
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "payment_id": self.payment_id,
            "amount": self.amount,
            "currency": self.currency,
            "created_at": self.created_at.isoformat(),
            "reason": self.reason,
            "metadata": self.metadata,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class WebhookEvent:
    """
    Provider-neutral webhook event payload.
    """
    id: str
    type: str
    created_at: _dt.datetime
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "created_at": int(self.created_at.timestamp()),
            "data": self.data,
        }


# -----------------------------
# Protocol for DI
# -----------------------------

class PaymentGateway(Protocol):
    def create_payment_intent(
        self,
        *,
        amount: int,
        currency: str,
        description: str = "",
        metadata: Optional[dict[str, Any]] = None,
        customer_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> PaymentIntent: ...

    async def acreate_payment_intent(
        self,
        *,
        amount: int,
        currency: str,
        description: str = "",
        metadata: Optional[dict[str, Any]] = None,
        customer_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> PaymentIntent: ...

    def confirm_payment(self, payment_id: str) -> PaymentIntent: ...
    async def aconfirm_payment(self, payment_id: str) -> PaymentIntent: ...

    def cancel_payment(self, payment_id: str, reason: str = "") -> PaymentIntent: ...
    async def acancel_payment(self, payment_id: str, reason: str = "") -> PaymentIntent: ...

    def get_payment(self, payment_id: str) -> PaymentIntent: ...
    async def aget_payment(self, payment_id: str) -> PaymentIntent: ...

    def refund(
        self,
        payment_id: str,
        *,
        amount: Optional[int] = None,
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Refund: ...

    async def arefund(
        self,
        payment_id: str,
        *,
        amount: Optional[int] = None,
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Refund: ...

    def make_webhook_event(self, event_type: str, data: dict[str, Any]) -> WebhookEvent: ...
    def sign_webhook(self, payload: bytes) -> str: ...
    def verify_webhook(self, payload: bytes, signature: str) -> bool: ...


# -----------------------------
# Industrial mock implementation
# -----------------------------

@dataclasses.dataclass(slots=True)
class PaymentMockConfig:
    """
    Configuration knobs for tests.
    """
    secret: bytes = b"test_webhook_secret"
    default_currency: str = "USD"
    require_confirmation: bool = True
    fail_on_confirm: bool = False
    fail_reason: str = "mock_failure"
    allow_negative_amount: bool = False
    min_amount: int = 1
    max_amount: int = 10**12
    provider_name: str = "mockpay"
    signature_algo: str = "sha256"  # used by HMAC


@dataclasses.dataclass(slots=True)
class PaymentMockJournalEntry:
    ts: _dt.datetime
    action: str
    payload: dict[str, Any]


class PaymentGatewayMock(PaymentGateway):
    """
    Thread-safe in-memory payment gateway mock.

    Features:
    - Idempotency support for create and refund
    - State machine validation
    - Webhook event creation + HMAC signature
    - Journal for deterministic assertions
    """

    def __init__(self, config: Optional[PaymentMockConfig] = None, *, now_fn: Optional[Callable[[], _dt.datetime]] = None) -> None:
        self._cfg = config or PaymentMockConfig()
        self._now = now_fn or (lambda: _dt.datetime.now(tz=_dt.timezone.utc))
        self._lock = threading.RLock()

        self._payments: dict[str, PaymentIntent] = {}
        self._refunds: dict[str, Refund] = {}

        # Idempotency maps:
        # key -> object_id
        self._create_idem: dict[str, str] = {}
        self._refund_idem: dict[str, str] = {}

        self.journal: list[PaymentMockJournalEntry] = []

    # -------------
    # Core helpers
    # -------------

    def _log(self, action: str, payload: dict[str, Any]) -> None:
        self.journal.append(PaymentMockJournalEntry(ts=self._now(), action=action, payload=payload))

    def _validate_amount(self, amount: int) -> None:
        if not self._cfg.allow_negative_amount and amount < 0:
            raise PaymentError(PaymentErrorCode.INVALID_REQUEST, "Amount must be non-negative.", {"amount": amount})
        if amount < self._cfg.min_amount:
            raise PaymentError(PaymentErrorCode.INVALID_REQUEST, "Amount below minimum.", {"amount": amount, "min": self._cfg.min_amount})
        if amount > self._cfg.max_amount:
            raise PaymentError(PaymentErrorCode.INVALID_REQUEST, "Amount exceeds maximum.", {"amount": amount, "max": self._cfg.max_amount})

    def _get(self, pid: str) -> PaymentIntent:
        p = self._payments.get(pid)
        if not p:
            raise PaymentError(PaymentErrorCode.NOT_FOUND, "Payment not found.", {"payment_id": pid})
        return p

    def _ensure_not_final(self, p: PaymentIntent) -> None:
        if p.status in (PaymentStatus.SUCCEEDED, PaymentStatus.CANCELED, PaymentStatus.REFUNDED):
            raise PaymentError(PaymentErrorCode.ALREADY_FINAL, "Payment is in final state.", {"payment_id": p.id, "status": p.status.value})

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4()}"

    # ------------------------
    # Sync and async endpoints
    # ------------------------

    def create_payment_intent(
        self,
        *,
        amount: int,
        currency: str,
        description: str = "",
        metadata: Optional[dict[str, Any]] = None,
        customer_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> PaymentIntent:
        with self._lock:
            self._validate_amount(amount)
            currency_norm = (currency or self._cfg.default_currency).upper()

            if idempotency_key:
                existing_id = self._create_idem.get(idempotency_key)
                if existing_id:
                    p = self._get(existing_id)
                    self._log("create_idempotent_hit", {"idempotency_key": idempotency_key, "payment_id": p.id})
                    return p

            pid = self._new_id("pi")
            created_at = self._now()
            status = PaymentStatus.REQUIRES_CONFIRMATION if self._cfg.require_confirmation else PaymentStatus.SUCCEEDED

            p = PaymentIntent(
                id=pid,
                amount=amount,
                currency=currency_norm,
                status=status,
                created_at=created_at,
                description=description,
                metadata=dict(metadata or {}),
                customer_id=customer_id,
                idempotency_key=idempotency_key,
                provider_ref=f"{self._cfg.provider_name}:{secrets.token_hex(8)}",
                confirmed_at=created_at if status == PaymentStatus.SUCCEEDED else None,
            )
            self._payments[pid] = p

            if idempotency_key:
                self._create_idem[idempotency_key] = pid

            self._log("create", {"payment": p.to_dict()})
            return p

    async def acreate_payment_intent(self, **kwargs: Any) -> PaymentIntent:
        return self.create_payment_intent(**kwargs)

    def confirm_payment(self, payment_id: str) -> PaymentIntent:
        with self._lock:
            p = self._get(payment_id)
            self._ensure_not_final(p)

            if p.status == PaymentStatus.SUCCEEDED:
                self._log("confirm_noop", {"payment_id": payment_id})
                return p

            if self._cfg.fail_on_confirm:
                p.status = PaymentStatus.FAILED
                p.failure_reason = self._cfg.fail_reason
                self._log("confirm_failed", {"payment": p.to_dict()})
                return p

            p.status = PaymentStatus.SUCCEEDED
            p.confirmed_at = self._now()
            self._log("confirm_succeeded", {"payment": p.to_dict()})
            return p

    async def aconfirm_payment(self, payment_id: str) -> PaymentIntent:
        return self.confirm_payment(payment_id)

    def cancel_payment(self, payment_id: str, reason: str = "") -> PaymentIntent:
        with self._lock:
            p = self._get(payment_id)
            self._ensure_not_final(p)

            p.status = PaymentStatus.CANCELED
            p.canceled_at = self._now()
            if reason:
                p.failure_reason = reason
            self._log("cancel", {"payment": p.to_dict()})
            return p

    async def acancel_payment(self, payment_id: str, reason: str = "") -> PaymentIntent:
        return self.cancel_payment(payment_id, reason=reason)

    def get_payment(self, payment_id: str) -> PaymentIntent:
        with self._lock:
            p = self._get(payment_id)
            self._log("get", {"payment_id": payment_id})
            return p

    async def aget_payment(self, payment_id: str) -> PaymentIntent:
        return self.get_payment(payment_id)

    def refund(
        self,
        payment_id: str,
        *,
        amount: Optional[int] = None,
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Refund:
        with self._lock:
            p = self._get(payment_id)

            if p.status not in (PaymentStatus.SUCCEEDED, PaymentStatus.PARTIALLY_REFUNDED, PaymentStatus.REFUNDED):
                raise PaymentError(
                    PaymentErrorCode.INVALID_REQUEST,
                    "Refund allowed only for succeeded payments.",
                    {"payment_id": payment_id, "status": p.status.value},
                )

            if idempotency_key:
                existing_id = self._refund_idem.get(idempotency_key)
                if existing_id:
                    r = self._refunds[existing_id]
                    self._log("refund_idempotent_hit", {"idempotency_key": idempotency_key, "refund_id": r.id})
                    return r

            refundable = p.amount - p.refunded_amount
            if refundable <= 0:
                raise PaymentError(PaymentErrorCode.AMOUNT_EXCEEDS, "Nothing to refund.", {"payment_id": payment_id})

            refund_amount = refundable if amount is None else amount
            self._validate_amount(refund_amount)
            if refund_amount > refundable:
                raise PaymentError(
                    PaymentErrorCode.AMOUNT_EXCEEDS,
                    "Refund amount exceeds refundable.",
                    {"requested": refund_amount, "refundable": refundable, "payment_id": payment_id},
                )

            rid = self._new_id("re")
            r = Refund(
                id=rid,
                payment_id=p.id,
                amount=refund_amount,
                currency=p.currency,
                created_at=self._now(),
                reason=reason,
                metadata=dict(metadata or {}),
            )
            self._refunds[rid] = r
            if idempotency_key:
                self._refund_idem[idempotency_key] = rid

            p.refunded_amount += refund_amount
            if p.refunded_amount >= p.amount:
                p.status = PaymentStatus.REFUNDED
            else:
                p.status = PaymentStatus.PARTIALLY_REFUNDED

            self._log("refund", {"refund": r.to_dict(), "payment": p.to_dict()})
            return r

    async def arefund(self, payment_id: str, **kwargs: Any) -> Refund:
        return self.refund(payment_id, **kwargs)

    # ------------------------
    # Webhook utilities (HMAC)
    # ------------------------

    def make_webhook_event(self, event_type: str, data: dict[str, Any]) -> WebhookEvent:
        with self._lock:
            ev = WebhookEvent(
                id=self._new_id("evt"),
                type=event_type,
                created_at=self._now(),
                data=data,
            )
            self._log("webhook_event", {"event": ev.to_dict()})
            return ev

    def sign_webhook(self, payload: bytes) -> str:
        """
        Returns hex digest of HMAC(secret, payload, sha256|sha1|sha512...).
        This is verifiable: Python hmac + hashlib.
        """
        algo = self._cfg.signature_algo.lower()
        try:
            h = hmac.new(self._cfg.secret, payload, getattr(hashlib, algo))
        except Exception as e:  # noqa: BLE001
            raise PaymentError(PaymentErrorCode.INVALID_REQUEST, "Invalid signature algorithm.", {"algo": algo, "err": str(e)})
        return h.hexdigest()

    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        expected = self.sign_webhook(payload)
        # constant-time compare
        return hmac.compare_digest(expected, signature)

    def build_webhook_payload_and_signature(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        json_dumps: Optional[Callable[..., str]] = None,
    ) -> tuple[bytes, str, WebhookEvent]:
        """
        Helper for tests: creates event, returns (payload_bytes, signature, event).
        """
        ev = self.make_webhook_event(event_type, data)
        dumps = json_dumps or (lambda obj, **kw: json.dumps(obj, separators=(",", ":"), sort_keys=True))
        payload_str = dumps(ev.to_dict())
        payload = payload_str.encode("utf-8")
        sig = self.sign_webhook(payload)
        self._log("webhook_signed", {"event_id": ev.id})
        return payload, sig, ev

    # ------------------------
    # Introspection helpers
    # ------------------------

    def payments(self) -> dict[str, PaymentIntent]:
        with self._lock:
            return dict(self._payments)

    def refunds(self) -> dict[str, Refund]:
        with self._lock:
            return dict(self._refunds)

    def last_journal(self) -> Optional[PaymentMockJournalEntry]:
        with self._lock:
            return self.journal[-1] if self.journal else None


# -----------------------------
# Convenience factory
# -----------------------------

def build_payment_gateway_mock(
    *,
    secret: bytes = b"test_webhook_secret",
    require_confirmation: bool = True,
    fail_on_confirm: bool = False,
    signature_algo: str = "sha256",
    now_fn: Optional[Callable[[], _dt.datetime]] = None,
) -> PaymentGatewayMock:
    """
    Builder with explicit knobs for tests.
    """
    cfg = PaymentMockConfig(
        secret=secret,
        require_confirmation=require_confirmation,
        fail_on_confirm=fail_on_confirm,
        signature_algo=signature_algo,
    )
    return PaymentGatewayMock(cfg, now_fn=now_fn)
