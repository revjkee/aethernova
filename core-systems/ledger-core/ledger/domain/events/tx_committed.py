# -*- coding: utf-8 -*-
"""
Domain Event: Transaction Committed (Posted)
- Immutable Pydantic v2 models
- Double-entry invariants (balanced per currency)
- Currency totals, entries hash, labels/attributes with PII redaction
- Canonical JSON serialization (stable ordering) + checksum
- Optional detached signature envelope (agnostic to crypto stack)
- Outbox/Kafka packing helpers (headers + key/value)
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from enum import Enum
from typing import Any, Iterable, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CURRENCY_RE = re.compile(r"^[A-Z0-9:_\-.]{3,32}$")
_PII_KEYS = {"password", "secret", "token", "card", "cvv", "ssn", "iban", "email", "phone"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_decimal_str(x: str | Decimal) -> str:
    """
    Canonical decimal (no exponent), up to 38 total digits, scale up to 18.
    """
    try:
        d = Decimal(str(x))
    except InvalidOperation as e:
        raise ValueError(f"bad decimal: {e}")
    # normalize: clamp scale to 18, no exponent
    q = d.quantize(Decimal(1).scaleb(-min(max(-d.as_tuple().exponent, 0), 18)), rounding=ROUND_DOWN)
    s = format(q, "f")
    if "e" in s.lower():
        raise ValueError("exponent not allowed")
    # 38 significant digits (excluding sign and dot)
    sig = s.replace("-", "").replace(".", "")
    if len(sig) > 38:
        raise ValueError("too many digits")
    return s


class Side(str, Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class Money(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    currency: str = Field(..., description="ISO 4217 or namespaced token code")
    amount: str = Field(..., description="Canonical decimal string, no exponent")

    @field_validator("currency")
    @classmethod
    def _val_currency(cls, v: str) -> str:
        if not _CURRENCY_RE.match(v or ""):
            raise ValueError("bad currency")
        return v

    @field_validator("amount")
    @classmethod
    def _val_amount(cls, v: str) -> str:
        return _to_decimal_str(v)


class EntrySnapshot(BaseModel):
    """
    Lightweight immutable snapshot of a posting line for hashing/rollup.
    """
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    account_id: UUID
    side: Side
    currency: str
    amount: str
    subledger: Optional[str] = Field(default=None, max_length=128)

    @field_validator("currency")
    @classmethod
    def _cur(cls, v: str) -> str:
        if not _CURRENCY_RE.match(v or ""):
            raise ValueError("bad currency")
        return v

    @field_validator("amount")
    @classmethod
    def _amt(cls, v: str) -> str:
        # positive magnitude; sign is encoded by side
        s = _to_decimal_str(v)
        if s.startswith("-") or s == "0" or Decimal(s) <= 0:
            raise ValueError("amount must be positive")
        return s


class CurrencyTotals(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    currency: str
    debits: str
    credits: str
    net: str  # debits - credits; for posted, must be "0" per currency

    @field_validator("currency")
    @classmethod
    def _cur(cls, v: str) -> str:
        if not _CURRENCY_RE.match(v or ""):
            raise ValueError("bad currency")
        return v

    @field_validator("debits", "credits", "net")
    @classmethod
    def _dec(cls, v: str) -> str:
        return _to_decimal_str(v)


class Correlation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    request_id: Optional[str] = Field(default=None, max_length=64)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    trace_id: Optional[str] = Field(default=None, max_length=64)
    span_id: Optional[str] = Field(default=None, max_length=32)


class Signature(BaseModel):
    """
    Detached signature over canonical JSON of the event without this field.
    The actual crypto/JWS is out of scope of the domain.
    """
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    alg: str = Field(..., max_length=16)   # e.g., HS256/RS256/EdDSA
    kid: str = Field(..., max_length=128)  # key identifier
    sig: str = Field(..., description="Base64/hex signature")


class TxCommitted(BaseModel):
    """
    Domain Event: transaction posted (committed).
    Invariants:
      - totals are computed per currency; net must be 0 per currency
      - entries_hash covers all postings in deterministic order
      - timestamps are UTC
    """
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    # Envelope
    event_type: str = Field(default="ledger.tx.committed", frozen=True)
    event_version: int = Field(default=1, ge=1, le=2, frozen=True)
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=_utcnow)

    # Identity
    journal: str = Field(..., min_length=1, max_length=128)
    tx_id: UUID
    posted_at: datetime

    # Domain surface
    reference: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=512)
    totals: list[CurrencyTotals] = Field(..., description="Per-currency debits/credits/net, sorted by currency")
    entries_count: int = Field(..., ge=1, le=1_000_000)
    entries_hash: str = Field(..., min_length=16, max_length=128, description="SHA-256 hex of entries snapshot")

    labels: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    etag: Optional[str] = Field(default=None, max_length=64)

    # Meta
    correlation: Correlation = Field(default_factory=Correlation)
    checksum: str = Field(..., min_length=64, max_length=64, description="SHA-256 hex of canonical JSON without signature")
    signature: Optional[Signature] = None

    # --- validators ---
    @field_validator("occurred_at", "posted_at")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _enforce_balanced(self) -> "TxCommitted":
        # per-currency net must be 0
        for t in self.totals:
            if Decimal(t.net) != Decimal("0"):
                raise ValueError(f"unbalanced totals for currency {t.currency}")
        # labels/attributes sanitation
        clean_attr: dict[str, Any] = {}
        for k, v in (self.attributes or {}).items():
            if (k or "").lower() in _PII_KEYS:
                continue
            clean_attr[k] = v
        object.__setattr__(self, "attributes", clean_attr)
        # stable sort of totals by currency
        st = sorted(self.totals, key=lambda x: x.currency)
        object.__setattr__(self, "totals", st)
        return self

    # --- construction helpers ---
    @staticmethod
    def _rollup_totals(entries: Iterable[EntrySnapshot]) -> list[CurrencyTotals]:
        acc: dict[str, dict[str, Decimal]] = {}
        for e in entries:
            amount = Decimal(e.amount)
            bucket = acc.setdefault(e.currency, {"debits": Decimal("0"), "credits": Decimal("0")})
            if e.side == Side.DEBIT:
                bucket["debits"] += amount
            else:
                bucket["credits"] += amount
        out: list[CurrencyTotals] = []
        for cur, vals in acc.items():
            net = vals["debits"] - vals["credits"]
            out.append(
                CurrencyTotals(
                    currency=cur,
                    debits=_to_decimal_str(vals["debits"]),
                    credits=_to_decimal_str(vals["credits"]),
                    net=_to_decimal_str(net),
                )
            )
        return sorted(out, key=lambda x: x.currency)

    @staticmethod
    def _entries_hash(entries: Iterable[EntrySnapshot]) -> str:
        """
        Deterministic SHA-256 over concatenation of canonical lines sorted by (account_id, side, currency, amount, subledger)
        """
        lines: list[str] = []
        for e in entries:
            sub = e.subledger or ""
            lines.append(f"{e.account_id}|{e.side}|{e.currency}|{_to_decimal_str(e.amount)}|{sub}")
        lines.sort()
        h = hashlib.sha256()
        for ln in lines:
            h.update(ln.encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()

    @staticmethod
    def _canonical(obj: dict, *, skip_signature: bool = True) -> bytes:
        """
        Canonical JSON (UTF-8, sorted keys, no spaces).
        If skip_signature, the 'signature' field is removed before dump.
        """
        if skip_signature:
            obj = dict(obj)
            obj.pop("signature", None)
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def build(
        cls,
        *,
        journal: str,
        tx_id: UUID,
        posted_at: datetime,
        entries: Iterable[EntrySnapshot],
        reference: Optional[str] = None,
        description: Optional[str] = None,
        labels: Optional[dict[str, str]] = None,
        attributes: Optional[dict[str, Any]] = None,
        etag: Optional[str] = None,
        correlation: Optional[Correlation] = None,
        occurred_at: Optional[datetime] = None,
    ) -> "TxCommitted":
        entries_list = list(entries)
        if not entries_list:
            raise ValueError("entries required")
        totals = cls._rollup_totals(entries_list)
        ehash = cls._entries_hash(entries_list)

        base = cls(
            journal=journal,
            tx_id=tx_id,
            posted_at=posted_at,
            reference=reference,
            description=description,
            totals=totals,
            entries_count=len(entries_list),
            entries_hash=ehash,
            labels=(labels or {}),
            attributes=(attributes or {}),
            etag=etag,
            correlation=(correlation or Correlation()),
            occurred_at=(occurred_at or _utcnow()),
            checksum="0" * 64,  # temporary; will be replaced after canonical serialization
        )
        # compute checksum over canonical JSON without signature and with checksum temporarily blanked
        payload = base.model_dump()
        payload["checksum"] = ""
        canon = cls._canonical(payload, skip_signature=True)
        checksum = hashlib.sha256(canon).hexdigest()
        # freeze final instance with checksum
        return base.model_copy(update={"checksum": checksum})

    # --- serialization/signature/outbox ---
    def to_canonical_json(self, *, include_signature: bool = True) -> bytes:
        data = self.model_dump()
        return self._canonical(data, skip_signature=not include_signature)

    def compute_checksum(self) -> str:
        data = self.model_dump()
        data["checksum"] = ""
        canon = self._canonical(data, skip_signature=True)
        return hashlib.sha256(canon).hexdigest()

    def with_signature(self, *, alg: str, kid: str, sig: str) -> "TxCommitted":
        """
        Attach detached signature metadata. Integrity of payload should be verified by consumer.
        """
        return self.model_copy(update={"signature": Signature(alg=alg, kid=kid, sig=sig)})

    def to_outbox_message(
        self,
        *,
        topic: str = "ledger.tx.posted.v1",
        content_type: str = "application/json",
    ) -> dict:
        """
        Build a generic outbox record for a message bus (e.g., Kafka).
        - key: tx_id bytes
        - value: canonical JSON bytes (without signature if not present)
        - headers: tuple[str, bytes][]
        """
        value = self.to_canonical_json(include_signature=bool(self.signature))
        headers = [
            ("event-type", f"{self.event_type}.v{self.event_version}".encode()),
            ("event-id", str(self.event_id).encode()),
            ("occurred-at", self.occurred_at.isoformat().encode()),
            ("journal", self.journal.encode()),
            ("tx-id", str(self.tx_id).encode()),
            ("content-type", content_type.encode()),
            ("checksum", self.checksum.encode()),
        ]
        if self.signature:
            headers.extend(
                [
                    ("sig-alg", self.signature.alg.encode()),
                    ("sig-kid", self.signature.kid.encode()),
                ]
            )
        return {
            "topic": topic,
            "key": str(self.tx_id).encode("utf-8"),
            "value": value,
            "headers": headers,
        }
