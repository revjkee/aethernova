# agent_mash/cfo/accounting/assistant/preprocessing.py
from __future__ import annotations

import dataclasses
import datetime as dt
import decimal
import hashlib
import hmac
import json
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union


JsonDict = Dict[str, Any]
JsonLike = Union[JsonDict, List[Any], str, int, float, bool, None]


class PreprocessingError(RuntimeError):
    pass


class PayloadInvalid(PreprocessingError):
    pass


class StepFailed(PreprocessingError):
    pass


class AuditIdError(PreprocessingError):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _stable_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        raise PayloadInvalid(f"Not JSON-serializable: {e}") from e


def _blake2b_hex(data: bytes, digest_size: int = 16) -> str:
    h_ = hashlib.blake2b(digest_size=digest_size)
    h_.update(data)
    return h_.hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _as_mapping(value: Any, name: str) -> Mapping[str, JsonLike]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return value  # type: ignore[return-value]
    raise PayloadInvalid(f"{name} must be a mapping/dict")


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        return s if s else None
    return str(value).strip() or None


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    return None


def _as_decimal(value: Any, *, quant: Optional[str] = None) -> Optional[decimal.Decimal]:
    if value is None:
        return None
    try:
        if isinstance(value, decimal.Decimal):
            d = value
        elif isinstance(value, (int, float)):
            d = decimal.Decimal(str(value))
        elif isinstance(value, str):
            s = value.strip().replace(" ", "")
            if not s:
                return None
            d = decimal.Decimal(s)
        else:
            d = decimal.Decimal(str(value))
        if quant is not None:
            q = decimal.Decimal(quant)
            d = d.quantize(q, rounding=decimal.ROUND_HALF_UP)
        return d
    except Exception:
        return None


def _upper_currency(value: Any) -> Optional[str]:
    s = _as_str(value)
    if not s:
        return None
    s = s.upper()
    if re.fullmatch(r"[A-Z]{3}", s):
        return s
    return None


_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?([Zz]|[+-]\d{2}:\d{2})?$")


def _parse_datetime(value: Any) -> Optional[dt.datetime]:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            if _ISO_DATE_RE.match(s):
                d = dt.date.fromisoformat(s)
                return dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc)
            if _ISO_DT_RE.match(s):
                s2 = s.replace(" ", "T")
                if s2.endswith(("Z", "z")):
                    s2 = s2[:-1] + "+00:00"
                dd = dt.datetime.fromisoformat(s2)
                return dd if dd.tzinfo else dd.replace(tzinfo=dt.timezone.utc)
        except Exception:
            return None
    return None


_REDACT_DEFAULT_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"iban", re.IGNORECASE),
    re.compile(r"pan", re.IGNORECASE),
    re.compile(r"card", re.IGNORECASE),
    re.compile(r"cvv", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
    re.compile(r"passport", re.IGNORECASE),
    re.compile(r"inn", re.IGNORECASE),
)


def redact_mapping(
    obj: Mapping[str, Any],
    *,
    redaction: str = "[REDACTED]",
    key_patterns: Sequence[re.Pattern[str]] = _REDACT_DEFAULT_PATTERNS,
    max_depth: int = 10,
    max_list: int = 128,
) -> Mapping[str, JsonLike]:
    def _should_redact_key(k: str) -> bool:
        for p in key_patterns:
            if p.search(k):
                return True
        return False

    def _walk(v: Any, depth: int) -> JsonLike:
        if depth <= 0:
            return "[TRUNCATED]"
        if isinstance(v, Mapping):
            out: Dict[str, JsonLike] = {}
            for kk, vv in v.items():
                key = str(kk)
                if _should_redact_key(key):
                    out[key] = redaction
                else:
                    out[key] = _walk(vv, depth - 1)
            return out
        if isinstance(v, (list, tuple)):
            out_list: List[JsonLike] = []
            for i, item in enumerate(v):
                if i >= max_list:
                    out_list.append("[TRUNCATED_LIST]")
                    break
                out_list.append(_walk(item, depth - 1))
            return out_list
        if isinstance(v, (str, int, float, bool)) or v is None:
            return v
        return str(v)

    return _walk(obj, max_depth)  # type: ignore[return-value]


@dataclasses.dataclass(frozen=True)
class PreprocessConfig:
    policy_version: str = "accounting-preprocess-v1"
    trace_hmac_key: Optional[bytes] = None
    max_payload_bytes: int = 512_000
    max_text_len: int = 200_000
    normalize_text: bool = True
    amount_quant: str = "0.01"
    require_type: bool = True
    allow_unknown_type: bool = True
    supported_types: Tuple[str, ...] = (
        "transaction",
        "invoice",
        "receipt",
        "expense",
        "payout",
        "salary",
        "bank_statement",
    )


@dataclasses.dataclass(frozen=True)
class PreprocessInput:
    payload: Mapping[str, JsonLike]
    source: str
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    actor_id: Optional[str] = None
    received_at_ms: Optional[int] = None


@dataclasses.dataclass(frozen=True)
class PreprocessOutput:
    trace_id: str
    request_id: str
    policy_version: str
    created_at_ms: int
    source: str
    tenant_id: Optional[str]
    actor_id: Optional[str]
    payload: Mapping[str, JsonLike]
    canonical: Mapping[str, JsonLike]
    redacted: Mapping[str, JsonLike]
    warnings: Tuple[str, ...] = ()

    def to_dict(self) -> JsonDict:
        return {
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "policy_version": self.policy_version,
            "created_at_ms": self.created_at_ms,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "warnings": list(self.warnings),
            "canonical": dict(self.canonical),
            "redacted": dict(self.redacted),
        }


class AuditSink(Protocol):
    async def emit(self, event: Mapping[str, JsonLike]) -> None:
        ...


class PreprocessStep(Protocol):
    step_id: str

    def run(self, *, payload: Mapping[str, JsonLike], canonical: MutableMapping[str, JsonLike], warnings: List[str]) -> None:
        ...


def _normalize_text(s: str, *, max_len: int) -> str:
    s2 = s.replace("\r\n", "\n").replace("\r", "\n")
    s2 = re.sub(r"[ \t]+", " ", s2).strip()
    if len(s2) > max_len:
        s2 = s2[: max_len - 12] + " [TRUNCATED]"
    return s2


def _payload_size_guard(payload: Mapping[str, JsonLike], *, max_bytes: int) -> None:
    raw = _stable_json(payload).encode("utf-8")
    if len(raw) > max_bytes:
        raise PayloadInvalid(f"payload exceeds max size: {len(raw)} > {max_bytes}")


def _make_request_id(*, created_at_ms: int, source: str, tenant_id: Optional[str], payload: Mapping[str, Any]) -> str:
    base = {"ts": created_at_ms, "source": source, "tenant": tenant_id, "payload": payload}
    raw = _stable_json(base).encode("utf-8")
    return _blake2b_hex(raw, digest_size=16)


def _make_trace_id(*, created_at_ms: int, source: str, tenant_id: Optional[str], payload: Mapping[str, Any], hmac_key: Optional[bytes]) -> str:
    base = {"ts": created_at_ms, "source": source, "tenant": tenant_id, "payload": payload}
    raw = _stable_json(base).encode("utf-8")
    if hmac_key:
        return _hmac_sha256_hex(hmac_key, raw)
    return _blake2b_hex(raw, digest_size=16)


def _canonicalize_common_fields(
    payload: Mapping[str, JsonLike],
    *,
    cfg: PreprocessConfig,
    warnings: List[str],
) -> Mapping[str, JsonLike]:
    canonical: Dict[str, JsonLike] = {}

    doc_type = _as_str(payload.get("type"))
    if cfg.require_type and not doc_type:
        warnings.append("missing:type")
    if doc_type:
        doc_type = doc_type.lower()
        if doc_type not in cfg.supported_types:
            if cfg.allow_unknown_type:
                warnings.append(f"unknown:type:{doc_type}")
            else:
                raise PayloadInvalid(f"unsupported type: {doc_type}")
        canonical["type"] = doc_type

    currency = _upper_currency(payload.get("currency"))
    if currency is None and payload.get("currency") is not None:
        warnings.append("invalid:currency")
    if currency:
        canonical["currency"] = currency

    amount = _as_decimal(payload.get("amount"), quant=cfg.amount_quant)
    if amount is None and payload.get("amount") is not None:
        warnings.append("invalid:amount")
    if amount is not None:
        canonical["amount"] = str(amount)

    occurred_at = _parse_datetime(payload.get("occurred_at") or payload.get("date") or payload.get("timestamp"))
    if occurred_at is None and (payload.get("occurred_at") or payload.get("date") or payload.get("timestamp")) is not None:
        warnings.append("invalid:occurred_at")
    if occurred_at is not None:
        canonical["occurred_at"] = occurred_at.astimezone(dt.timezone.utc).isoformat()

    description = _as_str(payload.get("description") or payload.get("memo") or payload.get("note"))
    if isinstance(description, str) and cfg.normalize_text:
        canonical["description"] = _normalize_text(description, max_len=cfg.max_text_len)
    elif description:
        canonical["description"] = description

    ext_id = _as_str(payload.get("external_id") or payload.get("id"))
    if ext_id:
        canonical["external_id"] = ext_id

    merchant = _as_str(payload.get("merchant") or payload.get("counterparty"))
    if merchant:
        canonical["merchant"] = _normalize_text(merchant, max_len=512) if cfg.normalize_text else merchant

    category = _as_str(payload.get("category"))
    if category:
        canonical["category"] = category.lower()

    is_refund = _as_bool(payload.get("is_refund"))
    if is_refund is not None:
        canonical["is_refund"] = bool(is_refund)

    return canonical


def _dedup_fingerprint(canonical: Mapping[str, JsonLike]) -> str:
    stable = _stable_json(canonical).encode("utf-8")
    return _blake2b_hex(stable, digest_size=16)


@dataclasses.dataclass(frozen=True)
class StepSpec:
    step: PreprocessStep
    required: bool = True


class Preprocessor:
    def __init__(
        self,
        *,
        config: PreprocessConfig,
        steps: Sequence[StepSpec] = (),
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        if not config.policy_version:
            raise PayloadInvalid("policy_version must be non-empty")
        self._cfg = config
        self._steps = tuple(steps)
        self._audit_sink = audit_sink

    @property
    def config(self) -> PreprocessConfig:
        return self._cfg

    async def run(self, inp: PreprocessInput) -> PreprocessOutput:
        created_at_ms = inp.received_at_ms or _now_ms()
        payload = _as_mapping(inp.payload, "payload")

        _payload_size_guard(payload, max_bytes=self._cfg.max_payload_bytes)

        # Redact for audit/logging safety first
        redacted = redact_mapping(payload)

        request_id = inp.request_id or _make_request_id(
            created_at_ms=created_at_ms,
            source=inp.source,
            tenant_id=inp.tenant_id,
            payload=redacted,
        )
        trace_id = _make_trace_id(
            created_at_ms=created_at_ms,
            source=inp.source,
            tenant_id=inp.tenant_id,
            payload=redacted,
            hmac_key=self._cfg.trace_hmac_key,
        )

        warnings: List[str] = []
        canonical: Dict[str, JsonLike] = dict(_canonicalize_common_fields(payload, cfg=self._cfg, warnings=warnings))

        # Fingerprint for dedup
        canonical["fingerprint"] = _dedup_fingerprint(canonical)

        # Custom steps
        for spec in self._steps:
            try:
                spec.step.run(payload=payload, canonical=canonical, warnings=warnings)
            except Exception as e:
                if spec.required:
                    raise StepFailed(f"step failed: {spec.step.step_id}: {e}") from e
                warnings.append(f"step_failed:{spec.step.step_id}")

        out = PreprocessOutput(
            trace_id=trace_id,
            request_id=request_id,
            policy_version=self._cfg.policy_version,
            created_at_ms=created_at_ms,
            source=inp.source,
            tenant_id=inp.tenant_id,
            actor_id=inp.actor_id,
            payload=payload,
            canonical=canonical,
            redacted=redacted,
            warnings=tuple(warnings),
        )

        await self._audit(out)
        return out

    async def _audit(self, out: PreprocessOutput) -> None:
        if self._audit_sink is None:
            return
        event: JsonDict = {
            "kind": "accounting_preprocess",
            "trace_id": out.trace_id,
            "request_id": out.request_id,
            "policy_version": out.policy_version,
            "created_at_ms": out.created_at_ms,
            "source": out.source,
            "tenant_id": out.tenant_id,
            "actor_id": out.actor_id,
            "warnings": list(out.warnings),
            "canonical": dict(out.canonical),
            "redacted": dict(out.redacted),
        }
        try:
            await self._audit_sink.emit(event)
        except Exception as e:
            raise AuditIdError(str(e)) from e


class InvoiceTotalsStep:
    step_id = "invoice_totals"

    def run(self, *, payload: Mapping[str, JsonLike], canonical: MutableMapping[str, JsonLike], warnings: List[str]) -> None:
        items = payload.get("items")
        if not isinstance(items, list):
            return

        quant = "0.01"
        total = decimal.Decimal("0")
        subtotal = decimal.Decimal("0")
        tax_total = decimal.Decimal("0")

        for i, raw in enumerate(items[:512]):
            if not isinstance(raw, Mapping):
                warnings.append(f"invalid:item:{i}")
                continue
            price = _as_decimal(raw.get("price") or raw.get("unit_price"), quant=quant) or decimal.Decimal("0")
            qty = _as_decimal(raw.get("qty") or raw.get("quantity"), quant="1") or decimal.Decimal("1")
            tax = _as_decimal(raw.get("tax"), quant=quant) or decimal.Decimal("0")
            line = (price * qty).quantize(decimal.Decimal(quant), rounding=decimal.ROUND_HALF_UP)

            subtotal += line
            tax_total += tax
            total += (line + tax)

        canonical["invoice_subtotal"] = str(subtotal.quantize(decimal.Decimal(quant), rounding=decimal.ROUND_HALF_UP))
        canonical["invoice_tax_total"] = str(tax_total.quantize(decimal.Decimal(quant), rounding=decimal.ROUND_HALF_UP))
        canonical["invoice_total_calc"] = str(total.quantize(decimal.Decimal(quant), rounding=decimal.ROUND_HALF_UP))


class BankStatementNormalizeStep:
    step_id = "bank_statement_normalize"

    def run(self, *, payload: Mapping[str, JsonLike], canonical: MutableMapping[str, JsonLike], warnings: List[str]) -> None:
        if (canonical.get("type") or "").__class__ is str and canonical.get("type") != "bank_statement":
            return

        account = _as_str(payload.get("account") or payload.get("account_number"))
        if account:
            canonical["account_ref"] = account[-6:] if len(account) >= 6 else account

        period_start = _parse_datetime(payload.get("period_start"))
        period_end = _parse_datetime(payload.get("period_end"))
        if period_start:
            canonical["period_start"] = period_start.astimezone(dt.timezone.utc).isoformat()
        if period_end:
            canonical["period_end"] = period_end.astimezone(dt.timezone.utc).isoformat()
        if period_start and period_end and period_end < period_start:
            warnings.append("invalid:period_range")


def default_preprocessor(*, audit_sink: Optional[AuditSink] = None, hmac_key: Optional[bytes] = None) -> Preprocessor:
    cfg = PreprocessConfig(trace_hmac_key=hmac_key)
    steps = (
        StepSpec(step=InvoiceTotalsStep(), required=False),
        StepSpec(step=BankStatementNormalizeStep(), required=False),
    )
    return Preprocessor(config=cfg, steps=steps, audit_sink=audit_sink)
