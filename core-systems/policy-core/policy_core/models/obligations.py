# policy-core/policy_core/models/obligations.py
from __future__ import annotations

import json
import re
import uuid
import base64
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union


__all__ = [
    "DecisionTrigger",
    "DeliveryGuarantee",
    "Urgency",
    "Confidentiality",
    "BackoffStrategy",
    "IdempotencyStrategy",
    "ParamType",
    "ParamSpec",
    "RetryPolicy",
    "ObligationDefinition",
    "ObligationInstance",
    "ObligationValidationError",
    "coerce_activation_value",
]


# -----------------------
# Helpers: time & JSON
# -----------------------

_RFC3339_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[T ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,6}))?"
    r"Z$"
)

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def to_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def parse_rfc3339(s: str) -> datetime:
    m = _RFC3339_RE.match(s)
    if not m:
        raise ValueError(f"Invalid RFC3339 UTC timestamp: {s}")
    parts = m.groupdict()
    micro = int(parts.get("fraction") or "0".ljust(6, "0"))
    return datetime(
        int(parts["year"]), int(parts["month"]), int(parts["day"]),
        int(parts["hour"]), int(parts["minute"]), int(parts["second"]),
        micro, tzinfo=timezone.utc
    )

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


# -----------------------
# Duration parsing (ISO-like subset)
# Supports: "PT10S", "PT5M10S", "PT2H", ints (ms), floats (seconds)
# -----------------------

_ISO_DUR_RE = re.compile(
    r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)(?:\.(?P<fraction>\d{1,6}))?S)?)?$"
)

def duration_to_milliseconds(value: Union[str, int, float]) -> int:
    if isinstance(value, int):
        # Interpret as milliseconds
        return max(0, value)
    if isinstance(value, float):
        # Interpret as seconds
        return max(0, int(round(value * 1000)))
    if isinstance(value, str):
        m = _ISO_DUR_RE.match(value)
        if not m:
            # Fallback: plain integer seconds as string
            if value.isdigit():
                return int(value) * 1000
            raise ValueError(f"Invalid ISO8601 duration: {value}")
        parts = m.groupdict()
        days = int(parts.get("days") or 0)
        hours = int(parts.get("hours") or 0)
        minutes = int(parts.get("minutes") or 0)
        seconds = int(parts.get("seconds") or 0)
        fraction = int((parts.get("fraction") or "0").ljust(6, "0"))
        total = (
            days * 86400
            + hours * 3600
            + minutes * 60
            + seconds
            + fraction / 1_000_000
        )
        return int(round(total * 1000))
    raise TypeError("Unsupported duration type")


# -----------------------
# Enums
# -----------------------

class DecisionTrigger(Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"
    ALWAYS = "ALWAYS"  # fires regardless of PDP decision

class DeliveryGuarantee(Enum):
    AT_MOST_ONCE = "AT_MOST_ONCE"
    AT_LEAST_ONCE = "AT_LEAST_ONCE"
    EXACTLY_ONCE = "EXACTLY_ONCE"

class Urgency(Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Confidentiality(Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"

class BackoffStrategy(Enum):
    NONE = "NONE"
    FIXED = "FIXED"
    EXPONENTIAL = "EXPONENTIAL"
    EXPONENTIAL_JITTER = "EXPONENTIAL_JITTER"

class IdempotencyStrategy(Enum):
    NONE = "NONE"
    HASH_OF_PARAMS = "HASH_OF_PARAMS"
    UUID4 = "UUID4"
    FROM_CONTEXT_KEY = "FROM_CONTEXT_KEY"  # e.g. request_id/session_id from activation

class ParamType(Enum):
    STRING = "STRING"
    INT = "INT"
    FLOAT = "FLOAT"
    BOOL = "BOOL"
    DECIMAL = "DECIMAL"
    BYTES_B64 = "BYTES_B64"
    JSON = "JSON"
    TIMESTAMP = "TIMESTAMP"  # RFC3339 UTC with 'Z'
    DURATION = "DURATION"    # ISO8601-like; stored as milliseconds


# -----------------------
# Errors
# -----------------------

class ObligationValidationError(ValueError):
    pass


# -----------------------
# ParamSpec: schema for a single parameter
# -----------------------

@dataclass(frozen=True)
class ParamSpec:
    name: str
    type: ParamType
    required: bool = False
    description: Optional[str] = None
    regex: Optional[str] = None
    min_value: Optional[Union[int, float, Decimal]] = None
    max_value: Optional[Union[int, float, Decimal]] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    allowed_values: Optional[List[Any]] = None
    is_secret: bool = False
    pii: bool = False

    def validate_and_coerce(self, value: Any) -> Any:
        if value is None:
            if self.required:
                raise ObligationValidationError(f"Parameter '{self.name}' is required")
            return None

        coerced = _coerce_by_type(self.type, value, self.name)

        # Length constraints (for STRING / BYTES_B64 / JSON[str repr])
        if isinstance(coerced, str):
            if self.min_length is not None and len(coerced) < self.min_length:
                raise ObligationValidationError(f"Parameter '{self.name}' length < {self.min_length}")
            if self.max_length is not None and len(coerced) > self.max_length:
                raise ObligationValidationError(f"Parameter '{self.name}' length > {self.max_length}")

        # Numeric range
        if isinstance(coerced, (int, float, Decimal)):
            if self.min_value is not None and coerced < self.min_value:
                raise ObligationValidationError(f"Parameter '{self.name}' < {self.min_value}")
            if self.max_value is not None and coerced > self.max_value:
                raise ObligationValidationError(f"Parameter '{self.name}' > {self.max_value}")

        # Regex
        if self.regex and isinstance(coerced, str):
            if not re.fullmatch(self.regex, coerced):
                raise ObligationValidationError(f"Parameter '{self.name}' does not match regex")

        # Allowed set
        if self.allowed_values is not None:
            if coerced not in self.allowed_values:
                raise ObligationValidationError(f"Parameter '{self.name}' not in allowed set")

        return coerced


def _coerce_by_type(ptype: ParamType, value: Any, pname: str) -> Any:
    try:
        if ptype is ParamType.STRING:
            return str(value)
        if ptype is ParamType.INT:
            if isinstance(value, bool):
                raise ValueError("bool not allowed for INT")
            return int(value)
        if ptype is ParamType.FLOAT:
            if isinstance(value, bool):
                raise ValueError("bool not allowed for FLOAT")
            return float(value)
        if ptype is ParamType.BOOL:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                v = value.strip().lower()
                if v in ("true", "1", "yes", "y", "on"):
                    return True
                if v in ("false", "0", "no", "n", "off"):
                    return False
            return bool(value)
        if ptype is ParamType.DECIMAL:
            if isinstance(value, Decimal):
                return value
            return Decimal(str(value))
        if ptype is ParamType.BYTES_B64:
            if isinstance(value, (bytes, bytearray)):
                return base64.b64encode(value).decode("ascii")
            if isinstance(value, str):
                # validate that it's base64
                base64.b64decode(value.encode("ascii"), validate=True)
                return value
            raise ValueError("BYTES_B64 expects bytes or base64 str")
        if ptype is ParamType.JSON:
            if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
                # ensure serializable
                json.loads(json.dumps(value, default=str))
                return value
            # generic object → stringified JSON
            return json.loads(json.dumps(value, default=str))
        if ptype is ParamType.TIMESTAMP:
            if isinstance(value, datetime):
                return to_rfc3339(value)
            if isinstance(value, str):
                # validate
                parse_rfc3339(value)
                return value
            raise ValueError("TIMESTAMP expects RFC3339 string or datetime")
        if ptype is ParamType.DURATION:
            # store canonical milliseconds
            return duration_to_milliseconds(value)
    except Exception as e:
        raise ObligationValidationError(f"Parameter '{pname}' type '{ptype.value}' error: {e}") from e

    raise ObligationValidationError(f"Unknown ParamType for '{pname}'")


# -----------------------
# Retry policy
# -----------------------

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 1
    backoff_strategy: BackoffStrategy = BackoffStrategy.NONE
    initial_delay_ms: int = 0
    max_delay_ms: Optional[int] = None
    jitter_ratio: float = 0.0  # 0..1, only for *_JITTER
    retry_on_transient_only: bool = True

    def schedule_ms(self) -> List[int]:
        """
        Deterministic (no random) schedule for planning/preview; runtime jitter
        добавляет исполнитель (executor).
        """
        if self.max_attempts <= 1:
            return []
        delays: List[int] = []
        base = max(0, self.initial_delay_ms)
        for attempt in range(1, self.max_attempts):
            if self.backoff_strategy is BackoffStrategy.NONE:
                delay = base
            elif self.backoff_strategy is BackoffStrategy.FIXED:
                delay = base
            elif self.backoff_strategy in (BackoffStrategy.EXPONENTIAL, BackoffStrategy.EXPONENTIAL_JITTER):
                delay = base * (2 ** (attempt - 1)) if base > 0 else (100 * (2 ** (attempt - 1)))
            else:
                delay = base
            if self.max_delay_ms is not None:
                delay = min(delay, self.max_delay_ms)
            delays.append(delay)
        return delays


# -----------------------
# Obligation definition
# -----------------------

@dataclass(frozen=True)
class ObligationDefinition:
    """
    Контракт обязательства, публикуемый политикой.
    """
    id: str
    version: str
    name: str
    description: Optional[str]
    triggers: List[DecisionTrigger] = field(default_factory=lambda: [DecisionTrigger.PERMIT])
    params: List[ParamSpec] = field(default_factory=list)
    delivery: DeliveryGuarantee = DeliveryGuarantee.AT_LEAST_ONCE
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    urgency: Urgency = Urgency.NORMAL
    confidentiality: Confidentiality = Confidentiality.INTERNAL
    idempotency: IdempotencyStrategy = IdempotencyStrategy.HASH_OF_PARAMS
    deadline_ms: Optional[int] = None  # relative deadline after issue
    audit_required: bool = True
    allow_extra_params: bool = False  # reject unknown keys if False
    tenant_scope: Optional[str] = None  # e.g. "global" / "tenant"

    def param_index(self) -> Dict[str, ParamSpec]:
        return {p.name: p for p in self.params}

    def to_json(self) -> str:
        payload = asdict(self)
        # Enums → values
        payload["triggers"] = [t.value for t in self.triggers]
        payload["delivery"] = self.delivery.value
        payload["urgency"] = self.urgency.value
        payload["confidentiality"] = self.confidentiality.value
        payload["idempotency"] = self.idempotency.value
        payload["retry"]["backoff_strategy"] = self.retry.backoff_strategy.value
        # ParamSpec enums
        for p in payload["params"]:
            p["type"] = p["type"].value
        return _canonical_json(payload)

    def fingerprint(self) -> str:
        """
        Канонический fingerprint дефиниции: SHA-256 от канонического JSON.
        """
        # Используем to_json() чтобы все Enums были нормализованы
        raw = self.to_json().encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ObligationDefinition":
        try:
            triggers = [DecisionTrigger(t) for t in d.get("triggers") or [DecisionTrigger.PERMIT.value]]
            params_list: List[ParamSpec] = []
            for p in d.get("params", []):
                params_list.append(ParamSpec(
                    name=p["name"],
                    type=ParamType(p["type"]),
                    required=bool(p.get("required", False)),
                    description=p.get("description"),
                    regex=p.get("regex"),
                    min_value=p.get("min_value"),
                    max_value=p.get("max_value"),
                    min_length=p.get("min_length"),
                    max_length=p.get("max_length"),
                    allowed_values=p.get("allowed_values"),
                    is_secret=bool(p.get("is_secret", False)),
                    pii=bool(p.get("pii", False)),
                ))
            retry_in = d.get("retry") or {}
            retry = RetryPolicy(
                max_attempts=int(retry_in.get("max_attempts", 1)),
                backoff_strategy=BackoffStrategy(retry_in.get("backoff_strategy", BackoffStrategy.NONE.value)),
                initial_delay_ms=int(retry_in.get("initial_delay_ms", 0)),
                max_delay_ms=int(retry_in["max_delay_ms"]) if retry_in.get("max_delay_ms") is not None else None,
                jitter_ratio=float(retry_in.get("jitter_ratio", 0.0)),
                retry_on_transient_only=bool(retry_in.get("retry_on_transient_only", True)),
            )
            return ObligationDefinition(
                id=str(d["id"]),
                version=str(d["version"]),
                name=str(d["name"]),
                description=d.get("description"),
                triggers=triggers,
                params=params_list,
                delivery=DeliveryGuarantee(d.get("delivery", DeliveryGuarantee.AT_LEAST_ONCE.value)),
                retry=retry,
                urgency=Urgency(d.get("urgency", Urgency.NORMAL.value)),
                confidentiality=Confidentiality(d.get("confidentiality", Confidentiality.INTERNAL.value)),
                idempotency=IdempotencyStrategy(d.get("idempotency", IdempotencyStrategy.HASH_OF_PARAMS.value)),
                deadline_ms=int(d["deadline_ms"]) if d.get("deadline_ms") is not None else None,
                audit_required=bool(d.get("audit_required", True)),
                allow_extra_params=bool(d.get("allow_extra_params", False)),
                tenant_scope=d.get("tenant_scope"),
            )
        except Exception as e:
            raise ObligationValidationError(f"Invalid ObligationDefinition: {e}") from e


# -----------------------
# Obligation instance
# -----------------------

@dataclass(frozen=True)
class ObligationInstance:
    """
    Конкретный экземпляр обязательства, выпуск которого инициирован PDP.
    """
    definition_id: str
    definition_version: str
    correlation_id: str
    issued_at: str  # RFC3339 UTC
    not_after: Optional[str] = None  # RFC3339 UTC, абсолютный дедлайн
    trigger: DecisionTrigger = DecisionTrigger.ALWAYS
    params: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    context_hash: Optional[str] = None
    priority: int = 100  # 0..100 (0 = max priority)
    tenant_scope: Optional[str] = None

    # --------- Builders ---------

    @staticmethod
    def issue(
        definition: ObligationDefinition,
        *,
        trigger: DecisionTrigger,
        provided_params: Mapping[str, Any],
        activation_context: Optional[Mapping[str, Any]] = None,
        context_hash_keys: Optional[List[str]] = None,
        priority: Optional[int] = None,
        idempotency_context_key: Optional[str] = None,
    ) -> "ObligationInstance":
        """
        Создаёт валидный экземпляр на основе дефиниции и входных параметров.
        """
        # 1) Валидация/коэрсия параметров
        params = _validate_and_coerce_params(definition, provided_params)

        # 2) Жизненный цикл/дедлайн
        issued_at_dt = utc_now()
        not_after = None
        if definition.deadline_ms is not None:
            not_after_dt = issued_at_dt + timedelta(milliseconds=max(0, definition.deadline_ms))
            not_after = to_rfc3339(not_after_dt)

        # 3) Идемпотентность
        idem_key = _make_idempotency_key(
            strategy=definition.idempotency,
            params=params,
            activation=activation_context or {},
            from_context_key=idempotency_context_key,
        )

        # 4) Контекстный хэш (для аудита/дедупликации)
        c_hash = _make_context_hash(activation_context or {}, include_keys=context_hash_keys)

        # 5) Приоритет
        pri = 100 if priority is None else max(0, min(100, int(priority)))

        return ObligationInstance(
            definition_id=definition.id,
            definition_version=definition.version,
            correlation_id=str(uuid.uuid4()),
            issued_at=to_rfc3339(issued_at_dt),
            not_after=not_after,
            trigger=trigger,
            params=params,
            idempotency_key=idem_key,
            context_hash=c_hash,
            priority=pri,
            tenant_scope=definition.tenant_scope,
        )

    # --------- Serialization ---------

    def to_dict(self, *, redact_secrets_within: Optional[ObligationDefinition] = None) -> Dict[str, Any]:
        payload = {
            "definition_id": self.definition_id,
            "definition_version": self.definition_version,
            "correlation_id": self.correlation_id,
            "issued_at": self.issued_at,
            "not_after": self.not_after,
            "trigger": self.trigger.value,
            "params": dict(self.params),
            "idempotency_key": self.idempotency_key,
            "context_hash": self.context_hash,
            "priority": self.priority,
            "tenant_scope": self.tenant_scope,
        }
        if redact_secrets_within is not None:
            payload["params"] = _redact_secret_params(redact_secrets_within, payload["params"])
        return payload

    def to_json(self, *, redact_secrets_within: Optional[ObligationDefinition] = None) -> str:
        return _canonical_json(self.to_dict(redact_secrets_within=redact_secrets_within))

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ObligationInstance":
        try:
            trig = DecisionTrigger(d.get("trigger", DecisionTrigger.ALWAYS.value))
            return ObligationInstance(
                definition_id=str(d["definition_id"]),
                definition_version=str(d["definition_version"]),
                correlation_id=str(d["correlation_id"]),
                issued_at=str(d["issued_at"]),
                not_after=d.get("not_after"),
                trigger=trig,
                params=dict(d.get("params", {})),
                idempotency_key=d.get("idempotency_key"),
                context_hash=d.get("context_hash"),
                priority=int(d.get("priority", 100)),
                tenant_scope=d.get("tenant_scope"),
            )
        except Exception as e:
            raise ObligationValidationError(f"Invalid ObligationInstance: {e}") from e

    def fingerprint(self) -> str:
        raw = self.to_json().encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


# -----------------------
# Validation / Coercion
# -----------------------

def _validate_and_coerce_params(defn: ObligationDefinition, provided: Mapping[str, Any]) -> Dict[str, Any]:
    provided = dict(provided or {})
    name_to_spec = defn.param_index()
    out: Dict[str, Any] = {}

    # Check unknown keys
    if not defn.allow_extra_params:
        unknown = set(provided.keys()) - set(name_to_spec.keys())
        if unknown:
            raise ObligationValidationError(f"Unknown parameters: {sorted(unknown)}")

    # Required & coercion
    for name, spec in name_to_spec.items():
        val = provided.get(name)
        coerced = spec.validate_and_coerce(val)
        if coerced is not None:
            out[name] = coerced

    # Pass-through extras if allowed
    if defn.allow_extra_params:
        for k, v in provided.items():
            if k not in out:
                out[k] = coerce_activation_value(v)  # best-effort for extras

    return out


def _redact_secret_params(defn: ObligationDefinition, params: Mapping[str, Any]) -> Dict[str, Any]:
    secrets = {p.name for p in defn.params if p.is_secret}
    redacted: Dict[str, Any] = {}
    for k, v in params.items():
        if k in secrets:
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted


def _make_idempotency_key(
    *,
    strategy: IdempotencyStrategy,
    params: Mapping[str, Any],
    activation: Mapping[str, Any],
    from_context_key: Optional[str],
) -> Optional[str]:
    if strategy is IdempotencyStrategy.NONE:
        return None
    if strategy is IdempotencyStrategy.UUID4:
        return str(uuid.uuid4())
    if strategy is IdempotencyStrategy.HASH_OF_PARAMS:
        blob = _canonical_json({"params": params}).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()
    if strategy is IdempotencyStrategy.FROM_CONTEXT_KEY:
        if not from_context_key:
            raise ObligationValidationError("FROM_CONTEXT_KEY requires 'idempotency_context_key'")
        key = activation.get(from_context_key)
        if key is None:
            raise ObligationValidationError(f"Activation missing context key '{from_context_key}'")
        return str(key)
    return None


def _make_context_hash(activation: Mapping[str, Any], *, include_keys: Optional[List[str]]) -> Optional[str]:
    if not activation:
        return None
    if include_keys:
        reduced = {k: activation.get(k) for k in include_keys}
    else:
        reduced = activation
    blob = _canonical_json(reduced).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# -----------------------
# Activation coercion (best-effort)
# -----------------------

def coerce_activation_value(v: Any) -> Any:
    """
    Безопасная коэрсия activation-значений к JSON-совместимым типам.
    """
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (list, tuple)):
        return [coerce_activation_value(x) for x in v]
    if isinstance(v, dict):
        return {str(k): coerce_activation_value(val) for k, val in v.items()}
    # Fallback
    return str(v)
