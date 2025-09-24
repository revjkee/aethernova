# path: veilmind-core/veilmind/detect/validators.py
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Pattern, Sequence, Set, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

from pydantic import (
    BaseModel,
    Field,
    RootModel,
    ValidationError as PydanticValidationError,
    field_validator,
    model_validator,
)
from pydantic.types import (
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    conint,
    conlist,
    constr,
)

# --------------------------------------------------------------------------------------
# Публичные ошибки и результаты
# --------------------------------------------------------------------------------------

class ConfigValidationError(ValueError):
    """Ошибка валидации конфигурации детектора."""


class EventValidationError(ValueError):
    """Ошибка валидации входящего события."""


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: Tuple[str, ...] = ()


# --------------------------------------------------------------------------------------
# Общие справочники/перечисления (синхронизировано с GraphQL/Protobuf)
# --------------------------------------------------------------------------------------

Severity = Literal["low", "medium", "high", "critical"]
Category = Literal[
    "INJECTION_ATTEMPT",
    "DATA_EXFILTRATION",
    "PII_PRESENT",
    "SEXUAL_MINORS",
    "EXPLICIT_SEXUAL",
    "SELF_HARM",
    "HATE_VIOLENCE",
    "ILLEGAL_ACTIVITY",
    "MALWARE_CYBERCRIME",
    "MEDICAL_ADVICE",
    "LEGAL_ADVICE",
    "FINANCIAL_ADVICE",
    "CODE_EXECUTION",
    "COPYRIGHT_RISKY",
    "ADULT_NSFW",
]

StreamName = Literal["authn", "http_access_log", "policy_core", "user_directory_change", "custom"]

# Разрешённые идентификаторы ключей в where‑выражениях (минимальный набор; расширяйте по мере надобности)
ALLOWED_FIELDS: Set[str] = {
    "user", "tenant", "ip", "path", "method", "status", "result", "provider",
    "decision", "resource_type", "action", "subject", "mfa", "geo.iso_code",
    "rep.score", "device.os", "device.os_up_to_date", "device.jailbroken",
}

# --------------------------------------------------------------------------------------
# Хелперы "безопасных" регулярных выражений и выражений фильтрации
# --------------------------------------------------------------------------------------

_RE_FORBIDDEN_TOKENS = re.compile(r"(?:__|import\s|exec\s|eval\s|os\.|sys\.|subprocess|pickle|open\s*\()")
_RE_ALLOWED_EXPR = re.compile(
    r"""(?xi)
    ^[ \t\(\)\[\]\{\}\.\,\:\-\+\*/%<>=!'"|&\w]+$
    """
)
_RE_POTENTIALLY_CATASTROPHIC = re.compile(
    r"""(?x)
    (?:                 # два и более квантификатора подряд
        (?:\.\*|\.\+|[^)]\+|[^)]\*|\{[^}]+\})
    ){2,}.*?(?:\+|\*|\{[^}]+\})
    """
)

def _assert_safe_regex(pattern: str, max_len: int = 2000, max_groups: int = 100) -> Pattern[str]:
    """
    Бюджетная эвристика против катастрофического бэктрекинга и злоупотреблений.
    Не гарантирует абсолютной безопасности, но отсекает заведомо опасные случаи.
    """
    if len(pattern) > max_len:
        raise ConfigValidationError(f"regex too long (> {max_len})")
    if _RE_POTENTIALLY_CATASTROPHIC.search(pattern):
        raise ConfigValidationError("regex may cause catastrophic backtracking")
    # ограничим число групп
    if pattern.count("(") - pattern.count(r"\(") > max_groups:
        raise ConfigValidationError(f"too many groups (> {max_groups})")
    try:
        return re.compile(pattern)
    except re.error as e:
        raise ConfigValidationError(f"invalid regex: {e}") from e


def _assert_safe_expr(expr: str) -> None:
    """
    Разрешаем ограниченный набор символов (простая DSL), запрещаем встроенные вызовы/атрибуты.
    """
    if not _RE_ALLOWED_EXPR.match(expr):
        raise ConfigValidationError("expression contains illegal characters")
    if _RE_FORBIDDEN_TOKENS.search(expr):
        raise ConfigValidationError("forbidden tokens in expression")
    # Токены вида a.b.c -> проверим, что базовые поля допустимы
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_\.]*", expr)
    for t in tokens:
        if "." in t:
            root = t.split(".", 1)[0]
            # допускаем составные из ALLOWED_FIELDS
            if t not in ALLOWED_FIELDS and root not in {f.split(".", 1)[0] for f in ALLOWED_FIELDS}:
                # пропускаем ключевые слова (and, or, not, in, etc.)
                if t not in {"and", "or", "not", "in", "True", "False"}:
                    raise ConfigValidationError(f"field not allowed in expression: {t}")
        else:
            if t not in ALLOWED_FIELDS and t not in {"and", "or", "not", "in", "True", "False"} and not t.isdigit():
                raise ConfigValidationError(f"field not allowed in expression: {t}")


# --------------------------------------------------------------------------------------
# Типы конфигурации детекторов
# --------------------------------------------------------------------------------------

class ThresholdConfig(BaseModel):
    count_ge: Optional[conint(ge=1)] = Field(default=None, description="Минимальное число событий за окно")
    when: Optional[StrictStr] = Field(default=None, description="Булево выражение DSL")

    @model_validator(mode="after")
    def _ensure_one_present(self) -> "ThresholdConfig":
        if self.count_ge is None and (not self.when or not self.when.strip()):
            raise ConfigValidationError("threshold: either 'count_ge' or 'when' must be set")
        if self.when:
            _assert_safe_expr(self.when.strip())
        return self


class BaselineConfig(BaseModel):
    method: Literal["ewma", "median", "p95"]
    alpha: Optional[StrictFloat] = Field(default=None, ge=0.01, le=0.99)
    min_samples: conint(ge=1) = 50

    @model_validator(mode="after")
    def _check_params(self) -> "BaselineConfig":
        if self.method == "ewma" and self.alpha is None:
            raise ConfigValidationError("baseline.ewma requires 'alpha'")
        if self.method != "ewma" and self.alpha is not None:
            raise ConfigValidationError("baseline.alpha is only valid for ewma")
        return self


class SequenceStep(BaseModel):
    within_s: conint(ge=1) = Field(..., description="Окно шага")
    eval: StrictStr = Field(..., description="Булево выражение DSL для шага")

    @field_validator("eval")
    @classmethod
    def _safe_eval(cls, v: str) -> str:
        _assert_safe_expr(v.strip())
        return v.strip()


class CorrelationConfig(BaseModel):
    type: Literal["sequence", "join"]
    by: conlist(StrictStr, min_items=1)
    within_s: conint(ge=1)
    steps: Optional[List[SequenceStep]] = None
    with_stream: Optional[StrictStr] = None
    predicate: Optional[StrictStr] = None

    @model_validator(mode="after")
    def _validate_by_type(self) -> "CorrelationConfig":
        if self.type == "sequence":
            if not self.steps or len(self.steps) == 0:
                raise ConfigValidationError("correlation.sequence requires non-empty steps")
        if self.type == "join":
            if not self.with_stream:
                raise ConfigValidationError("correlation.join requires 'with_stream'")
            if not self.predicate:
                raise ConfigValidationError("correlation.join requires 'predicate'")
            _assert_safe_expr(self.predicate.strip())
        return self


class WhereExpr(BaseModel):
    expr: constr(min_length=1, max_length=512)  # type: ignore

    @field_validator("expr")
    @classmethod
    def _safe_expr(cls, v: str) -> str:
        _assert_safe_expr(v.strip())
        return v.strip()


class DetectorConfig(BaseModel):
    id: constr(pattern=r"^[A-Z0-9_]{3,64}$")  # type: ignore
    name: constr(min_length=3, max_length=160)  # type: ignore
    stream: StreamName
    window_s: conint(ge=1, le=86400) = 900
    where: List[WhereExpr] = Field(default_factory=list)
    group_by: Optional[List[StrictStr]] = None
    threshold: Optional[ThresholdConfig] = None
    baseline: Optional[BaselineConfig] = None
    correlation: Optional[CorrelationConfig] = None
    risk_factors: Optional[Dict[StrictStr, StrictFloat]] = None
    output_title: Optional[StrictStr] = None
    output_severity: Optional[Literal["low", "medium", "high", "critical"]] = None

    @model_validator(mode="after")
    def _consistency(self) -> "DetectorConfig":
        if self.threshold is None and self.baseline is None and self.correlation is None:
            raise ConfigValidationError("detector must specify threshold, baseline, or correlation")
        if self.group_by:
            for key in self.group_by:
                if key not in ALLOWED_FIELDS and "." not in key:
                    raise ConfigValidationError(f"group_by key not allowed: {key}")
        return self


class DetectorsConfig(RootModel[List[DetectorConfig]]):
    root: List[DetectorConfig]

# --------------------------------------------------------------------------------------
# Валидация событий
# --------------------------------------------------------------------------------------

class DetectionEvent(BaseModel):
    ts: datetime
    stream: StreamName
    tenant: constr(min_length=1)  # type: ignore
    user: Optional[constr(min_length=1)] = None  # type: ignore
    ip: Optional[StrictStr] = None
    method: Optional[StrictStr] = None
    path: Optional[StrictStr] = None
    status: Optional[StrictInt] = None
    mfa: Optional[StrictBool] = None
    decision: Optional[Literal["Permit", "Deny", "Indeterminate"]] = None
    action: Optional[StrictStr] = None
    resource_type: Optional[StrictStr] = None
    subject: Optional[StrictStr] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _ts_aware_and_reasonable(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise EventValidationError("timestamp must be timezone-aware")
        # Ограничим будущее/прошлое разумными рамками (+/- 1 день)
        now = datetime.now(timezone.utc)
        delta = (v - now).total_seconds()
        if delta > 86400 or delta < -86400 * 30:
            raise EventValidationError("timestamp out of acceptable range")
        return v

    @field_validator("ip")
    @classmethod
    def _ip_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except Exception as e:
            raise EventValidationError(f"invalid ip: {v}") from e
        return v

    @model_validator(mode="after")
    def _required_by_stream(self) -> "DetectionEvent":
        if self.stream == "http_access_log":
            if not self.method or not self.path or self.status is None:
                raise EventValidationError("http_access_log requires method, path, status")
        if self.stream == "authn":
            if self.mfa is None or self.user is None:
                raise EventValidationError("authn requires user and mfa")
        if self.stream == "policy_core":
            if not self.decision or not self.action or not self.resource_type or not self.subject:
                raise EventValidationError("policy_core requires decision, action, resource_type, subject")
        return self


# --------------------------------------------------------------------------------------
# Публичный API: функции валидации
# --------------------------------------------------------------------------------------

def validate_detector_config(cfg: Dict[str, Any]) -> DetectorConfig:
    """
    Валидирует словарь детектора и возвращает нормализованную модель.
    Поднимает ConfigValidationError при ошибках.
    """
    try:
        return DetectorConfig.model_validate(cfg)
    except PydanticValidationError as e:
        raise ConfigValidationError(e.errors().__str__())


def validate_detectors_list(cfg_list: Iterable[Dict[str, Any]]) -> List[DetectorConfig]:
    """
    Валидирует список словарей-детекторов.
    """
    try:
        return DetectorsConfig.model_validate(list(cfg_list)).root
    except PydanticValidationError as e:
        raise ConfigValidationError(e.errors().__str__())


def validate_event_input(stream: str, payload: Dict[str, Any]) -> DetectionEvent:
    """
    Валидирует входящее событие по имени потока.
    """
    data = {"stream": stream, **payload}
    try:
        return DetectionEvent.model_validate(data)
    except PydanticValidationError as e:
        raise EventValidationError(e.errors().__str__())


def validate_regex_safe(pattern: str) -> Pattern[str]:
    """
    Публичная обёртка проверки безопасного регулярного выражения.
    """
    return _assert_safe_regex(pattern)


def validate_expression_safe(expr: str) -> None:
    """
    Публичная обёртка проверки безопасного where‑выражения.
    """
    _assert_safe_expr(expr)


def validate_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except Exception as e:
        raise ConfigValidationError(f"invalid CIDR: {value}") from e


# --------------------------------------------------------------------------------------
# Опциональная валидация YAML‑файла detectors.yaml
# --------------------------------------------------------------------------------------

def validate_detectors_yaml(path: str) -> List[DetectorConfig]:
    """
    Загружает и валидирует YAML конфиг детекторов вида:

    detectors:
      - id: AUTH_FAIL_BRUTEFORCE
        name: ...
        stream: authn
        window_s: 600
        where:
          - expr: 'result == "failure" and not (user in service_accounts)'
        threshold:
          count_ge: 10

    Возвращает список моделей DetectorConfig.
    """
    if yaml is None:
        raise ConfigValidationError("PyYAML is not installed")
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict) or "detectors" not in raw or not isinstance(raw["detectors"], list):
        raise ConfigValidationError("YAML must contain top-level 'detectors: [...]'")
    return validate_detectors_list(raw["detectors"])


# --------------------------------------------------------------------------------------
# Самотесты (минимальные быстрые проверки) — можно запускать из CI
# --------------------------------------------------------------------------------------

def _selftest() -> ValidationResult:
    errs: List[str] = []
    try:
        d = validate_detector_config(
            {
                "id": "API_RATE_SPIKE",
                "name": "Резкий всплеск запросов API c одного субъекта",
                "stream": "http_access_log",
                "window_s": 120,
                "where": [{"expr": "status not_in [429,499,500,502,503,504]"}],  # допустимо (ограниченный DSL)
                "baseline": {"method": "ewma", "alpha": 0.2, "min_samples": 50},
            }
        )
        assert d.id == "API_RATE_SPIKE"
    except Exception as e:
        errs.append(f"detector: {e}")

    try:
        e = validate_event_input(
            "authn",
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "tenant": "t1",
                "user": "alice",
                "ip": "203.0.113.10",
                "mfa": True,
            },
        )
        assert e.user == "alice"
    except Exception as e:
        errs.append(f"event: {e}")

    try:
        validate_regex_safe(r"^/api/v1/(admin|policies)$")
    except Exception as e:
        errs.append(f"regex: {e}")

    try:
        validate_expression_safe('user == "alice" and status == 200')
    except Exception as e:
        errs.append(f"expr: {e}")

    return ValidationResult(ok=not errs, errors=tuple(errs))


if __name__ == "__main__":  # pragma: no cover
    res = _selftest()
    print(json.dumps({"ok": res.ok, "errors": list(res.errors)}, ensure_ascii=False))
