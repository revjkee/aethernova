# policy_core/risk/scorer.py
from __future__ import annotations

import json
import logging
import math
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Tuple, Union

try:
    # numpy не обязателен: всё работает без него
    import numpy as _np  # type: ignore
    _HAS_NUMPY = True
except Exception:  # pragma: no cover
    _HAS_NUMPY = False

from pydantic import BaseModel, Field, ValidationError, field_validator, computed_field


# =========================
#        Core Enums
# =========================

class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"


class Operator(str, Enum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"
    IN = "in"
    NIN = "nin"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    CONTAINS = "contains"
    MATCH_ANY = "match_any"  # значение равно любому из списка (синоним IN)
    EXIST = "exist"          # признак присутствует (не None)
    MISSING = "missing"      # признак отсутствует (None)


# =========================
#     Utility structures
# =========================

class Issue(BaseModel):
    severity: Severity
    code: str
    message: str
    field: Optional[str] = None


class FeatureSpec(BaseModel):
    """
    Спецификация признака: тип, обязательность, дефолт, допустимые диапазоны/значения.
    """
    name: str
    required: bool = False
    dtype: str = Field(default="float", description="float|int|str|bool|category")
    default: Optional[Any] = None
    min: Optional[float] = None
    max: Optional[float] = None
    categories: Optional[List[str]] = None  # для category|str, whitelisting
    normalize_min: Optional[float] = None   # для нормализации [0..1]
    normalize_max: Optional[float] = None

    @field_validator("dtype")
    @classmethod
    def _dtype_supported(cls, v: str) -> str:
        if v not in {"float", "int", "str", "bool", "category"}:
            raise ValueError("Unsupported dtype")
        return v

    @computed_field
    @property
    def needs_normalize(self) -> bool:
        return self.dtype in {"float", "int"} and self.normalize_min is not None and self.normalize_max is not None


class Rule(BaseModel):
    """
    Правило без eval: оператор применяется к значению признака.
    При срабатывании добавляется вклад weight в «сырую» оценку.
    """
    id: str
    field: str
    op: Operator
    value: Optional[Any] = None
    weight: float = 0.0
    reason: Optional[str] = None
    negate: bool = False  # инвертировать результат матча

    @field_validator("weight")
    @classmethod
    def _finite_weight(cls, v: float) -> float:
        if not (math.isfinite(v)):
            raise ValueError("weight must be finite")
        return v


class RuleSet(BaseModel):
    """
    Набор правил + ограничители суммы вкладов.
    """
    rules: List[Rule] = Field(default_factory=list)
    cap_min: float = -1.0  # нижняя отсечка для raw score
    cap_max: float = 1.0   # верхняя отсечка для raw score

    @field_validator("cap_min", "cap_max")
    @classmethod
    def _finite(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("cap must be finite")
        return v

    @computed_field
    @property
    def is_empty(self) -> bool:
        return len(self.rules) == 0


class CalibratorConfig(BaseModel):
    """
    Калибратор переводит «сырые» значения в [0..1] вероятность.
    """
    kind: str = Field(default="sigmoid", description="sigmoid|linear|none")
    # sigmoid: p = 1 / (1 + exp(-(a*x + b)))
    a: float = 1.0
    b: float = 0.0
    # linear: p = clamp(slope*x + intercept, 0, 1)
    slope: float = 0.5
    intercept: float = 0.5


class Band(BaseModel):
    """
    Интервальные бэнды риска.
    """
    name: str
    min_inclusive: float
    max_exclusive: float
    decision: Decision

    @field_validator("min_inclusive", "max_exclusive")
    @classmethod
    def _range01(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("band borders must be within [0..1]")
        return v


class Bands(BaseModel):
    """
    Упорядоченный набор бэндов для полного покрытия [0..1].
    """
    items: List[Band]

    def resolve(self, prob: float) -> Decision:
        for b in self.items:
            if b.min_inclusive <= prob < b.max_exclusive:
                return b.decision
        # Если ничего не попало — последний бэнд по умолчанию DENY
        return Decision.DENY


class RiskInput(BaseModel):
    """
    Входные данные для оценивания.
    """
    context: Dict[str, Any] = Field(default_factory=dict)   # metadata (request_id, user_id и т.п.) — не влияют на расчёт
    features: Dict[str, Any] = Field(default_factory=dict)  # сырые признаки (могут быть «грязными»)


class Contribution(BaseModel):
    """
    Вклад отдельного правила или преобразования в итоговую оценку.
    """
    source: str
    delta: float
    reason: Optional[str] = None
    matched: Optional[bool] = None
    field: Optional[str] = None
    value: Optional[Any] = None


class RiskScore(BaseModel):
    """
    Итог: вероятность/риск, решение, разборка по вкладам и замечания.
    """
    ok: bool
    probability: float
    raw_score: float
    decision: Decision
    breakdown: List[Contribution] = Field(default_factory=list)
    issues: List[Issue] = Field(default_factory=list)

    @computed_field
    @property
    def contributions_total(self) -> float:
        return sum(c.delta for c in self.breakdown)


# =========================
#   Predictive Protocol
# =========================

class BinaryPredictor(Protocol):
    """
    Протокол для внешних ML-моделей.
    Должен возвращать вероятность «класса риска» в [0..1] для одной записи.
    """
    def predict_proba(self, features: Mapping[str, Any]) -> float:  # pragma: no cover - интерфейс
        ...


# =========================
#     Feature Mapping
# =========================

class FeatureMapper:
    """
    Приводит сырые признаки к спецификациям: типизация, дефолты, нормализация, whitelisting.
    """
    def __init__(self, specs: Iterable[FeatureSpec], logger: Optional[logging.Logger] = None):
        self._specs: Dict[str, FeatureSpec] = {s.name: s for s in specs}
        self.log = logger or logging.getLogger(__name__)

    def map(self, raw: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[Issue], List[Contribution]]:
        out: Dict[str, Any] = {}
        issues: List[Issue] = []
        contribs: List[Contribution] = []

        for name, spec in self._specs.items():
            val = raw.get(name, None)
            missing = val is None

            if missing and spec.required and spec.default is None:
                issues.append(Issue(severity=Severity.error, code="MISSING_REQUIRED", message="feature is required", field=name))
                continue

            if missing:
                val = spec.default

            coerced, iss = self._coerce(name, val, spec)
            issues.extend(iss)

            if coerced is None and spec.required:
                issues.append(Issue(severity=Severity.error, code="COERCE_FAILED", message="cannot coerce required feature", field=name))
                continue

            if coerced is not None:
                # диапазоны
                if spec.dtype in {"float", "int"}:
                    fval = float(coerced)
                    if spec.min is not None and fval < spec.min:
                        issues.append(Issue(severity=Severity.warning, code="BELOW_MIN", message=f"value {fval} < {spec.min}", field=name))
                    if spec.max is not None and fval > spec.max:
                        issues.append(Issue(severity=Severity.warning, code="ABOVE_MAX", message=f"value {fval} > {spec.max}", field=name))
                # категории
                if spec.categories is not None and spec.dtype in {"str", "category"} and coerced is not None:
                    if str(coerced) not in set(spec.categories):
                        issues.append(Issue(severity=Severity.warning, code="CATEGORY_NOT_WHITELISTED", message=f"{coerced} not in whitelist", field=name))

                # нормализация
                if spec.needs_normalize and isinstance(coerced, (int, float)):
                    nm, note = self._normalize(float(coerced), spec)
                    coerced = nm
                    contribs.append(Contribution(source="normalize", delta=0.0, reason=note, field=name, value=nm))

            out[name] = coerced

        # передаём также «избыточные» признаки без спецификаций (как есть)
        for k, v in raw.items():
            if k not in out:
                out[k] = v

        return out, issues, contribs

    def _coerce(self, name: str, v: Any, spec: FeatureSpec) -> Tuple[Optional[Any], List[Issue]]:
        issues: List[Issue] = []
        if v is None:
            return None, issues

        try:
            if spec.dtype == "float":
                return float(v), issues
            if spec.dtype == "int":
                # безопасное приведение: сначала float, затем int
                return int(float(v)), issues
            if spec.dtype == "bool":
                if isinstance(v, bool):
                    return v, issues
                if isinstance(v, (int, float)):
                    return (v != 0), issues
                if isinstance(v, str):
                    s = v.strip().lower()
                    if s in {"1", "true", "yes", "y", "on"}:
                        return True, issues
                    if s in {"0", "false", "no", "n", "off"}:
                        return False, issues
                issues.append(Issue(severity=Severity.warning, code="BOOL_COERCE", message=f"cannot coerce '{v}' to bool", field=name))
                return None, issues
            if spec.dtype in {"str", "category"}:
                return str(v), issues
        except Exception as e:
            issues.append(Issue(severity=Severity.warning, code="COERCE_ERROR", message=str(e), field=name))
            return None, issues

        issues.append(Issue(severity=Severity.warning, code="UNKNOWN_DTYPE", message=f"unsupported dtype {spec.dtype}", field=name))
        return None, issues

    def _normalize(self, val: float, spec: FeatureSpec) -> Tuple[float, str]:
        lo = float(spec.normalize_min)  # type: ignore[arg-type]
        hi = float(spec.normalize_max)  # type: ignore[arg-type]
        if hi <= lo:
            return 0.0, f"normalize skipped (hi<=lo for {spec.name})"
        x = (val - lo) / (hi - lo)
        return float(max(0.0, min(1.0, x))), f"normalize {spec.name} to [0..1] using [{lo},{hi}]"


# =========================
#       Rule Engine
# =========================

_OPS = {
    Operator.EQ: lambda a, b: a == b,
    Operator.NE: lambda a, b: a != b,
    Operator.GT: lambda a, b: _cmp(a, b, lambda x, y: x > y),
    Operator.GE: lambda a, b: _cmp(a, b, lambda x, y: x >= y),
    Operator.LT: lambda a, b: _cmp(a, b, lambda x, y: x < y),
    Operator.LE: lambda a, b: _cmp(a, b, lambda x, y: x <= y),
    Operator.IN: lambda a, b: a in set(b if isinstance(b, (list, tuple, set)) else [b]),
    Operator.NIN: lambda a, b: a not in set(b if isinstance(b, (list, tuple, set)) else [b]),
    Operator.STARTSWITH: lambda a, b: isinstance(a, str) and str(a).startswith(str(b)),
    Operator.ENDSWITH: lambda a, b: isinstance(a, str) and str(a).endswith(str(b)),
    Operator.CONTAINS: lambda a, b: (str(b) in str(a)) if a is not None else False,
    Operator.MATCH_ANY: lambda a, b: a in set(b if isinstance(b, (list, tuple, set)) else [b]),
    Operator.EXIST: lambda a, _: a is not None,
    Operator.MISSING: lambda a, _: a is None,
}

def _cmp(a: Any, b: Any, fn) -> bool:
    try:
        return fn(float(a), float(b))
    except Exception:
        return False


class RuleEngine:
    """
    Применяет набор правил к мэппед-признакам, собирая вклады.
    """
    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset

    def score(self, features: Mapping[str, Any]) -> Tuple[float, List[Contribution]]:
        raw = 0.0
        contribs: List[Contribution] = []

        for rule in self.ruleset.rules:
            val = features.get(rule.field, None)
            op_fn = _OPS.get(rule.op)
            matched = False
            if op_fn is not None:
                try:
                    matched = bool(op_fn(val, rule.value))
                except Exception:
                    matched = False

            if rule.negate:
                matched = not matched

            delta = rule.weight if matched else 0.0
            raw += delta
            contribs.append(Contribution(
                source=f"rule:{rule.id}",
                delta=delta,
                reason=rule.reason,
                matched=matched,
                field=rule.field,
                value=val
            ))

        # Ограничиваем «сырую» сумму
        raw = max(self.ruleset.cap_min, min(self.ruleset.cap_max, raw))
        return raw, contribs


# =========================
#        Calibrators
# =========================

class Calibrator:
    def __init__(self, cfg: CalibratorConfig):
        self.cfg = cfg

    def prob(self, raw_score: float) -> float:
        k = self.cfg.kind.lower()
        if k == "none":
            # предположим, что raw_score уже в [0..1]
            return float(_clip01(raw_score))
        if k == "linear":
            p = self.cfg.slope * raw_score + self.cfg.intercept
            return float(_clip01(p))
        # sigmoid
        z = self.cfg.a * raw_score + self.cfg.b
        # численно стабильная сигмоида
        if z >= 0:
            ez = math.exp(-z)
            p = 1.0 / (1.0 + ez)
        else:
            ez = math.exp(z)
            p = ez / (1.0 + ez)
        return float(_clip01(p))


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


# =========================
#          Bands
# =========================

class Bander:
    def __init__(self, bands: Bands):
        # гарантируем упорядоченность по min_inclusive
        self.bands = Bands(items=sorted(bands.items, key=lambda b: b.min_inclusive))

    def decide(self, p: float) -> Decision:
        return self.bands.resolve(p)


# =========================
#        Risk Scorer
# =========================

class RiskConfig(BaseModel):
    """
    Композитная конфигурация риск-модуля.
    """
    features: List[FeatureSpec]
    ruleset: RuleSet = Field(default_factory=RuleSet)
    calibrator: CalibratorConfig = Field(default_factory=CalibratorConfig)
    bands: Bands = Field(default_factory=lambda: Bands(items=[
        Band(name="low",  min_inclusive=0.0, max_exclusive=0.2, decision=Decision.ALLOW),
        Band(name="mid",  min_inclusive=0.2, max_exclusive=0.6, decision=Decision.REVIEW),
        Band(name="high", min_inclusive=0.6, max_exclusive=1.01, decision=Decision.DENY),
    ]))
    # Вес смешивания с внешней ML-моделью, если она задана (0..1)
    model_blend_weight: float = 0.0

    @field_validator("model_blend_weight")
    @classmethod
    def _w01(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("model_blend_weight must be within [0..1]")
        return v


class RiskScorer:
    """
    Промышленный оценщик риска:
      - безопасная типизация/нормализация признаков;
      - правило-движок без eval;
      - опциональный ML-предиктор;
      - калибровка и бэндинг;
      - explainability по вкладам и список issues.
    """
    def __init__(
        self,
        config: RiskConfig,
        predictor: Optional[BinaryPredictor] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.cfg = config
        self.mapper = FeatureMapper(config.features, logger=logger)
        self.engine = RuleEngine(config.ruleset)
        self.calib = Calibrator(config.calibrator)
        self.bander = Bander(config.bands)
        self.predictor = predictor
        self.log = logger or logging.getLogger(__name__)

    @lru_cache(maxsize=1024)
    def score_cached(self, features_json: str) -> RiskScore:
        """
        Кэш-вариант: ключ — JSON признаков (для идемпотентных повторов).
        """
        try:
            data = json.loads(features_json)
            return self.score(RiskInput(features=data))
        except Exception as e:
            return RiskScore(ok=False, probability=1.0, raw_score=1.0, decision=Decision.DENY,
                             issues=[Issue(severity=Severity.error, code="CACHE_INPUT_ERROR", message=str(e))])

    def score(self, req: RiskInput) -> RiskScore:
        issues: List[Issue] = []

        # 1) Map & normalize
        mapped, map_issues, map_contribs = self.mapper.map(req.features)
        issues.extend(map_issues)

        # 2) Rule engine
        raw_rule, rule_contribs = self.engine.score(mapped)

        # 3) Optional external model
        model_p: Optional[float] = None
        model_contribs: List[Contribution] = []
        if self.predictor is not None and self.cfg.model_blend_weight > 0.0:
            try:
                model_p = float(self.predictor.predict_proba(mapped))
                if not math.isfinite(model_p):
                    raise ValueError("model returned non-finite")
                model_p = _clip01(model_p)
                model_contribs.append(Contribution(source="model", delta=0.0, reason="external probability", matched=None))
            except Exception as e:
                issues.append(Issue(severity=Severity.warning, code="MODEL_ERROR", message=str(e)))

        # 4) Calibrate rule-score -> probability
        p_rule = self.calib.prob(raw_rule)

        # 5) Blend
        p_final = p_rule
        if model_p is not None:
            w = self.cfg.model_blend_weight
            p_final = w * model_p + (1.0 - w) * p_rule

        p_final = _clip01(p_final)

        # 6) Decision by bands
        decision = self.bander.decide(p_final)

        breakdown: List[Contribution] = []
        breakdown.extend(map_contribs)
        breakdown.extend(rule_contribs)
        breakdown.extend(model_contribs)
        breakdown.append(Contribution(source="calibrator", delta=0.0, reason=f"p_rule={p_rule:.6f}"))
        if model_p is not None:
            breakdown.append(Contribution(source="blend", delta=0.0, reason=f"w={self.cfg.model_blend_weight:.3f}, p_model={model_p:.6f}"))

        ok = all(i.severity != Severity.error for i in issues)

        return RiskScore(
            ok=ok,
            probability=p_final,
            raw_score=raw_rule,
            decision=decision,
            breakdown=breakdown,
            issues=issues,
        )


# =========================
#            CLI
# =========================

def _example_config() -> RiskConfig:
    """
    Пример дефолтной конфигурации (без ML-модели).
    """
    return RiskConfig(
        features=[
            FeatureSpec(name="amount", dtype="float", required=True, min=0.0, normalize_min=0.0, normalize_max=10_000.0),
            FeatureSpec(name="country", dtype="str", required=True, categories=["SE", "RU", "US", "DE", "FR"]),
            FeatureSpec(name="age_days", dtype="int", required=False, default=365, min=0, normalize_min=0.0, normalize_max=3650.0),
            FeatureSpec(name="is_vip", dtype="bool", required=False, default=False),
        ],
        ruleset=RuleSet(
            rules=[
                Rule(id="high_amount", field="amount", op=Operator.GT, value=5000, weight=0.6, reason="amount>5000"),
                Rule(id="risky_country", field="country", op=Operator.IN, value=["RU"], weight=0.3, reason="country in watchlist"),
                Rule(id="fresh_account", field="age_days", op=Operator.LT, value=30, weight=0.25, reason="account too new"),
                Rule(id="vip_discount", field="is_vip", op=Operator.EQ, value=True, weight=-0.2, reason="VIP"),
            ],
            cap_min=-1.0,
            cap_max=1.0,
        ),
        calibrator=CalibratorConfig(kind="sigmoid", a=3.0, b=0.0),
        bands=Bands(items=[
            Band(name="low",  min_inclusive=0.0, max_exclusive=0.2, decision=Decision.ALLOW),
            Band(name="mid",  min_inclusive=0.2, max_exclusive=0.6, decision=Decision.REVIEW),
            Band(name="high", min_inclusive=0.6, max_exclusive=1.01, decision=Decision.DENY),
        ]),
        model_blend_weight=0.0,
    )


def _load_config_from_json(cfg_json: str) -> RiskConfig:
    try:
        cfg = json.loads(cfg_json)
        return RiskConfig.model_validate(cfg)
    except Exception as e:
        raise RuntimeError(f"Invalid config JSON: {e}")


def _build_logger() -> logging.Logger:
    log = logging.getLogger("policy_core.risk.scorer")
    if not log.handlers:
        h = logging.StreamHandler()
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        h.setFormatter(fmt)
        log.addHandler(h)
        log.setLevel(logging.INFO)
    return log


def cli(argv: Optional[List[str]] = None) -> int:
    """
    Простой CLI:
      echo '{"features":{"amount":7500,"country":"SE"}}' | python -m policy_core.risk.scorer
    Или с конфигом:
      python -m policy_core.risk.scorer --config-file cfg.json --input-file request.json
    """
    import argparse, sys, pathlib
    p = argparse.ArgumentParser(description="Policy Core Risk Scorer")
    p.add_argument("--config-file", type=str, help="JSON file with RiskConfig", default=None)
    p.add_argument("--config-json", type=str, help="RiskConfig as JSON string", default=None)
    p.add_argument("--input-file", type=str, help="RiskInput JSON file", default=None)
    args = p.parse_args(argv)

    log = _build_logger()

    # Load config
    if args.config_json:
        cfg = _load_config_from_json(args.config_json)
    elif args.config_file:
        cfg_path = pathlib.Path(args.config_file)
        cfg = _load_config_from_json(cfg_path.read_text(encoding="utf-8"))
    else:
        cfg = _example_config()

    scorer = RiskScorer(config=cfg, predictor=None, logger=log)

    # Load input
    if args.input_file:
        req = RiskInput.model_validate_json(pathlib.Path(args.input_file).read_text(encoding="utf-8"))
    else:
        data = sys.stdin.read()
        if not data.strip():
            data = '{"features":{}}'
        req = RiskInput.model_validate_json(data)

    result = scorer.score(req)
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    import sys
    raise SystemExit(cli(sys.argv[1:]))
