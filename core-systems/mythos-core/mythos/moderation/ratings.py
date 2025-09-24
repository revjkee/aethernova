# -*- coding: utf-8 -*-
"""
Mythos Moderation — Ratings & Decisions

Назначение:
- Унифицированная оценка контента по категориям рисков
- Профили политик с настраиваемыми порогами/жёсткостью
- Итоговое решение (ALLOW/FLAG/LOCK/BLOCK) + возрастной рейтинг
- Объяснимые причины, детерминированность, идемпотентность

Зависимости: только стандартная библиотека + Pydantic (в экосистеме Mythos он уже используется).
Совместимость: Python 3.10+, Pydantic v1+.
"""
from __future__ import annotations

import re
import time
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:
    from pydantic import BaseModel, Field, validator, root_validator, conint, confloat
except Exception:  # pragma: no cover
    # Лёгкий graceful fallback, если pydantic отсутствует
    raise ImportError("ratings.py requires pydantic. Install it in mythos runtime.")

RATINGS_VERSION = "1.0.0"

# ------------------------------------------------------------------------------
# Категории/Severity/Действия/Возраст
# ------------------------------------------------------------------------------

class Category(str, Enum):
    VIOLENCE = "violence"
    SEXUAL = "sexual"
    NUDITY = "nudity"
    HATE = "hate"
    SELF_HARM = "self_harm"
    DRUGS = "drugs"
    WEAPONS = "weapons"
    PROFANITY = "profanity"
    OTHER = "other"

class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DecisionAction(str, Enum):
    ALLOW = "ALLOW"     # можно публиковать без ограничений
    FLAG = "FLAG"       # требуется ручная проверка/смягчение (mask/redact/age-gate)
    BLOCK = "BLOCK"     # нельзя публиковать (жёсткий запрет по политике)

class AgeBand(str, Enum):
    A0 = "0+"
    A7 = "7+"
    A12 = "12+"
    A16 = "16+"
    A18 = "18+"

# ------------------------------------------------------------------------------
# Пороговые матрицы и профили политик
# ------------------------------------------------------------------------------

# Пороговая шкала: score ∈ [0,1] => Severity
# Профили могут переопределять эти значения.
DEFAULT_THRESHOLDS: Dict[Category, Dict[Severity, float]] = {
    Category.VIOLENCE:  {Severity.LOW: 0.25, Severity.MEDIUM: 0.55, Severity.HIGH: 0.80, Severity.CRITICAL: 0.95},
    Category.SEXUAL:    {Severity.LOW: 0.20, Severity.MEDIUM: 0.45, Severity.HIGH: 0.70, Severity.CRITICAL: 0.90},
    Category.NUDITY:    {Severity.LOW: 0.25, Severity.MEDIUM: 0.50, Severity.HIGH: 0.75, Severity.CRITICAL: 0.92},
    Category.HATE:      {Severity.LOW: 0.15, Severity.MEDIUM: 0.40, Severity.HIGH: 0.70, Severity.CRITICAL: 0.90},
    Category.SELF_HARM: {Severity.LOW: 0.10, Severity.MEDIUM: 0.35, Severity.HIGH: 0.60, Severity.CRITICAL: 0.85},
    Category.DRUGS:     {Severity.LOW: 0.30, Severity.MEDIUM: 0.55, Severity.HIGH: 0.80, Severity.CRITICAL: 0.95},
    Category.WEAPONS:   {Severity.LOW: 0.30, Severity.MEDIUM: 0.55, Severity.HIGH: 0.80, Severity.CRITICAL: 0.95},
    Category.PROFANITY: {Severity.LOW: 0.25, Severity.MEDIUM: 0.50, Severity.HIGH: 0.75, Severity.CRITICAL: 0.95},
    Category.OTHER:     {Severity.LOW: 0.40, Severity.MEDIUM: 0.65, Severity.HIGH: 0.85, Severity.CRITICAL: 0.97},
}

# Возрастная политика: минимально допустимый age-band по максимальной серьёзности категории
# (чем строже политика, тем выше возраст).
DEFAULT_AGE_POLICY: Dict[Category, Dict[Severity, AgeBand]] = {
    Category.PROFANITY: {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A7,  Severity.MEDIUM: AgeBand.A12, Severity.HIGH: AgeBand.A16, Severity.CRITICAL: AgeBand.A18},
    Category.VIOLENCE:  {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A7,  Severity.MEDIUM: AgeBand.A12, Severity.HIGH: AgeBand.A16, Severity.CRITICAL: AgeBand.A18},
    Category.NUDITY:    {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A12, Severity.MEDIUM: AgeBand.A16, Severity.HIGH: AgeBand.A18, Severity.CRITICAL: AgeBand.A18},
    Category.SEXUAL:    {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A12, Severity.MEDIUM: AgeBand.A16, Severity.HIGH: AgeBand.A18, Severity.CRITICAL: AgeBand.A18},
    Category.HATE:      {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A12, Severity.MEDIUM: AgeBand.A16, Severity.HIGH: AgeBand.A18, Severity.CRITICAL: AgeBand.A18},
    Category.SELF_HARM: {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A12, Severity.MEDIUM: AgeBand.A16, Severity.HIGH: AgeBand.A18, Severity.CRITICAL: AgeBand.A18},
    Category.DRUGS:     {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A12, Severity.MEDIUM: AgeBand.A16, Severity.HIGH: AgeBand.A18, Severity.CRITICAL: AgeBand.A18},
    Category.WEAPONS:   {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A7,  Severity.MEDIUM: AgeBand.A12, Severity.HIGH: AgeBand.A16, Severity.CRITICAL: AgeBand.A18},
    Category.OTHER:     {Severity.NONE: AgeBand.A0,  Severity.LOW: AgeBand.A7,  Severity.MEDIUM: AgeBand.A12, Severity.HIGH: AgeBand.A16, Severity.CRITICAL: AgeBand.A18},
}

STRICT_KIDS_ZERO_TOLERANCE = {Category.SEXUAL, Category.NUDITY, Category.DRUGS, Category.SELF_HARM, Category.WEAPONS, Category.HATE}

class Profile(BaseModel):
    name: str = "default"
    thresholds: Dict[Category, Dict[Severity, confloat(ge=0.0, le=1.0)]] = Field(default_factory=lambda: DEFAULT_THRESHOLDS)
    age_policy: Dict[Category, Dict[Severity, AgeBand]] = Field(default_factory=lambda: DEFAULT_AGE_POLICY)
    zero_tolerance: List[Category] = Field(default_factory=list)  # категория → BLOCK при HIGH+
    flag_on_medium: bool = True  # FLAG при MEDIUM, если не zero_tolerance
    block_on_critical: bool = True
    redact_profanity: bool = True  # предлагать маскирование нецензурной лексики
    max_text_len: conint(gt=0) = 100_000

# Готовые профили
DEFAULT_PROFILE = Profile()
STRICT_KIDS_PROFILE = Profile(
    name="strict_kids",
    zero_tolerance=list(STRICT_KIDS_ZERO_TOLERANCE),
    thresholds={
        **DEFAULT_THRESHOLDS,
        Category.PROFANITY: {Severity.LOW: 0.10, Severity.MEDIUM: 0.25, Severity.HIGH: 0.50, Severity.CRITICAL: 0.80},
    },
    age_policy=DEFAULT_AGE_POLICY,
    flag_on_medium=True,
    block_on_critical=True,
    redact_profanity=True,
)
STREAMING_PROFILE = Profile(name="streaming", zero_tolerance=[Category.HATE, Category.SELF_HARM], redact_profanity=True)
SOCIAL_PROFILE = Profile(name="social", zero_tolerance=[Category.HATE], redact_profanity=True)

# ------------------------------------------------------------------------------
# Входные сигналы и структура решения
# ------------------------------------------------------------------------------

class CategoryScore(BaseModel):
    category: Category
    score: confloat(ge=0.0, le=1.0) = 0.0
    source: str = "unknown"   # detector name / heuristic

class Signals(BaseModel):
    # Нормализованные скоры по категориям (0..1). Отсутствующие будут заполнены нулями.
    scores: List[CategoryScore] = Field(default_factory=list)

    def to_map(self) -> Dict[Category, float]:
        out: Dict[Category, float] = {c: 0.0 for c in Category}
        for s in self.scores:
            out[s.category] = max(out.get(s.category, 0.0), float(s.score))
        return out

class ContentSample(BaseModel):
    text: Optional[str] = None
    lang: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    signals: Signals = Field(default_factory=Signals)

    @validator("text")
    def _len_guard(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # обрезка — только для защиты в рантайме; валидация профиля делается в compute_decision
        return v if len(v) <= 2_000_000 else v[:2_000_000]

class CategoryDecision(BaseModel):
    category: Category
    score: float
    severity: Severity
    reason: str

class RatingBreakdown(BaseModel):
    per_category: List[CategoryDecision]
    max_severity: Severity
    age_band: AgeBand

class ActionHint(BaseModel):
    # рекомендация к пост-обработке (маскировать/эйдж-гейт и т.п.)
    kind: str
    details: Dict[str, Any] = Field(default_factory=dict)

class ModerationDecision(BaseModel):
    version: str = RATINGS_VERSION
    profile: str
    action: DecisionAction
    breakdown: RatingBreakdown
    reasons: List[str]
    hints: List[ActionHint] = Field(default_factory=list)
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    request_id: Optional[str] = None  # для трассировки

# ------------------------------------------------------------------------------
# Эвристики (опциональные) для текста
# ------------------------------------------------------------------------------

# Нецензурная лексика (без крайне оскорбительных выражений)
_PROFANITY_PAT = re.compile(r"\b(?:fuck|shit|bitch|asshole|bastard|damn)\b", re.IGNORECASE)
# Простые индикаторы сексуального контента/наготы (без перечисления explicit-терминов)
_SEXUAL_PAT = re.compile(r"\b(?:nsfw|explicit|adult)\b", re.IGNORECASE)
_NUDITY_PAT = re.compile(r"\b(?:nude|nudity)\b", re.IGNORECASE)
_VIOLENCE_PAT = re.compile(r"\b(?:kill|murder|blood|assault)\b", re.IGNORECASE)
_DRUGS_PAT = re.compile(r"\b(?:cocaine|heroin|meth|marijuana)\b", re.IGNORECASE)
_WEAPONS_PAT = re.compile(r"\b(?:gun|rifle|pistol|knife|bomb)\b", re.IGNORECASE)
_HATE_PLACEHOLDER = re.compile(r"\b(?:hate|racist|bigot)\b", re.IGNORECASE)
_SELF_HARM_PAT = re.compile(r"\b(?:suicide|self[- ]?harm|kill myself)\b", re.IGNORECASE)

def _heuristic_scores(text: Optional[str]) -> Dict[Category, float]:
    if not text:
        return {c: 0.0 for c in Category}
    def bump(found: bool, base: float) -> float:
        return min(1.0, base)
    return {
        Category.PROFANITY: bump(bool(_PROFANITY_PAT.search(text)), 0.50),
        Category.SEXUAL:    bump(bool(_SEXUAL_PAT.search(text)),    0.40),
        Category.NUDITY:    bump(bool(_NUDITY_PAT.search(text)),    0.40),
        Category.VIOLENCE:  bump(bool(_VIOLENCE_PAT.search(text)),  0.45),
        Category.DRUGS:     bump(bool(_DRUGS_PAT.search(text)),     0.45),
        Category.WEAPONS:   bump(bool(_WEAPONS_PAT.search(text)),   0.45),
        Category.HATE:      bump(bool(_HATE_PLACEHOLDER.search(text)), 0.35),
        Category.SELF_HARM: bump(bool(_SELF_HARM_PAT.search(text)), 0.60),
        Category.OTHER:     0.0,
    }

# ------------------------------------------------------------------------------
# Основные функции вычисления
# ------------------------------------------------------------------------------

def _severity_for(category: Category, score: float, thresholds: Mapping[Severity, float]) -> Severity:
    # В порядке возрастания
    if score >= thresholds.get(Severity.CRITICAL, 0.99):
        return Severity.CRITICAL
    if score >= thresholds.get(Severity.HIGH, 0.85):
        return Severity.HIGH
    if score >= thresholds.get(Severity.MEDIUM, 0.5):
        return Severity.MEDIUM
    if score >= thresholds.get(Severity.LOW, 0.2):
        return Severity.LOW
    return Severity.NONE

def _max_age(a: AgeBand, b: AgeBand) -> AgeBand:
    order = [AgeBand.A0, AgeBand.A7, AgeBand.A12, AgeBand.A16, AgeBand.A18]
    return max(a, b, key=lambda x: order.index(x))

def _age_for_category(policy: Dict[Severity, AgeBand], sev: Severity) -> AgeBand:
    return policy.get(sev, AgeBand.A18)

def _explain_reason(category: Category, severity: Severity, score: float) -> str:
    return f"{category.value}={severity.value} (score={score:.2f})"

def _redact_profanity(text: str) -> Tuple[str, int]:
    """Маскирование нецензурной лексики звёздочками, возвращает (новый_текст, количество_замен)."""
    def repl(m: re.Match) -> str:
        w = m.group(0)
        if len(w) <= 2:
            return "*" * len(w)
        return w[0] + "*" * (len(w) - 2) + w[-1]
    new_text, n = _PROFANITY_PAT.subn(repl, text)
    return new_text, n

def compute_decision(
    sample: ContentSample,
    profile: Profile = DEFAULT_PROFILE,
    request_id: Optional[str] = None,
) -> ModerationDecision:
    # Валидация размера текста
    if sample.text and len(sample.text) > profile.max_text_len:
        # Слишком длинный текст — флагуем для ручной проверки
        reasons = [f"text too long: {len(sample.text)} > {profile.max_text_len}"]
        breakdown = RatingBreakdown(
            per_category=[CategoryDecision(category=c, score=0.0, severity=Severity.NONE, reason="not evaluated") for c in Category],
            max_severity=Severity.LOW,
            age_band=AgeBand.A0,
        )
        return ModerationDecision(
            profile=profile.name,
            action=DecisionAction.FLAG,
            breakdown=breakdown,
            reasons=reasons,
            hints=[ActionHint(kind="manual_review", details={"reason": "oversize"})],
            request_id=request_id,
        )

    # Объединяем внешние сигналы и эвристики (max-пулинг по категориям)
    ext = sample.signals.to_map()
    heur = _heuristic_scores(sample.text)
    merged: Dict[Category, float] = {c: max(ext.get(c, 0.0), heur.get(c, 0.0)) for c in Category}

    # Рассчитываем per-category решения
    per: List[CategoryDecision] = []
    max_sev = Severity.NONE
    age = AgeBand.A0
    reasons: List[str] = []
    for cat in Category:
        thr = profile.thresholds.get(cat, DEFAULT_THRESHOLDS[cat])
        sev = _severity_for(cat, merged[cat], thr)
        reason = _explain_reason(cat, sev, merged[cat])
        per.append(CategoryDecision(category=cat, score=merged[cat], severity=sev, reason=reason))
        reasons.append(reason)
        # агрегируем максимальную серьёзность и возраст
        if sev.value in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value):
            max_sev = max(max_sev, sev, key=lambda s: ["NONE","LOW","MEDIUM","HIGH","CRITICAL"].index(s.value))
        age = _max_age(age, _age_for_category(profile.age_policy.get(cat, DEFAULT_AGE_POLICY[cat]), sev))

    breakdown = RatingBreakdown(per_category=per, max_severity=max_sev, age_band=age)

    # Итоговое действие согласно политике
    action = DecisionAction.ALLOW
    zero_hit = any((d.severity in (Severity.HIGH, Severity.CRITICAL)) and (d.category in profile.zero_tolerance) for d in per)
    critical_hit = any(d.severity == Severity.CRITICAL for d in per)

    if zero_hit:
        action = DecisionAction.BLOCK
        reasons.append("zero_tolerance breached")
    elif profile.block_on_critical and critical_hit:
        action = DecisionAction.BLOCK
        reasons.append("critical severity present")
    elif profile.flag_on_medium and any(d.severity in (Severity.MEDIUM, Severity.HIGH) for d in per):
        action = DecisionAction.FLAG
        reasons.append("medium/high severity present")

    # Подсказки к пост-обработке
    hints: List[ActionHint] = []
    if action != DecisionAction.BLOCK and age in (AgeBand.A16, AgeBand.A18):
        hints.append(ActionHint(kind="age_gate", details={"min_age": age.value}))
    if action != DecisionAction.BLOCK and profile.redact_profanity and any(d.category == Category.PROFANITY and d.severity != Severity.NONE for d in per) and sample.text:
        redacted, n = _redact_profanity(sample.text)
        if n > 0:
            hints.append(ActionHint(kind="redact_profanity", details={"replacements": n}))
            # Пример: можно вернуть предпросмотр (не меняем входной текст!)
            # hints[-1].details["preview"] = redacted[:256]

    # Финальное решение
    return ModerationDecision(
        profile=profile.name,
        action=action,
        breakdown=breakdown,
        reasons=sorted(set(reasons)),
        hints=hints,
        request_id=request_id,
    )

# ------------------------------------------------------------------------------
# Утилиты агрегации групповых сэмплов
# ------------------------------------------------------------------------------

def aggregate_decisions(decisions: List[ModerationDecision]) -> ModerationDecision:
    """
    Агрегирует несколько решений (например, по частям мультимодального поста) в одно.
    Правило: максимум по действию (BLOCK > FLAG > ALLOW), max по возрасту, merge причин.
    """
    if not decisions:
        # Нейтральное пустое решение
        empty = RatingBreakdown(
            per_category=[CategoryDecision(category=c, score=0.0, severity=Severity.NONE, reason="not evaluated") for c in Category],
            max_severity=Severity.NONE,
            age_band=AgeBand.A0,
        )
        return ModerationDecision(profile="aggregate", action=DecisionAction.ALLOW, breakdown=empty, reasons=["no inputs"])
    order_action = {DecisionAction.ALLOW: 0, DecisionAction.FLAG: 1, DecisionAction.BLOCK: 2}
    order_age = {AgeBand.A0: 0, AgeBand.A7: 1, AgeBand.A12: 2, AgeBand.A16: 3, AgeBand.A18: 4}

    # Итоговые компоненты
    top_action = max(decisions, key=lambda d: order_action[d.action]).action
    max_age = max(decisions, key=lambda d: order_age[d.breakdown.age_band]).breakdown.age_band

    # Сливаем per_category по максимуму score и severity
    per_map: Dict[Category, CategoryDecision] = {}
    for d in decisions:
        for cd in d.breakdown.per_category:
            prev = per_map.get(cd.category)
            if prev is None:
                per_map[cd.category] = cd
            else:
                better = cd if cd.score >= prev.score else prev
                per_map[cd.category] = CategoryDecision(
                    category=cd.category,
                    score=better.score,
                    severity=better.severity if order_sev(better.severity) >= order_sev(prev.severity) else prev.severity,
                    reason=better.reason,
                )

    breakdown = RatingBreakdown(per_category=list(per_map.values()), max_severity=max(decisions, key=lambda d: order_sev(d.breakdown.max_severity)).breakdown.max_severity, age_band=max_age)
    all_reasons = sorted({r for d in decisions for r in d.reasons})
    all_hints: List[ActionHint] = [h for d in decisions for h in d.hints]
    return ModerationDecision(
        profile="aggregate",
        action=top_action,
        breakdown=breakdown,
        reasons=all_reasons,
        hints=all_hints,
    )

def order_sev(s: Severity) -> int:
    return {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[s.value]

# ------------------------------------------------------------------------------
# Примеры профилей-обёрток (для DI)
# ------------------------------------------------------------------------------

PROFILES: Dict[str, Profile] = {
    "default": DEFAULT_PROFILE,
    "strict_kids": STRICT_KIDS_PROFILE,
    "streaming": STREAMING_PROFILE,
    "social": SOCIAL_PROFILE,
}

def get_profile(name: str) -> Profile:
    return PROFILES.get(name, DEFAULT_PROFILE)

# ------------------------------------------------------------------------------
# Пример использования (докстрока):
# ------------------------------------------------------------------------------
"""
from mythos.moderation.ratings import ContentSample, Signals, CategoryScore, compute_decision, get_profile

sample = ContentSample(
    text="This is adult NSFW content with a gun and damn words",
    lang="en",
    signals=Signals(scores=[
        CategoryScore(category=Category.WEAPONS, score=0.7, source="ml-detector-1"),
        CategoryScore(category=Category.SEXUAL, score=0.6, source="ml-detector-1")
    ])
)

decision = compute_decision(sample, profile=get_profile("default"), request_id="req-123")
print(decision.action, decision.breakdown.age_band, decision.reasons)
for hint in decision.hints:
    print("hint:", hint.kind, hint.details)
"""
