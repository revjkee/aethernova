# cybersecurity-core/cybersecurity/vuln/risk_scoring.py
from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, root_validator, validator


# =============================== CVSS v3.1 Parser ===============================

class CvssVectorError(ValueError):
    """Ошибка парсинга/валидации вектора CVSS."""


class CvssV3(BaseModel):
    """
    Минимально необходимый парсер и вычислитель CVSS v3.1 Base Score.
    Поддерживает корректную формулу, зависимости PR от Scope и округление round_up1.
    """
    # Metrics
    AV: str  # Attack Vector: N, A, L, P
    AC: str  # Attack Complexity: L, H
    PR: str  # Privileges Required: N, L, H
    UI: str  # User Interaction: N, R
    S: str   # Scope: U, C
    C: str   # Confidentiality: H, L, N
    I: str   # Integrity: H, L, N
    A: str   # Availability: H, L, N

    # ---- Parsing ----
    @staticmethod
    def parse(vector: str) -> "CvssV3":
        """
        Ожидается формат: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        (допускается CVSS:3.0, значения метрик одинаковы для baseScore).
        """
        try:
            head, *parts = vector.strip().split("/")
            if not head.startswith("CVSS:3."):
                raise CvssVectorError("Требуется CVSS:3.x вектор")
            kv: Dict[str, str] = {}
            for p in parts:
                k, v = p.split(":")
                kv[k] = v
            required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
            for r in required:
                if r not in kv:
                    raise CvssVectorError(f"Отсутствует метрика {r}")
            return CvssV3(**{k: kv[k] for k in required})
        except Exception as e:
            raise CvssVectorError(f"Неверный вектор CVSS: {e}")

    # ---- Weights ----
    @property
    def _weights(self) -> Dict[str, float]:
        AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        AC_MAP = {"L": 0.77, "H": 0.44}
        UI_MAP = {"N": 0.85, "R": 0.62}
        C_MAP = {"N": 0.0, "L": 0.22, "H": 0.56}
        I_MAP = C_MAP
        A_MAP = C_MAP
        if self.S not in {"U", "C"}:
            raise CvssVectorError("S должен быть U или C")
        # PR зависит от S
        if self.S == "U":
            PR_MAP = {"N": 0.85, "L": 0.62, "H": 0.27}
        else:  # Scope=Changed
            PR_MAP = {"N": 0.85, "L": 0.68, "H": 0.5}
        try:
            return {
                "AV": AV_MAP[self.AV],
                "AC": AC_MAP[self.AC],
                "PR": PR_MAP[self.PR],
                "UI": UI_MAP[self.UI],
                "C": C_MAP[self.C],
                "I": I_MAP[self.I],
                "A": A_MAP[self.A],
            }
        except KeyError as e:
            raise CvssVectorError(f"Недопустимое значение метрики: {e}")

    # ---- Math ----
    @staticmethod
    def _round_up1(x: float) -> float:
        # Специфичное округление CVSS: вверх до одного знака после запятой
        return math.ceil(x * 10.0) / 10.0

    def base_components(self) -> Tuple[float, float]:
        """
        Возвращает (base_score, impact_subscore).
        impact_subscore — нормированная часть до 10 (как в CVSS), округление применяется к base_score.
        """
        w = self._weights
        # Exploitability
        exploitability = 8.22 * w["AV"] * w["AC"] * w["PR"] * w["UI"]
        # Impact
        impact = 1.0 - (1.0 - w["C"]) * (1.0 - w["I"]) * (1.0 - w["A"])
        if self.S == "U":
            impact_sub = 6.42 * impact
            base = min(impact_sub + exploitability, 10.0)
        else:
            impact_sub = 7.52 * (impact - 0.029) - 3.25 * pow((impact - 0.02), 15)
            base = min(1.08 * (impact_sub + exploitability), 10.0)
        base = 0.0 if impact <= 0 else self._round_up1(base)
        # impact_sub возвращаем в диапазоне [0, 10] без округления (для дальнейшей нормализации)
        impact_sub = max(0.0, min(10.0, impact_sub))
        return base, impact_sub


# ============================ Конфигурация весов ================================

class RiskWeights(BaseModel):
    """
    Веса компонентов риска. Все значения в [0..1]. Сумма блоков LIKELIHOOD и IMPACT — не обязана =1;
    итоговая формула использует alpha/beta/gamma.
    """
    # Likelihood weights
    w_epss: float = 0.30
    w_exploit_observed: float = 0.25
    w_exposure: float = 0.20
    w_kev: float = 0.15
    w_age: float = 0.05
    w_internet: float = 0.05

    # Impact blending weights
    w_cvss_base_to_impact: float = 0.6   # вклад baseScore в Impact
    w_cvss_impact_sub: float = 0.4       # вклад impact_subscore в Impact

    # Business/context impact multipliers
    k_asset_criticality: float = 0.10    # на шаг критичности (1..5) относительно 3
    k_data_sensitivity: float = 0.10     # на шаг чувствительности (0..3)

    # Mitigations
    k_controls_max_reduction: float = 0.8  # максимум снижения Likelihood за счет контролей/детектов

    # Risk composition
    alpha_impact: float = 0.35
    beta_likelihood: float = 0.35
    gamma_synergy: float = 0.30

    @validator("*")
    def _clamp(cls, v: float) -> float:
        if isinstance(v, float):
            return max(0.0, min(1.0, v))
        return v


# ================================ Модели ввода =================================

class RiskInput(BaseModel):
    """
    Данные для оценки одного инцидента/уязвимости в конкретном контексте актива.
    """
    cve_id: Optional[str] = Field(None, description="Напр. CVE-2024-XXXXX")
    title: Optional[str] = None

    # CVSS
    cvss_v3_vector: Optional[str] = Field(None, description="Строка CVSS:3.1/..")
    cvss_base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_impact_subscore: Optional[float] = Field(None, ge=0.0, le=10.0)

    # Exploitability
    epss: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS score [0..1]")
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_kev: bool = False  # присутствие в CISA KEV
    exploit_observed: bool = False  # подтвержденная эксплуатация в среде/в дикой природе

    # Exposure & mitigations
    internet_exposed: bool = False
    exposure_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Если не задано — выводится из internet_exposed и контролей"
    )
    controls_strength: float = Field(0.0, ge=0.0, le=1.0, description="Эффективность превентивных контролей (0..1)")
    detection_coverage: float = Field(0.0, ge=0.0, le=1.0, description="Покрытие детекта/алертов (0..1)")

    # Business context
    asset_criticality: int = Field(3, ge=1, le=5, description="Бизнес-критичность актива (1..5)")
    data_sensitivity: int = Field(0, ge=0, le=3, description="Чувствительность данных (0..3)")

    # Time
    age_days: Optional[int] = Field(None, ge=0, description="Возраст уязвимости от публикации/последнего апдейта")

    patch_available: Optional[bool] = None

    @root_validator
    def _ensure_cvss_source(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        v = values.get("cvss_v3_vector")
        b = values.get("cvss_base_score")
        if not v and b is None:
            raise ValueError("Нужно указать cvss_v3_vector или cvss_base_score")
        return values


class RiskResult(BaseModel):
    risk_score: float = Field(..., description="Итоговый риск [0..100]")
    impact: float = Field(..., description="Компонент воздействия [0..1]")
    likelihood: float = Field(..., description="Компонент вероятности [0..1]")
    priority: str = Field(..., description="P1|P2|P3|P4|P5")
    sla_days: Optional[int] = Field(None, description="Рекомендуемый срок ремедиации в днях")
    rationale: Dict[str, Any] = Field(default_factory=dict)


# ================================ Утилиты ======================================

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


@lru_cache(maxsize=4096)
def _cvss_from_vector(vector: str) -> Tuple[float, float]:
    """
    Возвращает (base_score, impact_subscore) по вектору CVSS v3.x.
    """
    cv = CvssV3.parse(vector)
    return cv.base_components()


def _derive_exposure(input: RiskInput) -> float:
    """
    Если exposure_score не задан, оцениваем по интернет-экспозиции и контролям.
    """
    if input.exposure_score is not None:
        return _clip01(input.exposure_score)
    base = 0.7 if input.internet_exposed else 0.3
    # Чем сильнее контроли, тем ниже экспозиция
    mitig = 0.5 * input.controls_strength + 0.5 * input.detection_coverage
    return _clip01(base * (1.0 - 0.6 * mitig))


def _age_component(age_days: Optional[int]) -> float:
    if age_days is None:
        return 0.3  # консервативная середина, если неизвестно
    # Линейная нормализация: 0..365 -> 0..1 (cap)
    return _clip01(age_days / 365.0)


def _impact_component(
    cvss_base: float,
    impact_sub: Optional[float],
    weights: RiskWeights,
    asset_criticality: int,
    data_sensitivity: int,
) -> float:
    # Нормируем CVSS к [0..1]
    base_norm = _clip01(cvss_base / 10.0)
    sub_norm = _clip01((impact_sub or cvss_base) / 10.0)
    # Блендинг технического импакта
    tech = _clip01(weights.w_cvss_base_to_impact * base_norm + weights.w_cvss_impact_sub * sub_norm)
    # Бизнес-мультипликаторы
    crit_delta = asset_criticality - 3  # -2..+2
    biz = 1.0 + weights.k_asset_criticality * crit_delta + weights.k_data_sensitivity * data_sensitivity
    # Ограничим мультипликатор разумно (до 1.8)
    biz = max(0.5, min(1.8, biz))
    return _clip01(tech * biz)


def _likelihood_component(input: RiskInput, weights: RiskWeights) -> float:
    epss = input.epss if input.epss is not None else 0.05
    kev = 1.0 if input.is_kev else 0.0
    exploit = 1.0 if input.exploit_observed else 0.0
    exposure = _derive_exposure(input)
    age = _age_component(input.age_days)
    internet = 1.0 if input.internet_exposed else 0.0

    raw = (
        weights.w_epss * epss
        + weights.w_exploit_observed * exploit
        + weights.w_exposure * exposure
        + weights.w_kev * kev
        + weights.w_age * age
        + weights.w_internet * internet
    )
    # Нормируем по сумме весов (все заданы так, что суммарно 1.0 по умолчанию)
    sum_w = (
        weights.w_epss
        + weights.w_exploit_observed
        + weights.w_exposure
        + weights.w_kev
        + weights.w_age
        + weights.w_internet
    ) or 1.0
    raw = _clip01(raw / sum_w)

    # Снижение вероятности за счет контролей/детектов
    mitig = 0.5 * input.controls_strength + 0.5 * input.detection_coverage
    mitig = _clip01(mitig)
    reduced = raw * (1.0 - weights.k_controls_max_reduction * mitig)
    return _clip01(reduced)


def _priority_and_sla(score: float, input: RiskInput) -> Tuple[str, Optional[int]]:
    """
    Маппинг на приоритет и SLA. Правила жестко зафиксированы и детерминированы.
    """
    # Правила эскалации P1 (очевидки)
    if (
        score >= 85.0
        or (input.is_kev and input.internet_exposed and ((input.epss or 0.0) >= 0.5 or input.exploit_observed))
    ):
        return "P1", (1 if input.internet_exposed else 3)

    if score >= 70.0:
        return "P2", (7 if input.internet_exposed else 14)

    if score >= 50.0:
        return "P3", (30 if input.internet_exposed else 60)

    if score >= 25.0:
        return "P4", (90 if input.internet_exposed else 180)

    return "P5", None


# ============================== Публичный API ==================================

def score_vulnerability(input: RiskInput, weights: Optional[RiskWeights] = None) -> RiskResult:
    """
    Рассчитать риск для одной уязвимости/находки в контексте конкретного актива.
    Возвращает RiskResult с компонентами и расшифровкой.
    """
    w = weights or RiskWeights()

    # CVSS: берем baseScore напрямую или считаем из вектора
    if input.cvss_base_score is not None:
        base = float(input.cvss_base_score)
        impact_sub = input.cvss_impact_subscore
    else:
        base, impact_sub = _cvss_from_vector(input.cvss_v3_vector or "")

    impact = _impact_component(
        cvss_base=base,
        impact_sub=impact_sub,
        weights=w,
        asset_criticality=input.asset_criticality,
        data_sensitivity=input.data_sensitivity,
    )
    likelihood = _likelihood_component(input, w)

    # Итоговый риск с синергией
    synergy = impact * likelihood
    risk = 100.0 * (w.alpha_impact * impact + w.beta_likelihood * likelihood + w.gamma_synergy * synergy)
    risk = round(min(100.0, max(0.0, risk)), 1)

    prio, sla = _priority_and_sla(risk, input)

    rationale: Dict[str, Any] = {
        "cve_id": input.cve_id,
        "title": input.title,
        "cvss_base_score": base,
        "cvss_impact_subscore": impact_sub,
        "epss": input.epss,
        "is_kev": input.is_kev,
        "exploit_observed": input.exploit_observed,
        "internet_exposed": input.internet_exposed,
        "exposure_score": _derive_exposure(input),
        "controls_strength": input.controls_strength,
        "detection_coverage": input.detection_coverage,
        "asset_criticality": input.asset_criticality,
        "data_sensitivity": input.data_sensitivity,
        "age_days": input.age_days,
        "weights": w.dict(),
        "synergy": round(synergy, 4),
    }

    # Дополнительная разметка
    if input.patch_available is True:
        rationale["note_patch"] = "Патч доступен, задержка ремедиации повышает риск остаточного окна."

    return RiskResult(
        risk_score=risk,
        impact=round(impact, 4),
        likelihood=round(likelihood, 4),
        priority=prio,
        sla_days=sla,
        rationale=rationale,
    )


class PortfolioResult(BaseModel):
    total: int
    by_priority: Dict[str, int]
    avg_risk: float
    max_risk: float
    top: List[RiskResult]


def rank_findings(
    items: List[RiskInput],
    weights: Optional[RiskWeights] = None,
    top_k: int = 50,
) -> PortfolioResult:
    """
    Оценить портфель находок, вернуть агрегаты и топ-N по риску.
    """
    results: List[RiskResult] = [score_vulnerability(i, weights) for i in items]
    results.sort(key=lambda r: r.risk_score, reverse=True)
    by_priority: Dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
    s = 0.0
    m = 0.0
    for r in results:
        by_priority[r.priority] += 1
        s += r.risk_score
        if r.risk_score > m:
            m = r.risk_score
    avg = round((s / len(results)) if results else 0.0, 2)
    return PortfolioResult(
        total=len(results),
        by_priority=by_priority,
        avg_risk=avg,
        max_risk=round(m, 1),
        top=results[: max(0, top_k)],
    )


# ================================ Пример (doc) =================================
"""
Пример использования:

from cybersecurity.vuln.risk_scoring import RiskInput, score_vulnerability

inp = RiskInput(
    cve_id="CVE-2024-XXXX",
    cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    epss=0.92,
    is_kev=True,
    exploit_observed=False,
    internet_exposed=True,
    controls_strength=0.2,
    detection_coverage=0.3,
    asset_criticality=5,
    data_sensitivity=2,
    age_days=120,
    patch_available=True,
)

res = score_vulnerability(inp)
print(res.json(indent=2, ensure_ascii=False))

Гарантии:
- Детерминированный расчет; нет внешних запросов.
- Корректное вычисление CVSS v3.1 Base (формула и округление по спецификации).
- Риск входит в [0..100], компоненты — в [0..1].
- Ясная расшифровка факторов в поле rationale.
"""
