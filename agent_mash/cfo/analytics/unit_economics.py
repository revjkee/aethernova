# agent_mash/cfo/analytics/unit_economics.py
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation, getcontext
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


getcontext().prec = 36


class UnitEconomicsError(RuntimeError):
    pass


class UnitEconomicsValidationError(UnitEconomicsError):
    pass


def _d(v: Any, field: str) -> Decimal:
    try:
        if isinstance(v, Decimal):
            return v
        if isinstance(v, (int, float)):
            return Decimal(str(v))
        if isinstance(v, str):
            s = v.strip()
            if not s:
                raise UnitEconomicsValidationError(f"{field} must be non-empty")
            return Decimal(s)
        raise UnitEconomicsValidationError(f"{field} must be Decimal, int, float, or str")
    except (InvalidOperation, ValueError) as e:
        raise UnitEconomicsValidationError(f"{field} invalid decimal") from e


def _ensure_non_negative_money(v: Any, field: str) -> Decimal:
    x = _d(v, field)
    if x < 0:
        raise UnitEconomicsValidationError(f"{field} must be >= 0")
    return x


def _ensure_non_negative_ratio(v: Any, field: str) -> Decimal:
    x = _d(v, field)
    if x < 0 or x > 1:
        raise UnitEconomicsValidationError(f"{field} must be in [0, 1]")
    return x


def _ensure_positive(v: Any, field: str) -> Decimal:
    x = _d(v, field)
    if x <= 0:
        raise UnitEconomicsValidationError(f"{field} must be > 0")
    return x


def _ensure_int_ge(v: Any, field: str, min_value: int) -> int:
    if not isinstance(v, int):
        raise UnitEconomicsValidationError(f"{field} must be int")
    if v < min_value:
        raise UnitEconomicsValidationError(f"{field} must be >= {min_value}")
    return v


def _q_money(x: Decimal, scale: str = "0.01") -> Decimal:
    return x.quantize(Decimal(scale), rounding=ROUND_HALF_UP)


def _q_ratio(x: Decimal, scale: str = "0.0001") -> Decimal:
    return x.quantize(Decimal(scale), rounding=ROUND_HALF_UP)


def _safe_div(n: Decimal, d: Decimal) -> Decimal:
    if d == 0:
        return Decimal("0")
    return n / d


@dataclass(frozen=True)
class PeriodSpec:
    """
    period: "month" или "year"
    """
    period: str

    @staticmethod
    def validate(period: Any) -> "PeriodSpec":
        if not isinstance(period, str):
            raise UnitEconomicsValidationError("period must be str")
        p = period.strip().lower()
        if p not in {"month", "year"}:
            raise UnitEconomicsValidationError("period must be 'month' or 'year'")
        return PeriodSpec(period=p)

    def per_year_multiplier(self) -> Decimal:
        if self.period == "month":
            return Decimal("12")
        return Decimal("1")

    def per_month_multiplier(self) -> Decimal:
        if self.period == "year":
            return Decimal("1") / Decimal("12")
        return Decimal("1")


@dataclass(frozen=True)
class AcquisitionInputs:
    """
    Параметры привлечения.
    marketing_spend: затраты на маркетинг за период
    sales_spend: затраты на продажи за период
    new_customers: новые клиенты за период
    """
    marketing_spend: Decimal
    sales_spend: Decimal
    new_customers: int

    @staticmethod
    def validate(marketing_spend: Any, sales_spend: Any, new_customers: Any) -> "AcquisitionInputs":
        ms = _ensure_non_negative_money(marketing_spend, "marketing_spend")
        ss = _ensure_non_negative_money(sales_spend, "sales_spend")
        nc = _ensure_int_ge(new_customers, "new_customers", 0)
        return AcquisitionInputs(marketing_spend=ms, sales_spend=ss, new_customers=nc)


@dataclass(frozen=True)
class RevenueInputs:
    """
    Параметры выручки.
    price: средняя цена (ARPU до скидок, если usage модель можно подать среднее)
    discount_rate: доля скидки [0..1]
    refunds_rate: доля возвратов [0..1]
    """
    price: Decimal
    discount_rate: Decimal
    refunds_rate: Decimal

    @staticmethod
    def validate(price: Any, discount_rate: Any = "0", refunds_rate: Any = "0") -> "RevenueInputs":
        pr = _ensure_non_negative_money(price, "price")
        dr = _ensure_non_negative_ratio(discount_rate, "discount_rate")
        rr = _ensure_non_negative_ratio(refunds_rate, "refunds_rate")
        return RevenueInputs(price=pr, discount_rate=dr, refunds_rate=rr)

    def net_price(self) -> Decimal:
        return self.price * (Decimal("1") - self.discount_rate) * (Decimal("1") - self.refunds_rate)


@dataclass(frozen=True)
class CostInputs:
    """
    Переменные затраты на 1 клиента за период и доли комиссий.
    cogs_per_customer: прямые переменные затраты (себестоимость) на клиента за период
    payment_fee_rate: комиссия платёжки [0..1] от выручки
    fulfillment_per_customer: доставка, поддержка, иные переменные
    """
    cogs_per_customer: Decimal
    payment_fee_rate: Decimal
    fulfillment_per_customer: Decimal

    @staticmethod
    def validate(
        cogs_per_customer: Any = "0",
        payment_fee_rate: Any = "0",
        fulfillment_per_customer: Any = "0",
    ) -> "CostInputs":
        cogs = _ensure_non_negative_money(cogs_per_customer, "cogs_per_customer")
        pfr = _ensure_non_negative_ratio(payment_fee_rate, "payment_fee_rate")
        fpc = _ensure_non_negative_money(fulfillment_per_customer, "fulfillment_per_customer")
        return CostInputs(cogs_per_customer=cogs, payment_fee_rate=pfr, fulfillment_per_customer=fpc)


@dataclass(frozen=True)
class RetentionInputs:
    """
    Параметры удержания.
    churn_rate: отток за период [0..1]
    retention_rate: удержание за период [0..1]
    Можно задать либо churn_rate, либо retention_rate. Если заданы оба, они должны быть согласованы.
    """
    churn_rate: Decimal
    retention_rate: Decimal

    @staticmethod
    def validate(churn_rate: Any = None, retention_rate: Any = None) -> "RetentionInputs":
        if churn_rate is None and retention_rate is None:
            raise UnitEconomicsValidationError("either churn_rate or retention_rate must be provided")

        cr = None if churn_rate is None else _ensure_non_negative_ratio(churn_rate, "churn_rate")
        rr = None if retention_rate is None else _ensure_non_negative_ratio(retention_rate, "retention_rate")

        if cr is None:
            cr = Decimal("1") - rr
        if rr is None:
            rr = Decimal("1") - cr

        if (cr + rr).copy_abs() == 0:
            raise UnitEconomicsValidationError("invalid retention inputs")

        if (cr + rr) != Decimal("1"):
            if (cr + rr - Decimal("1")).copy_abs() > Decimal("0.0001"):
                raise UnitEconomicsValidationError("churn_rate and retention_rate are inconsistent")

        return RetentionInputs(churn_rate=cr, retention_rate=rr)


@dataclass(frozen=True)
class UnitEconomicsInputs:
    """
    Главный контейнер входных данных unit economics за выбранный период.
    """
    period: PeriodSpec
    acquisition: AcquisitionInputs
    revenue: RevenueInputs
    costs: CostInputs
    retention: RetentionInputs
    gross_margin_floor: Decimal = Decimal("0")

    @staticmethod
    def validate(
        period: Any,
        marketing_spend: Any,
        sales_spend: Any,
        new_customers: Any,
        price: Any,
        discount_rate: Any = "0",
        refunds_rate: Any = "0",
        cogs_per_customer: Any = "0",
        payment_fee_rate: Any = "0",
        fulfillment_per_customer: Any = "0",
        churn_rate: Any = None,
        retention_rate: Any = None,
        gross_margin_floor: Any = "0",
    ) -> "UnitEconomicsInputs":
        p = PeriodSpec.validate(period)
        acq = AcquisitionInputs.validate(marketing_spend, sales_spend, new_customers)
        rev = RevenueInputs.validate(price, discount_rate, refunds_rate)
        cst = CostInputs.validate(cogs_per_customer, payment_fee_rate, fulfillment_per_customer)
        ret = RetentionInputs.validate(churn_rate=churn_rate, retention_rate=retention_rate)
        gmf = _ensure_non_negative_ratio(gross_margin_floor, "gross_margin_floor")
        return UnitEconomicsInputs(
            period=p,
            acquisition=acq,
            revenue=rev,
            costs=cst,
            retention=ret,
            gross_margin_floor=gmf,
        )


@dataclass(frozen=True)
class UnitEconomicsResult:
    """
    Итоговый отчёт unit economics.
    Все значения Decimal, пригодны для сериализации.
    """
    period: str
    net_price: Decimal
    variable_cost_per_customer: Decimal
    gross_profit_per_customer: Decimal
    gross_margin: Decimal

    cac_blended: Decimal
    cac_marketing: Decimal
    cac_sales: Decimal

    arpu: Decimal
    contribution_profit_per_customer: Decimal
    contribution_margin: Decimal

    churn_rate: Decimal
    retention_rate: Decimal

    ltv_simple: Decimal
    ltv_gross: Decimal
    ltv_contribution: Decimal

    payback_periods: Decimal
    breakeven_customers: Decimal

    assumptions: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        def dec(x: Decimal) -> str:
            return format(x, "f")

        return {
            "period": self.period,
            "net_price": dec(self.net_price),
            "variable_cost_per_customer": dec(self.variable_cost_per_customer),
            "gross_profit_per_customer": dec(self.gross_profit_per_customer),
            "gross_margin": dec(self.gross_margin),
            "cac_blended": dec(self.cac_blended),
            "cac_marketing": dec(self.cac_marketing),
            "cac_sales": dec(self.cac_sales),
            "arpu": dec(self.arpu),
            "contribution_profit_per_customer": dec(self.contribution_profit_per_customer),
            "contribution_margin": dec(self.contribution_margin),
            "churn_rate": dec(self.churn_rate),
            "retention_rate": dec(self.retention_rate),
            "ltv_simple": dec(self.ltv_simple),
            "ltv_gross": dec(self.ltv_gross),
            "ltv_contribution": dec(self.ltv_contribution),
            "payback_periods": dec(self.payback_periods),
            "breakeven_customers": dec(self.breakeven_customers),
            "assumptions": dict(self.assumptions),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class UnitEconomicsEngine:
    """
    Промышленный вычислитель unit economics.
    Математика детерминирована, входы строго валидируются.
    """

    def __init__(self, money_scale: str = "0.01", ratio_scale: str = "0.0001") -> None:
        self.money_scale = money_scale
        self.ratio_scale = ratio_scale

    def compute(self, inp: UnitEconomicsInputs) -> UnitEconomicsResult:
        acq = inp.acquisition
        rev = inp.revenue
        cst = inp.costs
        ret = inp.retention

        net_price = rev.net_price()
        if net_price < 0:
            raise UnitEconomicsValidationError("net price must be >= 0")

        arpu = net_price

        payment_fee = arpu * cst.payment_fee_rate
        variable_cost = cst.cogs_per_customer + cst.fulfillment_per_customer + payment_fee
        gross_profit = arpu - (cst.cogs_per_customer + payment_fee)

        gross_margin = _safe_div(gross_profit, arpu)
        if arpu == 0:
            gross_margin = Decimal("0")

        if gross_margin < inp.gross_margin_floor:
            raise UnitEconomicsValidationError("gross margin below configured floor")

        contribution_profit = arpu - variable_cost
        contribution_margin = _safe_div(contribution_profit, arpu)
        if arpu == 0:
            contribution_margin = Decimal("0")

        total_spend = acq.marketing_spend + acq.sales_spend
        cac_blended = _safe_div(total_spend, Decimal(acq.new_customers))
        cac_marketing = _safe_div(acq.marketing_spend, Decimal(acq.new_customers))
        cac_sales = _safe_div(acq.sales_spend, Decimal(acq.new_customers))

        churn_rate = ret.churn_rate
        retention_rate = ret.retention_rate

        ltv_simple = Decimal("0")
        if churn_rate > 0:
            ltv_simple = arpu / churn_rate

        ltv_gross = Decimal("0")
        ltv_contribution = Decimal("0")
        if churn_rate > 0:
            ltv_gross = gross_profit / churn_rate
            ltv_contribution = contribution_profit / churn_rate

        payback = Decimal("0")
        if contribution_profit > 0:
            payback = cac_blended / contribution_profit

        breakeven = Decimal("0")
        if contribution_profit > 0:
            breakeven = total_spend / contribution_profit

        assumptions: Dict[str, Any] = {
            "period": inp.period.period,
            "ltv_method": "geometric_expected_lifetime_approx",
            "expected_lifetime_periods": format(_safe_div(Decimal("1"), churn_rate), "f") if churn_rate > 0 else "0",
            "notes": "LTV computed using per-period churn approximation; ensure churn_rate matches the same period as ARPU and costs",
        }

        return UnitEconomicsResult(
            period=inp.period.period,
            net_price=_q_money(net_price, self.money_scale),
            variable_cost_per_customer=_q_money(variable_cost, self.money_scale),
            gross_profit_per_customer=_q_money(gross_profit, self.money_scale),
            gross_margin=_q_ratio(gross_margin, self.ratio_scale),
            cac_blended=_q_money(cac_blended, self.money_scale),
            cac_marketing=_q_money(cac_marketing, self.money_scale),
            cac_sales=_q_money(cac_sales, self.money_scale),
            arpu=_q_money(arpu, self.money_scale),
            contribution_profit_per_customer=_q_money(contribution_profit, self.money_scale),
            contribution_margin=_q_ratio(contribution_margin, self.ratio_scale),
            churn_rate=_q_ratio(churn_rate, self.ratio_scale),
            retention_rate=_q_ratio(retention_rate, self.ratio_scale),
            ltv_simple=_q_money(ltv_simple, self.money_scale),
            ltv_gross=_q_money(ltv_gross, self.money_scale),
            ltv_contribution=_q_money(ltv_contribution, self.money_scale),
            payback_periods=_q_ratio(payback, self.ratio_scale),
            breakeven_customers=_q_ratio(breakeven, self.ratio_scale),
            assumptions=assumptions,
        )


@dataclass(frozen=True)
class Scenario:
    """
    Сценарный расчёт: модификации базовых входов.
    """
    name: str
    overrides: Dict[str, Any]

    @staticmethod
    def validate(name: Any, overrides: Any) -> "Scenario":
        if not isinstance(name, str) or not name.strip():
            raise UnitEconomicsValidationError("scenario name must be non-empty str")
        if not isinstance(overrides, dict):
            raise UnitEconomicsValidationError("scenario overrides must be dict")
        return Scenario(name=name.strip(), overrides=dict(overrides))


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    result: UnitEconomicsResult

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "result": self.result.to_dict()}


def apply_overrides(base: UnitEconomicsInputs, overrides: Mapping[str, Any]) -> UnitEconomicsInputs:
    """
    Безопасное применение overrides только к известным полям.
    Не допускает произвольных атрибутов.
    """
    allowed = {
        "period",
        "marketing_spend",
        "sales_spend",
        "new_customers",
        "price",
        "discount_rate",
        "refunds_rate",
        "cogs_per_customer",
        "payment_fee_rate",
        "fulfillment_per_customer",
        "churn_rate",
        "retention_rate",
        "gross_margin_floor",
    }

    for k in overrides.keys():
        if k not in allowed:
            raise UnitEconomicsValidationError("override key not allowed")

    period = overrides.get("period", base.period.period)

    marketing_spend = overrides.get("marketing_spend", base.acquisition.marketing_spend)
    sales_spend = overrides.get("sales_spend", base.acquisition.sales_spend)
    new_customers = overrides.get("new_customers", base.acquisition.new_customers)

    price = overrides.get("price", base.revenue.price)
    discount_rate = overrides.get("discount_rate", base.revenue.discount_rate)
    refunds_rate = overrides.get("refunds_rate", base.revenue.refunds_rate)

    cogs_per_customer = overrides.get("cogs_per_customer", base.costs.cogs_per_customer)
    payment_fee_rate = overrides.get("payment_fee_rate", base.costs.payment_fee_rate)
    fulfillment_per_customer = overrides.get("fulfillment_per_customer", base.costs.fulfillment_per_customer)

    churn_rate = overrides.get("churn_rate", base.retention.churn_rate)
    retention_rate = overrides.get("retention_rate", base.retention.retention_rate)

    gross_margin_floor = overrides.get("gross_margin_floor", base.gross_margin_floor)

    return UnitEconomicsInputs.validate(
        period=period,
        marketing_spend=marketing_spend,
        sales_spend=sales_spend,
        new_customers=new_customers,
        price=price,
        discount_rate=discount_rate,
        refunds_rate=refunds_rate,
        cogs_per_customer=cogs_per_customer,
        payment_fee_rate=payment_fee_rate,
        fulfillment_per_customer=fulfillment_per_customer,
        churn_rate=churn_rate,
        retention_rate=retention_rate,
        gross_margin_floor=gross_margin_floor,
    )


def compute_scenarios(
    base: UnitEconomicsInputs,
    scenarios: Sequence[Scenario],
    engine: Optional[UnitEconomicsEngine] = None,
) -> Tuple[ScenarioResult, ...]:
    eng = engine or UnitEconomicsEngine()
    out: list[ScenarioResult] = []
    for sc in scenarios:
        inp = apply_overrides(base, sc.overrides)
        res = eng.compute(inp)
        out.append(ScenarioResult(name=sc.name, result=res))
    return tuple(out)
