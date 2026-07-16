# agent_mash/cfo/analytics/scenarios.py
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# ============================================================
# Errors
# ============================================================
class ScenarioError(RuntimeError):
    """Base error for CFO scenario analytics."""


class ValidationError(ScenarioError):
    """Invalid inputs, illegal state."""


class CalculationError(ScenarioError):
    """Numeric issues (e.g., IRR not converging)."""


# ============================================================
# Helpers
# ============================================================
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _safe_float(x: Any, *, name: str) -> float:
    try:
        v = float(x)
    except Exception as e:
        raise ValidationError(f"{name} must be a number") from e
    if math.isnan(v) or math.isinf(v):
        raise ValidationError(f"{name} must be finite")
    return v


def _round(v: float, nd: int = 6) -> float:
    return float(f"{v:.{nd}f}")


def _fingerprint(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ============================================================
# Time series / assumptions
# ============================================================
@dataclass(frozen=True, slots=True)
class TimeGrid:
    """
    Discrete time grid.
    periods: number of periods (>=1)
    period_years: fraction of year per period (e.g., 1/12 for monthly)
    """
    periods: int
    period_years: float = 1.0 / 12.0

    def __post_init__(self) -> None:
        if not isinstance(self.periods, int) or self.periods <= 0:
            raise ValidationError("TimeGrid.periods must be a positive int")
        py = _safe_float(self.period_years, name="TimeGrid.period_years")
        if py <= 0:
            raise ValidationError("TimeGrid.period_years must be > 0")
        object.__setattr__(self, "period_years", py)

    def years(self) -> float:
        return self.periods * self.period_years


@dataclass(frozen=True, slots=True)
class Assumptions:
    """
    Core CFO model inputs.

    All rates are per-year decimals (e.g., 0.12).
    Growth is applied per period, derived from annual growth and period_years.
    """
    currency: str
    grid: TimeGrid

    start_revenue: float
    revenue_cagr_annual: float

    gross_margin: float  # 0..1
    opex_fixed_per_period: float
    opex_variable_ratio: float  # share of revenue, 0..1

    capex_per_period: float
    depreciation_years: float  # straight-line, if >0
    working_capital_ratio: float  # share of revenue locked in WC, 0..1

    tax_rate: float  # 0..1
    discount_rate_annual: float  # WACC, 0..1+

    debt_principal: float = 0.0
    debt_rate_annual: float = 0.0
    debt_amortization_periods: int = 0  # if 0 -> bullet

    def __post_init__(self) -> None:
        if not self.currency or not isinstance(self.currency, str):
            raise ValidationError("currency must be a non-empty string")

        sr = _safe_float(self.start_revenue, name="start_revenue")
        if sr < 0:
            raise ValidationError("start_revenue must be >= 0")

        cagr = _safe_float(self.revenue_cagr_annual, name="revenue_cagr_annual")

        gm = _safe_float(self.gross_margin, name="gross_margin")
        if not (0.0 <= gm <= 1.0):
            raise ValidationError("gross_margin must be in [0,1]")

        of = _safe_float(self.opex_fixed_per_period, name="opex_fixed_per_period")
        if of < 0:
            raise ValidationError("opex_fixed_per_period must be >= 0")

        ov = _safe_float(self.opex_variable_ratio, name="opex_variable_ratio")
        if not (0.0 <= ov <= 1.0):
            raise ValidationError("opex_variable_ratio must be in [0,1]")

        cx = _safe_float(self.capex_per_period, name="capex_per_period")
        if cx < 0:
            raise ValidationError("capex_per_period must be >= 0")

        depy = _safe_float(self.depreciation_years, name="depreciation_years")
        if depy < 0:
            raise ValidationError("depreciation_years must be >= 0")

        wc = _safe_float(self.working_capital_ratio, name="working_capital_ratio")
        if not (0.0 <= wc <= 1.0):
            raise ValidationError("working_capital_ratio must be in [0,1]")

        tx = _safe_float(self.tax_rate, name="tax_rate")
        if not (0.0 <= tx <= 1.0):
            raise ValidationError("tax_rate must be in [0,1]")

        dr = _safe_float(self.discount_rate_annual, name="discount_rate_annual")
        if dr < -0.99:
            raise ValidationError("discount_rate_annual too low")

        dp = _safe_float(self.debt_principal, name="debt_principal")
        if dp < 0:
            raise ValidationError("debt_principal must be >= 0")

        drr = _safe_float(self.debt_rate_annual, name="debt_rate_annual")
        if drr < 0:
            raise ValidationError("debt_rate_annual must be >= 0")

        dap = int(self.debt_amortization_periods)
        if dap < 0:
            raise ValidationError("debt_amortization_periods must be >= 0")

        object.__setattr__(self, "start_revenue", sr)
        object.__setattr__(self, "revenue_cagr_annual", cagr)
        object.__setattr__(self, "gross_margin", gm)
        object.__setattr__(self, "opex_fixed_per_period", of)
        object.__setattr__(self, "opex_variable_ratio", ov)
        object.__setattr__(self, "capex_per_period", cx)
        object.__setattr__(self, "depreciation_years", depy)
        object.__setattr__(self, "working_capital_ratio", wc)
        object.__setattr__(self, "tax_rate", tx)
        object.__setattr__(self, "discount_rate_annual", dr)
        object.__setattr__(self, "debt_principal", dp)
        object.__setattr__(self, "debt_rate_annual", drr)
        object.__setattr__(self, "debt_amortization_periods", dap)


# ============================================================
# Scenario definitions
# ============================================================
@dataclass(frozen=True, slots=True)
class Shock:
    """
    Parametric shock applied to base assumptions.

    Supported keys:
      - revenue_cagr_annual_delta
      - gross_margin_delta
      - opex_fixed_per_period_delta
      - opex_variable_ratio_delta
      - capex_per_period_delta
      - working_capital_ratio_delta
      - tax_rate_delta
      - discount_rate_annual_delta
      - debt_rate_annual_delta
    """
    key: str
    delta: float

    def __post_init__(self) -> None:
        if not self.key or not isinstance(self.key, str):
            raise ValidationError("Shock.key must be non-empty string")
        d = _safe_float(self.delta, name="Shock.delta")
        object.__setattr__(self, "delta", d)


@dataclass(frozen=True, slots=True)
class Scenario:
    """
    Scenario = base assumptions + shocks + optional overrides.
    """
    scenario_id: str
    title: str
    base: Assumptions
    shocks: Tuple[Shock, ...] = ()
    overrides: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.scenario_id or not isinstance(self.scenario_id, str):
            raise ValidationError("scenario_id must be non-empty string")
        if not self.title or not isinstance(self.title, str):
            raise ValidationError("title must be non-empty string")


# ============================================================
# Results
# ============================================================
@dataclass(frozen=True, slots=True)
class FinancialSeries:
    revenue: Tuple[float, ...]
    gross_profit: Tuple[float, ...]
    opex: Tuple[float, ...]
    ebitda: Tuple[float, ...]
    depreciation: Tuple[float, ...]
    ebit: Tuple[float, ...]
    taxes: Tuple[float, ...]
    nopat: Tuple[float, ...]
    capex: Tuple[float, ...]
    delta_working_capital: Tuple[float, ...]
    free_cash_flow: Tuple[float, ...]
    interest: Tuple[float, ...]
    principal_repayment: Tuple[float, ...]
    cash_flow_to_equity: Tuple[float, ...]


@dataclass(frozen=True, slots=True)
class Metrics:
    npv: float
    irr: Optional[float]
    mirr: Optional[float]
    payback_periods: Optional[int]
    payback_years: Optional[float]
    dscr_min: Optional[float]
    dscr_avg: Optional[float]
    fcf_total: float
    equity_cf_total: float


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario_id: str
    title: str
    ts_utc: str
    assumptions_effective: Mapping[str, Any]
    fingerprint: str
    series: FinancialSeries
    metrics: Metrics

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "ts_utc": self.ts_utc,
            "fingerprint": self.fingerprint,
            "assumptions_effective": dict(self.assumptions_effective),
            "metrics": dataclasses.asdict(self.metrics),
            "series": {
                "revenue": list(self.series.revenue),
                "gross_profit": list(self.series.gross_profit),
                "opex": list(self.series.opex),
                "ebitda": list(self.series.ebitda),
                "depreciation": list(self.series.depreciation),
                "ebit": list(self.series.ebit),
                "taxes": list(self.series.taxes),
                "nopat": list(self.series.nopat),
                "capex": list(self.series.capex),
                "delta_working_capital": list(self.series.delta_working_capital),
                "free_cash_flow": list(self.series.free_cash_flow),
                "interest": list(self.series.interest),
                "principal_repayment": list(self.series.principal_repayment),
                "cash_flow_to_equity": list(self.series.cash_flow_to_equity),
            },
        }

    def export_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=indent)


# ============================================================
# Engine
# ============================================================
class ScenarioEngine:
    """
    Industrial scenario engine:
    - resolves effective assumptions
    - builds financial projection on discrete grid
    - computes investment and credit metrics
    - provides sensitivity and Monte Carlo utilities
    """

    def __init__(self) -> None:
        pass

    def run(self, scenario: Scenario) -> ScenarioResult:
        eff = self._apply(scenario.base, scenario.shocks, scenario.overrides)
        eff_payload = _assumptions_payload(eff)

        fp = _fingerprint(
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "assumptions": eff_payload,
            }
        )

        series = _project(eff)
        metrics = _metrics(eff, series)

        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            title=scenario.title,
            ts_utc=_now_utc_iso(),
            assumptions_effective=eff_payload,
            fingerprint=fp,
            series=series,
            metrics=metrics,
        )

    def compare(self, base_result: ScenarioResult, other_result: ScenarioResult) -> Dict[str, Any]:
        """
        Deterministic delta report: metrics and top-line.
        """
        b = base_result
        o = other_result
        return {
            "base": {"scenario_id": b.scenario_id, "fingerprint": b.fingerprint},
            "other": {"scenario_id": o.scenario_id, "fingerprint": o.fingerprint},
            "delta_metrics": {
                "npv": _round(o.metrics.npv - b.metrics.npv),
                "irr": _diff_optional(o.metrics.irr, b.metrics.irr),
                "mirr": _diff_optional(o.metrics.mirr, b.metrics.mirr),
                "fcf_total": _round(o.metrics.fcf_total - b.metrics.fcf_total),
                "equity_cf_total": _round(o.metrics.equity_cf_total - b.metrics.equity_cf_total),
                "dscr_min": _diff_optional(o.metrics.dscr_min, b.metrics.dscr_min),
                "dscr_avg": _diff_optional(o.metrics.dscr_avg, b.metrics.dscr_avg),
            },
            "delta_revenue_total": _round(sum(o.series.revenue) - sum(b.series.revenue)),
            "delta_ebitda_total": _round(sum(o.series.ebitda) - sum(b.series.ebitda)),
        }

    def sensitivity(
        self,
        base: Scenario,
        *,
        key: str,
        deltas: Sequence[float],
    ) -> Tuple[ScenarioResult, ...]:
        """
        One-factor sensitivity: apply Shock(key, delta) across deltas.
        """
        if not key:
            raise ValidationError("sensitivity key must be non-empty")
        if not deltas:
            raise ValidationError("deltas must be non-empty")

        out: List[ScenarioResult] = []
        for d in deltas:
            shock = Shock(key=key, delta=_safe_float(d, name="delta"))
            sc = Scenario(
                scenario_id=f"{base.scenario_id}__sens__{key}__{d}",
                title=f"{base.title} sensitivity {key} {d}",
                base=base.base,
                shocks=tuple(base.shocks) + (shock,),
                overrides=dict(base.overrides),
            )
            out.append(self.run(sc))
        return tuple(out)

    def stress_test(
        self,
        base: Scenario,
        *,
        shocks: Sequence[Shock],
        stress_id: str,
        title: str,
    ) -> ScenarioResult:
        """
        Apply multiple shocks as a bundle (stress).
        """
        if not stress_id:
            raise ValidationError("stress_id required")
        if not title:
            raise ValidationError("title required")
        sc = Scenario(
            scenario_id=stress_id,
            title=title,
            base=base.base,
            shocks=tuple(base.shocks) + tuple(shocks),
            overrides=dict(base.overrides),
        )
        return self.run(sc)

    def monte_carlo(
        self,
        base: Scenario,
        *,
        trials: int,
        seed: int,
        distributions: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Monte Carlo over shocks.

        distributions format:
          {
            "gross_margin_delta": {"type": "normal", "mu": 0.0, "sigma": 0.02, "clip": [-0.2, 0.2]},
            "revenue_cagr_annual_delta": {"type": "triangular", "low": -0.05, "mode": 0.0, "high": 0.05},
          }

        Returns deterministic summary statistics.
        """
        if trials <= 0 or trials > 1_000_000:
            raise ValidationError("trials must be in 1..1_000_000")
        rng = random.Random(int(seed))
        engine = self

        npvs: List[float] = []
        irrs: List[float] = []
        dscr_mins: List[float] = []

        for i in range(trials):
            shocks: List[Shock] = []
            for key, dist in distributions.items():
                delta = _sample_dist(rng, key, dist)
                shocks.append(Shock(key=key, delta=delta))

            sc = Scenario(
                scenario_id=f"{base.scenario_id}__mc__{seed}__{i}",
                title=f"{base.title} MC {i}",
                base=base.base,
                shocks=tuple(base.shocks) + tuple(shocks),
                overrides=dict(base.overrides),
            )
            r = engine.run(sc)
            npvs.append(r.metrics.npv)
            if r.metrics.irr is not None:
                irrs.append(r.metrics.irr)
            if r.metrics.dscr_min is not None:
                dscr_mins.append(r.metrics.dscr_min)

        return {
            "trials": trials,
            "seed": seed,
            "npv": _summary_stats(npvs),
            "irr": _summary_stats(irrs) if irrs else {"count": 0},
            "dscr_min": _summary_stats(dscr_mins) if dscr_mins else {"count": 0},
        }

    def _apply(self, base: Assumptions, shocks: Sequence[Shock], overrides: Mapping[str, Any]) -> Assumptions:
        b = base
        d: Dict[str, Any] = dataclasses.asdict(b)

        # Apply shocks
        for s in shocks:
            k = s.key.strip()
            if not k.endswith("_delta"):
                raise ValidationError("Shock.key must end with _delta")
            target = k[: -len("_delta")]
            if target not in d:
                raise ValidationError(f"Unknown shock target: {target}")
            d[target] = _safe_float(d[target], name=target) + _safe_float(s.delta, name="delta")

        # Apply overrides
        for k, v in (overrides or {}).items():
            if k not in d:
                raise ValidationError(f"Unknown override key: {k}")
            d[k] = v

        # Reconstruct with strong validation
        return Assumptions(
            currency=d["currency"],
            grid=TimeGrid(**d["grid"]) if isinstance(d["grid"], dict) else b.grid,
            start_revenue=d["start_revenue"],
            revenue_cagr_annual=d["revenue_cagr_annual"],
            gross_margin=d["gross_margin"],
            opex_fixed_per_period=d["opex_fixed_per_period"],
            opex_variable_ratio=d["opex_variable_ratio"],
            capex_per_period=d["capex_per_period"],
            depreciation_years=d["depreciation_years"],
            working_capital_ratio=d["working_capital_ratio"],
            tax_rate=d["tax_rate"],
            discount_rate_annual=d["discount_rate_annual"],
            debt_principal=d.get("debt_principal", b.debt_principal),
            debt_rate_annual=d.get("debt_rate_annual", b.debt_rate_annual),
            debt_amortization_periods=d.get("debt_amortization_periods", b.debt_amortization_periods),
        )


# ============================================================
# Projection model
# ============================================================
def _assumptions_payload(a: Assumptions) -> Dict[str, Any]:
    return {
        "currency": a.currency,
        "grid": {"periods": a.grid.periods, "period_years": a.grid.period_years},
        "start_revenue": a.start_revenue,
        "revenue_cagr_annual": a.revenue_cagr_annual,
        "gross_margin": a.gross_margin,
        "opex_fixed_per_period": a.opex_fixed_per_period,
        "opex_variable_ratio": a.opex_variable_ratio,
        "capex_per_period": a.capex_per_period,
        "depreciation_years": a.depreciation_years,
        "working_capital_ratio": a.working_capital_ratio,
        "tax_rate": a.tax_rate,
        "discount_rate_annual": a.discount_rate_annual,
        "debt_principal": a.debt_principal,
        "debt_rate_annual": a.debt_rate_annual,
        "debt_amortization_periods": a.debt_amortization_periods,
    }


def _period_rate_from_annual(annual: float, period_years: float) -> float:
    # Convert annual effective rate to per-period effective rate
    return (1.0 + annual) ** period_years - 1.0


def _project(a: Assumptions) -> FinancialSeries:
    g = a.grid
    n = g.periods
    py = g.period_years

    rev_growth_p = _period_rate_from_annual(a.revenue_cagr_annual, py)
    disc_p = _period_rate_from_annual(a.discount_rate_annual, py)

    debt_rate_p = _period_rate_from_annual(a.debt_rate_annual, py) if a.debt_principal > 0 else 0.0

    revenue: List[float] = []
    gross_profit: List[float] = []
    opex: List[float] = []
    ebitda: List[float] = []
    depreciation: List[float] = []
    ebit: List[float] = []
    taxes: List[float] = []
    nopat: List[float] = []
    capex: List[float] = []
    d_wc: List[float] = []
    fcf: List[float] = []
    interest: List[float] = []
    principal: List[float] = []
    equity_cf: List[float] = []

    # Depreciation: straight-line over depreciation_years
    dep_per_period = 0.0
    if a.depreciation_years > 0:
        dep_periods = max(1, int(round(a.depreciation_years / py)))
        # Approx: depreciate only recurring capex as if steady-state
        dep_per_period = a.capex_per_period / dep_periods

    # Working capital: wc_ratio * revenue; delta WC reduces cash when WC increases
    prev_wc = a.working_capital_ratio * a.start_revenue

    # Debt schedule
    debt_outstanding = a.debt_principal
    if a.debt_principal > 0 and a.debt_amortization_periods > 0:
        amort_p = a.debt_principal / a.debt_amortization_periods
    else:
        amort_p = 0.0

    r = a.start_revenue
    for t in range(n):
        if t > 0:
            r = r * (1.0 + rev_growth_p)

        gp = r * a.gross_margin
        op = a.opex_fixed_per_period + (r * a.opex_variable_ratio)
        eb = gp - op
        dep = dep_per_period
        e = eb - dep
        tx = max(0.0, e) * a.tax_rate
        np = e - tx  # NOPAT proxy (ignoring interest shield inside FCF)

        cx = a.capex_per_period

        wc = a.working_capital_ratio * r
        delta_wc = wc - prev_wc
        prev_wc = wc

        # Free cash flow to firm (simplified):
        # FCF = NOPAT + Dep - Capex - ΔWC
        f = np + dep - cx - delta_wc

        # Debt cashflows
        if debt_outstanding > 0:
            intr = debt_outstanding * debt_rate_p
            if amort_p > 0:
                prin = min(amort_p, debt_outstanding)
            else:
                # bullet at last period
                prin = debt_outstanding if (t == n - 1) else 0.0
            debt_outstanding = max(0.0, debt_outstanding - prin)
        else:
            intr = 0.0
            prin = 0.0

        # Cash flow to equity (FCF after debt service; simplified)
        eq = f - intr - prin

        revenue.append(_round(r))
        gross_profit.append(_round(gp))
        opex.append(_round(op))
        ebitda.append(_round(eb))
        depreciation.append(_round(dep))
        ebit.append(_round(e))
        taxes.append(_round(tx))
        nopat.append(_round(np))
        capex.append(_round(cx))
        d_wc.append(_round(delta_wc))
        fcf.append(_round(f))
        interest.append(_round(intr))
        principal.append(_round(prin))
        equity_cf.append(_round(eq))

    return FinancialSeries(
        revenue=tuple(revenue),
        gross_profit=tuple(gross_profit),
        opex=tuple(opex),
        ebitda=tuple(ebitda),
        depreciation=tuple(depreciation),
        ebit=tuple(ebit),
        taxes=tuple(taxes),
        nopat=tuple(nopat),
        capex=tuple(capex),
        delta_working_capital=tuple(d_wc),
        free_cash_flow=tuple(fcf),
        interest=tuple(interest),
        principal_repayment=tuple(principal),
        cash_flow_to_equity=tuple(equity_cf),
    )


# ============================================================
# Metrics
# ============================================================
def _npv(cashflows: Sequence[float], rate_per_period: float) -> float:
    npv = 0.0
    for t, cf in enumerate(cashflows, start=1):
        npv += cf / ((1.0 + rate_per_period) ** t)
    return npv


def _irr_bisection(cashflows: Sequence[float], *, lo: float = -0.99, hi: float = 10.0, iters: int = 200) -> Optional[float]:
    """
    IRR on per-period basis; returns None if cannot bracket root.
    """
    def f(rate: float) -> float:
        return _npv(cashflows, rate)

    flo = f(lo)
    fhi = f(hi)
    if math.isnan(flo) or math.isnan(fhi):
        return None
    if flo == 0.0:
        return lo
    if fhi == 0.0:
        return hi
    if flo * fhi > 0:
        return None

    a, b = lo, hi
    fa, fb = flo, fhi
    for _ in range(iters):
        m = (a + b) / 2.0
        fm = f(m)
        if abs(fm) < 1e-10:
            return m
        if fa * fm <= 0:
            b, fb = m, fm
        else:
            a, fa = m, fm
    return (a + b) / 2.0


def _mirr(cashflows: Sequence[float], finance_rate: float, reinvest_rate: float) -> Optional[float]:
    """
    MIRR per-period.
    """
    if not cashflows:
        return None
    n = len(cashflows)
    pv_neg = 0.0
    fv_pos = 0.0
    for t, cf in enumerate(cashflows, start=1):
        if cf < 0:
            pv_neg += cf / ((1.0 + finance_rate) ** t)
        elif cf > 0:
            fv_pos += cf * ((1.0 + reinvest_rate) ** (n - t))
    if pv_neg == 0.0:
        return None
    mirr = (fv_pos / abs(pv_neg)) ** (1.0 / n) - 1.0
    if math.isnan(mirr) or math.isinf(mirr):
        return None
    return mirr


def _payback_period(cashflows: Sequence[float]) -> Optional[int]:
    cum = 0.0
    for i, cf in enumerate(cashflows, start=1):
        cum += cf
        if cum >= 0:
            return i
    return None


def _dscr(series: FinancialSeries) -> Tuple[Optional[float], Optional[float]]:
    """
    DSCR = (EBITDA - taxes approx) / (interest + principal) per period.
    Uses NOPAT+Dep as proxy for CFADS (simplified, deterministic).
    """
    vals: List[float] = []
    for t in range(len(series.revenue)):
        debt_service = series.interest[t] + series.principal_repayment[t]
        if debt_service <= 0:
            continue
        cfads = series.nopat[t] + series.depreciation[t]
        vals.append(cfads / debt_service)
    if not vals:
        return None, None
    return min(vals), sum(vals) / len(vals)


def _metrics(a: Assumptions, s: FinancialSeries) -> Metrics:
    py = a.grid.period_years
    disc_p = _period_rate_from_annual(a.discount_rate_annual, py)

    # Treat initial investment as negative cashflow at t=0:
    # approximate as first period capex + initial WC build.
    initial_wc = a.working_capital_ratio * a.start_revenue
    init_outflow = -(a.capex_per_period + max(0.0, initial_wc))
    cashflows = [init_outflow] + list(s.free_cash_flow)

    # NPV on period cashflows; note: includes t=0 explicitly
    npv = cashflows[0] + _npv(cashflows[1:], disc_p)

    irr_p = _irr_bisection(cashflows)  # per-period IRR
    irr_a = None
    if irr_p is not None:
        irr_a = (1.0 + irr_p) ** (1.0 / py) - 1.0

    mirr_p = _mirr(cashflows, finance_rate=disc_p, reinvest_rate=disc_p)
    mirr_a = None
    if mirr_p is not None:
        mirr_a = (1.0 + mirr_p) ** (1.0 / py) - 1.0

    pb = _payback_period(cashflows)
    pb_years = (pb * py) if pb is not None else None

    dscr_min, dscr_avg = _dscr(s)

    return Metrics(
        npv=_round(npv, 6),
        irr=_round(irr_a, 6) if irr_a is not None else None,
        mirr=_round(mirr_a, 6) if mirr_a is not None else None,
        payback_periods=pb,
        payback_years=_round(pb_years, 6) if pb_years is not None else None,
        dscr_min=_round(dscr_min, 6) if dscr_min is not None else None,
        dscr_avg=_round(dscr_avg, 6) if dscr_avg is not None else None,
        fcf_total=_round(sum(s.free_cash_flow), 6),
        equity_cf_total=_round(sum(s.cash_flow_to_equity), 6),
    )


def _diff_optional(a: Optional[float], b: Optional[float]) -> Optional[float]:
    if a is None or b is None:
        return None
    return _round(a - b, 6)


# ============================================================
# Monte Carlo distributions
# ============================================================
def _sample_dist(rng: random.Random, key: str, dist: Mapping[str, Any]) -> float:
    if not isinstance(dist, Mapping):
        raise ValidationError(f"distribution for {key} must be an object")
    t = str(dist.get("type", "")).strip().lower()
    if not t:
        raise ValidationError(f"distribution for {key} missing type")

    if t == "normal":
        mu = _safe_float(dist.get("mu", 0.0), name=f"{key}.mu")
        sigma = _safe_float(dist.get("sigma", 1.0), name=f"{key}.sigma")
        if sigma < 0:
            raise ValidationError(f"{key}.sigma must be >= 0")
        v = rng.gauss(mu, sigma)
        clip = dist.get("clip")
        if isinstance(clip, (list, tuple)) and len(clip) == 2:
            lo = _safe_float(clip[0], name=f"{key}.clip[0]")
            hi = _safe_float(clip[1], name=f"{key}.clip[1]")
            v = _clamp(v, lo, hi)
        return float(v)

    if t == "triangular":
        low = _safe_float(dist.get("low"), name=f"{key}.low")
        mode = _safe_float(dist.get("mode"), name=f"{key}.mode")
        high = _safe_float(dist.get("high"), name=f"{key}.high")
        if not (low <= mode <= high):
            raise ValidationError(f"{key}: require low <= mode <= high")
        v = rng.triangular(low, high, mode)
        return float(v)

    if t == "uniform":
        lo = _safe_float(dist.get("low"), name=f"{key}.low")
        hi = _safe_float(dist.get("high"), name=f"{key}.high")
        if hi < lo:
            raise ValidationError(f"{key}: require high >= low")
        return float(rng.uniform(lo, hi))

    raise ValidationError(f"unsupported distribution type for {key}: {t}")


def _summary_stats(xs: Sequence[float]) -> Dict[str, Any]:
    if not xs:
        return {"count": 0}
    arr = sorted(float(x) for x in xs)
    n = len(arr)
    mean = sum(arr) / n
    p50 = arr[n // 2]
    p05 = arr[max(0, int(round(0.05 * (n - 1))))]
    p95 = arr[min(n - 1, int(round(0.95 * (n - 1))))]

    # sample std
    if n > 1:
        var = sum((x - mean) ** 2 for x in arr) / (n - 1)
        std = math.sqrt(var)
    else:
        std = 0.0

    return {
        "count": n,
        "min": _round(arr[0], 6),
        "max": _round(arr[-1], 6),
        "mean": _round(mean, 6),
        "std": _round(std, 6),
        "p05": _round(p05, 6),
        "p50": _round(p50, 6),
        "p95": _round(p95, 6),
    }
