# agent_mash/cfo/analytics/agent.py
from __future__ import annotations

import abc
import asyncio
import dataclasses
import datetime as dt
import decimal
import json
import logging
import os
import statistics
import time
import typing as t
import uuid

from agent_mash.governance.audit_log import AuditConfig, AuditContext, AuditLogger, AuditError

Decimal = decimal.Decimal
Json = dict[str, t.Any]


class AnalyticsError(RuntimeError):
    pass


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _to_decimal(x: t.Any) -> Decimal:
    if isinstance(x, Decimal):
        return x
    if isinstance(x, int):
        return Decimal(x)
    if isinstance(x, float):
        # float небезопасен для денег, но иногда приходит как вход
        return Decimal(str(x))
    if isinstance(x, str):
        s = x.strip()
        if not s:
            return Decimal("0")
        return Decimal(s)
    raise AnalyticsError(f"Unsupported numeric type: {type(x).__name__}")


def _safe_uuid() -> str:
    return str(uuid.uuid4())


def _stable_json(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _date_key(d: dt.date) -> str:
    return d.isoformat()


def _clamp_int(v: int, *, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


@dataclasses.dataclass(frozen=True, slots=True)
class AnalyticsAgentConfig:
    enabled: bool = True
    environment: str = "dev"  # dev|test|staging|prod

    default_currency: str = "USD"
    lookback_days: int = 90

    # Anomaly detection
    anomaly_window_days: int = 30
    anomaly_zscore_threshold: Decimal = Decimal("3.0")
    min_days_for_anomaly: int = 10

    # Audit
    audit_enabled: bool = True
    audit_sink: str = "file"  # stdout|file|http|multi
    audit_file_path: str = "var/audit/cfo_analytics.log"
    audit_chain_state_path: str = "var/audit/cfo_analytics.chain.state"
    audit_enable_hash_chain: bool = True

    # Behavior
    strict_currency: bool = True
    fail_fast: bool = True

    @staticmethod
    def from_env(prefix: str = "AGENT_MASH_CFO_") -> "AnalyticsAgentConfig":
        def env(name: str, default: str) -> str:
            v = os.environ.get(prefix + name, default)
            v = v.strip()
            return v if v else default

        def env_bool(name: str, default: bool) -> bool:
            v = os.environ.get(prefix + name)
            if v is None:
                return default
            s = v.strip().lower()
            if s in {"1", "true", "yes", "y", "on"}:
                return True
            if s in {"0", "false", "no", "n", "off"}:
                return False
            return default

        def env_int(name: str, default: int) -> int:
            v = env(name, str(default))
            try:
                return int(v)
            except ValueError as e:
                raise AnalyticsError(f"Invalid int env {prefix}{name}={v}") from e

        enabled = env_bool("ENABLED", True)
        environment = env("ENV", "dev").lower()

        default_currency = env("DEFAULT_CURRENCY", "USD").upper()
        lookback_days = _clamp_int(env_int("LOOKBACK_DAYS", 90), lo=1, hi=3650)

        anomaly_window_days = _clamp_int(env_int("ANOMALY_WINDOW_DAYS", 30), lo=3, hi=3650)
        anomaly_z = env("ANOMALY_ZSCORE", "3.0")
        anomaly_zscore_threshold = _to_decimal(anomaly_z)
        min_days_for_anomaly = _clamp_int(env_int("MIN_DAYS_FOR_ANOMALY", 10), lo=3, hi=3650)

        audit_enabled = env_bool("AUDIT_ENABLED", True)
        audit_sink = env("AUDIT_SINK", "file").lower()
        audit_file_path = env("AUDIT_FILE_PATH", "var/audit/cfo_analytics.log")
        audit_chain_state_path = env("AUDIT_CHAIN_STATE_PATH", "var/audit/cfo_analytics.chain.state")
        audit_enable_hash_chain = env_bool("AUDIT_HASH_CHAIN", True)

        strict_currency = env_bool("STRICT_CURRENCY", True)
        fail_fast = env_bool("FAIL_FAST", True)

        return AnalyticsAgentConfig(
            enabled=enabled,
            environment=environment,
            default_currency=default_currency,
            lookback_days=lookback_days,
            anomaly_window_days=anomaly_window_days,
            anomaly_zscore_threshold=anomaly_zscore_threshold,
            min_days_for_anomaly=min_days_for_anomaly,
            audit_enabled=audit_enabled,
            audit_sink=audit_sink,
            audit_file_path=audit_file_path,
            audit_chain_state_path=audit_chain_state_path,
            audit_enable_hash_chain=audit_enable_hash_chain,
            strict_currency=strict_currency,
            fail_fast=fail_fast,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class Transaction:
    tx_id: str
    occurred_at: dt.datetime
    amount: Decimal
    currency: str
    direction: str  # in|out
    category: str
    counterparty: str | None = None
    description: str | None = None
    meta: Json = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tx_id:
            raise AnalyticsError("tx_id must be non-empty")
        if self.occurred_at.tzinfo is None:
            raise AnalyticsError("occurred_at must be timezone-aware")
        if self.currency is None or not str(self.currency).strip():
            raise AnalyticsError("currency must be non-empty")
        cur = str(self.currency).upper()
        if cur != self.currency:
            object.__setattr__(self, "currency", cur)  # type: ignore[misc]
        if self.direction not in {"in", "out"}:
            raise AnalyticsError("direction must be 'in' or 'out'")
        if not self.category:
            raise AnalyticsError("category must be non-empty")


@dataclasses.dataclass(frozen=True, slots=True)
class KPIResult:
    as_of: dt.datetime
    currency: str

    total_inflow: Decimal
    total_outflow: Decimal
    net_cashflow: Decimal

    avg_daily_outflow: Decimal
    burn_rate_monthly: Decimal
    runway_days: int | None

    inflow_growth_rate: Decimal | None
    outflow_growth_rate: Decimal | None

    def to_dict(self) -> Json:
        def d(x: Decimal | None) -> str | None:
            return str(x) if x is not None else None

        return {
            "as_of": self.as_of.isoformat(),
            "currency": self.currency,
            "total_inflow": str(self.total_inflow),
            "total_outflow": str(self.total_outflow),
            "net_cashflow": str(self.net_cashflow),
            "avg_daily_outflow": str(self.avg_daily_outflow),
            "burn_rate_monthly": str(self.burn_rate_monthly),
            "runway_days": self.runway_days,
            "inflow_growth_rate": d(self.inflow_growth_rate),
            "outflow_growth_rate": d(self.outflow_growth_rate),
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Anomaly:
    day: dt.date
    metric: str
    value: Decimal
    mean: Decimal
    stdev: Decimal
    zscore: Decimal

    def to_dict(self) -> Json:
        return {
            "day": self.day.isoformat(),
            "metric": self.metric,
            "value": str(self.value),
            "mean": str(self.mean),
            "stdev": str(self.stdev),
            "zscore": str(self.zscore),
        }


@dataclasses.dataclass(frozen=True, slots=True)
class AnalyticsReport:
    report_id: str
    generated_at: dt.datetime
    window_days: int
    currency: str
    kpis: KPIResult
    anomalies: list[Anomaly]
    summary: Json

    def to_dict(self) -> Json:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "window_days": self.window_days,
            "currency": self.currency,
            "kpis": self.kpis.to_dict(),
            "anomalies": [a.to_dict() for a in self.anomalies],
            "summary": self.summary,
        }


class TransactionsRepository(abc.ABC):
    @abc.abstractmethod
    async def list_transactions(
        self,
        *,
        from_ts: dt.datetime,
        to_ts: dt.datetime,
        currency: str | None = None,
    ) -> list[Transaction]:
        raise NotImplementedError


class BalanceRepository(abc.ABC):
    @abc.abstractmethod
    async def get_cash_balance(
        self,
        *,
        as_of: dt.datetime,
        currency: str,
    ) -> Decimal:
        raise NotImplementedError


class AnalyticsSink(abc.ABC):
    @abc.abstractmethod
    async def persist_report(self, report: AnalyticsReport) -> None:
        raise NotImplementedError


class NullAnalyticsSink(AnalyticsSink):
    async def persist_report(self, report: AnalyticsReport) -> None:
        return


def _build_audit_logger(cfg: AnalyticsAgentConfig) -> AuditLogger:
    audit_cfg = AuditConfig(
        enabled=cfg.audit_enabled,
        app_name="agent_mash",
        environment=cfg.environment,
        sink=cfg.audit_sink,
        file_path=cfg.audit_file_path,
        enable_hash_chain=cfg.audit_enable_hash_chain,
        chain_state_path=cfg.audit_chain_state_path,
        background_worker=True,
        strict_schema=True,
        redact_sensitive=True,
    )
    return AuditLogger(audit_cfg)


class CFOAnalyticsAgent:
    def __init__(
        self,
        *,
        cfg: AnalyticsAgentConfig,
        tx_repo: TransactionsRepository,
        balance_repo: BalanceRepository,
        sink: AnalyticsSink | None = None,
        audit_logger: AuditLogger | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._cfg = cfg
        self._tx_repo = tx_repo
        self._balance_repo = balance_repo
        self._sink = sink or NullAnalyticsSink()
        self._audit = audit_logger or _build_audit_logger(cfg)
        self._log = logger or logging.getLogger("agent_mash.cfo.analytics.agent")

    @property
    def config(self) -> AnalyticsAgentConfig:
        return self._cfg

    async def run_once(
        self,
        *,
        as_of: dt.datetime | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> AnalyticsReport | None:
        if not self._cfg.enabled:
            return None

        as_of_dt = as_of or _utc_now()
        if as_of_dt.tzinfo is None:
            raise AnalyticsError("as_of must be timezone-aware")

        corr = correlation_id or _safe_uuid()
        audit_ctx = AuditContext(
            correlation_id=corr,
            actor_id=actor_id,
            actor_type="service",
            request_id=_safe_uuid(),
        )

        start_ts = time.time()
        with t.cast(t.Any, _audit_context_guard(audit_ctx)):
            try:
                report = await self._compute_report(as_of_dt=as_of_dt)
                await self._sink.persist_report(report)

                self._audit.log(
                    "cfo_analytics.report_generated",
                    severity="INFO",
                    message="CFO analytics report generated",
                    data={
                        "report_id": report.report_id,
                        "as_of": report.generated_at.isoformat(),
                        "window_days": report.window_days,
                        "currency": report.currency,
                        "anomalies_count": len(report.anomalies),
                        "duration_ms": int((time.time() - start_ts) * 1000),
                    },
                )
                return report
            except BaseException as e:  # noqa: BLE001
                self._audit.log(
                    "cfo_analytics.report_failed",
                    severity="ERROR",
                    message="CFO analytics report failed",
                    data={
                        "error_type": type(e).__name__,
                        "error": str(e),
                        "duration_ms": int((time.time() - start_ts) * 1000),
                    },
                )
                self._log.exception("cfo_analytics_failed")
                if self._cfg.fail_fast:
                    raise
                return None

    async def _compute_report(self, *, as_of_dt: dt.datetime) -> AnalyticsReport:
        window_days = int(self._cfg.lookback_days)
        from_ts = as_of_dt - dt.timedelta(days=window_days)

        currency = self._cfg.default_currency.upper()
        txs = await self._tx_repo.list_transactions(from_ts=from_ts, to_ts=as_of_dt, currency=currency)

        if self._cfg.strict_currency:
            for tx in txs:
                if tx.currency.upper() != currency:
                    raise AnalyticsError(f"Unexpected currency in transaction: {tx.currency} expected {currency}")

        # Рассчитываем KPI
        kpis = self._calc_kpis(as_of_dt=as_of_dt, currency=currency, txs=txs)

        # Детект аномалий по дневному outflow
        anomalies = self._detect_anomalies(currency=currency, txs=txs, as_of_dt=as_of_dt)

        # Баланс и сводка
        cash_balance = await self._balance_repo.get_cash_balance(as_of=as_of_dt, currency=currency)
        summary = self._build_summary(currency=currency, cash_balance=cash_balance, kpis=kpis, anomalies=anomalies)

        report = AnalyticsReport(
            report_id=_safe_uuid(),
            generated_at=as_of_dt,
            window_days=window_days,
            currency=currency,
            kpis=kpis,
            anomalies=anomalies,
            summary=summary,
        )

        return report

    def _calc_kpis(self, *, as_of_dt: dt.datetime, currency: str, txs: list[Transaction]) -> KPIResult:
        inflow = Decimal("0")
        outflow = Decimal("0")

        for tx in txs:
            amt = _to_decimal(tx.amount)
            if tx.direction == "in":
                inflow += amt
            else:
                outflow += amt

        net = inflow - outflow

        # Средний дневной расход
        days = max(1, self._cfg.lookback_days)
        avg_daily_out = (outflow / Decimal(days)).quantize(Decimal("0.0001"))

        burn_month = (avg_daily_out * Decimal("30")).quantize(Decimal("0.0001"))

        # Runway: cash_balance / avg_daily_outflow
        runway_days: int | None = None
        # баланс берём в summary, но runway считать нужно уже тут; если avg_daily_out == 0, runway бесконечный, представляем None
        # чтобы избежать ложных чисел
        # runway считается позже при наличии баланса; здесь ставим None
        inflow_growth: Decimal | None = None
        outflow_growth: Decimal | None = None

        # Рост: сравнение последних N/2 дней к первым N/2 дням
        if len(txs) >= 4 and days >= 4:
            mid = as_of_dt - dt.timedelta(days=days // 2)
            inflow_a, outflow_a = self._sum_range(txs, to_ts=mid)
            inflow_b, outflow_b = self._sum_range(txs, from_ts=mid)

            inflow_growth = self._growth_rate(inflow_a, inflow_b)
            outflow_growth = self._growth_rate(outflow_a, outflow_b)

        return KPIResult(
            as_of=as_of_dt,
            currency=currency,
            total_inflow=inflow.quantize(Decimal("0.0001")),
            total_outflow=outflow.quantize(Decimal("0.0001")),
            net_cashflow=net.quantize(Decimal("0.0001")),
            avg_daily_outflow=avg_daily_out,
            burn_rate_monthly=burn_month,
            runway_days=runway_days,
            inflow_growth_rate=inflow_growth,
            outflow_growth_rate=outflow_growth,
        )

    def _sum_range(
        self,
        txs: list[Transaction],
        *,
        from_ts: dt.datetime | None = None,
        to_ts: dt.datetime | None = None,
    ) -> tuple[Decimal, Decimal]:
        inflow = Decimal("0")
        outflow = Decimal("0")
        for tx in txs:
            if from_ts is not None and tx.occurred_at < from_ts:
                continue
            if to_ts is not None and tx.occurred_at >= to_ts:
                continue
            amt = _to_decimal(tx.amount)
            if tx.direction == "in":
                inflow += amt
            else:
                outflow += amt
        return inflow, outflow

    def _growth_rate(self, base: Decimal, current: Decimal) -> Decimal | None:
        if base <= 0:
            return None
        return ((current - base) / base).quantize(Decimal("0.0001"))

    def _detect_anomalies(self, *, currency: str, txs: list[Transaction], as_of_dt: dt.datetime) -> list[Anomaly]:
        window_days = int(self._cfg.anomaly_window_days)
        from_ts = as_of_dt - dt.timedelta(days=window_days)

        daily_out: dict[dt.date, Decimal] = {}
        for tx in txs:
            if tx.occurred_at < from_ts:
                continue
            if tx.direction != "out":
                continue
            day = tx.occurred_at.date()
            daily_out[day] = daily_out.get(day, Decimal("0")) + _to_decimal(tx.amount)

        if len(daily_out) < int(self._cfg.min_days_for_anomaly):
            return []

        days_sorted = sorted(daily_out.keys())
        values = [daily_out[d] for d in days_sorted]

        # stdev по Decimal напрямую отсутствует; переводим в float только для stdev,
        # zscore возвращаем как Decimal строкой; это компромисс, но не смешивает деньги в float в итогах.
        # Денежные суммы остаются Decimal.
        try:
            mean_f = statistics.mean([float(v) for v in values])
            stdev_f = statistics.pstdev([float(v) for v in values])
        except Exception as e:
            raise AnalyticsError(f"Failed to compute anomaly statistics: {e}") from e

        mean = _to_decimal(str(mean_f)).quantize(Decimal("0.0001"))
        stdev = _to_decimal(str(stdev_f)).quantize(Decimal("0.0001"))

        if stdev <= 0:
            return []

        threshold = self._cfg.anomaly_zscore_threshold
        out: list[Anomaly] = []
        for d in days_sorted:
            v = daily_out[d].quantize(Decimal("0.0001"))
            z = (v - mean) / stdev
            zq = z.quantize(Decimal("0.0001"))
            if zq.copy_abs() >= threshold:
                out.append(
                    Anomaly(
                        day=d,
                        metric="daily_outflow",
                        value=v,
                        mean=mean,
                        stdev=stdev,
                        zscore=zq,
                    )
                )
        return out

    def _build_summary(
        self,
        *,
        currency: str,
        cash_balance: Decimal,
        kpis: KPIResult,
        anomalies: list[Anomaly],
    ) -> Json:
        avg_daily_out = kpis.avg_daily_outflow
        runway_days: int | None = None
        if avg_daily_out > 0:
            try:
                runway = (cash_balance / avg_daily_out)
                runway_days = int(runway.to_integral_value(rounding=decimal.ROUND_FLOOR))
                runway_days = max(0, runway_days)
            except Exception:
                runway_days = None

        # Обновляем runway в KPIResult без мутаций
        kpi_dict = kpis.to_dict()
        kpi_dict["runway_days"] = runway_days

        return {
            "cash_balance": str(cash_balance.quantize(Decimal("0.0001"))),
            "runway_days": runway_days,
            "anomalies_count": len(anomalies),
            "kpis": kpi_dict,
        }


class _audit_context_guard:
    def __init__(self, ctx: AuditContext) -> None:
        self._ctx = ctx
        self._prev = None

    def __enter__(self) -> None:
        try:
            from agent_mash.governance.audit_log import set_audit_context  # local import to avoid cycles

            self._prev = None
            set_audit_context(self._ctx)
        except Exception:
            return

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            from agent_mash.governance.audit_log import set_audit_context  # local import to avoid cycles

            set_audit_context(None)
        except Exception:
            return


__all__ = [
    "AnalyticsAgentConfig",
    "AnalyticsError",
    "Transaction",
    "KPIResult",
    "Anomaly",
    "AnalyticsReport",
    "TransactionsRepository",
    "BalanceRepository",
    "AnalyticsSink",
    "NullAnalyticsSink",
    "CFOAnalyticsAgent",
]
