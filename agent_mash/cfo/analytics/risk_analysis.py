# agent_mash/cfo/analytics/risk_analysis.py
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

JsonValue = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class RiskError(RuntimeError):
    pass


class ValidationError(RiskError):
    pass


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    PAYMENT = "payment"
    REFUND = "refund"
    CHARGEBACK = "chargeback"
    TRANSFER = "transfer"
    WITHDRAWAL = "withdrawal"
    DEPOSIT = "deposit"
    ADJUSTMENT = "adjustment"
    INVOICE = "invoice"
    PAYROLL = "payroll"
    OTHER = "other"


class Channel(str, Enum):
    CARD = "card"
    BANK = "bank"
    CRYPTO = "crypto"
    CASH = "cash"
    INTERNAL = "internal"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class Money:
    amount: float
    currency: str

    def __post_init__(self) -> None:
        if not isinstance(self.currency, str) or not self.currency:
            raise ValidationError("Money.currency must be non-empty string")
        if not isinstance(self.amount, (int, float)) or math.isnan(float(self.amount)) or math.isinf(float(self.amount)):
            raise ValidationError("Money.amount must be finite number")

    def abs(self) -> "Money":
        return Money(amount=abs(float(self.amount)), currency=self.currency)


@dataclass(frozen=True, slots=True)
class Counterparty:
    id: str
    kind: str = "unknown"  # customer, merchant, supplier, employee, etc.
    country: Optional[str] = None
    risk_tags: dict[str, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValidationError("Counterparty.id must be non-empty string")
        if not isinstance(self.kind, str) or not self.kind:
            raise ValidationError("Counterparty.kind must be non-empty string")


@dataclass(frozen=True, slots=True)
class FinancialEvent:
    """
    Универсальное финансовое событие для аналитики риска.

    Инварианты:
    - id обязателен (строка), используется в дедупликации и корреляции.
    - occurred_at обязателен и должен быть timezone-aware.
    - money.amount может быть отрицательным (например, refund), но риск анализируется по abs().
    """

    id: str
    event_type: EventType
    channel: Channel
    money: Money
    occurred_at: datetime

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    counterparty: Optional[Counterparty] = None

    reference_id: Optional[str] = None  # invoice_id, order_id, etc.
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValidationError("FinancialEvent.id must be non-empty string")
        if self.occurred_at.tzinfo is None:
            raise ValidationError("FinancialEvent.occurred_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RiskSignal:
    name: str
    score: float  # 0..100
    weight: float  # 0..1
    evidence: dict[str, JsonValue] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValidationError("RiskSignal.name must be non-empty string")
        if not (0.0 <= float(self.score) <= 100.0):
            raise ValidationError("RiskSignal.score must be in [0, 100]")
        if not (0.0 <= float(self.weight) <= 1.0):
            raise ValidationError("RiskSignal.weight must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class RiskFinding:
    flag: str
    severity: RiskLevel
    message: str
    evidence: dict[str, JsonValue] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.flag or not isinstance(self.flag, str):
            raise ValidationError("RiskFinding.flag must be non-empty string")
        if not self.message or not isinstance(self.message, str):
            raise ValidationError("RiskFinding.message must be non-empty string")


@dataclass(frozen=True, slots=True)
class EventRiskReport:
    event_id: str
    risk_score: float  # 0..100
    level: RiskLevel
    signals: list[RiskSignal]
    findings: list[RiskFinding]
    computed_at: datetime
    fingerprint: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "event_id": self.event_id,
            "risk_score": float(self.risk_score),
            "level": self.level.value,
            "signals": [
                {"name": s.name, "score": float(s.score), "weight": float(s.weight), "evidence": dict(s.evidence)}
                for s in self.signals
            ],
            "findings": [
                {"flag": f.flag, "severity": f.severity.value, "message": f.message, "evidence": dict(f.evidence)}
                for f in self.findings
            ],
            "computed_at": self.computed_at.isoformat(),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class PortfolioRiskReport:
    tenant_id: str
    window_start: datetime
    window_end: datetime
    total_events: int
    total_abs_amount: dict[str, float]
    avg_risk_score: float
    p95_risk_score: float
    level: RiskLevel
    top_findings: list[RiskFinding]
    computed_at: datetime
    fingerprint: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "tenant_id": self.tenant_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "total_events": int(self.total_events),
            "total_abs_amount": {k: float(v) for k, v in self.total_abs_amount.items()},
            "avg_risk_score": float(self.avg_risk_score),
            "p95_risk_score": float(self.p95_risk_score),
            "level": self.level.value,
            "top_findings": [
                {"flag": f.flag, "severity": f.severity.value, "message": f.message, "evidence": dict(f.evidence)}
                for f in self.top_findings
            ],
            "computed_at": self.computed_at.isoformat(),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class RiskConfig:
    allowed_currencies: set[str] = dataclasses.field(default_factory=lambda: {"USD", "EUR", "SEK", "RUB", "GBP"})
    high_amount_threshold: float = 10_000.0
    critical_amount_threshold: float = 50_000.0

    # Робастный выброс: MAD z-score порог
    outlier_mad_z_threshold: float = 6.0

    # Временной риск: события ночью/нерабочее время
    night_hours_utc: tuple[int, int] = (0, 5)  # inclusive start, inclusive end
    weekend_risk_weight: float = 0.10

    # Риски по типам/каналам (базовые приоритеты)
    base_event_type_risk: dict[EventType, float] = dataclasses.field(
        default_factory=lambda: {
            EventType.PAYMENT: 20.0,
            EventType.REFUND: 35.0,
            EventType.CHARGEBACK: 75.0,
            EventType.TRANSFER: 30.0,
            EventType.WITHDRAWAL: 45.0,
            EventType.DEPOSIT: 20.0,
            EventType.ADJUSTMENT: 40.0,
            EventType.INVOICE: 15.0,
            EventType.PAYROLL: 25.0,
            EventType.OTHER: 25.0,
        }
    )
    base_channel_risk: dict[Channel, float] = dataclasses.field(
        default_factory=lambda: {
            Channel.CARD: 35.0,
            Channel.BANK: 25.0,
            Channel.CRYPTO: 55.0,
            Channel.CASH: 60.0,
            Channel.INTERNAL: 15.0,
            Channel.OTHER: 30.0,
        }
    )

    # Весовые коэффициенты сигналов (сумма может быть не равна 1, нормализуется)
    w_amount: float = 0.30
    w_event_type: float = 0.15
    w_channel: float = 0.15
    w_time: float = 0.10
    w_counterparty_tags: float = 0.15
    w_outlier: float = 0.15

    # Пороговые уровни
    level_medium: float = 35.0
    level_high: float = 65.0
    level_critical: float = 85.0


@dataclass(frozen=True, slots=True)
class StressScenario:
    """
    Стресс-сценарий для портфеля:
    - множитель риска по channel / event_type
    - усиление риска на выходные/ночь
    """

    id: str
    channel_multiplier: dict[Channel, float] = dataclasses.field(default_factory=dict)
    event_type_multiplier: dict[EventType, float] = dataclasses.field(default_factory=dict)
    global_multiplier: float = 1.0

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise ValidationError("StressScenario.id must be non-empty string")
        if self.global_multiplier <= 0:
            raise ValidationError("StressScenario.global_multiplier must be positive")


class RiskAnalyzer:
    """
    CFO Risk Analyzer.
    Назначение:
    - оценка риска события (EventRiskReport)
    - агрегирование риска портфеля (PortfolioRiskReport)
    - стресс-анализ

    Важное:
    - модуль не делает FX-конвертацию (нет надёжного источника курсов в оффлайне).
      Не могу подтвердить это: какие курсы/источники вы используете, поэтому суммы считаются по валютам отдельно.
    """

    def __init__(self, *, config: Optional[RiskConfig] = None) -> None:
        self._cfg = config or RiskConfig()

    def assess_event(
        self,
        event: FinancialEvent,
        *,
        historical_events: Optional[Sequence[FinancialEvent]] = None,
    ) -> EventRiskReport:
        self._validate_event(event)

        abs_amount = float(event.money.abs().amount)

        signals: list[RiskSignal] = []
        findings: list[RiskFinding] = []

        s_amount = self._score_amount(abs_amount)
        signals.append(RiskSignal("amount", s_amount, self._cfg.w_amount, {"abs_amount": abs_amount}))

        s_type = float(self._cfg.base_event_type_risk.get(event.event_type, 25.0))
        signals.append(RiskSignal("event_type", s_type, self._cfg.w_event_type, {"event_type": event.event_type.value}))

        s_channel = float(self._cfg.base_channel_risk.get(event.channel, 30.0))
        signals.append(RiskSignal("channel", s_channel, self._cfg.w_channel, {"channel": event.channel.value}))

        s_time, time_evidence, time_findings = self._score_time(event.occurred_at)
        signals.append(RiskSignal("time", s_time, self._cfg.w_time, time_evidence))
        findings.extend(time_findings)

        s_cp, cp_evidence, cp_findings = self._score_counterparty(event.counterparty)
        signals.append(RiskSignal("counterparty", s_cp, self._cfg.w_counterparty_tags, cp_evidence))
        findings.extend(cp_findings)

        s_outlier, out_evidence, out_findings = self._score_outlier(event, historical_events or [])
        signals.append(RiskSignal("outlier", s_outlier, self._cfg.w_outlier, out_evidence))
        findings.extend(out_findings)

        risk_score = self._combine(signals)
        level = self._level(risk_score)

        if risk_score >= self._cfg.level_high and event.event_type in (EventType.REFUND, EventType.CHARGEBACK):
            findings.append(
                RiskFinding(
                    flag="refund_or_chargeback_high_risk",
                    severity=RiskLevel.HIGH,
                    message="Refund/chargeback with high overall risk score",
                    evidence={"event_type": event.event_type.value, "risk_score": float(risk_score)},
                )
            )

        if abs_amount >= self._cfg.critical_amount_threshold:
            findings.append(
                RiskFinding(
                    flag="critical_amount",
                    severity=RiskLevel.CRITICAL,
                    message="Amount exceeds critical threshold",
                    evidence={"abs_amount": abs_amount, "threshold": float(self._cfg.critical_amount_threshold)},
                )
            )
        elif abs_amount >= self._cfg.high_amount_threshold:
            findings.append(
                RiskFinding(
                    flag="high_amount",
                    severity=RiskLevel.HIGH,
                    message="Amount exceeds high threshold",
                    evidence={"abs_amount": abs_amount, "threshold": float(self._cfg.high_amount_threshold)},
                )
            )

        computed_at = utc_now()
        fingerprint = self._fingerprint_event(event, risk_score, signals, findings)

        return EventRiskReport(
            event_id=event.id,
            risk_score=float(risk_score),
            level=level,
            signals=signals,
            findings=self._dedupe_findings(findings),
            computed_at=computed_at,
            fingerprint=fingerprint,
        )

    def assess_portfolio(
        self,
        events: Sequence[FinancialEvent],
        *,
        tenant_id: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        scenario: Optional[StressScenario] = None,
    ) -> PortfolioRiskReport:
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValidationError("tenant_id must be non-empty string")
        if not events:
            raise ValidationError("events must not be empty")

        ws = window_start or min(e.occurred_at for e in events)
        we = window_end or max(e.occurred_at for e in events)
        if ws.tzinfo is None or we.tzinfo is None:
            raise ValidationError("window_start/window_end must be timezone-aware")

        # фильтр по tenant
        scoped = [e for e in events if (e.tenant_id or "public") == tenant_id]
        if not scoped:
            raise ValidationError("no events for tenant_id in provided events")

        # риск каждого события
        reports = [self.assess_event(e, historical_events=scoped) for e in scoped]
        scores = [r.risk_score for r in reports]

        # агрегаты сумм по валютам (abs)
        totals: dict[str, float] = {}
        for e in scoped:
            cur = e.money.currency
            totals[cur] = totals.get(cur, 0.0) + float(e.money.abs().amount)

        avg_score = float(sum(scores) / len(scores))
        p95 = self._percentile(scores, 95)

        # стресс
        if scenario is not None:
            avg_score, p95 = self._apply_scenario(avg_score, p95, scoped, scenario)

        level = self._level(max(avg_score, p95))

        # топ-флаги по серьёзности и частоте
        all_findings: list[RiskFinding] = []
        for r in reports:
            all_findings.extend(r.findings)
        top = self._top_findings(all_findings, limit=10)

        computed_at = utc_now()
        fingerprint = self._fingerprint_portfolio(tenant_id, ws, we, totals, avg_score, p95, level, top, scenario)

        return PortfolioRiskReport(
            tenant_id=tenant_id,
            window_start=ws,
            window_end=we,
            total_events=len(scoped),
            total_abs_amount=totals,
            avg_risk_score=float(avg_score),
            p95_risk_score=float(p95),
            level=level,
            top_findings=top,
            computed_at=computed_at,
            fingerprint=fingerprint,
        )

    def make_default_scenario_crypto_run(self) -> StressScenario:
        return StressScenario(
            id="stress.crypto_run",
            channel_multiplier={Channel.CRYPTO: 1.25, Channel.CASH: 1.10},
            event_type_multiplier={EventType.WITHDRAWAL: 1.20, EventType.TRANSFER: 1.10},
            global_multiplier=1.05,
        )

    def _validate_event(self, event: FinancialEvent) -> None:
        if event.money.currency not in self._cfg.allowed_currencies:
            raise ValidationError(f"currency not allowed: {event.money.currency}")
        if event.occurred_at.tzinfo is None:
            raise ValidationError("occurred_at must be timezone-aware")

    def _score_amount(self, abs_amount: float) -> float:
        # Логарифмическая шкала: малые суммы дают небольшой риск, большие растут быстрее.
        # 0 -> 0, 10 -> ~10, 100 -> ~20, 1k -> ~35, 10k -> ~55, 50k -> ~75, 200k -> ~90
        if abs_amount <= 0:
            return 0.0
        x = math.log10(abs_amount + 1.0)
        score = 20.0 * x
        return float(max(0.0, min(100.0, score)))

    def _score_time(self, ts: datetime) -> tuple[float, dict[str, JsonValue], list[RiskFinding]]:
        findings: list[RiskFinding] = []
        hour = int(ts.astimezone(timezone.utc).hour)
        weekday = int(ts.astimezone(timezone.utc).weekday())  # 0 Mon .. 6 Sun
        is_weekend = weekday >= 5
        night_start, night_end = self._cfg.night_hours_utc
        is_night = night_start <= hour <= night_end

        score = 0.0
        if is_night:
            score += 35.0
            findings.append(
                RiskFinding(
                    flag="night_time_activity",
                    severity=RiskLevel.MEDIUM,
                    message="Event occurred during night hours (UTC)",
                    evidence={"hour_utc": hour},
                )
            )
        if is_weekend:
            score += 25.0
            findings.append(
                RiskFinding(
                    flag="weekend_activity",
                    severity=RiskLevel.MEDIUM,
                    message="Event occurred during weekend (UTC)",
                    evidence={"weekday_utc": weekday},
                )
            )

        evidence = {"hour_utc": hour, "weekday_utc": weekday, "is_weekend": is_weekend, "is_night": is_night}
        return float(min(100.0, score)), evidence, findings

    def _score_counterparty(
        self, cp: Optional[Counterparty]
    ) -> tuple[float, dict[str, JsonValue], list[RiskFinding]]:
        if cp is None:
            return 25.0, {"counterparty": None}, []

        findings: list[RiskFinding] = []
        tags = dict(cp.risk_tags)
        evidence: dict[str, JsonValue] = {"counterparty_id": cp.id, "counterparty_kind": cp.kind, "risk_tags": tags}

        score = 0.0
        # Универсальные теги (если ваш домен использует другие ключи, это не ломает работу)
        if tags.get("kyc") == "missing":
            score += 55.0
            findings.append(
                RiskFinding(
                    flag="kyc_missing",
                    severity=RiskLevel.HIGH,
                    message="Counterparty has missing KYC flag",
                    evidence={"counterparty_id": cp.id},
                )
            )
        if tags.get("sanctions") == "hit":
            score += 90.0
            findings.append(
                RiskFinding(
                    flag="sanctions_hit",
                    severity=RiskLevel.CRITICAL,
                    message="Counterparty has sanctions hit flag",
                    evidence={"counterparty_id": cp.id},
                )
            )
        if tags.get("pep") == "true":
            score += 45.0
            findings.append(
                RiskFinding(
                    flag="pep",
                    severity=RiskLevel.HIGH,
                    message="Counterparty is PEP flagged",
                    evidence={"counterparty_id": cp.id},
                )
            )

        # Страна сама по себе не является фактом риска без авторитетной политики.
        # Здесь мы лишь фиксируем, что страна присутствует; скоринг не добавляем.
        return float(min(100.0, score)), evidence, findings

    def _score_outlier(
        self, event: FinancialEvent, history: Sequence[FinancialEvent]
    ) -> tuple[float, dict[str, JsonValue], list[RiskFinding]]:
        """
        Робастная детекция выброса по abs(amount) на основе MAD.
        Если истории нет, риск outlier нейтральный.
        """
        findings: list[RiskFinding] = []
        if len(history) < 20:
            return 0.0, {"history_size": len(history), "method": "mad_z", "status": "insufficient_history"}, findings

        vals = [float(e.money.abs().amount) for e in history]
        med = statistics.median(vals)
        abs_dev = [abs(v - med) for v in vals]
        mad = statistics.median(abs_dev)

        x = float(event.money.abs().amount)

        if mad <= 0:
            return 0.0, {"history_size": len(history), "method": "mad_z", "median": med, "mad": mad}, findings

        # Константа 1.4826 приводит MAD к оценке sigma при нормальном распределении
        robust_sigma = 1.4826 * mad
        z = abs(x - med) / robust_sigma

        evidence: dict[str, JsonValue] = {
            "history_size": len(history),
            "method": "mad_z",
            "median": float(med),
            "mad": float(mad),
            "robust_sigma": float(robust_sigma),
            "z": float(z),
            "x": float(x),
        }

        if z >= self._cfg.outlier_mad_z_threshold:
            score = min(100.0, 20.0 + 10.0 * (z - self._cfg.outlier_mad_z_threshold))
            findings.append(
                RiskFinding(
                    flag="amount_outlier",
                    severity=RiskLevel.HIGH,
                    message="Amount is a robust outlier vs historical distribution",
                    evidence={"z": float(z), "threshold": float(self._cfg.outlier_mad_z_threshold)},
                )
            )
            return float(score), evidence, findings

        return 0.0, evidence, findings

    def _combine(self, signals: Sequence[RiskSignal]) -> float:
        # Нормализуем веса, чтобы итог был устойчивым при изменениях конфигурации
        w_sum = sum(float(s.weight) for s in signals)
        if w_sum <= 0:
            raise ValidationError("sum of signal weights must be positive")
        score = 0.0
        for s in signals:
            w = float(s.weight) / w_sum
            score += w * float(s.score)
        return float(max(0.0, min(100.0, score)))

    def _level(self, score: float) -> RiskLevel:
        s = float(score)
        if s >= self._cfg.level_critical:
            return RiskLevel.CRITICAL
        if s >= self._cfg.level_high:
            return RiskLevel.HIGH
        if s >= self._cfg.level_medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _percentile(self, values: Sequence[float], p: int) -> float:
        if not values:
            return 0.0
        xs = sorted(float(v) for v in values)
        if p <= 0:
            return xs[0]
        if p >= 100:
            return xs[-1]
        k = (len(xs) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return xs[int(k)]
        d0 = xs[int(f)] * (c - k)
        d1 = xs[int(c)] * (k - f)
        return float(d0 + d1)

    def _apply_scenario(
        self,
        avg_score: float,
        p95: float,
        events: Sequence[FinancialEvent],
        scenario: StressScenario,
    ) -> tuple[float, float]:
        """
        Упрощённый стресс: повышаем агрегатный риск на основе доли событий в каналах/типах.
        """
        if not events:
            return avg_score, p95

        n = len(events)
        channel_counts: dict[Channel, int] = {}
        type_counts: dict[EventType, int] = {}
        for e in events:
            channel_counts[e.channel] = channel_counts.get(e.channel, 0) + 1
            type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1

        mult = float(scenario.global_multiplier)

        for ch, m in scenario.channel_multiplier.items():
            if ch in channel_counts:
                mult *= 1.0 + (float(m) - 1.0) * (channel_counts[ch] / n)

        for et, m in scenario.event_type_multiplier.items():
            if et in type_counts:
                mult *= 1.0 + (float(m) - 1.0) * (type_counts[et] / n)

        avg2 = min(100.0, float(avg_score) * mult)
        p952 = min(100.0, float(p95) * mult)
        return float(avg2), float(p952)

    def _top_findings(self, findings: Sequence[RiskFinding], *, limit: int = 10) -> list[RiskFinding]:
        if not findings:
            return []

        severity_rank = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
        }

        counts: dict[str, int] = {}
        latest: dict[str, RiskFinding] = {}
        for f in findings:
            counts[f.flag] = counts.get(f.flag, 0) + 1
            latest[f.flag] = f

        items = []
        for flag, cnt in counts.items():
            f = latest[flag]
            items.append((severity_rank[f.severity], cnt, f))

        items.sort(key=lambda x: (x[0], x[1]), reverse=True)
        out = [x[2] for x in items[: max(0, int(limit))]]
        return out

    def _dedupe_findings(self, findings: Sequence[RiskFinding]) -> list[RiskFinding]:
        seen: set[str] = set()
        out: list[RiskFinding] = []
        for f in findings:
            key = f"{f.flag}:{f.severity.value}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _fingerprint_event(
        self,
        event: FinancialEvent,
        risk_score: float,
        signals: Sequence[RiskSignal],
        findings: Sequence[RiskFinding],
    ) -> str:
        base = {
            "event": {
                "id": event.id,
                "type": event.event_type.value,
                "channel": event.channel.value,
                "money": {"amount": float(event.money.amount), "currency": event.money.currency},
                "occurred_at": event.occurred_at.isoformat(),
                "tenant_id": event.tenant_id,
                "user_id": event.user_id,
                "counterparty_id": event.counterparty.id if event.counterparty else None,
                "reference_id": event.reference_id,
            },
            "risk_score": float(risk_score),
            "signals": [{"n": s.name, "s": float(s.score), "w": float(s.weight)} for s in signals],
            "findings": [{"f": f.flag, "sev": f.severity.value} for f in findings],
        }
        return _sha256_hex(_stable_json(base))

    def _fingerprint_portfolio(
        self,
        tenant_id: str,
        ws: datetime,
        we: datetime,
        totals: Mapping[str, float],
        avg_score: float,
        p95: float,
        level: RiskLevel,
        findings: Sequence[RiskFinding],
        scenario: Optional[StressScenario],
    ) -> str:
        base = {
            "tenant_id": tenant_id,
            "window_start": ws.isoformat(),
            "window_end": we.isoformat(),
            "totals": {k: float(v) for k, v in sorted(totals.items(), key=lambda kv: kv[0])},
            "avg": float(avg_score),
            "p95": float(p95),
            "level": level.value,
            "findings": [{"f": f.flag, "sev": f.severity.value} for f in findings],
            "scenario": scenario.id if scenario else None,
        }
        return _sha256_hex(_stable_json(base))
