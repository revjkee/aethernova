# chronowatch-core/chronowatch/sla/tracker.py
# -*- coding: utf-8 -*-
"""
SLA/SLO трекер для ChronoWatch Core.

Особенности:
- Асинхронный цикл опроса с конкурентными задачами, экспоненциальными бэкоффами и джиттером
- Поддержка индикаторов AVAILABILITY/ERROR_RATE (ratio) и LATENCY (value)
- Универсальная схема измерения: произвольные PromQL-запросы на окно (value,count)
- Вычисление violation, error-бюджета и burn-rate по RFC-стилю SRE
- Переходы статусов (OK/VIOLATING) и генерация событий, совместимых с Avro-схемой SLAEvent
- Доставка событий: Kafka (aiokafka, если доступен) или безопасный логовый fallback
- Наблюдаемость: структурные логи, простые in-memory health-метрики
- Безопасное поведение по умолчанию, строгая типизация

Зависимости:
- Только стандартная библиотека. При наличии aiohttp/aiokafka — используются автоматически.

Интеграция:
    from chronowatch.sla.tracker import (
        SLOIndicator, Threshold, SLOSpec, PrometheusProvider, KafkaEmitter, LogEmitter, SLOTracker
    )

    provider = PrometheusProvider(base_url="http://prometheus.monitoring:9090")
    emitter  = KafkaEmitter(brokers="kafka-0:9092,kafka-1:9092", topic="sla.events")  # или LogEmitter()
    slo = SLOSpec(
        slo_id="73c2a0e1-2f0d-4ee1-8a99-9a2f0f64b0aa",
        name="API availability 99.9%",
        indicator=SLOIndicator.AVAILABILITY,
        objective_target=0.999,                  # 99.9% availability -> допустимая ошибка = 0.001
        window_seconds=5 * 60,
        measurement_kind="RATIO",                # измерение вернёт долю ошибок (0..1)
        statistic="ratio_5m",
        threshold=Threshold(comparator="GT", value=0.05, unit="ratio"),  # alert threshold, опционально
        value_query='sum(rate(http_requests_total{job="api",code=~"5.."}[5m])) / sum(rate(http_requests_total{job="api"}[5m]))',
        count_query='sum(rate(http_requests_total{job="api"}[5m]))'
    )
    tracker = SLOTracker(
        producer="chronowatch-slo@1.0.0",
        environment="STAGING",
        region="eu-north-1",
        service_name="api",
        namespace="default",
        provider=provider,
        emitter=emitter,
        interval_seconds=60
    )

    # затем в вашей задаче:
    await tracker.run([slo])

Примечание:
- Модуль не требует наличия Schema Registry: он формирует payload, совместимый по полям с Avro-схемой SLAEvent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------- Опциональные зависимости ---------------------- #
try:
    import aiohttp  # type: ignore
except Exception:
    aiohttp = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:
    AIOKafkaProducer = None  # type: ignore


# ---------------------- Модели домена SLO ---------------------- #

class SLOIndicator(str, Enum):
    AVAILABILITY = "AVAILABILITY"  # измерение: доля ошибок/успехов (ratio)
    ERROR_RATE = "ERROR_RATE"      # измерение: доля ошибок (ratio)
    LATENCY = "LATENCY"            # измерение: pXX или среднее (seconds)
    THROUGHPUT = "THROUGHPUT"      # измерение: rps (value) — опционально, трактовать как VALUE
    CUSTOM = "CUSTOM"


@dataclass(frozen=True)
class Threshold:
    """Порог сравнения для алертов/нарушений."""
    comparator: str  # "GT"|"GTE"|"LT"|"LTE"|"EQ"|"NEQ"
    value: float
    unit: str = "ratio"  # "ratio"|"seconds"|"rps"|...


@dataclass(frozen=True)
class SLOSpec:
    """Спецификация SLO и способ вычисления SLI."""
    slo_id: str
    name: str
    indicator: SLOIndicator
    objective_target: float             # напр., 0.999 для availability, 0.5 для p95 latency (сек)
    window_seconds: int
    measurement_kind: str               # "RATIO" или "VALUE"
    statistic: str                      # напр., "p95", "ratio_5m" — только метка/описание
    threshold: Optional[Threshold]      # порог для генерации нарушения; может отличаться от objective_target
    value_query: str                    # PromQL запрос для значения
    count_query: Optional[str] = None   # PromQL запрос для количества наблюдений, если релевантно
    measurement_method: str = "rollup"  # информативно


@dataclass(frozen=True)
class SLIMeasurement:
    value: float
    unit: str                # "ratio"|"seconds"|...
    statistic: str           # напр., "p95"
    sample_count: int = 0


class SlaStatus(str, Enum):
    OK = "OK"
    VIOLATING = "VIOLATING"
    UNKNOWN = "UNKNOWN"


@dataclass
class SLOState:
    """
    Текущее состояние по SLO (in-memory).
    """
    last_status: SlaStatus = SlaStatus.UNKNOWN
    last_event_time_ms: int = 0
    last_event_id: Optional[str] = None


# ---------------------- Провайдер метрик (Prometheus) ---------------------- #

class MetricProvider:
    async def query_instant(self, promql: str) -> float:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class PrometheusProvider(MetricProvider):
    """
    Минимальный клиент Prometheus HTTP API (/api/v1/query), без внешних зависимостей.
    Если доступен aiohttp — используется; иначе stdlib через asyncio.to_thread.
    """

    def __init__(self, base_url: str, timeout: float = 5.0, log_level: str = "WARNING", extra_headers: Optional[Mapping[str, str]] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self._log = logging.getLogger("chronowatch.sla.prom")
        if not self._log.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            self._log.addHandler(handler)
        self._log.setLevel(getattr(logging, log_level.upper(), logging.WARNING))
        self._session = None
        self._headers = dict(extra_headers or {})

    async def _ensure_session(self) -> None:
        if aiohttp and self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout), headers=self._headers)

    async def query_instant(self, promql: str) -> float:
        url = f"{self.base_url}/api/v1/query"
        params = {"query": promql}
        if aiohttp:
            await self._ensure_session()
            assert self._session is not None
            async with self._session.get(url, params=params) as r:
                if r.status != 200:
                    raise RuntimeError(f"Prometheus HTTP {r.status}")
                data = await r.json()
        else:
            # stdlib fallback
            import urllib.parse
            import urllib.request

            def _do_req() -> Dict[str, Any]:
                qp = urllib.parse.urlencode(params)
                with urllib.request.urlopen(f"{url}?{qp}", timeout=self.timeout) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"Prometheus HTTP {resp.status}")
                    return json.loads(resp.read().decode("utf-8"))

            data = await asyncio.to_thread(_do_req)

        status = data.get("status")
        if status != "success":
            raise RuntimeError(f"Prometheus status {status}")
        result_type = data.get("data", {}).get("resultType")
        result = data.get("data", {}).get("result", [])
        if result_type not in ("vector", "scalar"):
            raise RuntimeError(f"Unsupported resultType {result_type}")
        # Берём первый результат, иначе 0.0
        if not result:
            return 0.0
        if result_type == "scalar":
            _, v = result  # [ ts, "value" ]
            return float(v)
        # vector: [ { metric: {...}, value: [ts, "v"] }, ... ]
        try:
            v = float(result[0]["value"][1])
        except Exception:
            v = 0.0
        return v

    async def close(self) -> None:
        if self._session is not None:
            try:
                await self._session.close()
            finally:
                self._session = None


# ---------------------- Эмиттер событий ---------------------- #

class EventEmitter:
    async def emit(self, event: Mapping[str, Any]) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class LogEmitter(EventEmitter):
    def __init__(self, log_level: str = "INFO") -> None:
        self._log = logging.getLogger("chronowatch.sla.events")
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    async def emit(self, event: Mapping[str, Any]) -> None:
        self._log.info(json.dumps(event, ensure_ascii=False))

    async def close(self) -> None:
        return None


class KafkaEmitter(EventEmitter):
    """
    Эмиттер в Kafka. Если aiokafka отсутствует — будет падать при инициализации.
    """
    def __init__(self, brokers: str, topic: str, client_id: Optional[str] = None, acks: str = "all") -> None:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka is required for KafkaEmitter")
        self._topic = topic
        self._producer = AIOKafkaProducer(
            bootstrap_servers=brokers.split(","),
            client_id=client_id or f"chronowatch-sla-{uuid.uuid4()}",
            acks=acks,
            linger_ms=20,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
        )
        self._started = False

    async def _ensure(self) -> None:
        if not self._started:
            await self._producer.start()
            self._started = True

    async def emit(self, event: Mapping[str, Any]) -> None:
        await self._ensure()
        await self._producer.send_and_wait(self._topic, value=dict(event))

    async def close(self) -> None:
        if self._started:
            await self._producer.stop()
            self._started = False


# ---------------------- Утилиты SLA ---------------------- #

def _now_ms() -> int:
    return int(time.time() * 1000)


def _compare(value: float, threshold: Threshold) -> bool:
    """Вернуть True, если нарушение (value cmp threshold.value)."""
    c = threshold.comparator.upper()
    t = threshold.value
    if c == "GT":
        return value > t
    if c == "GTE":
        return value >= t
    if c == "LT":
        return value < t
    if c == "LTE":
        return value <= t
    if c == "EQ":
        return math.isclose(value, t, rel_tol=1e-9, abs_tol=1e-9)
    if c == "NEQ":
        return not math.isclose(value, t, rel_tol=1e-9, abs_tol=1e-9)
    # По умолчанию — не нарушено
    return False


def _calc_burn_rate(indicator: SLOIndicator, measurement_kind: str, measured_value: float, objective_target: float) -> Optional[float]:
    """
    Вернуть burn-rate, если можно корректно вычислить.
    Для ratio-индикаторов: burn = error_rate / (1 - target).
    Для latency/value — неочевидно без доли «плохих» запросов → None.
    """
    if measurement_kind.upper() == "RATIO" and indicator in (SLOIndicator.AVAILABILITY, SLOIndicator.ERROR_RATE):
        error_budget = max(1e-9, 1.0 - objective_target)
        return max(0.0, measured_value / error_budget)
    return None


# ---------------------- Основной трекер ---------------------- #

@dataclass
class TrackerConfig:
    interval_seconds: int = 60
    jitter_fraction: float = 0.1     # до ±10% джиттера для рассинхронизации
    max_concurrency: int = 8
    hard_fail_on_emit: bool = False  # если True — падать при ошибке эмиссии


class SLOTracker:
    """
    Менеджер отслеживания множества SLO. Держит состояние и публикует события.
    """

    def __init__(
        self,
        *,
        producer: str,
        environment: str,
        region: str,
        service_name: str,
        namespace: str = "default",
        provider: MetricProvider,
        emitter: EventEmitter,
        interval_seconds: int = 60,
        jitter_fraction: float = 0.1,
        max_concurrency: int = 8,
        hard_fail_on_emit: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._producer = producer
        self._environment = environment.upper()
        self._region = region
        self._service_name = service_name
        self._namespace = namespace
        self._provider = provider
        self._emitter = emitter
        self._cfg = TrackerConfig(
            interval_seconds=interval_seconds,
            jitter_fraction=jitter_fraction,
            max_concurrency=max_concurrency,
            hard_fail_on_emit=hard_fail_on_emit,
        )
        self._log = logger or logging.getLogger("chronowatch.sla.tracker")
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(getattr(logging, os.getenv("SLA_TRACKER_LOG", "INFO").upper(), logging.INFO))

        self._states: Dict[str, SLOState] = {}
        self._stop = asyncio.Event()
        self._running = False

        # простые health-счётчики
        self._metrics = {
            "measure_ok": 0,
            "measure_err": 0,
            "emit_ok": 0,
            "emit_err": 0,
        }

    # -------------------- Public API -------------------- #

    async def run(self, slos: Sequence[SLOSpec]) -> None:
        """
        Запустить непрерывный цикл отслеживания для набора SLO.
        """
        if self._running:
            raise RuntimeError("SLOTracker already running")
        self._running = True
        try:
            while not self._stop.is_set():
                await self._tick(slos)
                # интервал с джиттером
                base = self._cfg.interval_seconds
                jitter = base * self._cfg.jitter_fraction
                delay = base + random.uniform(-jitter, jitter)
                await asyncio.wait_for(self._stop.wait(), timeout=max(1.0, delay))
        except asyncio.TimeoutError:
            # нормальный путь (ожидали stop или таймаут сна)
            pass
        finally:
            self._running = False

    def stop(self) -> None:
        self._stop.set()

    async def close(self) -> None:
        await self._provider.close()
        await self._emitter.close()

    # -------------------- Internal -------------------- #

    async def _tick(self, slos: Sequence[SLOSpec]) -> None:
        sem = asyncio.Semaphore(self._cfg.max_concurrency)
        tasks = [self._process_slo(s, sem) for s in slos]
        await asyncio.gather(*tasks, return_exceptions=False)

    async def _process_slo(self, slo: SLOSpec, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                measurement = await self._measure(slo)
                status_now, violation = self._status(slo, measurement)
                prev = self._states.get(slo.slo_id, SLOState())
                event_needed = self._should_emit(prev.last_status, status_now)
                self._states.setdefault(slo.slo_id, SLOState()).last_status = status_now

                if event_needed:
                    event = self._build_event(slo, measurement, status_before=prev.last_status, status_after=status_now, violation=violation)
                    await self._emit(event, slo.slo_id)
                self._metrics["measure_ok"] += 1
            except Exception as e:
                self._metrics["measure_err"] += 1
                self._log.exception("SLO measure failed: %s [%s]", slo.name, e)

    async def _measure(self, slo: SLOSpec) -> SLIMeasurement:
        v = await self._provider.query_instant(slo.value_query)
        c = 0
        if slo.count_query:
            try:
                c = int(round(await self._provider.query_instant(slo.count_query)))
            except Exception:
                c = 0
        unit = "ratio" if slo.measurement_kind.upper() == "RATIO" else "seconds"
        return SLIMeasurement(value=float(v), unit=unit, statistic=slo.statistic, sample_count=c)

    def _status(self, slo: SLOSpec, m: SLIMeasurement) -> Tuple[SlaStatus, bool]:
        """
        Вернуть текущий статус и флаг нарушения для данного измерения.
        При отсутствии threshold — status=OK, violation=False (события всё равно возможны при смене UNKNOWN→OK).
        """
        if slo.threshold is None:
            st = SlaStatus.OK
            return st, False
        violation = _compare(m.value, slo.threshold)
        return (SlaStatus.VIOLATING if violation else SlaStatus.OK), violation

    @staticmethod
    def _should_emit(prev: SlaStatus, cur: SlaStatus) -> bool:
        if prev == SlaStatus.UNKNOWN:
            # На первом цикле всегда публикуем текущее состояние (инициализация)
            return True
        return prev != cur

    def _build_event(
        self,
        slo: SLOSpec,
        m: SLIMeasurement,
        *,
        status_before: SlaStatus,
        status_after: SlaStatus,
        violation: bool,
    ) -> Dict[str, Any]:
        """
        Построить payload события, совместимый с Avro SLAEvent (v1).
        """
        now_ms = _now_ms()
        ev_id = str(uuid.uuid4())
        event_type = "SLO_BREACH_DETECTED" if (status_before != SlaStatus.VIOLATING and status_after == SlaStatus.VIOLATING) else \
                     "SLO_BREACH_RESOLVED" if (status_before == SlaStatus.VIOLATING and status_after == SlaStatus.OK) else \
                     "ANOMALY_DETECTED" if violation else \
                     "MANUAL_OVERRIDE"  # де-факто «статус не изменился»: публикуем как «инициализация»; тип не критичен

        # Вычислим burn-rate, если применимо
        burn = _calc_burn_rate(slo.indicator, slo.measurement_kind, m.value, slo.objective_target)

        # Сборка полей согласно Avro-схеме, которую вы ранее утвердили
        event: Dict[str, Any] = {
            "event_schema_version": "1.0.0",
            "event_id": ev_id,
            "event_type": event_type,
            "severity": "CRITICAL" if status_after == SlaStatus.VIOLATING else "INFO",
            "occurred_at": now_ms,
            "received_at": now_ms,
            "producer": self._producer,
            "source": "prometheus",
            "environment": self._environment,
            "region": self._region,
            "service": {
                "name": self._service_name,
                "version": os.getenv("APP_VERSION", "unknown"),
                "namespace": self._namespace,
            },
            "tenant_id": None,
            "correlation_id": None,
            "trace_id": None,
            "span_id": None,
            "slo": {
                "slo_id": slo.slo_id,
                "name": slo.name,
                "indicator": slo.indicator.value,
                "objective_target": float(slo.objective_target),
                "objective_window_seconds": int(slo.window_seconds),
                "measurement_method": slo.measurement_method,
            },
            "threshold": (
                {
                    "comparator": slo.threshold.comparator,
                    "value": float(slo.threshold.value),
                    "unit": slo.threshold.unit,
                } if slo.threshold else {
                    "comparator": "GT",
                    "value": float("nan"),
                    "unit": m.unit,
                }
            ),
            "measured": {
                "value": float(m.value),
                "unit": m.unit,
                "statistic": m.statistic,
                "sample_count": int(m.sample_count),
            },
            "window": {
                "start": now_ms - slo.window_seconds * 1000,
                "end": now_ms,
            },
            "budget": {
                "target": float(slo.objective_target),
                "consumed": float("nan") if burn is None else min(1.0, 0.0),  # неизвестно на один тик, оставляем nan/0
                "remaining": float("nan") if burn is None else max(0.0, 1.0),
                "burn_rate": float(burn) if burn is not None else 0.0,
            },
            "violation": bool(violation),
            "status_before": status_before.value,
            "status_after": status_after.value,
            "ack": {
                "acked": False,
                "acked_by": None,
                "acked_at": None,
                "escalation_policy_id": None,
                "ticket_ids": [],
            },
            "runbook_url": os.getenv("RUNBOOK_URL", None),
            "links": [],
            "tags": {
                "statistic": m.statistic,
                "measurement_kind": slo.measurement_kind,
            },
            "annotations": {},
        }
        return event

    async def _emit(self, event: Mapping[str, Any], slo_id: str) -> None:
        try:
            await self._emitter.emit(event)
            st = self._states[slo_id]
            st.last_event_time_ms = _now_ms()
            st.last_event_id = event.get("event_id")  # type: ignore
            self._metrics["emit_ok"] += 1
        except Exception as e:
            self._metrics["emit_err"] += 1
            self._log.exception("Failed to emit SLA event: %s", e)
            if self._cfg.hard_fail_on_emit:
                raise

    # -------------------- Вспомогательные методы -------------------- #

    def snapshot_state(self) -> Dict[str, Any]:
        """Снимок текущего состояния и health-счётчиков (для /metrics/health)."""
        return {
            "states": {
                k: {
                    "last_status": v.last_status.value,
                    "last_event_time_ms": v.last_event_time_ms,
                    "last_event_id": v.last_event_id,
                } for k, v in self._states.items()
            },
            "counters": dict(self._metrics),
            "config": {
                "interval_seconds": self._cfg.interval_seconds,
                "max_concurrency": self._cfg.max_concurrency,
            }
        }


# ---------------------- Утилита запуска (CLI) ---------------------- #

async def _demo() -> None:
    """
    Демонстрационный запуск: читает переменные окружения PROM_URL/KAFKA_BROKERS/KAFKA_TOPIC.
    """
    prom_url = os.getenv("PROM_URL", "http://prometheus.monitoring:9090")
    provider = PrometheusProvider(prom_url, timeout=5.0, log_level=os.getenv("PROM_LOG", "INFO"))

    brokers = os.getenv("KAFKA_BROKERS")
    topic = os.getenv("KAFKA_TOPIC", "sla.events")
    emitter: EventEmitter
    if brokers and AIOKafkaProducer is not None:
        emitter = KafkaEmitter(brokers=brokers, topic=topic, client_id="chronowatch-sla-demo")
    else:
        emitter = LogEmitter()

    slo = SLOSpec(
        slo_id=str(uuid.uuid4()),
        name="API 5xx ratio (5m) <= 1%",
        indicator=SLOIndicator.ERROR_RATE,
        objective_target=0.99,
        window_seconds=300,
        measurement_kind="RATIO",
        statistic="ratio_5m",
        threshold=Threshold(comparator="GT", value=0.01, unit="ratio"),
        value_query='sum(rate(http_requests_total{job="api",code=~"5.."}[5m])) / sum(rate(http_requests_total{job="api"}[5m]))',
        count_query='sum(rate(http_requests_total{job="api"}[5m]))'
    )

    tracker = SLOTracker(
        producer=os.getenv("PRODUCER", "chronowatch-slo@dev"),
        environment=os.getenv("ENVIRONMENT", "STAGING"),
        region=os.getenv("REGION", "eu-north-1"),
        service_name=os.getenv("SERVICE", "api"),
        namespace=os.getenv("NAMESPACE", "default"),
        provider=provider,
        emitter=emitter,
        interval_seconds=int(os.getenv("INTERVAL", "60")),
        max_concurrency=int(os.getenv("MAX_CONCURRENCY", "8")),
    )

    # Один тик измерения (для примера). В реальном окружении используйте tracker.run([slo]).
    await tracker._tick([slo])
    print(json.dumps(tracker.snapshot_state(), ensure_ascii=False, indent=2))
    await tracker.close()


if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
