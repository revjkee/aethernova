# SPDX-License-Identifier: Apache-2.0
"""
physical_integration/telemetry/units.py

Асинхронный сервис телеметрии для киберфизических единиц (units):
- Модели событий (GAUGE/COUNTER/HISTOGRAM/HEARTBEAT/EVENT) с Pydantic-валидацией
- Очереди с backpressure, приоритетами и бэчингом
- Экспортеры (sinks): Prometheus (локальный экспорт) и Kafka (опционально, aiokafka)
- Экспоненциальные ретраи с джиттером, идемпотентность по ключам событий
- Промышленные метрики самого сервиса (если установлен prometheus_client)

Зависимости (мягкие):
  - pydantic>=1.10
  - prometheus_client (опционально)
  - aiokafka (опционально, для Kafka)
Python >= 3.10
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:  # pragma: no cover
    raise RuntimeError("pydantic is required for telemetry models") from e

# Опциональные зависимости
try:
    from prometheus_client import Counter as PmCounter, Gauge as PmGauge, Histogram as PmHistogram, start_http_server  # type: ignore
    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
    _KAFKA_AVAILABLE = True
except Exception:
    _KAFKA_AVAILABLE = False


log = logging.getLogger(__name__)
logging.basicConfig(
    level=os.getenv("PIC_TEL_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# =========================
# Модели событий телеметрии
# =========================

class MetricKind(str):
    GAUGE = "gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    HEARTBEAT = "heartbeat"
    EVENT = "event"  # нефакторизуемое событие (не уходит в Prometheus метрику)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _sanitize_label_key(k: str) -> str:
    # Prometheus допускает [a-zA-Z_][a-zA-Z0-9_]*
    safe = []
    for i, ch in enumerate(k):
        if (ch.isalpha() or ch == "_") if i == 0 else (ch.isalnum() or ch == "_"):
            safe.append(ch)
        else:
            safe.append("_")
    return "".join(safe)


class UnitMetric(BaseModel):
    """Единичная метрика/событие телеметрии."""
    unit_id: str = Field(..., description="UUID устройства или стабильный идентификатор")
    name: str = Field(..., min_length=1, max_length=128, description="Имя метрики, например 'cpu_util' или 'temperature_c'")
    kind: str = Field(..., regex="^(gauge|counter|histogram|heartbeat|event)$")
    value: Optional[float] = Field(None, description="Значение для gauge/counter/histogram")
    labels: Dict[str, str] = Field(default_factory=dict, description="Доп. метки (Prometheus-совместимые)")
    timestamp: str = Field(default_factory=_now_iso, description="ISO8601 UTC")
    idempotency_key: Optional[str] = Field(None, description="Ключ идемпотентности для доставки")
    priority: int = Field(5, ge=0, le=9, description="0=максимальный приоритет, 9=минимальный")

    # Специфично для histogram
    histogram_buckets: Optional[List[float]] = Field(None, description="Пользовательские границы бакетов")

    # Полезная нагрузка для EVENT
    event_payload: Optional[Dict[str, Any]] = Field(None)

    @validator("unit_id")
    def _unit_id_not_empty(cls, v: str) -> str:
        if not v or len(v) < 3:
            raise ValueError("unit_id must be non-empty")
        return v

    @validator("labels", pre=True)
    def _labels_sanitize(cls, v: Mapping[str, Any] | None) -> Dict[str, str]:
        v = dict(v or {})
        out = {}
        for k, val in v.items():
            out[_sanitize_label_key(str(k))] = str(val)
        return out

    @validator("value")
    def _value_required_for_metric(cls, v: Optional[float], values: Mapping[str, Any]) -> Optional[float]:
        if values.get("kind") in (MetricKind.GAUGE, MetricKind.COUNTER, MetricKind.HISTOGRAM, MetricKind.HEARTBEAT):
            if v is None:
                raise ValueError("value is required for gauge/counter/histogram/heartbeat")
        return v

    @validator("histogram_buckets")
    def _buckets_sorted(cls, v: Optional[List[float]], values: Mapping[str, Any]) -> Optional[List[float]]:
        if values.get("kind") == MetricKind.HISTOGRAM and v:
            if sorted(v) != v:
                raise ValueError("histogram_buckets must be sorted ascending")
        return v


# =========================
# Конфиги приёмников и сервиса
# =========================

@dataclass
class PrometheusConfig:
    enabled: bool = True
    http_port: int = 9108
    namespace: str = "pic"
    subsystem: str = "telemetry"
    # Бакеты по умолчанию — подходят для температур/времени/небольших величин
    default_buckets: Tuple[float, ...] = (0.1, 0.5, 1, 2.5, 5, 10, 20, 50, 100)

@dataclass
class KafkaConfig:
    enabled: bool = False
    bootstrap_servers: str = "localhost:9092"
    topic: str = "pic.telemetry"
    acks: str = "all"
    linger_ms: int = 10
    batch_size: int = 16384
    compression_type: Optional[str] = "gzip"
    # SASL/SSL при необходимости
    security_protocol: Optional[str] = None  # PLAINTEXT, SASL_PLAINTEXT, SASL_SSL, SSL
    sasl_mechanism: Optional[str] = None     # SCRAM-SHA-256/SCRAM-SHA-512/PLAIN
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None

@dataclass
class TelemetryServiceConfig:
    queue_maxsize: int = 10000
    batch_max: int = 500
    flush_interval_s: float = 1.0
    max_retry_backoff_s: float = 30.0
    idempotency_ttl_s: int = 300


# =========================
# Интерфейс sink’а
# =========================

class TelemetrySink(ABC):
    @abstractmethod
    async def start(self) -> None: ...
    @abstractmethod
    async def stop(self) -> None: ...
    @abstractmethod
    async def submit(self, items: Sequence[UnitMetric]) -> None: ...


# =========================
# Prometheus sink
# =========================

class PrometheusSink(TelemetrySink):
    """
    Экспортер в локальный Prometheus-реестр.
    Динамически создает семейства метрик по ключу (name, kind, tuple(sorted(labels))).
    """
    def __init__(self, cfg: PrometheusConfig):
        if not _PROM_AVAILABLE and cfg.enabled:
            log.warning("prometheus_client not installed; Prometheus sink will be disabled")
        self.cfg = cfg
        self._families: Dict[Tuple[str, str, Tuple[str, ...]], Any] = {}
        self._server_started = False

    async def start(self) -> None:
        if not self.cfg.enabled or not _PROM_AVAILABLE:
            return
        if not self._server_started:
            try:
                start_http_server(self.cfg.http_port)
                self._server_started = True
                log.info("Prometheus exporter started on :%d", self.cfg.http_port)
            except Exception as e:
                log.warning("Failed to start Prometheus exporter: %s", e)

    async def stop(self) -> None:
        # prometheus_client не поддерживает останов HTTP сервера; ничего не делаем
        return

    def _key(self, m: UnitMetric) -> Tuple[str, str, Tuple[str, ...]]:
        label_keys = tuple(sorted(m.labels.keys()))
        return (m.name, m.kind, label_keys)

    def _family(self, m: UnitMetric):
        key = self._key(m)
        fam = self._families.get(key)
        if fam:
            return fam

        # Создание подходящего семейства
        help_text = f"{self.cfg.namespace}_{self.cfg.subsystem}_{m.name}"
        label_names = list(sorted(m.labels.keys()))
        if m.kind == MetricKind.GAUGE:
            fam = PmGauge(help_text, help_text, labelnames=label_names) if _PROM_AVAILABLE else None
        elif m.kind == MetricKind.COUNTER:
            fam = PmCounter(help_text, help_text, labelnames=label_names) if _PROM_AVAILABLE else None
        elif m.kind in (MetricKind.HISTOGRAM, MetricKind.HEARTBEAT):
            buckets = tuple(m.histogram_buckets) if m.histogram_buckets else self.cfg.default_buckets
            fam = PmHistogram(help_text, help_text, labelnames=label_names, buckets=buckets) if _PROM_AVAILABLE else None
        else:
            fam = None  # EVENT не отображается в Prometheus
        self._families[key] = fam
        return fam

    async def submit(self, items: Sequence[UnitMetric]) -> None:
        if not self.cfg.enabled or not _PROM_AVAILABLE:
            return
        for m in items:
            fam = self._family(m)
            if not fam:
                continue
            labels = [m.labels[k] for k in sorted(m.labels.keys())]
            if m.kind == MetricKind.GAUGE:
                fam.labels(*labels).set(float(m.value))
            elif m.kind == MetricKind.COUNTER:
                fam.labels(*labels).inc(float(m.value))
            elif m.kind in (MetricKind.HISTOGRAM, MetricKind.HEARTBEAT):
                fam.labels(*labels).observe(float(m.value))


# =========================
# Kafka sink (опционально)
# =========================

class KafkaSink(TelemetrySink):
    """
    Отправка батчей телеметрии в Kafka в JSONL.
    Если aiokafka отсутствует или отключено — sink неактивен, вызовы no-op.
    """
    def __init__(self, cfg: KafkaConfig):
        self.cfg = cfg
        self._producer: Optional[AIOKafkaProducer] = None  # type: ignore

        if not _KAFKA_AVAILABLE and self.cfg.enabled:
            log.warning("aiokafka not installed; Kafka sink will be disabled")

    async def start(self) -> None:
        if not self.cfg.enabled or not _KAFKA_AVAILABLE:
            return
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.cfg.bootstrap_servers,
            acks=self.cfg.acks,
            linger_ms=self.cfg.linger_ms,
            batch_size=self.cfg.batch_size,
            compression_type=self.cfg.compression_type,
            security_protocol=self.cfg.security_protocol,
            sasl_mechanism=self.cfg.sasl_mechanism,
            sasl_plain_username=self.cfg.sasl_username,
            sasl_plain_password=self.cfg.sasl_password,
            value_serializer=lambda v: v,  # bytes already
            key_serializer=lambda v: v,    # bytes or None
        )
        await self._producer.start()
        log.info("Kafka producer started to %s topic=%s", self.cfg.bootstrap_servers, self.cfg.topic)

    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()
            self._producer = None

    async def submit(self, items: Sequence[UnitMetric]) -> None:
        if not self._producer or not self.cfg.enabled:
            return
        # Формат: JSONL (по одной записи на строку), ключ — unit_id
        payloads: List[Tuple[bytes, bytes]] = []
        for m in items:
            body = {
                "unit_id": m.unit_id,
                "name": m.name,
                "kind": m.kind,
                "value": m.value,
                "labels": m.labels,
                "timestamp": m.timestamp,
                "idempotency_key": m.idempotency_key,
                "event_payload": m.event_payload,
            }
            payloads.append((m.unit_id.encode("utf-8"), json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))

        # Параллельно отправим все записи
        futures = []
        for key, val in payloads:
            futures.append(self._producer.send_and_wait(self.cfg.topic, value=val, key=key))
        # Дожидаемся всех
        await asyncio.gather(*futures)


# =========================
# Сервис телеметрии
# =========================

class TelemetryService:
    """
    Асинхронный сервис приема и доставки метрик.
    Использует одну основную очередь с ограничением размера и приоритетный сброс.
    """

    def __init__(
        self,
        svc_cfg: TelemetryServiceConfig,
        prom_cfg: PrometheusConfig | None = None,
        kafka_cfg: KafkaConfig | None = None,
    ):
        self.cfg = svc_cfg
        self.queue: asyncio.PriorityQueue[Tuple[int, float, UnitMetric]] = asyncio.PriorityQueue(maxsize=svc_cfg.queue_maxsize)
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._sinks: List[TelemetrySink] = []

        # идемпотентность (память на короткое время)
        self._idem: Dict[str, float] = {}
        self._idem_ttl = svc_cfg.idempotency_ttl_s

        # Метрики сервиса
        self._m = self._init_metrics()

        if prom_cfg and prom_cfg.enabled:
            self._sinks.append(PrometheusSink(prom_cfg))
        if kafka_cfg and kafka_cfg.enabled:
            self._sinks.append(KafkaSink(kafka_cfg))

    # ---------- Публичный API ----------

    async def start(self) -> None:
        for s in self._sinks:
            await s.start()
        self._task = asyncio.create_task(self._run(), name="telemetry-service")
        log.info("TelemetryService started with %d sinks", len(self._sinks))

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
        for s in self._sinks:
            await s.stop()
        log.info("TelemetryService stopped")

    async def emit(self, metric: UnitMetric) -> bool:
        """
        Публикация метрики во внутреннюю очередь.
        Возвращает True, если принято; False, если отброшено (переполнение и приоритет ниже).
        """
        # Идемпотентность (если задан ключ)
        if metric.idempotency_key:
            if not self._check_and_store_idem(metric.idempotency_key):
                self._inc("dropped_idempotent_total")
                return True  # молча считаем, что событие уже доставлено

        prio_key = metric.priority  # 0..9
        ts = time.time()

        try:
            self.queue.put_nowait((prio_key, ts, metric))
            self._gauge("queue_size", self.queue.qsize())
            self._inc("accepted_total")
            return True
        except asyncio.QueueFull:
            # Вытесняем самым низким приоритетом: если у нового приоритет выше (число меньше) — заменяем
            try:
                worst = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                self._inc("dropped_queue_full_total")
                return False
            worst_prio, _, _ = worst
            if prio_key < worst_prio:
                # Новый важнее — вытесняем старый
                self._inc("evicted_total")
                try:
                    self.queue.put_nowait((prio_key, ts, metric))
                    self._gauge("queue_size", self.queue.qsize())
                    return True
                except asyncio.QueueFull:
                    self._inc("dropped_queue_full_total")
                    return False
            else:
                # Новый менее важен — отброс
                self._inc("dropped_queue_full_total")
                # Возвратим старый назад
                try:
                    self.queue.put_nowait(worst)
                except asyncio.QueueFull:
                    # редкий случай, игнорируем
                    pass
                return False

    # ---------- Внутренняя логика ----------

    async def _run(self) -> None:
        backoff = 0.5
        last_flush = time.time()
        batch: List[UnitMetric] = []

        # Метрики Prometheus-экспортера (если доступен)
        prom_http_port = None
        for s in self._sinks:
            if isinstance(s, PrometheusSink) and s.cfg.enabled:
                prom_http_port = s.cfg.http_port
        if _PROM_AVAILABLE and prom_http_port:
            try:
                # Если PrometheusSink ещё не поднял HTTP сервер — стартует сам в start()
                pass
            except Exception:
                pass

        while not self._stop.is_set():
            flush_due = (time.time() - last_flush) >= self.cfg.flush_interval_s
            need_more = len(batch) < self.cfg.batch_max

            try:
                timeout = 0 if (flush_due or not need_more) else max(0.0, self.cfg.flush_interval_s - (time.time() - last_flush))
                item = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                batch.append(item[2])
                self._inc("dequeued_total")
                self._gauge("queue_size", self.queue.qsize())
            except asyncio.TimeoutError:
                pass

            if len(batch) >= self.cfg.batch_max or (batch and flush_due):
                ok = await self._flush_with_retry(batch)
                last_flush = time.time()
                if ok:
                    batch.clear()
                    backoff = 0.5
                else:
                    # оставим batch и попробуем позже с увеличенным бэкоффом
                    await asyncio.sleep(backoff + random.random() * 0.2)
                    backoff = min(backoff * 2, self.cfg.max_retry_backoff_s)

        # Финальный сброс при остановке
        if batch:
            await self._flush_with_retry(batch)

    async def _flush_with_retry(self, batch: List[UnitMetric]) -> bool:
        if not batch:
            return True
        # Раскидаем по sink’ам
        ok_all = True
        for s in self._sinks:
            try:
                await s.submit(batch)
            except Exception as e:
                ok_all = False
                self._inc("sink_errors_total")
                log.warning("Telemetry sink %s failed: %s", s.__class__.__name__, e)
        cnt = len(batch)
        if ok_all:
            self._inc("flushed_records_total", cnt)
        return ok_all

    def _check_and_store_idem(self, key: str) -> bool:
        now = time.time()
        exp = self._idem.get(key)
        if exp and exp > now:
            return False
        self._idem[key] = now + self._idem_ttl
        # Очистка старых ключей по мере роста
        if len(self._idem) > 100_000:
            to_del = [k for k, v in self._idem.items() if v <= now]
            for k in to_del:
                self._idem.pop(k, None)
        return True

    # ---------- Метрики сервиса ----------

    def _init_metrics(self) -> Dict[str, Any]:
        if not _PROM_AVAILABLE:
            return {}
        ns = "pic"
        subsys = "telemetry_srv"
        return {
            "accepted_total": PmCounter(f"{ns}_{subsys}_accepted_total", "Accepted metrics"),
            "dequeued_total": PmCounter(f"{ns}_{subsys}_dequeued_total", "Dequeued metrics"),
            "flushed_records_total": PmCounter(f"{ns}_{subsys}_flushed_records_total", "Flushed records"),
            "dropped_queue_full_total": PmCounter(f"{ns}_{subsys}_dropped_queue_full_total", "Dropped due to full queue"),
            "dropped_idempotent_total": PmCounter(f"{ns}_{subsys}_dropped_idempotent_total", "Dropped due to idempotency"),
            "evicted_total": PmCounter(f"{ns}_{subsys}_evicted_total", "Evicted lower-priority item"),
            "sink_errors_total": PmCounter(f"{ns}_{subsys}_sink_errors_total", "Sink errors"),
            "queue_size": PmGauge(f"{ns}_{subsys}_queue_size", "Current queue size"),
        }

    def _inc(self, name: str, n: int = 1) -> None:
        m = self._m.get(name)
        if m:
            m.inc(n)

    def _gauge(self, name: str, val: float) -> None:
        g = self._m.get(name)
        if g:
            g.set(val)


# =========================
# Утилиты для клиента
# =========================

def make_idempotency_key(unit_id: str, name: str, timestamp: str, value: Optional[float]) -> str:
    raw = f"{unit_id}|{name}|{timestamp}|{value}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


# =========================
# Пример самостоятельного запуска
# =========================

async def _demo() -> None:
    """
    Пример: локальный Prometheus-экспорт и (если доступен) Kafka.
    Переменные окружения управляют включением.
      PIC_TEL_PROM_ENABLED=true|false
      PIC_TEL_PROM_PORT=9108
      PIC_TEL_KAFKA_ENABLED=true|false
      PIC_TEL_KAFKA_BOOTSTRAP=localhost:9092
      PIC_TEL_KAFKA_TOPIC=pic.telemetry
    """
    prom_enabled = os.getenv("PIC_TEL_PROM_ENABLED", "true").lower() == "true"
    kafka_enabled = os.getenv("PIC_TEL_KAFKA_ENABLED", "false").lower() == "true"

    prom_cfg = PrometheusConfig(
        enabled=prom_enabled,
        http_port=int(os.getenv("PIC_TEL_PROM_PORT", "9108")),
        namespace="pic",
        subsystem="unit",
    )
    kafka_cfg = KafkaConfig(
        enabled=kafka_enabled,
        bootstrap_servers=os.getenv("PIC_TEL_KAFKA_BOOTSTRAP", "localhost:9092"),
        topic=os.getenv("PIC_TEL_KAFKA_TOPIC", "pic.telemetry"),
    )

    svc = TelemetryService(
        TelemetryServiceConfig(
            queue_maxsize=int(os.getenv("PIC_TEL_QUEUE_MAX", "10000")),
            batch_max=int(os.getenv("PIC_TEL_BATCH_MAX", "500")),
            flush_interval_s=float(os.getenv("PIC_TEL_FLUSH_INTERVAL", "1.0")),
        ),
        prom_cfg=prom_cfg,
        kafka_cfg=kafka_cfg,
    )

    await svc.start()

    unit_id = os.getenv("PIC_UNIT_ID", str(uuid.uuid4()))
    # Сгенерируем несколько метрик
    for i in range(1000):
        m = UnitMetric(
            unit_id=unit_id,
            name="temperature_c",
            kind=MetricKind.GAUGE,
            value=20.0 + random.random() * 5.0,
            labels={"site": "plant-a", "room": "210", "sensor": "temp1"},
            idempotency_key=make_idempotency_key(unit_id, "temperature_c", _now_iso(), i),
            priority=5,
        )
        await svc.emit(m)
        await asyncio.sleep(0.01)

    # heartbeat как histogram (в секундах)
    hb = UnitMetric(
        unit_id=unit_id,
        name="heartbeat_s",
        kind=MetricKind.HEARTBEAT,
        value=1.0,
        labels={"site": "plant-a"},
        histogram_buckets=[0.5, 1, 2, 5],
        priority=3,
    )
    await svc.emit(hb)

    # Событие (EVENT) — попадет только в Kafka sink
    ev = UnitMetric(
        unit_id=unit_id,
        name="disk_alert",
        kind=MetricKind.EVENT,
        value=0.0,
        labels={"severity": "warning"},
        event_payload={"free_bytes": 12345678, "path": "/var"},
        priority=2,
    )
    await svc.emit(ev)

    # Ждем доставки
    await asyncio.sleep(2.0)
    await svc.stop()


if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
