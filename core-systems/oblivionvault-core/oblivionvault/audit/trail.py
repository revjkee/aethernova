# File: oblivionvault/audit/trail.py
# Industrial audit trail for oblivionvault-core
# Python 3.10+

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import io
import json
import logging
import os
import queue
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    _TRACER = None  # type: ignore

# Optional BigQuery sink dependency (adapter from oblivionvault.adapters.storage_bigquery)
try:
    from google.cloud import bigquery  # type: ignore
    _HAS_BQ = True
except Exception:  # pragma: no cover
    _HAS_BQ = False

try:
    # Adapter is optional; sink will guard import
    from oblivionvault.adapters.storage_bigquery import (
        BigQueryStorageAdapter,
        BigQueryConfig,
        BQField,
    )  # type: ignore
    _HAS_OV_BQ_ADAPTER = True
except Exception:  # pragma: no cover
    _HAS_OV_BQ_ADAPTER = False


# ============================== Utilities ===================================

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return uuid.uuid4().hex


def _canonical_dumps(obj: Any) -> str:
    """
    Deterministic JSON canonicalization: UTF-8, sorted keys, no spaces.
    RFC8785-совместимость частичная (без нормализации чисел IEEE-754).
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _blake2b_hex(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _secure_hmac_blake2b(key: bytes, data: bytes) -> str:
    # HMAC с blake2b через hmac.new(digestmod=hashlib.blake2b)
    return hmac.new(key, data, hashlib.blake2b).hexdigest()


def _maybe_span(name: str):
    class _NullCtx:
        def __enter__(self): return None
        def __exit__(self, exc_type, exc, tb): return False
    if _TRACER:
        return _TRACER.start_as_current_span(name)
    return _NullCtx()


# ============================== Data model ==================================

@dataclass(slots=True)
class AuditContext:
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None
    app_name: Optional[str] = None
    node_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    @staticmethod
    def from_env(default_app: Optional[str] = None, default_node: Optional[str] = None) -> "AuditContext":
        # Попытка взять trace_id из OpenTelemetry при наличии
        trace_id = None
        span_id = None
        if _TRACER and trace:
            span = trace.get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and ctx.is_valid:
                trace_id = "{:032x}".format(ctx.trace_id)
                span_id = "{:016x}".format(ctx.span_id)
        return AuditContext(
            app_name=default_app or os.getenv("APP_NAME"),
            node_id=default_node or os.getenv("NODE_ID"),
            tenant_id=os.getenv("TENANT_ID"),
            trace_id=trace_id,
            span_id=span_id,
        )


@dataclass(slots=True)
class AuditEvent:
    # Основные поля аудита
    action: str
    subject: Dict[str, Any]                # напр. {"type": "user", "id": "u123"}
    actor: Optional[Dict[str, Any]] = None # напр. {"type": "service", "id": "svc-api", "roles": ["system"]}
    resource: Optional[Dict[str, Any]] = None  # напр. {"type": "vault_record", "id": "rec_1"}
    outcome: str = "SUCCESS"               # SUCCESS | FAILURE | DENY
    severity: str = "INFO"                 # INFO | WARN | CRITICAL
    labels: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None  # полезная нагрузка (до редактирования PII)
    ctx: Optional[AuditContext] = None

    # Системные поля, заполняются треком
    event_id: Optional[str] = None
    ts: Optional[str] = None
    seq: Optional[int] = None
    prev_hash: Optional[str] = None
    hash: Optional[str] = None
    sig: Optional[Dict[str, str]] = None   # {"alg": "HMAC-BLAKE2B", "key_id": "...", "value": "hex"}
    version: int = 1

    def to_body(self) -> Dict[str, Any]:
        # Тело без хешей и подписи, но с редактированными данными
        return {
            "version": self.version,
            "event_id": self.event_id,
            "ts": self.ts,
            "seq": self.seq,
            "action": self.action,
            "outcome": self.outcome,
            "severity": self.severity,
            "subject": self.subject,
            "actor": self.actor,
            "resource": self.resource,
            "labels": self.labels,
            "data": self.data,
            "ctx": dataclasses.asdict(self.ctx) if self.ctx else None,
        }

    def to_envelope(self) -> Dict[str, Any]:
        # Полный конверт для записи
        body = self.to_body()
        body["prev_hash"] = self.prev_hash
        body["hash"] = self.hash
        body["sig"] = self.sig
        return body


# ============================== Config ======================================

@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 5
    initial_delay: float = 0.5
    max_delay: float = 8.0
    multiplier: float = 2.0


@dataclass(slots=True)
class AuditConfig:
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "oblivionvault"))
    node_id: str = field(default_factory=lambda: os.getenv("NODE_ID", "node-unknown"))
    tenant_id: Optional[str] = field(default_factory=lambda: os.getenv("TENANT_ID", None))

    # Очередь и батч
    queue_capacity: int = 10000
    batch_size: int = 200
    flush_interval_sec: float = 2.0
    block_on_full_queue: bool = True  # иначе будет drop oldest

    # Безопасность
    hmac_keys: Dict[str, bytes] = field(default_factory=dict)  # {"k2025q3": b"..."}
    active_key_id: Optional[str] = None
    redact_keys: Sequence[str] = field(default_factory=lambda: ("password", "secret", "token", "ssn"))

    # Политика ретраев
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    # Семплирование: 1.0 = писать все
    sample_rate: float = 1.0

    # Ведение состояния цепочки (последний хеш/seq) на узле
    state_path: Optional[str] = None  # если None — только в памяти


# ============================== Sink API ====================================

class AuditSink(Protocol):
    def write_batch(self, events: List[Dict[str, Any]]) -> None: ...
    def close(self) -> None: ...


class StdoutJsonSink:
    """
    Простой потоковый sink в stdout (JSON Lines).
    Подходит как дефолтный/резервный.
    """
    def __init__(self, stream: io.TextIOBase | None = None, logger: Optional[logging.Logger] = None):
        self._stream = stream or sys.stdout
        self._logger = logger or logging.getLogger(__name__)

    def write_batch(self, events: List[Dict[str, Any]]) -> None:
        for e in events:
            line = _canonical_dumps(e)
            self._stream.write(line + "\n")
        self._stream.flush()

    def close(self) -> None:
        try:
            if self._stream not in (sys.stdout, sys.stderr):
                self._stream.close()
        except Exception as e:
            self._logger.warning("StdoutJsonSink close error: %s", e)


class BigQueryAuditSink:
    """
    Опциональный sink в BigQuery через oblivionvault.adapters.storage_bigquery.
    Требует: google-cloud-bigquery и локальный адаптер.
    """
    def __init__(
        self,
        dataset: Optional[str] = None,
        table: str = "audit_events",
        config: Optional[BigQueryConfig] = None,
        logger: Optional[logging.Logger] = None,
        ensure_table: bool = True,
    ):
        if not (_HAS_BQ and _HAS_OV_BQ_ADAPTER):
            raise RuntimeError("BigQuery dependencies are not available")

        self._logger = logger or logging.getLogger(__name__)
        self._bq = BigQueryStorageAdapter(config=config or BigQueryConfig(dataset=dataset or os.getenv("BQ_DATASET", "oblivionvault")))
        self._table = table

        if ensure_table:
            self._ensure_table_schema()

    def _ensure_table_schema(self) -> None:
        # BigQuery JSON-friendly schema (nested RECORDs + JSON)
        schema: List[BQField] = [
            bigquery.SchemaField("version", "INT64", mode="REQUIRED"),
            bigquery.SchemaField("event_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("ts", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("seq", "INT64", mode="REQUIRED"),
            bigquery.SchemaField("action", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("outcome", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("subject", "RECORD", mode="REQUIRED", fields=[
                bigquery.SchemaField("type", "STRING"),
                bigquery.SchemaField("id", "STRING"),
            ]),
            bigquery.SchemaField("actor", "RECORD", mode="NULLABLE", fields=[
                bigquery.SchemaField("type", "STRING"),
                bigquery.SchemaField("id", "STRING"),
                bigquery.SchemaField("roles", "STRING", mode="REPEATED"),
            ]),
            bigquery.SchemaField("resource", "RECORD", mode="NULLABLE", fields=[
                bigquery.SchemaField("type", "STRING"),
                bigquery.SchemaField("id", "STRING"),
                bigquery.SchemaField("path", "STRING"),
            ]),
            bigquery.SchemaField("labels", "RECORD", mode="REPEATED", fields=[
                bigquery.SchemaField("key", "STRING"),
                bigquery.SchemaField("value", "STRING"),
            ]),
            bigquery.SchemaField("data_json", "JSON", mode="NULLABLE"),
            bigquery.SchemaField("ctx", "RECORD", mode="NULLABLE", fields=[
                bigquery.SchemaField("ip", "STRING"),
                bigquery.SchemaField("user_agent", "STRING"),
                bigquery.SchemaField("session_id", "STRING"),
                bigquery.SchemaField("tenant_id", "STRING"),
                bigquery.SchemaField("app_name", "STRING"),
                bigquery.SchemaField("node_id", "STRING"),
                bigquery.SchemaField("trace_id", "STRING"),
                bigquery.SchemaField("span_id", "STRING"),
            ]),
            bigquery.SchemaField("prev_hash", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("hash", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("sig", "RECORD", mode="REQUIRED", fields=[
                bigquery.SchemaField("alg", "STRING"),
                bigquery.SchemaField("key_id", "STRING"),
                bigquery.SchemaField("value", "STRING"),
            ]),
        ]
        self._bq.ensure_dataset()
        self._bq.ensure_table(
            table=self._table,
            schema=schema,
            description="OblivionVault immutable audit trail",
            time_partitioning_field="ts",
            time_partitioning_type="DAY",
            clustering_fields=("action", "outcome"),
            labels={"purpose": "audit"},
        )

    @staticmethod
    def _labels_map_to_pairs(labels: Dict[str, str]) -> List[Dict[str, str]]:
        return [{"key": k, "value": v} for k, v in sorted(labels.items())]

    def write_batch(self, events: List[Dict[str, Any]]) -> None:
        rows = []
        for e in events:
            e2 = dict(e)
            # Преобразуем labels в пары и data -> data_json
            labels = e2.pop("labels", {}) or {}
            e2["labels"] = self._labels_map_to_pairs(labels)
            data_json = e2.pop("data", None)
            if data_json is not None:
                # BigQuery JSON поле принимает dict; клиент сам сериализует
                e2["data_json"] = data_json
            rows.append(e2)
        self._bq.insert_rows_json(table=self._table, rows=rows, skip_invalid_rows=False, ignore_unknown_values=False)

    def close(self) -> None:
        self._bq.close()


# ============================== Audit Trail =================================

class AuditTrail:
    """
    Высоконадежный журнал аудита:
      - Хеш-цепочка (blake2b) и HMAC-подпись тела события + prev_hash
      - Каноническая сериализация JSON
      - Асинхронная запись батчами с ретраями
      - Политики редактирования PII
      - Плагинообразные sinks (Stdout, BigQuery)
      - Опционально хранит seq/prev_hash на диске
    """

    def __init__(self, config: AuditConfig, sink: AuditSink, logger: Optional[logging.Logger] = None):
        self.cfg = config
        self.sink = sink
        self.log = logger or logging.getLogger(__name__)

        self._q: "queue.Queue[AuditEvent]" = queue.Queue(maxsize=self.cfg.queue_capacity)
        self._stop = threading.Event()
        self._flush_signal = threading.Event()
        self._worker = threading.Thread(target=self._run, name="audit-writer", daemon=True)

        self._seq = 0
        self._prev_hash = None  # type: Optional[str]
        self._lock = threading.RLock()

        self._load_state()
        self._worker.start()

    # ---------------------- Public API --------------------------------------

    def log_event(self, event: AuditEvent) -> None:
        """
        Неблокирующий (или блокирующий при cfg.block_on_full_queue) enqueue события.
        """
        # Семплирование
        if self.cfg.sample_rate < 1.0:
            # детерминированный sample по event_id
            event_id = event.event_id or _uuid()
            if (int(event_id[:8], 16) / 0xFFFFFFFF) > self.cfg.sample_rate:
                return

        # Обогатим контекстом по умолчанию
        if event.ctx is None:
            event.ctx = AuditContext.from_env(self.cfg.app_name, self.cfg.node_id)
        if event.ctx and self.cfg.tenant_id and not event.ctx.tenant_id:
            event.ctx.tenant_id = self.cfg.tenant_id

        # Редакция PII
        if event.data:
            event.data = self._redact(event.data)

        # Присвоим базовые системные поля
        event.event_id = event.event_id or _uuid()
        event.ts = event.ts or _utcnow_iso()

        # Добавим обязательные метки
        event.labels = {"app": self.cfg.app_name, "node": self.cfg.node_id, **(event.labels or {})}

        try:
            if self.cfg.block_on_full_queue:
                self._q.put(event, block=True)
            else:
                self._q.put_nowait(event)
        except queue.Full:
            # При переполнении — удаляем самый старый и вставляем новый
            try:
                self._q.get_nowait()
                self._q.put_nowait(event)
                self.log.warning("Audit queue full: dropped oldest event to enqueue a new one")
            except queue.Empty:
                pass

    def flush(self, timeout: Optional[float] = None) -> None:
        """
        Сигнал к немедленной отправке батча и ожидание завершения.
        """
        self._flush_signal.set()
        start = time.time()
        while not self._q.empty():
            if timeout is not None and (time.time() - start) > timeout:
                break
            time.sleep(0.01)
        self._flush_signal.clear()

    def close(self) -> None:
        """
        Корректное завершение и закрытие sink.
        """
        self._stop.set()
        self._flush_signal.set()
        self._worker.join(timeout=15.0)
        try:
            self.sink.close()
        finally:
            self._save_state()

    # ---------------------- Internal worker ---------------------------------

    def _run(self) -> None:
        batch: List[AuditEvent] = []
        last_flush = time.time()
        interval = self.cfg.flush_interval_sec

        while not self._stop.is_set():
            timeout = max(0.0, interval - (time.time() - last_flush))
            try:
                ev = self._q.get(timeout=timeout)
                batch.append(ev)
                if len(batch) >= self.cfg.batch_size:
                    self._commit(batch)
                    batch = []
                    last_flush = time.time()
            except queue.Empty:
                # таймаут — пришло время флеша
                if batch:
                    self._commit(batch)
                    batch = []
                last_flush = time.time()

            if self._flush_signal.is_set():
                if batch:
                    self._commit(batch)
                    batch = []
                last_flush = time.time()
                self._flush_signal.clear()

        # Drain on stop
        try:
            while True:
                ev = self._q.get_nowait()
                batch.append(ev)
                if len(batch) >= self.cfg.batch_size:
                    self._commit(batch)
                    batch = []
        except queue.Empty:
            pass
        if batch:
            self._commit(batch)

    # ---------------------- Commit path -------------------------------------

    def _commit(self, events: List[AuditEvent]) -> None:
        # Подготовка конвертов: seq, prev_hash, hash, sig
        envelopes: List[Dict[str, Any]] = []
        with self._lock:
            for ev in events:
                self._seq += 1
                ev.seq = self._seq
                ev.prev_hash = self._prev_hash

                body_json = _canonical_dumps(ev.to_body())
                # Включаем prev_hash в хеш-цепочку
                link = {"prev_hash": ev.prev_hash}
                link_json = _canonical_dumps(link)
                chain_bytes = (body_json + "|" + link_json).encode("utf-8")
                ev.hash = _blake2b_hex(chain_bytes)

                # Подпись
                ev.sig = self._sign_event(ev.hash)
                # Обновляем хвост цепи
                self._prev_hash = ev.hash

                envelopes.append(ev.to_envelope())

        # Пишем батч с ретраями
        delay = self.cfg.retry.initial_delay
        attempts = 0
        while True:
            attempts += 1
            try:
                with _maybe_span("audit.write_batch"):
                    self.sink.write_batch(envelopes)
                # Успех — сохраняем state
                self._save_state()
                return
            except Exception as e:
                if attempts >= self.cfg.retry.max_attempts:
                    self.log.error("Audit sink failed permanently after %s attempts: %s", attempts, e, exc_info=True)
                    return
                self.log.warning("Audit sink write failed (attempt %s): %s; retrying in %.2fs",
                                 attempts, e, delay)
                time.sleep(delay)
                delay = min(delay * self.cfg.retry.multiplier, self.cfg.retry.max_delay)

    # ---------------------- Security helpers --------------------------------

    def _sign_event(self, event_hash_hex: str) -> Dict[str, str]:
        key_id = self.cfg.active_key_id
        if not key_id or key_id not in self.cfg.hmac_keys:
            # Без ключа — подпись невозможна: Zero-Trust требует явного ключа
            raise RuntimeError("Active HMAC key is not configured for audit trail")
        key = self.cfg.hmac_keys[key_id]
        sig_hex = _secure_hmac_blake2b(key, event_hash_hex.encode("utf-8"))
        return {"alg": "HMAC-BLAKE2B", "key_id": key_id, "value": sig_hex}

    def _redact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        def _mask(value: Any) -> Any:
            if value is None:
                return None
            s = str(value)
            if len(s) <= 4:
                return "***"
            return s[:2] + "***" + s[-2:]

        def _walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: (_mask(v) if k.lower() in self.cfg.redact_keys else _walk(v)) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(v) for v in obj]
            return obj

        return _walk(data)

    # ---------------------- State persistence --------------------------------

    def _load_state(self) -> None:
        self._seq = 0
        self._prev_hash = None
        if not self.cfg.state_path:
            return
        try:
            with open(self.cfg.state_path, "r", encoding="utf-8") as f:
                st = json.load(f)
            self._seq = int(st.get("seq", 0))
            self._prev_hash = st.get("prev_hash")
        except FileNotFoundError:
            return
        except Exception as e:
            self.log.warning("Failed to load audit state: %s", e)

    def _save_state(self) -> None:
        if not self.cfg.state_path:
            return
        try:
            tmp = self.cfg.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"seq": self._seq, "prev_hash": self._prev_hash}, f)
            os.replace(tmp, self.cfg.state_path)
        except Exception as e:
            self.log.warning("Failed to persist audit state: %s", e)

    # ---------------------- Verification helper ------------------------------

    @staticmethod
    def verify_chain(events: Sequence[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
        """
        Проверка хеш-цепочки в переданной последовательности событий.
        Возвращает (ok, idx_bad), где idx_bad — индекс нарушенного элемента, либо None.
        """
        prev = None
        for idx, ev in enumerate(events):
            body = dict(ev)
            # Извлечь обязательные поля
            ev_hash = body.pop("hash", None)
            prev_hash = body.get("prev_hash", None)
            body_json = _canonical_dumps({
                "version": body.get("version"),
                "event_id": body.get("event_id"),
                "ts": body.get("ts"),
                "seq": body.get("seq"),
                "action": body.get("action"),
                "outcome": body.get("outcome"),
                "severity": body.get("severity"),
                "subject": body.get("subject"),
                "actor": body.get("actor"),
                "resource": body.get("resource"),
                "labels": body.get("labels"),
                "data": body.get("data") if "data" in body else body.get("data_json"),
                "ctx": body.get("ctx"),
            })
            link_json = _canonical_dumps({"prev_hash": prev})
            expect = _blake2b_hex((body_json + "|" + link_json).encode("utf-8"))
            if ev_hash != expect or prev_hash != prev:
                return False, idx
            prev = ev_hash
        return True, None


# ============================== Example wiring ===============================
# Пример настройки:
#
# logger = logging.getLogger("oblivionvault.audit")
# logger.setLevel(logging.INFO)
# logger.addHandler(logging.StreamHandler(sys.stdout))
#
# cfg = AuditConfig(
#     app_name="oblivionvault",
#     node_id="node-a1",
#     tenant_id="tenant-1",
#     hmac_keys={"k2025q3": os.urandom(32)},
#     active_key_id="k2025q3",
#     state_path="/var/lib/oblivionvault/audit_state.json",
# )
#
# sink = StdoutJsonSink()
# # либо BigQuery:
# # sink = BigQueryAuditSink(dataset="oblivionvault", table="audit_events")
#
# trail = AuditTrail(cfg, sink, logger=logger)
# trail.log_event(AuditEvent(
#     action="vault.record.read",
#     subject={"type": "user", "id": "u123"},
#     actor={"type": "service", "id": "api-gateway", "roles": ["system"]},
#     resource={"type": "vault_record", "id": "rec-42"},
#     outcome="SUCCESS",
#     severity="INFO",
#     labels={"module": "vault"},
#     data={"record_key": "abcdef1234567890", "password": "SecretPass"},
# ))
# trail.flush()
# trail.close()
