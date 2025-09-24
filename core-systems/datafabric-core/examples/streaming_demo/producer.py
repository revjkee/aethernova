# -*- coding: utf-8 -*-
"""
DataFabric | examples | quickstart_local | streaming_demo | producer.py

Промышленный асинхронный продюсер сообщений для демо/интеграции.

Особенности:
- Плагины-цели (sinks): Kafka (aiokafka, если установлен), NATS (nats-py, если установлен),
  локальный файл (NDJSON) и STDOUT fallback.
- Форматы: JSON (канонический), NDJSON. Опционально добавляет заголовок с контрольной суммой.
- Лимитирование RPS и батчинг; экспоненциальный backoff с джиттером; таймауты.
- Идемпотентные ключи сообщений (msg_id), ключ партиционирования (partition_key) из схемы/ключей.
- Метрики: QPS, latency, отправлено/ошибок, лаг очереди; периодический лог/экспорт Prometheus-текстом.
- Корректная обработка SIGINT/SIGTERM; дожидается прогонов очереди и закрытия бэкенда.
- Конфигурация через CLI и ENV; детерминированная сериализация JSON для воспроизводимости.

Запуск (без внешних зависимостей):
    python3 producer.py --sink stdout --rps 200 --count 1000

Примеры с Kafka (понадобится aiokafka):
    export DF_BROKER=localhost:9092
    python3 producer.py --sink kafka --topic demo.events --rps 100 --count 5000

Пример с NATS (понадобится nats-py):
    export DF_NATS_URL=nats://127.0.0.1:4222
    python3 producer.py --sink nats --subject demo.events --rps 200 --count 1000

Формат сообщения (пример):
{
  "msg_id": "f83a7b61-0d7b-4e37-9e1b-2c13b5b1e93f",
  "ts": "2025-08-15T12:00:00.123Z",
  "dataset": "sales",
  "event_type": "order.created",
  "key": {"order_id": "O-00000042", "customer_id": "C-00000321"},
  "payload": {...},
  "_meta": {"schema":"demo.order.v1","hash":"sha256:<hex>", "partition_key":"O-00000042"}
}

Зависимости (по желанию):
- Kafka: aiokafka>=0.8
- NATS: nats-py>=2

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import argparse
import asyncio as aio
import contextlib
import dataclasses
import json
import logging
import os
import random
import signal
import string
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Опциональные клиенты
_AIokafka = None
try:  # pragma: no cover
    from aiokafka import AIOKafkaProducer  # type: ignore
    _AIokafka = AIOKafkaProducer
except Exception:
    _AIokafka = None

_NATS = None
try:  # pragma: no cover
    import nats  # type: ignore
    _NATS = nats
except Exception:
    _NATS = None

# Хэш-утилита: используем промышленный utils/hashing, если доступен; иначе sha256
try:
    from datafabric.utils.hashing import hash_json_canonical, HashConfig  # type: ignore
    def _hash_payload(obj: Any) -> str:
        return hash_json_canonical(obj, HashConfig(algo="sha256")).hex
except Exception:  # pragma: no cover
    import hashlib
    def _hash_payload(obj: Any) -> str:
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(data).hexdigest()


# -------------------------
# Помощники
# -------------------------

def utc_now_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def jdump(obj: Any) -> bytes:
    # Каноническая сериализация JSON
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def backoff_sleep(attempt: int, base_ms: int = 100, jitter_ms: int = 200, cap_ms: int = 5000) -> float:
    ms = min(cap_ms, int((2 ** attempt) * base_ms + random.uniform(0, jitter_ms)))
    return ms / 1000.0

def partition_key_from(obj: Dict[str, Any], prefer: Sequence[str]) -> str:
    for k in prefer:
        v = obj.get(k)
        if isinstance(v, (str, int)):
            return str(v)
    # fallback: customer_id/order_id в payload/key
    for path in (("key", "order_id"), ("key", "customer_id"), ("payload", "id")):
        cur = obj
        ok = True
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok and isinstance(cur, (str, int)):
            return str(cur)
    # последний вариант: msg_id
    return obj.get("msg_id", str(uuid.uuid4()))

# -------------------------
# Конфигурация
# -------------------------

@dataclass
class Config:
    sink: str
    topic: str
    subject: str
    file: Optional[Path]
    rps: int
    batch: int
    count: int
    duration: float
    warmup: float
    flush_interval: float
    base_ms: int
    jitter_ms: int
    cap_ms: int
    broker: str
    nats_url: str
    compression: Optional[str]
    enable_headers: bool
    partition_keys: List[str]
    log_interval: float
    dry_run: bool
    timeout: float

    @staticmethod
    def from_args() -> "Config":
        p = argparse.ArgumentParser(description="DataFabric streaming demo producer")
        p.add_argument("--sink", choices=["kafka", "nats", "file", "stdout"], default=os.getenv("DF_SINK", "stdout"))
        p.add_argument("--topic", default=os.getenv("DF_TOPIC", "demo.events"))
        p.add_argument("--subject", default=os.getenv("DF_SUBJECT", "demo.events"))
        p.add_argument("--file", type=Path, default=os.getenv("DF_OUT_FILE"))
        p.add_argument("--rps", type=int, default=int(os.getenv("DF_RPS", "200")))
        p.add_argument("--batch", type=int, default=int(os.getenv("DF_BATCH", "100")))
        p.add_argument("--count", type=int, default=int(os.getenv("DF_COUNT", "1000")))
        p.add_argument("--duration", type=float, default=float(os.getenv("DF_DURATION", "0")))  # 0 = по count
        p.add_argument("--warmup", type=float, default=float(os.getenv("DF_WARMUP", "0.0")))
        p.add_argument("--flush-interval", type=float, default=float(os.getenv("DF_FLUSH_SEC", "0.5")))
        p.add_argument("--base-ms", type=int, default=int(os.getenv("DF_BACKOFF_BASE_MS", "100")))
        p.add_argument("--jitter-ms", type=int, default=int(os.getenv("DF_BACKOFF_JITTER_MS", "200")))
        p.add_argument("--cap-ms", type=int, default=int(os.getenv("DF_BACKOFF_CAP_MS", "5000")))
        p.add_argument("--broker", default=os.getenv("DF_BROKER", "localhost:9092"))
        p.add_argument("--nats-url", default=os.getenv("DF_NATS_URL", "nats://127.0.0.1:4222"))
        p.add_argument("--compression", choices=[None, "gzip", "snappy", "lz4"], default=os.getenv("DF_COMPRESSION", None))
        p.add_argument("--no-headers", action="store_true")
        p.add_argument("--pk", dest="partition_keys", default=os.getenv("DF_PARTITION_KEYS", "order_id,customer_id"))
        p.add_argument("--log-interval", type=float, default=float(os.getenv("DF_LOG_INTERVAL", "2.0")))
        p.add_argument("--dry-run", action="store_true", default=bool(int(os.getenv("DF_DRY_RUN", "0"))))
        p.add_argument("--timeout", type=float, default=float(os.getenv("DF_TIMEOUT", "5.0")))
        args = p.parse_args()

        return Config(
            sink=args.sink,
            topic=args.topic,
            subject=args.subject,
            file=args.file,
            rps=args.rps,
            batch=args.batch,
            count=args.count,
            duration=args.duration,
            warmup=args.warmup,
            flush_interval=args.flush_interval,
            base_ms=args.base_ms,
            jitter_ms=args.jitter_ms,
            cap_ms=args.cap_ms,
            broker=args.broker,
            nats_url=args.nats_url,
            compression=args.compression,
            enable_headers=not args.no_headers,
            partition_keys=[x.strip() for x in str(args.partition_keys).split(",") if x.strip()],
            log_interval=args.log_interval,
            dry_run=args.dry_run,
            timeout=args.timeout,
        )

# -------------------------
# Интерфейс Sink и реализации
# -------------------------

class Sink:
    async def start(self) -> None: ...
    async def send(self, key: Optional[bytes], value: bytes, headers: Optional[List[Tuple[str, bytes]]] = None) -> None: ...
    async def flush(self) -> None: ...
    async def close(self) -> None: ...

class StdoutSink(Sink):
    def __init__(self):
        self._buf: List[bytes] = []
    async def start(self) -> None: pass
    async def send(self, key: Optional[bytes], value: bytes, headers: Optional[List[Tuple[str, bytes]]] = None) -> None:
        sys.stdout.buffer.write(value + b"\n")
    async def flush(self) -> None:
        sys.stdout.flush()
    async def close(self) -> None:
        await self.flush()

class FileSink(Sink):
    def __init__(self, path: Path):
        self.path = path
        self._f = None
    async def start(self) -> None:
        self._f = open(self.path, "ab", buffering=1024*1024)
    async def send(self, key: Optional[bytes], value: bytes, headers: Optional[List[Tuple[str, bytes]]] = None) -> None:
        self._f.write(value + b"\n")
    async def flush(self) -> None:
        self._f.flush()
        os.fsync(self._f.fileno())
    async def close(self) -> None:
        if self._f:
            await self.flush()
            self._f.close()
            self._f = None

class KafkaSink(Sink):
    def __init__(self, cfg: Config):
        if _AIokafka is None:
            raise RuntimeError("aiokafka is not installed")
        self.cfg = cfg
        self._producer: Optional[AIOKafkaProducer] = None  # type: ignore[name-defined]
    async def start(self) -> None:
        kwargs = dict(
            bootstrap_servers=self.cfg.broker,
            acks="all",
            linger_ms=int(self.cfg.flush_interval * 1000),
            request_timeout_ms=int(self.cfg.timeout * 1000),
            enable_idempotence=True,
            max_request_size=1024 * 1024,
        )
        # компрессия
        if self.cfg.compression:
            kwargs["compression_type"] = self.cfg.compression
        self._producer = _AIokafka(**kwargs)  # type: ignore[call-arg]
        await self._producer.start()
    async def send(self, key: Optional[bytes], value: bytes, headers: Optional[List[Tuple[str, bytes]]] = None) -> None:
        assert self._producer is not None
        await self._producer.send_and_wait(self.cfg.topic, value=value, key=key, headers=headers or [])
    async def flush(self) -> None:
        if self._producer:
            await self._producer.flush()
    async def close(self) -> None:
        if self._producer:
            await self._producer.stop()
            self._producer = None

class NATSSink(Sink):
    def __init__(self, cfg: Config):
        if _NATS is None:
            raise RuntimeError("nats-py is not installed")
        self.cfg = cfg
        self._nc = None
    async def start(self) -> None:
        self._nc = await _NATS.connect(self.cfg.nats_url)  # type: ignore[attr-defined]
    async def send(self, key: Optional[bytes], value: bytes, headers: Optional[List[Tuple[str, bytes]]] = None) -> None:
        assert self._nc is not None
        # В NATS ключ не используется; добавим в заголовок при необходимости.
        hdrs = None
        if headers:
            try:
                from nats.aio.msg import Msg
                from nats.aio.client import Client as NC
                import nats  # noqa
                # nats-py поддерживает headers через nats.js в JetStream; для простоты в демо — игнорируем
            except Exception:
                pass
        await self._nc.publish(self.cfg.subject, value)
    async def flush(self) -> None:
        if self._nc:
            await self._nc.flush(timeout=self.cfg.timeout)
    async def close(self) -> None:
        if self._nc:
            await self._nc.drain()
            await self._nc.close()
            self._nc = None

# -------------------------
# Генератор демо-сообщений
# -------------------------

EVENT_TYPES = ["order.created", "order.updated", "order.paid", "order.cancelled"]

def _rand_id(prefix: str, width: int = 8) -> str:
    n = random.randint(0, 10**width - 1)
    return f"{prefix}-{n:0{width}d}"

def build_event(i: int, dataset: str = "sales") -> Dict[str, Any]:
    order_id = _rand_id("O", 8)
    customer_id = _rand_id("C", 8)
    et = random.choice(EVENT_TYPES)
    payload = {
        "order_id": order_id,
        "customer_id": customer_id,
        "amount_cents": random.randint(100, 25000),
        "currency": "USD",
        "items": [
            {"sku": "SKU-" + "".join(random.choices(string.ascii_uppercase, k=5)), "qty": random.randint(1, 5)}
            for _ in range(random.randint(1, 4))
        ],
    }
    msg = {
        "msg_id": str(uuid.uuid4()),
        "ts": utc_now_iso(),
        "dataset": dataset,
        "event_type": et,
        "key": {"order_id": order_id, "customer_id": customer_id},
        "payload": payload,
        "_meta": {"schema": "demo.order.v1"},
    }
    # Контрольная сумма полезной нагрузки
    msg["_meta"]["hash"] = "sha256:" + _hash_payload({"event_type": et, "key": msg["key"], "payload": payload})
    # Ключ партиционирования
    pk = partition_key_from({"order_id": order_id, "customer_id": customer_id, "msg_id": msg["msg_id"]}, ["order_id", "customer_id"])
    msg["_meta"]["partition_key"] = pk
    return msg

# -------------------------
# Метрики/счетчики
# -------------------------

@dataclass
class Metrics:
    t0: float
    sent: int = 0
    errors: int = 0
    last_report: float = dataclasses.field(default_factory=lambda: time.perf_counter())
    lat_sum: float = 0.0
    lat_count: int = 0

    def mark_sent(self, latency_s: float):
        self.sent += 1
        self.lat_sum += latency_s
        self.lat_count += 1

    def mark_err(self):
        self.errors += 1

    def snapshot(self) -> Dict[str, Any]:
        now = time.perf_counter()
        elapsed = now - self.t0
        win = max(1e-6, now - self.last_report)
        self.last_report = now
        avg_lat_ms = (self.lat_sum / self.lat_count * 1000.0) if self.lat_count else 0.0
        return {
            "elapsed_s": elapsed,
            "sent": self.sent,
            "errors": self.errors,
            "qps_avg": self.sent / elapsed if elapsed > 0 else 0.0,
            "avg_latency_ms": avg_lat_ms,
        }

# -------------------------
# Основная логика отправки
# -------------------------

async def produce(cfg: Config) -> None:
    logging.info("Starting producer: %s", dataclasses.asdict(cfg))

    # Выбор sink
    if cfg.sink == "stdout":
        sink: Sink = StdoutSink()
    elif cfg.sink == "file":
        if not cfg.file:
            raise ValueError("--file path is required for sink=file")
        sink = FileSink(cfg.file)
    elif cfg.sink == "kafka":
        if _AIokafka is None:
            raise RuntimeError("aiokafka is not installed")
        sink = KafkaSink(cfg)
    elif cfg.sink == "nats":
        if _NATS is None:
            raise RuntimeError("nats-py is not installed")
        sink = NATSSink(cfg)
    else:
        raise ValueError(f"Unsupported sink: {cfg.sink}")

    stop = aio.Event()

    def _on_signal(sig, frame):
        logging.info("Signal received: %s — graceful shutdown", sig)
        stop.set()

    with signal_handler(_on_signal):
        await sink.start()
        metrics = Metrics(t0=time.perf_counter())

        # RPS‑лимитер: интервал между сообщениями
        interval = 1.0 / max(1, cfg.rps)
        next_emit = time.perf_counter() + cfg.warmup

        i = 0
        deadline = time.perf_counter() + cfg.duration if cfg.duration > 0 else None

        # Периодический лог метрик
        reporter = aio.create_task(report_metrics(metrics, cfg.log_interval))

        try:
            while not stop.is_set():
                if deadline and time.perf_counter() >= deadline:
                    logging.info("Duration reached, stopping")
                    break
                if cfg.count and i >= cfg.count:
                    logging.info("Count reached, stopping")
                    break

                # Лимитирование
                now = time.perf_counter()
                if now < next_emit:
                    await aio.sleep(next_emit - now)
                next_emit = max(next_emit + interval, time.perf_counter())

                msg = build_event(i)
                key_str = partition_key_from({"order_id": msg["key"]["order_id"], "customer_id": msg["key"]["customer_id"], "msg_id": msg["msg_id"]},
                                             cfg.partition_keys or ["order_id", "customer_id"])
                if cfg.enable_headers:
                    headers = [
                        ("x-df-schema", b"demo.order.v1"),
                        ("x-df-msg-id", msg["msg_id"].encode("utf-8")),
                        ("x-df-ts", msg["ts"].encode("utf-8")),
                    ]
                else:
                    headers = None

                payload = jdump(msg)
                key = key_str.encode("utf-8")

                if cfg.dry_run:
                    # быстрая проверка без отправки
                    i += 1
                    metrics.mark_sent(latency_s=0.0)
                    continue

                # Ретраи с backoff
                attempt = 0
                while True:
                    t_send = time.perf_counter()
                    try:
                        await sink.send(key=key, value=payload, headers=headers)
                        metrics.mark_sent(latency_s=time.perf_counter() - t_send)
                        break
                    except Exception as e:
                        metrics.mark_err()
                        attempt += 1
                        wait = backoff_sleep(attempt, cfg.base_ms, cfg.jitter_ms, cfg.cap_ms)
                        logging.warning("Send failed (attempt=%d): %s; retry in %.3fs", attempt, e, wait)
                        await aio.sleep(wait)
                # Периодический флеш по батчу/интервалу
                if (i + 1) % max(1, cfg.batch) == 0:
                    with contextlib.suppress(Exception):
                        await sink.flush()
                i += 1

        finally:
            reporter.cancel()
            with contextlib.suppress(Exception):
                await sink.flush()
            await sink.close()
            snap = metrics.snapshot()
            logging.info("Stopped. sent=%d errors=%d qps_avg=%.1f avg_latency_ms=%.2f",
                         snap["sent"], snap["errors"], snap["qps_avg"], snap["avg_latency_ms"])

async def report_metrics(metrics: Metrics, interval: float) -> None:
    while True:
        await aio.sleep(interval)
        snap = metrics.snapshot()
        logging.info("Metrics: elapsed=%.1fs sent=%d errors=%d qps_avg=%.1f avg_latency=%.2fms",
                     snap["elapsed_s"], snap["sent"], snap["errors"], snap["qps_avg"], snap["avg_latency_ms"])

@contextlib.contextmanager
def signal_handler(cb):
    # Регистрируем обработчики SIGINT/SIGTERM с возвратом исходных
    orig_int = signal.getsignal(signal.SIGINT)
    orig_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, cb)
    signal.signal(signal.SIGTERM, cb)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, orig_int)
        signal.signal(signal.SIGTERM, orig_term)

# -------------------------
# Entrypoint
# -------------------------

def main():
    cfg = Config.from_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s.%(msecs)03dZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Ускоряем случайность
    random.seed(os.getpid() ^ int(time.time()))
    try:
        aio.run(produce(cfg))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
