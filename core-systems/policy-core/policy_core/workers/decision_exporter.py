from __future__ import annotations

import argparse
import asyncio
import contextlib
import gzip
import json
import logging
import os
import random
import signal
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# ============================================================
# Опциональные зависимости (используются, если доступны)
# ============================================================
try:
    import aiohttp  # type: ignore
except Exception:
    aiohttp = None  # pragma: no cover

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:
    AIOKafkaProducer = None  # pragma: no cover


# ============================================================
# Утилиты и сериализация
# ============================================================
def _stable_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now_ms() -> int:
    return int(time.time() * 1000)


# ============================================================
# Модель события решения (DecisionEvent)
# ============================================================
@dataclass(frozen=True)
class DecisionEvent:
    id: str
    ts: int
    subject: str
    action: str
    resource: str
    effect: str                     # "allow" | "deny"
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    used_conditions: List[str] = field(default_factory=list)
    ctx_hash: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_mapping(m: Mapping[str, Any]) -> "DecisionEvent":
        # Валидация ключевых полей
        required = ("subject", "action", "resource", "effect")
        for k in required:
            if m.get(k) in (None, ""):
                raise ValueError(f"missing required field '{k}'")
        ev_id = str(m.get("id") or uuid.uuid4())
        ts = int(m.get("ts") or _now_ms())
        uc = list(m.get("used_conditions", []) or [])
        extras = dict(m.get("extras", {}) or {})
        return DecisionEvent(
            id=ev_id,
            ts=ts,
            subject=str(m["subject"]),
            action=str(m["action"]),
            resource=str(m["resource"]),
            effect=str(m["effect"]),
            rule_id=(None if m.get("rule_id") in ("", None) else str(m.get("rule_id"))),
            reason=(None if m.get("reason") in ("", None) else str(m.get("reason"))),
            used_conditions=[str(x) for x in uc],
            ctx_hash=(None if m.get("ctx_hash") in ("", None) else str(m.get("ctx_hash"))),
            context=(None if m.get("context") in ("", None) else dict(m.get("context"))),
            extras=extras,
        )

    def to_export_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Контекст может быть тяжёлым — выносим под ключ "context" как есть
        return d


# ============================================================
# Метрики
# ============================================================
@dataclass
class ExporterMetrics:
    accepted: int = 0
    dropped: int = 0
    batched: int = 0
    exported: int = 0
    errors: int = 0
    retries: int = 0
    cb_opened: int = 0
    cb_half_open: int = 0
    cb_closed: int = 0

    def snapshot(self) -> Dict[str, int]:
        return asdict(self)


# ============================================================
# Бэкпрешер и настройки
# ============================================================
class BackpressureMode:
    BLOCK = "block"
    DROP = "drop"
    COALESCE = "coalesce"


@dataclass
class RetryPolicy:
    max_retries: int = 5
    backoff_ms: int = 200
    backoff_factor: float = 2.0
    jitter_ms: int = 1000


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    open_ms: int = 10_000
    half_open_successes: int = 3


@dataclass
class ExporterConfig:
    batch_size: int = 500
    flush_interval_ms: int = 1000
    queue_size: int = 50_000
    backpressure: str = BackpressureMode.BLOCK
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    cb: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    # лимит кэша идемпотентности (скользящее окно последних ID)
    dedup_cache_size: int = 200_000
    # предельный размер сериализованной записи (для HTTP/UDP); oversize — отбрасываем
    max_record_bytes: int = 1_000_000


# ============================================================
# Сники (плагины приёмников)
# Базовый интерфейс + реализации: stdout, file, udp, http, kafka*
# ============================================================
class ExportSink:
    name: str = "sink"

    async def open(self) -> None:
        return None

    async def export(self, batch: List[bytes]) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class StdoutSink(ExportSink):
    name = "stdout"

    async def export(self, batch: List[bytes]) -> None:
        out = sys.stdout.buffer
        for row in batch:
            out.write(row)
            out.write(b"\n")
        out.flush()


class FileSink(ExportSink):
    name = "file"

    def __init__(self, path: str, rotate_max_bytes: int = 256 * 1024 * 1024, rotate_backups: int = 20):
        self.path = Path(path)
        self.rotate_max_bytes = int(rotate_max_bytes)
        self.rotate_backups = int(rotate_backups)
        self._fh: Optional[Any] = None
        self._size = 0

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("ab", buffering=0)
        self._size = self.path.stat().st_size if self.path.exists() else 0

    def _rotate(self) -> None:
        if self._fh:
            with contextlib.suppress(Exception):
                self._fh.close()
        # Ротация file.log -> file.log.1 ... .N
        for i in range(self.rotate_backups, 0, -1):
            src = self.path.with_suffix(self.path.suffix + ("" if i == 0 else f".{i}")) if i == 0 else self.path
        # простая схема: file, file.1, ..., file.N
        for i in range(self.rotate_backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            dst = self.path.with_suffix(self.path.suffix + f".{i+1}")
            if src.exists():
                with contextlib.suppress(Exception):
                    src.replace(dst)
        if self.path.exists():
            with contextlib.suppress(Exception):
                self.path.replace(self.path.with_suffix(self.path.suffix + ".1"))
        self._fh = self.path.open("ab", buffering=0)
        self._size = 0

    async def export(self, batch: List[bytes]) -> None:
        if not self._fh:
            await self.open()
        assert self._fh is not None
        for row in batch:
            if self._size + len(row) + 1 > self.rotate_max_bytes:
                self._rotate()
            written = self._fh.write(row + b"\n")
            self._size += int(written)

    async def close(self) -> None:
        if self._fh:
            with contextlib.suppress(Exception):
                self._fh.close()
            self._fh = None


class UDPSink(ExportSink):
    name = "udp"

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = int(port)
        self._transport: Optional[asyncio.DatagramTransport] = None

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(self.host, self.port))
        self._transport = transport

    async def export(self, batch: List[bytes]) -> None:
        if not self._transport:
            await self.open()
        assert self._transport is not None
        for row in batch:
            self._transport.sendto(row)

    async def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None


class HTTPSink(ExportSink):
    """
    Отправка батча HTTP POST’ом.
    При наличии aiohttp — natively async; иначе stdlib через thread-executor.
    Поддержка gzip (optional), заголовков и таймаутов.
    """
    name = "http"

    def __init__(self, url: str, headers: Optional[Mapping[str, str]] = None, timeout_s: int = 10, gzip_enabled: bool = False):
        self.url = url
        self.headers = dict(headers or {})
        self.timeout_s = int(timeout_s)
        self.gzip_enabled = bool(gzip_enabled)
        self._session = None

    async def open(self) -> None:
        if aiohttp:
            timeout = aiohttp.ClientTimeout(total=self.timeout_s)
            self._session = aiohttp.ClientSession(timeout=timeout)

    async def export(self, batch: List[bytes]) -> None:
        body = b"\n".join(batch)  # JSON Lines
        headers = dict(self.headers)
        data = body
        if self.gzip_enabled:
            data = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
        headers.setdefault("Content-Type", "application/x-ndjson; charset=utf-8")
        if aiohttp and self._session:
            async with self._session.post(self.url, data=data, headers=headers) as resp:
                if resp.status >= 300:
                    text = await resp.text()
                    raise RuntimeError(f"HTTP sink status={resp.status} body={text[:500]}")
        else:
            # stdlib fallback
            await asyncio.get_running_loop().run_in_executor(None, self._post_blocking, data, headers)

    def _post_blocking(self, data: bytes, headers: Mapping[str, str]) -> None:
        import urllib.request
        req = urllib.request.Request(self.url, data=data, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # nosec - доверяем конфигу
            if int(resp.status) >= 300:
                raise RuntimeError(f"HTTP sink status={resp.status}")

    async def close(self) -> None:
        if aiohttp and self._session:
            await self._session.close()
            self._session = None


class KafkaSink(ExportSink):
    """
    Kafka с aiokafka (опционально). Если aiokafka недоступен — возбуждаем ошибку при open().
    """
    name = "kafka"

    def __init__(self, bootstrap_servers: str, topic: str, **kwargs: Any):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.kwargs = kwargs
        self._producer = None

    async def open(self) -> None:
        if not AIOKafkaProducer:
            raise RuntimeError("aiokafka is not installed")
        self._producer = AIOKafkaProducer(bootstrap_servers=self.bootstrap_servers, **self.kwargs)
        await self._producer.start()

    async def export(self, batch: List[bytes]) -> None:
        if not self._producer:
            await self.open()
        assert self._producer is not None
        send_futs = [self._producer.send_and_wait(self.topic, value=row) for row in batch]
        await asyncio.gather(*send_futs)

    async def close(self) -> None:
        if self._producer:
            await self._producer.stop()
            self._producer = None


# Фабрика сников по конфигу
def build_sink(name: str, cfg: Mapping[str, Any]) -> ExportSink:
    kind = str(cfg.get("kind", name)).lower()
    if kind == "stdout":
        return StdoutSink()
    if kind == "file":
        return FileSink(path=str(cfg["path"]), rotate_max_bytes=int(cfg.get("rotate_max_bytes", 256 * 1024 * 1024)),
                        rotate_backups=int(cfg.get("rotate_backups", 20)))
    if kind == "udp":
        host, port = str(cfg["address"]).rsplit(":", 1)
        return UDPSink(host, int(port))
    if kind == "http":
        return HTTPSink(url=str(cfg["url"]), headers=cfg.get("headers") or {}, timeout_s=int(cfg.get("timeout_s", 10)),
                        gzip_enabled=bool(cfg.get("gzip", False)))
    if kind == "kafka":
        return KafkaSink(bootstrap_servers=str(cfg["bootstrap_servers"]), topic=str(cfg["topic"]),
                         **{k: v for k, v in cfg.items() if k not in ("kind", "bootstrap_servers", "topic")})
    raise ValueError(f"unsupported sink kind: {kind}")


# ============================================================
# Circuit Breaker на сник
# ============================================================
class CircuitState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    cfg: CircuitBreakerConfig
    state: str = CircuitState.CLOSED
    failures: int = 0
    opened_at_ms: int = 0
    half_open_successes: int = 0

    def on_success(self) -> None:
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_successes += 1
            if self.half_open_successes >= self.cfg.half_open_successes:
                self._close()
        else:
            self._close()

    def on_failure(self) -> None:
        if self.state == CircuitState.CLOSED:
            self.failures += 1
            if self.failures >= self.cfg.failure_threshold:
                self._open()
        elif self.state == CircuitState.HALF_OPEN:
            # повторный провал — снова OPEN
            self._open()
        # если OPEN — просто ждём истечения таймаута

    def should_skip(self) -> bool:
        if self.state == CircuitState.OPEN:
            if _now_ms() - self.opened_at_ms >= self.cfg.open_ms:
                self._half_open()
                return False
            return True
        return False

    def _open(self) -> None:
        self.state = CircuitState.OPEN
        self.opened_at_ms = _now_ms()
        self.half_open_successes = 0

    def _half_open(self) -> None:
        self.state = CircuitState.HALF_OPEN
        self.half_open_successes = 0

    def _close(self) -> None:
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.half_open_successes = 0


# ============================================================
# DecisionExporter Worker
# ============================================================
class DecisionExporter:
    """
    Асинхронный воркер экспорта решений в один или несколько сников.
    Особенности:
      - Очередь и бэкпрешер (BLOCK/DROP/COALESCE)
      - Батчинг по размеру/времени
      - Ретраи с экспоненциальным бэк-оффом и джиттером
      - Circuit Breaker на каждый сник
      - Идемпотентность по ID (скользящее окно)
      - Метрики
    """

    def __init__(self, cfg: Optional[ExporterConfig] = None, sinks: Optional[List[ExportSink]] = None):
        self.cfg = cfg or ExporterConfig()
        self.metrics = ExporterMetrics()
        self._queue: asyncio.Queue[DecisionEvent] = asyncio.Queue(self.cfg.queue_size)
        self._sinks: List[ExportSink] = list(sinks or [])
        self._sink_cb: Dict[ExportSink, CircuitBreaker] = {s: CircuitBreaker(self.cfg.cb) for s in self._sinks}
        self._stop = asyncio.Event()
        self._worker: Optional[asyncio.Task] = None
        self._started = False
        # Идемпотентность
        self._dedup: Dict[str, None] = {}
        self._dedup_order: List[str] = []
        # COALESCE по ключу
        self._coalesce: Dict[str, DecisionEvent] = {}

        # SIGHUP: мягкое reopen для файловых сников
        with contextlib.suppress(Exception):
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(signal.SIGHUP, self._on_sighup)

    # ---------------- Lifecycle ----------------
    async def start(self) -> None:
        if self._started:
            return
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.open()
        self._stop.clear()
        self._worker = asyncio.create_task(self._run())
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        if self._worker:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.close()
        self._started = False

    def _on_sighup(self) -> None:
        # Переоткрываем файловые сники
        for s in self._sinks:
            if isinstance(s, FileSink):
                asyncio.create_task(self._reopen_sink(s))

    async def _reopen_sink(self, s: ExportSink) -> None:
        with contextlib.suppress(Exception):
            await s.close()
            await s.open()

    # ---------------- Public API ----------------
    def add_sink(self, sink: ExportSink) -> None:
        self._sinks.append(sink)
        self._sink_cb[sink] = CircuitBreaker(self.cfg.cb)

    def remove_sink(self, sink: ExportSink) -> None:
        with contextlib.suppress(ValueError):
            self._sinks.remove(sink)
        self._sink_cb.pop(sink, None)

    def submit(self, event: Mapping[str, Any]) -> None:
        ev = DecisionEvent.from_mapping(event)
        if self._dedup_seen(ev.id):
            self.metrics.dropped += 1
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._enqueue(ev))
        except RuntimeError:
            asyncio.run(self._enqueue(ev))

    async def submit_async(self, event: Mapping[str, Any]) -> None:
        ev = DecisionEvent.from_mapping(event)
        if self._dedup_seen(ev.id):
            self.metrics.dropped += 1
            return
        await self._enqueue(ev)

    def get_metrics(self) -> Dict[str, int]:
        return self.metrics.snapshot()

    # ---------------- Internal ----------------
    async def _enqueue(self, ev: DecisionEvent) -> None:
        mode = self.cfg.backpressure
        if mode == BackpressureMode.BLOCK:
            await self._queue.put(ev)
            self.metrics.accepted += 1
            return
        if mode == BackpressureMode.DROP:
            if self._queue.full():
                self.metrics.dropped += 1
                return
            await self._queue.put(ev)
            self.metrics.accepted += 1
            return
        # COALESCE
        key = f"{ev.subject}|{ev.action}|{ev.resource}|{ev.rule_id or ''}|{ev.effect}"
        self._coalesce[key] = ev
        self.metrics.accepted += 1

    def _dedup_seen(self, ev_id: str) -> bool:
        if ev_id in self._dedup:
            return True
        self._dedup[ev_id] = None
        self._dedup_order.append(ev_id)
        if len(self._dedup_order) > self.cfg.dedup_cache_size:
            old = self._dedup_order.pop(0)
            self._dedup.pop(old, None)
        return False

    async def _run(self) -> None:
        try:
            last_flush = _now_ms()
            batch: List[DecisionEvent] = []
            while not self._stop.is_set():
                timeout = self.cfg.flush_interval_ms / 1000
                try:
                    ev = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(ev)
                except asyncio.TimeoutError:
                    # таймаут — попробуем слить
                    pass

                # Подмешиваем коалесцированные
                if self.cfg.backpressure == BackpressureMode.COALESCE and self._coalesce:
                    batch.extend(list(self._coalesce.values()))
                    self._coalesce.clear()

                now = _now_ms()
                if len(batch) >= self.cfg.batch_size or (batch and now - last_flush >= self.cfg.flush_interval_ms):
                    await self._flush(batch)
                    batch.clear()
                    last_flush = now
        except asyncio.CancelledError:
            # финальный слив
            pending = []
            with contextlib.suppress(asyncio.TimeoutError):
                while True:
                    pending.append(self._queue.get_nowait())
            if self.cfg.backpressure == BackpressureMode.COALESCE and self._coalesce:
                pending.extend(list(self._coalesce.values()))
                self._coalesce.clear()
            if pending:
                await self._flush(pending)
            raise

    async def _flush(self, items: List[DecisionEvent]) -> None:
        # сериализация и фильтрация по max_record_bytes
        rows: List[bytes] = []
        for ev in items:
            row = _stable_json_bytes(ev.to_export_dict())
            if len(row) <= self.cfg.max_record_bytes:
                rows.append(row)
        if not rows:
            return
        self.metrics.batched += len(rows)
        # экспортируем в каждый сник независимо
        for sink in list(self._sinks):
            await self._export_to_sink(sink, rows)

    async def _export_to_sink(self, sink: ExportSink, rows: List[bytes]) -> None:
        cb = self._sink_cb[sink]
        if cb.should_skip():
            self.metrics.cb_opened += 1
            return
        # Ретраи с экспоненциальным бэк-оффом
        attempt = 0
        delay = self.cfg.retry.backoff_ms / 1000
        while True:
            try:
                await sink.export(rows)
                cb.on_success()
                self.metrics.exported += len(rows)
                return
            except Exception as e:
                attempt += 1
                self.metrics.errors += 1
                cb.on_failure()
                if attempt > self.cfg.retry.max_retries:
                    # сдаёмся для этого сника
                    return
                self.metrics.retries += 1
                # джиттер
                jitter = random.randint(0, self.cfg.retry.jitter_ms) / 1000
                await asyncio.sleep(delay + jitter)
                delay *= self.cfg.retry.backoff_factor


# ============================================================
# Конструирование экспортера из словаря конфигурации
# ============================================================
def build_exporter(config: Mapping[str, Any]) -> DecisionExporter:
    # Основная конфигурация воркера
    retry = config.get("retry", {}) or {}
    cb = config.get("circuit_breaker", {}) or {}
    ex_cfg = ExporterConfig(
        batch_size=int(config.get("batch_size", 500)),
        flush_interval_ms=int(config.get("flush_interval_ms", 1000)),
        queue_size=int(config.get("queue_size", 50_000)),
        backpressure=str(config.get("backpressure", BackpressureMode.BLOCK)).lower(),
        retry=RetryPolicy(
            max_retries=int(retry.get("max_retries", 5)),
            backoff_ms=int(retry.get("backoff_ms", 200)),
            backoff_factor=float(retry.get("backoff_factor", 2.0)),
            jitter_ms=int(retry.get("jitter_ms", 1000)),
        ),
        cb=CircuitBreakerConfig(
            failure_threshold=int(cb.get("failure_threshold", 5)),
            open_ms=int(cb.get("open_ms", 10_000)),
            half_open_successes=int(cb.get("half_open_successes", 3)),
        ),
        dedup_cache_size=int(config.get("dedup_cache_size", 200_000)),
        max_record_bytes=int(config.get("max_record_bytes", 1_000_000)),
    )

    # Сники
    sinks_cfg = config.get("sinks", [])
    if not isinstance(sinks_cfg, list) or not sinks_cfg:
        # По умолчанию — stdout
        sinks = [StdoutSink()]
    else:
        sinks = [build_sink(str(i), d) for d in sinks_cfg for i in [d.get("kind", "stdout")]]

    return DecisionExporter(ex_cfg, sinks)


# ============================================================
# Минимальный CLI для теста/интеграции
# Примеры:
#   echo '{"subject":"u1","action":"read","resource":"doc:1","effect":"allow"}' | \
#     python -m policy_core.workers.decision_exporter --sink stdout
#
#   cat decisions.jsonl | python -m policy_core.workers.decision_exporter \
#     --sink file --file-path ./out/decisions.jsonl
#
#   cat decisions.jsonl | python -m policy_core.workers.decision_exporter \
#     --sink http --http-url http://127.0.0.1:8080/ingest --http-gzip
# ============================================================
def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="decision-exporter")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--flush-interval-ms", type=int, default=1000)
    p.add_argument("--queue-size", type=int, default=50_000)
    p.add_argument("--backpressure", choices=[BackpressureMode.BLOCK, BackpressureMode.DROP, BackpressureMode.COALESCE], default=BackpressureMode.BLOCK)
    p.add_argument("--max-record-bytes", type=int, default=1_000_000)

    # Ретрай/CB
    p.add_argument("--retries", type=int, default=5)
    p.add_argument("--backoff-ms", type=int, default=200)
    p.add_argument("--backoff-factor", type=float, default=2.0)
    p.add_argument("--jitter-ms", type=int, default=1000)
    p.add_argument("--cb-failure-threshold", type=int, default=5)
    p.add_argument("--cb-open-ms", type=int, default=10_000)
    p.add_argument("--cb-half-open-successes", type=int, default=3)

    # Один сник через CLI
    p.add_argument("--sink", choices=["stdout", "file", "udp", "http"], default="stdout")
    p.add_argument("--file-path")
    p.add_argument("--udp-address")  # host:port
    p.add_argument("--http-url")
    p.add_argument("--http-header", action="append", help="key:value")
    p.add_argument("--http-timeout-s", type=int, default=10)
    p.add_argument("--http-gzip", action="store_true")

    return p


async def _cli_main(args: argparse.Namespace) -> int:
    # Сборка конфига и сника
    sinks: List[ExportSink] = []
    if args.sink == "stdout":
        sinks.append(StdoutSink())
    elif args.sink == "file":
        if not args.file_path:
            print("file sink requires --file-path", file=sys.stderr)
            return 2
        sinks.append(FileSink(args.file_path))
    elif args.sink == "udp":
        if not args.udp_address or ":" not in args.udp_address:
            print("udp sink requires --udp-address host:port", file=sys.stderr)
            return 2
        host, port = args.udp_address.rsplit(":", 1)
        sinks.append(UDPSink(host, int(port)))
    elif args.sink == "http":
        headers = {}
        for h in args.http_header or []:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        if not args.http_url:
            print("http sink requires --http-url", file=sys.stderr)
            return 2
        sinks.append(HTTPSink(args.http_url, headers=headers, timeout_s=args.http_timeout_s, gzip_enabled=args.http_gzip))

    exp = DecisionExporter(
        cfg=ExporterConfig(
            batch_size=args.batch_size,
            flush_interval_ms=args.flush_interval_ms,
            queue_size=args.queue_size,
            backpressure=args.backpressure,
            retry=RetryPolicy(
                max_retries=args.retries,
                backoff_ms=args.backoff_ms,
                backoff_factor=args.backoff_factor,
                jitter_ms=args.jitter_ms,
            ),
            cb=CircuitBreakerConfig(
                failure_threshold=args.cb_failure_threshold,
                open_ms=args.cb_open_ms,
                half_open_successes=args.cb_half_open_successes,
            ),
            max_record_bytes=args.max_record_bytes,
        ),
        sinks=sinks,
    )

    await exp.start()
    # Чтение JSONL со stdin и отправка
    try:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        while True:
            line = await reader.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line.decode("utf-8"))
                await exp.submit_async(obj)
            except Exception as e:
                print(f"skip invalid line: {e}", file=sys.stderr)
        # подождём финальный флеш
        await asyncio.sleep(max(0.1, args.flush_interval_ms / 1000))
    finally:
        await exp.stop()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    return asyncio.run(_cli_main(args))


if __name__ == "__main__":
    sys.exit(main())
