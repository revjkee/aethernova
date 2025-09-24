# cybersecurity-core/cybersecurity/ids/suricata_bridge.py
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict, ValidationError

# -----------------------------------------------------------------------------
# Логгер
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

_TZ_FIX_RE = re.compile(r"(.*)([+-])(\d{2})(\d{2})$")


def parse_rfc3339(ts: str) -> datetime:
    """
    Парсинг временной метки Suricata EVE (варианты с Z и +0000).
    Возвращает timezone-aware datetime (UTC и др. смещения поддержаны).
    """
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    else:
        m = _TZ_FIX_RE.match(s)
        if m:
            # Превращаем +HHMM в +HH:MM (для fromisoformat)
            s = f"{m.group(1)}{m.group(2)}{m.group(3)}:{m.group(4)}"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        # Фоллбек: попробуем без смещения и затем присвоим UTC
        try:
            dt = datetime.fromisoformat(s.split("+")[0].split("-")[0])
            return dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            raise ValueError(f"Invalid timestamp: {ts}") from e


def lower_or(value: Optional[str], default: str) -> str:
    return value.lower() if isinstance(value, str) else default


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default


# -----------------------------------------------------------------------------
# Нормализованная модель события IDS (соответствует вашему OpenAPI IDSEvent)
# -----------------------------------------------------------------------------

class ProductInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = "Suricata"
    version: Optional[str] = None


class HTTPInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    method: Optional[str] = None
    host: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = Field(default=None, ge=100, le=599)


class GeoIPInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    country: Optional[str] = None
    city: Optional[str] = None


class ASNInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    number: Optional[int] = None
    org: Optional[str] = None


class Enrichment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    geoip: Optional[GeoIPInfo] = None
    asn: Optional[ASNInfo] = None


class IDSEvent(BaseModel):
    """
    Минимально требуемые поля:
    id, timestamp, category, action, severity, src_ip, dst_ip, protocol
    """
    model_config = ConfigDict(extra="ignore")

    id: UUID
    timestamp: datetime
    product: Optional[ProductInfo] = None
    category: str  # network | host | application
    action: str    # alert | block | allow | drop
    severity: str  # low | medium | high | critical
    signature_id: Optional[str] = None
    message: Optional[str] = None
    src_ip: str
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_ip: str
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: str  # tcp | udp | icmp | other
    http: Optional[HTTPInfo] = None
    tags: List[str] = Field(default_factory=list)
    enrichment: Optional[Enrichment] = None


# -----------------------------------------------------------------------------
# Протокол приемника событий (sink) и базовые реализации
# -----------------------------------------------------------------------------

class EventSink(Protocol):
    """
    Абстракция места назначения для нормализованных событий.
    Реализации: KafkaSink, HttpSink, QueueSink и т.п.
    """
    async def write_batch(self, events: List[IDSEvent]) -> None:
        ...


class QueueSink(EventSink):
    """
    Простой sink на основе asyncio.Queue для межкомпонентного обмена.
    """
    def __init__(self, queue: asyncio.Queue[IDSEvent]) -> None:
        self._q = queue

    async def write_batch(self, events: List[IDSEvent]) -> None:
        for ev in events:
            await self._q.put(ev)


class NullSink(EventSink):
    """
    Поглотитель, используемый по умолчанию при отладке.
    """
    async def write_batch(self, events: List[IDSEvent]) -> None:
        # Ничего не делаем, только логируем объём
        logger.debug("NullSink absorbed %d events", len(events))


# -----------------------------------------------------------------------------
# Конфигурация моста
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class SuricataBridgeConfig:
    eve_path: Path
    batch_size: int = 200
    flush_interval_sec: float = 0.5
    from_start: bool = False            # читать с начала файла или с конца
    reopen_on_rotate: bool = True       # поддержка ротации файла
    poll_interval_sec: float = 0.1      # интервал проверки новых строк
    max_queue_bytes: int = 16 * 1024 * 1024
    drop_on_backpressure: bool = False  # если True, то переполнение приведет к сбросу входных строк с метрикой


# -----------------------------------------------------------------------------
# Метрики и здоровье
# -----------------------------------------------------------------------------

@dataclass(slots=True)
class BridgeStats:
    started_at: float = field(default_factory=time.time)
    lines_read: int = 0
    json_parsed: int = 0
    json_failed: int = 0
    events_built: int = 0
    events_dropped: int = 0
    batches_flushed: int = 0
    last_error: Optional[str] = None

    @property
    def uptime_sec(self) -> float:
        return time.time() - self.started_at


# -----------------------------------------------------------------------------
# Трансформация Suricata EVE JSON -> IDSEvent
# -----------------------------------------------------------------------------

_SEVERITY_MAP = {
    1: "high",
    2: "medium",
    3: "low",
}

def _map_severity(alert: Dict[str, Any]) -> str:
    sev_num = to_int(alert.get("severity"), 2) or 2
    return _SEVERITY_MAP.get(sev_num, "medium")


def _map_action(rec: Dict[str, Any]) -> str:
    et = rec.get("event_type")
    # IPS режим может генерировать event_type=drop
    if et == "drop":
        return "drop"
    if et == "alert":
        # В некоторых сборках присутствует alert.action: allowed/blocked
        a = lower_or(rec.get("alert", {}).get("action"), "")
        if a in {"blocked", "deny", "drop"}:
            return "block"
        if a in {"allowed", "permit"}:
            return "allow"
        return "alert"
    # Телееметрия http/dns/tls и т.п. — не алерт, трактуем как allow
    return "allow"


def _map_protocol(proto: Optional[str]) -> str:
    p = lower_or(proto, "other")
    if p in {"tcp", "udp", "icmp"}:
        return p
    return "other"


def transform_suricata_eve(rec: Dict[str, Any]) -> IDSEvent:
    """
    Преобразует один JSON-объект Suricata EVE к нормализованному IDSEvent.
    Бросает ValidationError при несоответствии модели.
    """
    # Базовые поля сети
    src_ip = rec.get("src_ip") or rec.get("src") or ""
    dst_ip = rec.get("dest_ip") or rec.get("dst_ip") or ""
    if not src_ip or not dst_ip:
        raise ValidationError.from_exception_data("IDSEvent", [{"loc": ("src_ip/dst_ip",), "msg": "src_ip/dst_ip required", "type": "value_error"}])

    http_raw = rec.get("http") or {}
    http = HTTPInfo(
        method=http_raw.get("http_method") or http_raw.get("method"),
        host=http_raw.get("hostname") or http_raw.get("host"),
        url=http_raw.get("url"),
        status=to_int(http_raw.get("status")),
    ) if http_raw else None

    alert = rec.get("alert") or {}
    signature = alert.get("signature")
    signature_id = alert.get("signature_id")
    category = "network"  # Suricata — сетевой IDS/IPS

    ev = IDSEvent(
        id=uuid4(),
        timestamp=parse_rfc3339(rec.get("timestamp") or rec.get("flow", {}).get("start") or datetime.now(timezone.utc).isoformat()),
        product=ProductInfo(),
        category=category,
        action=_map_action(rec),
        severity=_map_severity(alert) if alert else "low",
        signature_id=str(signature_id) if signature_id is not None else None,
        message=signature,
        src_ip=src_ip,
        src_port=to_int(rec.get("src_port")),
        dst_ip=dst_ip,
        dst_port=to_int(rec.get("dest_port") or rec.get("dst_port")),
        protocol=_map_protocol(rec.get("proto")),
        http=http,
        tags=_build_tags(rec),
        enrichment=None,  # Заполняется внешними энрихментами при необходимости
    )
    return ev


def _build_tags(rec: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    et = rec.get("event_type")
    if et:
        tags.append(str(et))
    app_proto = rec.get("app_proto")
    if app_proto:
        tags.append(str(app_proto))
    # TLS/JA3 маркеры
    tls = rec.get("tls") or {}
    if "ja3" in tls:
        tags.append("ja3")
    if "ja3s" in tls:
        tags.append("ja3s")
    # Кастомные теги из Suricata
    if isinstance(rec.get("tag"), str):
        tags.append(rec["tag"])
    elif isinstance(rec.get("tags"), list):
        tags.extend([str(t) for t in rec["tags"] if t])
    return tags


# -----------------------------------------------------------------------------
# Tailer файла с поддержкой ротации
# -----------------------------------------------------------------------------

class FileTailer:
    """
    Асинхронное чтение построчно с конца (или начала) файла с поддержкой ротации.
    """
    def __init__(self, path: Path, poll_interval_sec: float = 0.1, from_start: bool = False, reopen_on_rotate: bool = True) -> None:
        self._path = path
        self._poll = poll_interval_sec
        self._from_start = from_start
        self._reopen = reopen_on_rotate
        self._fd: Optional[io.TextIOWrapper] = None
        self._inode: Optional[int] = None
        self._st_size: int = 0
        self._st_dev: Optional[int] = None
        self._st_ino: Optional[int] = None
        self._closed = False

    async def __aenter__(self) -> "FileTailer":
        await self._open_initial()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        try:
            if self._fd:
                self._fd.close()
        finally:
            self._fd = None

    async def _open_initial(self) -> None:
        self._fd = open(self._path, "r", encoding="utf-8", errors="replace")
        st = os.fstat(self._fd.fileno())
        self._st_dev, self._st_ino, self._st_size = st.st_dev, st.st_ino, st.st_size
        if self._from_start:
            self._fd.seek(0, os.SEEK_SET)
        else:
            self._fd.seek(0, os.SEEK_END)
        logger.info("FileTailer opened %s (dev=%s ino=%s)", self._path, self._st_dev, self._st_ino)

    def _rotated(self) -> bool:
        try:
            cur = os.stat(self._path)
        except FileNotFoundError:
            return False
        return (self._st_dev != cur.st_dev) or (self._st_ino != cur.st_ino)

    async def lines(self) -> Iterable[str]:
        """
        Асинхронный генератор строк. Блокирует цикл лишь короткими sleep.
        """
        assert self._fd is not None
        buff = ""
        while not self._closed:
            line = self._fd.readline()
            if line:
                yield line
                continue
            # EOF
            await asyncio.sleep(self._poll)
            # Проверка ротации
            if self._reopen and self._rotated():
                try:
                    old = self._fd
                    self._fd = open(self._path, "r", encoding="utf-8", errors="replace")
                    os.close(old.fileno())  # безопасно закрыть старый дескриптор
                    st = os.fstat(self._fd.fileno())
                    self._st_dev, self._st_ino, self._st_size = st.st_dev, st.st_ino, st.st_size
                    self._fd.seek(0, os.SEEK_SET)  # читаем с начала нового файла
                    logger.info("File rotated, reopened %s (dev=%s ino=%s)", self._path, self._st_dev, self._st_ino)
                except Exception as e:
                    logger.exception("Failed to reopen rotated file: %s", e)


# -----------------------------------------------------------------------------
# Основной мост Suricata -> Sink
# -----------------------------------------------------------------------------

class SuricataBridge:
    """
    Асинхронный мост: читает eve.json, парсит JSON, трансформирует в IDSEvent и отправляет пакетами в sink.
    """

    def __init__(self, config: SuricataBridgeConfig, sink: Optional[EventSink] = None) -> None:
        self.cfg = config
        self.sink: EventSink = sink or NullSink()
        self.stats = BridgeStats()
        self._task: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()
        self._batch: List[IDSEvent] = []
        self._batch_bytes: int = 0
        self._last_flush: float = time.time()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_evt.clear()
        self._task = asyncio.create_task(self._run(), name="suricata-bridge-runloop")
        logger.info("SuricataBridge started (path=%s)", self.cfg.eve_path)

    async def stop(self) -> None:
        self._stop_evt.set()
        if self._task:
            await self._task
        await self._flush(force=True)
        logger.info("SuricataBridge stopped. Stats: %s", self.stats.__dict__)

    async def _run(self) -> None:
        try:
            async with FileTailer(
                self.cfg.eve_path,
                poll_interval_sec=self.cfg.poll_interval_sec,
                from_start=self.cfg.from_start,
                reopen_on_rotate=self.cfg.reopen_on_rotate,
            ) as tail:
                async for line in tail.lines():
                    if self._stop_evt.is_set():
                        break
                    await self._handle_line(line)
                    await self._maybe_flush()
        except Exception as e:
            self.stats.last_error = str(e)
            logger.exception("Bridge run failed: %s", e)

    async def _handle_line(self, line: str) -> None:
        self.stats.lines_read += 1
        s = line.strip()
        if not s:
            return
        # EVE может содержать несколько JSON в одной строке при склейке; попытаемся разбирать строчно
        try:
            obj = json.loads(s)
            self.stats.json_parsed += 1
        except json.JSONDecodeError:
            self.stats.json_failed += 1
            logger.debug("Skipping non-JSON line")
            return

        # Некоторые event_type не являются алертами — допускаем трансформацию только релевантных типов
        allowed = {"alert", "drop", "http", "dns", "tls"}
        et = obj.get("event_type")
        if et not in allowed:
            return

        try:
            ev = transform_suricata_eve(obj)
        except ValidationError as ve:
            self.stats.json_failed += 1
            logger.warning("Validation failed for EVE record: %s", ve)
            return
        except Exception as e:
            self.stats.json_failed += 1
            logger.exception("Transform error: %s", e)
            return

        # Контроль обратного давления по объёму
        approx_size = len(s)
        if self.cfg.max_queue_bytes and (self._batch_bytes + approx_size) > self.cfg.max_queue_bytes:
            if self.cfg.drop_on_backpressure:
                self.stats.events_dropped += 1
                logger.warning("Dropping event due to backpressure (batch_bytes=%d)", self._batch_bytes)
                return
            # Иначе принудительно сбрасываем батч
            await self._flush(force=True)

        self._batch.append(ev)
        self._batch_bytes += approx_size
        self.stats.events_built += 1

    async def _maybe_flush(self) -> None:
        now = time.time()
        if len(self._batch) >= self.cfg.batch_size or (now - self._last_flush) >= self.cfg.flush_interval_sec:
            await self._flush()

    async def _flush(self, force: bool = False) -> None:
        if not self._batch:
            self._last_flush = time.time()
            return
        batch = self._batch
        self._batch = []
        self._batch_bytes = 0
        self._last_flush = time.time()
        try:
            await self.sink.write_batch(batch)
            self.stats.batches_flushed += 1
            logger.debug("Flushed %d events", len(batch))
        except Exception as e:
            # При ошибке доставки не возвращаем события в память, чтобы избежать бесконечного роста.
            self.stats.last_error = str(e)
            self.stats.events_dropped += len(batch)
            logger.exception("Sink write_batch failed; dropped %d events: %s", len(batch), e)

    # ---------------------------------------------
    # Служебные методы мониторинга/здоровья
    # ---------------------------------------------
    def health(self) -> Dict[str, Any]:
        healthy = self.stats.last_error is None
        return {
            "healthy": healthy,
            "uptime_sec": self.stats.uptime_sec,
            "lines_read": self.stats.lines_read,
            "json_parsed": self.stats.json_parsed,
            "json_failed": self.stats.json_failed,
            "events_built": self.stats.events_built,
            "events_dropped": self.stats.events_dropped,
            "batches_flushed": self.stats.batches_flushed,
            "last_error": self.stats.last_error,
            "eve_path": str(self.cfg.eve_path),
        }


# -----------------------------------------------------------------------------
# Пример использования (не запускается автоматически, оставлено для интеграции):
# -----------------------------------------------------------------------------
# async def main():
#     cfg = SuricataBridgeConfig(eve_path=Path("/var/log/suricata/eve.json"))
#     q: asyncio.Queue[IDSEvent] = asyncio.Queue(maxsize=10000)
#     sink = QueueSink(q)
#     bridge = SuricataBridge(cfg, sink)
#     await bridge.start()
#     try:
#         while True:
#             ev = await q.get()
#             # Дальнейшая обработка нормализованных событий...
#     finally:
#         await bridge.stop()
#
# if __name__ == "__main__":
#     asyncio.run(main())
