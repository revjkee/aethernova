from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# PySerial-asyncio (желательно установить pyserial-asyncio>=0.6)
try:
    import serial_asyncio  # type: ignore
except Exception:  # pragma: no cover
    serial_asyncio = None  # type: ignore

# Метрики (no-op, если prometheus_client недоступен)
try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def set(self, *_): return
        def inc(self, *_): return
    Counter = Gauge = _Noop  # type: ignore


# ======================================================================
# МОДЕЛИ ДАННЫХ
# ======================================================================

@dataclass(frozen=True)
class CANFrame:
    """
    Представление CAN кадра на уровне приложения.
    - id: 11-бит или 29-бит идентификатор (целое)
    - data: bytes длиной 0..8
    - is_extended: 29-битный кадр (True) или классический 11-бит (False)
    - is_remote: Remote Transmission Request (RTR)
    - timestamp_ms: опциональный штамп приёма (мс)
    """
    id: int
    data: bytes = dataclasses.field(default_factory=bytes)
    is_extended: bool = False
    is_remote: bool = False
    timestamp_ms: Optional[int] = None

    def __post_init__(self) -> None:
        if not (0 <= len(self.data) <= 8):
            raise ValueError("CAN data length must be in 0..8")
        if self.is_extended:
            if not (0 <= self.id <= 0x1FFFFFFF):
                raise ValueError("Extended CAN id must be in 0..0x1FFFFFFF")
        else:
            if not (0 <= self.id <= 0x7FF):
                raise ValueError("Standard CAN id must be in 0..0x7FF")

    # ---------------- SLCAN (LAWICEL ASCII) ----------------

    @staticmethod
    def _hex(n: int, width: int) -> str:
        return f"{n:0{width}X}"

    def to_slcan(self, include_timestamp: bool = False) -> str:
        """
        Форматирует команду SLCAN для отправки кадра.
        - t/T: data frame, r/R: remote frame
        Формат без таймстампа:
          tIII DLC DATA...\r  | TIIIIIIII DLC DATA...\r
          rIII DLC\r          | RIIIIIIII DLC\r
        where I... — hex id, DLC — hex, DATA — 2*DLC hex.
        """
        kind = (
            ("R" if self.is_remote else "T") if self.is_extended else
            ("r" if self.is_remote else "t")
        )
        if self.is_extended:
            ident = self._hex(self.id & 0x1FFFFFFF, 8)
        else:
            ident = self._hex(self.id & 0x7FF, 3)

        dlc = len(self.data)
        head = f"{kind}{ident}{self._hex(dlc, 1)}"
        payload = "" if self.is_remote else self.data.hex().upper()
        # Большинство адаптеров ожидает CR как терминатор команды.
        # Таймстамп при отправке, как правило, не включается; опционально поддерживаем.
        if include_timestamp and self.timestamp_ms is not None:
            # Используем 4-значный HEX модульного таймстампа по линии (если устройство это поддерживает).
            ts = self._hex(int(self.timestamp_ms) & 0xFFFF, 4)
            return f"{head}{payload}{ts}\r"
        return f"{head}{payload}\r"

    @staticmethod
    def from_slcan(frame_str: str) -> "CANFrame":
        """
        Парсит строку SLCAN одной рамки (без завершающего CR).
        Допускает наличие или отсутствие хвостового hex-таймстампа.
        """
        if not frame_str:
            raise ValueError("empty slcan frame")
        kind = frame_str[0]
        is_ext = kind in ("T", "R")
        is_remote = kind in ("r", "R")

        # Определяем длины полей ID/DLC согласно типу кадра
        id_len = 8 if is_ext else 3
        if len(frame_str) < 1 + id_len + 1:
            raise ValueError("invalid slcan length")

        ident_hex = frame_str[1:1 + id_len]
        dlc_hex = frame_str[1 + id_len:1 + id_len + 1]
        try:
            ident = int(ident_hex, 16)
            dlc = int(dlc_hex, 16)
        except ValueError as e:
            raise ValueError(f"invalid hex in slcan frame: {e}")

        # Данные и опциональный таймстамп — оставшаяся часть строки
        rest = frame_str[1 + id_len + 1:]
        data_len_hex = 0 if is_remote else dlc * 2
        if len(rest) < data_len_hex:
            raise ValueError("invalid slcan payload length")

        data_hex = rest[:data_len_hex]
        data = bytes.fromhex(data_hex) if data_len_hex else b""

        ts_ms: Optional[int] = None
        ts_tail = rest[data_len_hex:]
        # Если остались строго 4 HEX-символа — интерпретируем как таймстамп (распространённый вариант)
        if len(ts_tail) == 4 and re.fullmatch(r"[0-9A-Fa-f]{4}", ts_tail):
            ts_ms = int(ts_tail, 16)

        return CANFrame(id=ident, data=data, is_extended=is_ext, is_remote=is_remote, timestamp_ms=ts_ms)


# ======================================================================
# КОНФИГУРАЦИЯ ТРАНСПОРТА
# ======================================================================

@dataclass(frozen=True)
class SerialCANConfig:
    port: str
    baudrate: int = 115200
    # Если указан bitrate_preset, при подключении отправляется команда установки (S0..S8), затем Open (O).
    bitrate_preset: Optional[int] = None  # 0..8 — конкретные значения определяются адаптером
    # Таймаут ожидания ответа на сервисные команды (сек)
    command_timeout_s: float = 1.0
    # Очередь входящих кадров (bounded): защита от backpressure
    rx_queue_size: int = 4096
    # Ретраи коннекта
    reconnect_initial_delay_s: float = 0.5
    reconnect_max_delay_s: float = 15.0
    reconnect_jitter_s: float = 0.2
    # Разрешить автоматический reopen канала при reconnect
    auto_open_channel: bool = True
    # Включить аппаратные фильтры через команды адаптера (если поддерживается)
    acceptance_code: Optional[int] = None
    acceptance_mask: Optional[int] = None
    # Логирование
    log_json: bool = True


# ======================================================================
# ОСНОВНОЙ ТРАНСПОРТ SLCAN
# ======================================================================

class SerialSLCANTransport:
    """
    Асинхронный транспорт SLCAN с надёжной обработкой разрывов связи и бэкпрешера.

    Жизненный цикл:
      await start() -> (re)connect -> configure -> open -> read loop
      await stop()  -> close serial

    Подписки:
      add_subscriber(callable(frame: CANFrame) -> Awaitable[None] | None)
    Чтение:
      async for frame in transport: ...

    Метрики:
      - serial_can_rx_frames_total{port}
      - serial_can_tx_frames_total{port}
      - serial_can_rx_dropped_total{reason="queue_full"|...}
      - serial_can_health_gauge{port} (1=ok, 0=disconnected)
    """
    def __init__(self, cfg: SerialCANConfig, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        if serial_asyncio is None:
            raise RuntimeError("pyserial-asyncio is required")
        self.cfg = cfg
        self.loop = loop or asyncio.get_event_loop()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._read_task: Optional[asyncio.Task] = None
        self._state_lock = asyncio.Lock()
        self._running = False
        self._rx_queue: asyncio.Queue[CANFrame] = asyncio.Queue(maxsize=cfg.rx_queue_size)
        self._subs: List[Callable[[CANFrame], Any]] = []
        self._last_rx_ms: int = 0
        self._health_ok = False
        self._logger = logging.getLogger(f"serial_can[{cfg.port}]")
        self._logger.setLevel(logging.INFO)

        # Метрики
        self.m_rx = Counter("serial_can_rx_frames_total", "Received CAN frames", ["port"])
        self.m_tx = Counter("serial_can_tx_frames_total", "Transmitted CAN frames", ["port"])
        self.m_drop = Counter("serial_can_rx_dropped_total", "Dropped frames", ["port", "reason"])
        self.g_health = Gauge("serial_can_health_gauge", "Transport health (1 ok / 0 down)", ["port"])

    # ---------------- ПУБЛИЧНОЕ API ----------------

    async def start(self) -> None:
        async with self._state_lock:
            if self._running:
                return
            self._running = True
            self._read_task = self.loop.create_task(self._run(), name=f"slcan-read-{self.cfg.port}")

    async def stop(self) -> None:
        async with self._state_lock:
            self._running = False
        await self._close_io()

    async def send(self, frame: CANFrame) -> None:
        """
        Отправка CAN кадра. Блокирующая до записи в UART.
        """
        writer = self._writer
        if writer is None:
            raise ConnectionError("serial not connected")
        payload = frame.to_slcan()
        writer.write(payload.encode("ascii"))
        await writer.drain()
        self.m_tx.labels(self.cfg.port).inc()

    def add_subscriber(self, callback: Callable[[CANFrame], Any]) -> None:
        """
        Регистрирует обработчик входящих кадров. Допускаются sync/async функции.
        """
        self._subs.append(callback)

    def health(self) -> Dict[str, Any]:
        return {
            "port": self.cfg.port,
            "connected": self._writer is not None and self._reader is not None,
            "last_rx_ms": self._last_rx_ms,
            "queue_size": self._rx_queue.qsize(),
        }

    # Итерация по входящим кадрам (удобно для «reader»-потребителей)
    def __aiter__(self) -> AsyncIterator[CANFrame]:
        return self._iter_frames()

    async def _iter_frames(self) -> AsyncIterator[CANFrame]:
        while True:
            frame = await self._rx_queue.get()
            yield frame

    # ---------------- ВНУТРЕННЕЕ ----------------

    async def _run(self) -> None:
        delay = self.cfg.reconnect_initial_delay_s
        while self._running:
            try:
                await self._connect_and_read()
                # Если read завершился без исключений — значит stop()
                break
            except asyncio.CancelledError:
                break
            except Exception as e:  # pragma: no cover
                self._log("warn", "connection_error", {"error": str(e)})
                await self._close_io()
                self._set_health(False)
                await asyncio.sleep(delay)
                delay = min(self.cfg.reconnect_max_delay_s, delay * 2)  # экспоненциальный бэкофф
            else:
                delay = self.cfg.reconnect_initial_delay_s

    async def _connect_and_read(self) -> None:
        self._log("info", "connecting", {"port": self.cfg.port, "baudrate": self.cfg.baudrate})
        reader, writer = await serial_asyncio.open_serial_connection(url=self.cfg.port, baudrate=self.cfg.baudrate)  # type: ignore
        self._reader, self._writer = reader, writer
        self._set_health(True)

        # Конфигурация канала
        if self.cfg.bitrate_preset is not None:
            await self._send_command(f"S{int(self.cfg.bitrate_preset)}")
        if self.cfg.acceptance_code is not None:
            # Некоторые адаптеры используют M/m или иные команды; здесь отправляем, если задано.
            await self._send_command(f"M{self.cfg.acceptance_code:08X}")
        if self.cfg.acceptance_mask is not None:
            await self._send_command(f"m{self.cfg.acceptance_mask:08X}")
        if self.cfg.auto_open_channel:
            await self._send_command("O")  # open CAN channel

        # Read loop
        buf = bytearray()
        while self._running and self._reader is reader:
            chunk = await reader.read(256)
            if not chunk:
                raise ConnectionError("serial read returned EOF")
            for b in chunk:
                if b in (0x0D,):  # CR — завершение сообщения
                    if not buf:
                        continue
                    try:
                        line = buf.decode("ascii")
                    except Exception:
                        self.m_drop.labels(self.cfg.port, "decode").inc()
                        buf.clear()
                        continue
                    buf.clear()
                    await self._handle_line(line)
                elif b in (0x0A,):  # LF — игнорируем
                    continue
                else:
                    buf.append(b)

    async def _send_command(self, cmd: str) -> None:
        """
        Отправляет сервисную команду (без ожидания специфичного ответа).
        Для некоторых команд адаптер отвечает короткими статусами; здесь не требуем их.
        """
        w = self._writer
        if not w:
            raise ConnectionError("serial not connected")
        msg = (cmd + "\r").encode("ascii")
        w.write(msg)
        await w.drain()
        # Небольшая пауза, чтобы адаптер обработал команду (в пределах таймаута).
        await asyncio.sleep(min(0.01, self.cfg.command_timeout_s))

    async def _handle_line(self, line: str) -> None:
        # Возможные строки: t/T/r/R кадры; статус/инфо-строки адаптера — игнорируем/логируем.
        if not line:
            return
        first = line[0]
        if first in ("t", "T", "r", "R"):
            try:
                frame = CANFrame.from_slcan(line)
            except Exception as e:
                self.m_drop.labels(self.cfg.port, "parse").inc()
                self._log("warn", "parse_error", {"line": line, "error": str(e)})
                return
            self._last_rx_ms = int(time.time() * 1000)
            self.m_rx.labels(self.cfg.port).inc()
            # Фильтрация приложением (если заданы acceptance_code/mask и устройство их не поддерживает)
            if self.cfg.acceptance_code is not None and self.cfg.acceptance_mask is not None:
                if not self._match_filter(frame.id, self.cfg.acceptance_code, self.cfg.acceptance_mask):
                    return
            # Публикация
            await self._publish(frame)
        else:
            # Статусные/диагностические строки адаптера
            self._log("info", "adapter", {"line": line})

    async def _publish(self, frame: CANFrame) -> None:
        # Очередь для «читателей»
        if self._rx_queue.full():
            # Дроп без блокировки, чтобы не стопорить read-loop
            self.m_drop.labels(self.cfg.port, "queue_full").inc()
        else:
            self._rx_queue.put_nowait(frame)
        # Подписчики (в фоне, без ожидания)
        for cb in list(self._subs):
            try:
                res = cb(frame)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)  # fire-and-forget
            except Exception as e:
                self._log("warn", "subscriber_error", {"error": str(e)})

    def _match_filter(self, can_id: int, code: int, mask: int) -> bool:
        return (can_id & mask) == (code & mask)

    async def _close_io(self) -> None:
        # Пытаемся закрыть канал на адаптере
        if self._writer:
            try:
                self._writer.write(b"C\r")  # close channel (если поддерживается)
                await self._writer.drain()
            except Exception:
                pass
        # Закрываем стримы
        try:
            if self._writer:
                self._writer.close()
                try:
                    await self._writer.wait_closed()  # type: ignore[attr-defined]
                except Exception:
                    pass
        finally:
            self._reader, self._writer = None, None

    def _set_health(self, ok: bool) -> None:
        self._health_ok = ok
        try:
            self.g_health.labels(self.cfg.port).set(1 if ok else 0)
        except Exception:
            pass

    def _log(self, level: str, msg: str, extra: Dict[str, Any]) -> None:  # pragma: no cover
        if self.cfg.log_json:
            payload = {"level": level, "msg": msg, "port": self.cfg.port, **extra}
            print(payload)  # либо отправьте в структурированный логгер
        else:
            getattr(self._logger, level, self._logger.info)(f"{msg} {extra}")


# ======================================================================
# УТИЛИТЫ ВЫСОКОГО УРОВНЯ
# ======================================================================

class CANBus:
    """
    Высокоуровневый фасад над SerialSLCANTransport:
      - автоматическая сериализация/парсинг
      - ожидание кадров по фильтру с таймаутом
    """
    def __init__(self, transport: SerialSLCANTransport) -> None:
        self.t = transport

    async def send_data(self, can_id: int, data: bytes, *, extended: bool = False) -> None:
        await self.t.send(CANFrame(id=can_id, data=data, is_extended=extended, is_remote=False))

    async def send_remote(self, can_id: int, *, dlc: int = 0, extended: bool = False) -> None:
        await self.t.send(CANFrame(id=can_id, data=b"\x00" * dlc, is_extended=extended, is_remote=True))

    async def recv_until(
        self,
        predicate: Callable[[CANFrame], bool],
        timeout_s: float = 1.0,
    ) -> Optional[CANFrame]:
        """
        Ожидает первый кадр, удовлетворяющий predicate, в течение timeout_s.
        """
        try:
            while True:
                frame = await asyncio.wait_for(self._next_frame(), timeout=timeout_s)
                if predicate(frame):
                    return frame
        except asyncio.TimeoutError:
            return None

    async def _next_frame(self) -> CANFrame:
        async for frame in self.t:
            return frame
        raise RuntimeError("transport stopped")

# ======================================================================
# CLI-ДЕМО (опционально)
# ======================================================================

async def _demo() -> None:  # pragma: no cover
    port = os.getenv("SLCAN_PORT", "/dev/ttyACM0" if sys.platform != "win32" else "COM5")
    cfg = SerialCANConfig(port=port, baudrate=115200, bitrate_preset=int(os.getenv("SLCAN_PRESET", "5")))
    tr = SerialSLCANTransport(cfg)

    def printer(frame: CANFrame) -> None:
        print(f"RX id=0x{frame.id:X} dlc={len(frame.data)} ext={frame.is_extended} rtr={frame.is_remote} data={frame.data.hex()} ts={frame.timestamp_ms}")

    tr.add_subscriber(printer)

    await tr.start()
    bus = CANBus(tr)
    # Пример передачи стандартного кадра
    await asyncio.sleep(1.0)
    await bus.send_data(0x123, b"\xDE\xAD\xBE\xEF")
    # Чтение несколько секунд
    await asyncio.sleep(10.0)
    await tr.stop()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
