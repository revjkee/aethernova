# physical_integration/control/plc_bridge.py
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Literal, Deque
from collections import deque

# Протокольный адаптер: используем ваш модуль Modbus-TCP
from physical_integration.protocols.modbus_tcp import (
    ModbusTcpClient,
    BatchMapItem,
    RateLimit as MbRateLimit,
    BackoffPolicy as MbBackoffPolicy,
    CircuitBreakerConfig as MbCBConfig,
    NullMetrics as MbNullMetrics,
    ModbusError,
    ModbusIOError,
    ModbusProtocolError,
)

# ============================
# Метрики/наблюдаемость (минимум)
# ============================

class Metrics:
    def inc(self, name: str, **labels: Any) -> None: ...
    def observe(self, name: str, value_ms: float, **labels: Any) -> None: ...
    def gauge(self, name: str, value: float, **labels: Any) -> None: ...

class NullMetrics(Metrics):
    def inc(self, name: str, **labels: Any) -> None: pass
    def observe(self, name: str, value_ms: float, **labels: Any) -> None: pass
    def gauge(self, name: str, value: float, **labels: Any) -> None: pass

# ============================
# Абстракции шины
# ============================

class EventSink:
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

class CommandSource:
    async def get(self) -> Dict[str, Any]:
        """Блокирующее получение следующей команды; возвращает dict с полями ниже."""
        raise NotImplementedError

class PolicyEvaluator:
    async def allow(self, command: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Возвращает (allow, reasons)."""
        return True, []

# Примитивные реализации для отладки/юнит-тестов
class InMemoryEventSink(EventSink):
    def __init__(self):
        self.events: Deque[Tuple[str, Dict[str, Any]]] = deque(maxlen=10000)
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        self.events.append((topic, payload))

class InMemoryCommandQueue(CommandSource):
    def __init__(self):
        self.q: asyncio.Queue = asyncio.Queue()
    async def put(self, cmd: Dict[str, Any]) -> None:
        await self.q.put(cmd)
    async def get(self) -> Dict[str, Any]:
        return await self.q.get()

class AllowAllPolicy(PolicyEvaluator):
    async def allow(self, command: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return True, []

# ============================
# Конфигурации устройств/опроса
# ============================

Kind = Literal["holding", "input"]  # для опроса регистров (coils можно добавить аналогично)

@dataclass
class RegisterBlock:
    """Один блок опроса с картой тегов для дешифровки."""
    name: str
    kind: Kind
    address: int
    count: int
    mapping: List[BatchMapItem] = field(default_factory=list)
    period_sec: float = 1.0
    max_skew_sec: float = 0.2  # распределение нагрузки (джиттер периода)
    endian: Literal["big", "little"] = "big"

@dataclass
class WriteLimit:
    max_multi_write_registers: int = 64  # защита от массовой записи
    min_interval_ms: int = 50            # анти-дрожь

@dataclass
class DeviceConfig:
    device_id: str
    protocol: Literal["modbus_tcp"] = "modbus_tcp"
    host: str = "127.0.0.1"
    port: int = 502
    unit_id: int = 1
    connect_timeout: float = 5.0
    request_timeout: float = 2.0
    backoff: MbBackoffPolicy = field(default_factory=MbBackoffPolicy)
    breaker: MbCBConfig = field(default_factory=MbCBConfig)
    rate: MbRateLimit = field(default_factory=lambda: MbRateLimit(tokens_per_sec=40.0, burst=80))
    metrics: Optional[Metrics] = None
    write_limit: WriteLimit = field(default_factory=WriteLimit)
    read_blocks: List[RegisterBlock] = field(default_factory=list)

# ============================
# Протокольный адаптер (обобщение)
# ============================

class ProtocolAdapter:
    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def read_block(self, b: RegisterBlock) -> Dict[str, Any]: ...
    async def write_typed(self, address: int, value: Any, *, typ: str, endian: str, word_order: str,
                          scale: float, offset: float, idem_key: Optional[str],
                          max_multi_write: int) -> None: ...

class ModbusAdapter(ProtocolAdapter):
    def __init__(self, cfg: DeviceConfig):
        self.cfg = cfg
        self.metrics = cfg.metrics or NullMetrics()
        self.client = ModbusTcpClient(
            host=cfg.host, port=cfg.port, unit_id=cfg.unit_id,
            connect_timeout=cfg.connect_timeout, request_timeout=cfg.request_timeout,
            backoff=cfg.backoff, rate_limit=cfg.rate, breaker=cfg.breaker,
            metrics=MbNullMetrics(),  # используем свой metrics на уровне bridge
            name=f"modbus:{cfg.device_id}"
        )

    async def connect(self) -> None:
        await self.client.connect()

    async def close(self) -> None:
        await self.client.close()

    async def read_block(self, b: RegisterBlock) -> Dict[str, Any]:
        t0 = time.perf_counter()
        res = await self.client.read_batch(
            b.address, b.count, kind=b.kind, mapping=b.mapping, endian=b.endian
        )
        self.metrics.observe("bridge_read_ms", (time.perf_counter() - t0) * 1000.0, device=self.cfg.device_id, block=b.name)
        if not res.ok:
            raise ModbusError(res.error or "unknown read error")
        out = {"_ts_ms": res.ts_ms, "_block": b.name}
        if res.values:
            out.update(res.values)
        else:
            # если mapping пуст, публикуем «сырые» регистры
            out["registers"] = res.registers
        return out

    async def write_typed(self, address: int, value: Any, *, typ: str, endian: str, word_order: str,
                          scale: float, offset: float, idem_key: Optional[str],
                          max_multi_write: int) -> None:
        t0 = time.perf_counter()
        await self.client.write_typed(
            address=address, value=value, typ=typ, endian=endian, word_order=word_order,
            scale=scale, offset=offset, idempotency_key=idem_key, max_multi_write=max_multi_write
        )
        self.metrics.observe("bridge_write_ms", (time.perf_counter() - t0) * 1000.0, device=self.cfg.device_id)

# ============================
# Маппинг команд на регистры
# ============================

@dataclass
class CommandMapItem:
    name: str                 # имя команды, приходящее в шину (например, "setpoint_write")
    address: int              # адрес регистра
    typ: Literal["bool","uint16","int16","uint32","int32","float32","uint64","int64","float64"] = "uint16"
    endian: Literal["big","little"] = "big"
    word_order: Literal["AB","BA"] = "AB"
    scale: float = 1.0
    offset: float = 0.0

@dataclass
class DeviceCommandMap:
    device_id: str
    items: Dict[str, CommandMapItem] = field(default_factory=dict)

# ============================
# PLCBridge
# ============================

@dataclass
class PLCBridgeConfig:
    devices: List[DeviceConfig] = field(default_factory=list)
    command_maps: List[DeviceCommandMap] = field(default_factory=list)
    telemetry_topic: str = "telemetry.{device_id}.{block}"
    state_topic: str = "twins.{device_id}.state"     # агрегированная публикация
    cmd_status_topic: str = "commands.{command_id}.status"
    dlq_topic: str = "dlq.commands"
    idempotency_window: int = 10_000  # сколько msg_id хранить для защиты от ретраев
    start_connect_parallelism: int = 4

class PLCBridge:
    def __init__(self,
                 cfg: PLCBridgeConfig,
                 sink: EventSink,
                 commands: CommandSource,
                 policy: PolicyEvaluator,
                 metrics: Optional[Metrics] = None):
        self.cfg = cfg
        self.sink = sink
        self.commands = commands
        self.policy = policy
        self.metrics = metrics or NullMetrics()
        self.adapters: Dict[str, ProtocolAdapter] = {}
        self.dev_cfg: Dict[str, DeviceConfig] = {d.device_id: d for d in cfg.devices}
        self.cmd_map: Dict[str, DeviceCommandMap] = {m.device_id: m for m in cfg.command_maps}
        self._idem: Deque[str] = deque(maxlen=cfg.idempotency_window)
        self._last_write_ts: Dict[Tuple[str,int], float] = {}
        self._tasks: List[asyncio.Task] = []
        self._stop = asyncio.Event()

    # ---------- Жизненный цикл ----------

    async def start(self):
        # Инициализация адаптеров и соединений
        async def init_device(d: DeviceConfig):
            adapter = ModbusAdapter(d) if d.protocol == "modbus_tcp" else None
            if adapter is None:
                raise RuntimeError(f"Unsupported protocol: {d.protocol}")
            await adapter.connect()
            self.adapters[d.device_id] = adapter

        sem = asyncio.Semaphore(self.cfg.start_connect_parallelism)
        async def guarded(d: DeviceConfig):
            async with sem:
                await init_device(d)

        await asyncio.gather(*(guarded(d) for d in self.cfg.devices))

        # Запускаем опросные лупы и потребителя команд
        for d in self.cfg.devices:
            self._tasks.append(asyncio.create_task(self._poll_device_loop(d)))
        self._tasks.append(asyncio.create_task(self._command_consumer_loop()))

    async def stop(self):
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for a in self.adapters.values():
            try:
                await a.close()
            except Exception:
                pass

    # ---------- Опрос устройств ----------

    async def _poll_device_loop(self, d: DeviceConfig):
        """Планирует независимые «тиковые» запускы опроса блоков с джиттером."""
        blocks = list(d.read_blocks)
        # случайный стартовый сдвиг для рассинхронизации
        await asyncio.sleep(random.random() * 0.5)
        next_at: Dict[str, float] = {}
        now = time.monotonic()
        for b in blocks:
            next_at[b.name] = now + random.random() * min(b.max_skew_sec, b.period_sec)

        adapter = self.adapters[d.device_id]

        while not self._stop.is_set():
            now = time.monotonic()
            due = [b for b in blocks if now >= next_at[b.name]]
            if not due:
                await asyncio.sleep(0.02)
                continue

            for b in due:
                next_at[b.name] = now + b.period_sec + random.uniform(-b.max_skew_sec, b.max_skew_sec)
                try:
                    payload = await adapter.read_block(b)
                    # публикация по двум схемам: агрегированная и помодульная
                    await self._publish_state(d.device_id, payload, block=b.name)
                except (ModbusError, ModbusIOError, ModbusProtocolError) as e:
                    self.metrics.inc("bridge_read_error", device=d.device_id, block=b.name, err=type(e).__name__)
                    await self._emit_dlq("read", d.device_id, reason=str(e), block=b.name)
                except Exception as e:
                    self.metrics.inc("bridge_read_error", device=d.device_id, block=b.name, err="Exception")
                    await self._emit_dlq("read", d.device_id, reason=str(e), block=b.name)

    async def _publish_state(self, device_id: str, payload: Dict[str, Any], block: str):
        # агрегированная публикация состояния twin
        topic_state = self.cfg.state_topic.format(device_id=device_id)
        data = {"device_id": device_id, **payload}
        await self.sink.publish(topic_state, data)
        # публикация «помодульно» (для потребителей с высоким трафиком)
        topic_tele = self.cfg.telemetry_topic.format(device_id=device_id, block=block)
        await self.sink.publish(topic_tele, data)

    # ---------- Обработка команд ----------

    async def _command_consumer_loop(self):
        while not self._stop.is_set():
            try:
                cmd = await asyncio.wait_for(self.commands.get(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            try:
                await self._handle_command(cmd)
            except Exception as e:
                # Последняя линия обороны
                await self._emit_dlq("command", cmd.get("device_id","?"), reason=str(e), command=cmd)

    async def _handle_command(self, cmd: Dict[str, Any]):
        """
        Ожидаемый формат команды:
        {
          "command_id": "uuid",
          "device_id": "plc-1",
          "name": "setpoint_write",
          "value": 42.5,
          "address": null,   # опционально; если не задан — ищем по карте DeviceCommandMap
          "typ": null,       # опционально; берём из карты
          "impact_level": "high",
          "idempotency_key": "uuid-xyz",
          "labels": {...}
        }
        """
        device_id: str = cmd["device_id"]
        command_id: str = cmd.get("command_id") or cmd.get("msg_id") or ""
        name: str = cmd["name"]

        if command_id and command_id in self._idem:
            # идемпотентно подтверждаем
            await self._ack(command_id, "duplicate", device_id, note="idempotent replay")
            return
        if command_id:
            self._idem.append(command_id)

        # политика допуска
        allow, reasons = await self.policy.allow(cmd)
        if not allow:
            await self._ack(command_id, "denied", device_id, reasons=reasons)
            return

        # карта команд
        cmap = self.cmd_map.get(device_id)
        item: Optional[CommandMapItem] = None
        if cmap:
            item = cmap.items.get(name)
        # приоритет: явные параметры команды перекрывают карту
        addr = cmd.get("address") if cmd.get("address") is not None else (item.address if item else None)
        typ = cmd.get("typ") or (item.typ if item else "uint16")
        endian = cmd.get("endian") or (item.endian if item else "big")
        worder = cmd.get("word_order") or (item.word_order if item else "AB")
        scale = float(cmd.get("scale") if cmd.get("scale") is not None else (item.scale if item else 1.0))
        offset = float(cmd.get("offset") if cmd.get("offset") is not None else (item.offset if item else 0.0))

        if addr is None:
            await self._ack(command_id, "failed", device_id, reasons=["unknown command mapping"])
            return

        adapter = self.adapters.get(device_id)
        if not adapter:
            await self._ack(command_id, "failed", device_id, reasons=["device not connected"])
            return

        # анти-дрожь/частые записи в один адрес
        wl = self.dev_cfg[device_id].write_limit
        now = time.monotonic()
        last = self._last_write_ts.get((device_id, addr), 0.0)
        if (now - last) * 1000.0 < wl.min_interval_ms:
            await asyncio.sleep(wl.min_interval_ms / 1000.0)
        self._last_write_ts[(device_id, addr)] = time.monotonic()

        # выполняем запись
        try:
            await adapter.write_typed(
                address=addr,
                value=cmd.get("value"),
                typ=typ, endian=endian, word_order=worder,
                scale=scale, offset=offset,
                idem_key=cmd.get("idempotency_key"),
                max_multi_write=self.dev_cfg[device_id].write_limit.max_multi_write_registers
            )
            await self._ack(command_id, "completed", device_id)
        except (ModbusError, ModbusProtocolError, ModbusIOError) as e:
            await self._ack(command_id, "failed", device_id, reasons=[str(e)])
            await self._emit_dlq("command", device_id, reason=str(e), command=cmd)

    async def _ack(self, command_id: str, status: Literal["completed","failed","denied","duplicate"], device_id: str, reasons: Optional[Iterable[str]] = None, note: Optional[str] = None):
        topic = self.cfg.cmd_status_topic.format(command_id=command_id)
        payload = {
            "command_id": command_id,
            "device_id": device_id,
            "status": status,
            "reasons": list(reasons) if reasons else [],
            "note": note or "",
            "ts_ms": int(time.time() * 1000),
        }
        await self.sink.publish(topic, payload)

    async def _emit_dlq(self, kind: str, device_id: str, *, reason: str, block: Optional[str] = None, command: Optional[Dict[str, Any]] = None):
        payload = {
            "kind": kind,
            "device_id": device_id,
            "reason": reason,
            "block": block,
            "command": command,
            "ts_ms": int(time.time() * 1000),
        }
        await self.sink.publish(self.cfg.dlq_topic, payload)

# ============================
# Утилита: сборка конфигурации из «карты тегов»
# ============================

def make_batch_map_item(name: str, at: int, typ: str = "uint16",
                        scale: float = 1.0, offset: float = 0.0,
                        word_order: str = "AB", endian: str = "big") -> BatchMapItem:
    return BatchMapItem(name=name, at=at, type=typ, scale=scale, offset=offset,
                        word_order=word_order, endian=endian)

# ============================
# Пример использования (док-строка)
# ============================

"""
Пример:
--------
import asyncio
from physical_integration.control.plc_bridge import (
    PLCBridge, PLCBridgeConfig, DeviceConfig, RegisterBlock, make_batch_map_item,
    InMemoryEventSink, InMemoryCommandQueue, AllowAllPolicy, DeviceCommandMap, CommandMapItem
)

async def main():
    sink = InMemoryEventSink()
    cmds = InMemoryCommandQueue()
    policy = AllowAllPolicy()

    dev = DeviceConfig(
        device_id="plc-1",
        host="10.0.0.10", port=502, unit_id=1,
        read_blocks=[
            RegisterBlock(
                name="metering",
                kind="holding",
                address=0,
                count=16,
                mapping=[
                    make_batch_map_item("voltage_v", 0, "uint16", scale=0.1),
                    make_batch_map_item("current_a", 1, "uint16", scale=0.01),
                    make_batch_map_item("energy_kwh", 2, "uint32", scale=0.001),
                    make_batch_map_item("temp_c", 4, "float32", word_order="BA"),
                ],
                period_sec=1.0,
                max_skew_sec=0.2
            )
        ]
    )

    cmap = DeviceCommandMap(
        device_id="plc-1",
        items={
            "setpoint_write": CommandMapItem(name="setpoint_write", address=100, typ="float32", word_order="BA")
        }
    )

    bridge = PLCBridge(
        PLCBridgeConfig(devices=[dev], command_maps=[cmap]),
        sink=sink, commands=cmds, policy=policy
    )
    await bridge.start()

    # Отправим команду
    await cmds.put({"command_id":"cmd-1","device_id":"plc-1","name":"setpoint_write","value":42.5,"impact_level":"high","idempotency_key":"cmd-1"})

    await asyncio.sleep(5)
    await bridge.stop()

asyncio.run(main())
"""

# Конец файла
