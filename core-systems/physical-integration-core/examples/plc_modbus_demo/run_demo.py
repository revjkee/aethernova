# examples/plc_modbus_demo/run_demo.py
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# ---------------------------
# Optional fast JSON encoder
# ---------------------------
try:
    import orjson  # type: ignore
except Exception:
    orjson = None

def j_dumps(obj: Any) -> bytes:
    if orjson is not None:
        return orjson.dumps(obj)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def j_loads(data: Union[str, bytes]) -> Any:
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    return json.loads(data)

# ---------------------------
# Optional Kafka bridge (project local)
# ---------------------------
class _NoKafka:
    async def start_producer(self) -> None: ...
    async def start_consumer(self, topics: Iterable[str]) -> None: ...
    async def send(self, *a: Any, **kw: Any) -> None: ...
    async def consume(self, *a: Any, **kw: Any) -> None: ...
    async def close(self) -> None: ...

def _load_kafka_adapter():
    try:
        # project local path: physical_integration.adapters.kafka_adapter
        from physical_integration.adapters.kafka_adapter import KafkaAdapter, KafkaConfig  # type: ignore
        return KafkaAdapter, KafkaConfig
    except Exception:
        return None, None

KafkaAdapter, KafkaConfig = _load_kafka_adapter()

# ---------------------------
# Modbus client (async, pymodbus v3)
# ---------------------------
# We require pymodbus>=3 with AsyncModbusTcpClient. If absent — explicit error.
try:
    from pymodbus.client import AsyncModbusTcpClient  # type: ignore
    from pymodbus.exceptions import ModbusException  # type: ignore
except Exception as e:  # pragma: no cover
    AsyncModbusTcpClient = None
    ModbusException = Exception

# ---------------------------
# Logging
# ---------------------------
LOG = logging.getLogger("plc_modbus_demo")

# ---------------------------
# Types & config
# ---------------------------

class FC(Enum):
    COILS = 1                  # Read Coils
    DISCRETE = 2               # Read Discrete Inputs
    HOLDING = 3                # Read Holding Registers
    INPUT = 4                  # Read Input Registers

class WordOrder(Enum):
    MSW_FIRST = "msw_first"    # [reg0][reg1] -> words as 0,1
    LSW_FIRST = "lsw_first"    # [reg1][reg0]

class Endian(Enum):
    BIG = "big"
    LITTLE = "little"

class DataType(Enum):
    BOOL = "bool"              # coils/discrete
    INT16 = "int16"
    UINT16 = "uint16"
    INT32 = "int32"
    UINT32 = "uint32"
    FLOAT32 = "float32"

@dataclass
class Tag:
    name: str
    fc: FC
    address: int                 # 0-based PLC address
    count: int                   # registers or bits to read (for bool — 1)
    datatype: DataType
    scale: float = 1.0
    offset: float = 0.0
    endian: Endian = Endian.BIG
    word_order: WordOrder = WordOrder.MSW_FIRST
    unit_id: int = 1

@dataclass
class DemoConfig:
    plc_host: str = "127.0.0.1"
    plc_port: int = 502
    unit_id: int = 1
    poll_interval_s: float = 0.5
    reconnect_base_s: float = 0.5
    reconnect_max_s: float = 10.0
    publish_every_s: float = 5.0  # periodic full publish even if no changes
    float_epsilon: float = 1e-6
    kafka_bootstrap: Optional[str] = None
    kafka_topic_out: str = "plc.telemetry"
    kafka_topic_cmd: str = "plc.commands"
    kafka_client_id: str = "plc_modbus_demo"
    kafka_group_id: Optional[str] = "plc_modbus_demo"
    log_level: int = logging.INFO
    tags: List[Tag] = field(default_factory=list)

# ---------------------------
# Modbus decoding helpers
# ---------------------------

def _merge_words(words: List[int], word_order: WordOrder) -> List[int]:
    if len(words) < 2:
        return words
    if word_order == WordOrder.MSW_FIRST:
        return words
    # swap words in pairs
    out = words[:]
    for i in range(0, len(words) - 1, 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return out

def decode_value(tag: Tag, regs_or_bits: List[int]) -> Union[bool, int, float]:
    if tag.datatype == DataType.BOOL:
        return bool(regs_or_bits[0])

    # 16/32-bit numeric types from holding/input registers
    words = regs_or_bits[: tag.count]
    words = _merge_words(words, tag.word_order)

    # pack words into bytes
    b = bytearray()
    for w in words:
        if tag.endian == Endian.BIG:
            b.extend(struct.pack(">H", w & 0xFFFF))
        else:
            b.extend(struct.pack("<H", w & 0xFFFF))

    if tag.datatype == DataType.INT16:
        val = struct.unpack((">" if tag.endian == Endian.BIG else "<") + "h", bytes(b))[0]
    elif tag.datatype == DataType.UINT16:
        val = struct.unpack((">" if tag.endian == Endian.BIG else "<") + "H", bytes(b))[0]
    elif tag.datatype == DataType.INT32:
        val = struct.unpack((">" if tag.endian == Endian.BIG else "<") + "i", bytes(b))[0]
    elif tag.datatype == DataType.UINT32:
        val = struct.unpack((">" if tag.endian == Endian.BIG else "<") + "I", bytes(b))[0]
    elif tag.datatype == DataType.FLOAT32:
        val = struct.unpack((">" if tag.endian == Endian.BIG else "<") + "f", bytes(b))[0]
    else:
        raise ValueError(f"Unsupported datatype: {tag.datatype}")

    return float(val) * tag.scale + tag.offset if isinstance(val, (int, float)) else val

# ---------------------------
# Modbus PLC wrapper
# ---------------------------

class PLCClient:
    def __init__(self, host: str, port: int, unit_id: int) -> None:
        if AsyncModbusTcpClient is None:
            raise RuntimeError(
                "pymodbus is required. Install: pip install 'pymodbus[async]'>=3.0.0"
            )
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self._client: Optional[AsyncModbusTcpClient] = None
        self._connected = asyncio.Event()

    async def connect(self) -> None:
        self._client = AsyncModbusTcpClient(self.host, self.port)
        await self._client.connect()
        if not self._client.connected:
            raise RuntimeError(f"PLC connect failed to {self.host}:{self.port}")
        self._connected.set()
        LOG.info("PLC connected %s:%s", self.host, self.port)

    async def close(self) -> None:
        self._connected.clear()
        if self._client:
            try:
                await self._client.close()
            finally:
                self._client = None
        LOG.info("PLC disconnected")

    @property
    def connected(self) -> bool:
        return bool(self._client and self._client.connected)

    async def ensure_connection(self) -> None:
        if not self.connected:
            await self.connect()

    async def read_bits(self, fc: FC, address: int, count: int, unit_id: Optional[int] = None) -> List[int]:
        if fc not in (FC.COILS, FC.DISCRETE):
            raise ValueError("read_bits: fc must be COILS or DISCRETE")
        await self.ensure_connection()
        assert self._client is not None
        if fc == FC.COILS:
            rr = await self._client.read_coils(address, count, unit=unit_id or self.unit_id)
        else:
            rr = await self._client.read_discrete_inputs(address, count, unit=unit_id or self.unit_id)
        if rr.isError():  # type: ignore
            raise ModbusException(str(rr))
        return [int(x) for x in rr.bits[:count]]  # type: ignore

    async def read_regs(self, fc: FC, address: int, count: int, unit_id: Optional[int] = None) -> List[int]:
        if fc not in (FC.HOLDING, FC.INPUT):
            raise ValueError("read_regs: fc must be HOLDING or INPUT")
        await self.ensure_connection()
        assert self._client is not None
        if fc == FC.HOLDING:
            rr = await self._client.read_holding_registers(address, count, unit=unit_id or self.unit_id)
        else:
            rr = await self._client.read_input_registers(address, count, unit=unit_id or self.unit_id)
        if rr.isError():  # type: ignore
            raise ModbusException(str(rr))
        return [int(x) for x in (rr.registers or [])]  # type: ignore

    async def write_coil(self, address: int, value: bool, unit_id: Optional[int] = None) -> None:
        await self.ensure_connection()
        assert self._client is not None
        rr = await self._client.write_coil(address, value, unit=unit_id or self.unit_id)
        if rr.isError():  # type: ignore
            raise ModbusException(str(rr))

    async def write_register(self, address: int, value: int, unit_id: Optional[int] = None) -> None:
        await self.ensure_connection()
        assert self._client is not None
        rr = await self._client.write_register(address, int(value) & 0xFFFF, unit=unit_id or self.unit_id)
        if rr.isError():  # type: ignore
            raise ModbusException(str(rr))

# ---------------------------
# Tag poller with grouping
# ---------------------------

@dataclass
class _ReadBlock:
    fc: FC
    unit_id: int
    start: int
    count: int
    tags: List[Tag] = field(default_factory=list)

def _group_tags(tags: List[Tag], max_span: int = 32) -> List[_ReadBlock]:
    """
    Group tags by FC/unit into compact read blocks (contiguous windows).
    max_span limits how far we stretch a window to avoid huge reads.
    """
    out: List[_ReadBlock] = []
    by_key: Dict[Tuple[FC, int], List[Tag]] = {}
    for t in tags:
        by_key.setdefault((t.fc, t.unit_id), []).append(t)
    for (fc, unit), items in by_key.items():
        items.sort(key=lambda t: t.address)
        if not items:
            continue
        block_start = items[0].address
        block_end = items[0].address + max(1, items[0].count)
        block_tags: List[Tag] = [items[0]]
        for t in items[1:]:
            need_end = t.address + max(1, t.count)
            # extend block if within span
            if need_end - block_start <= max_span:
                block_end = max(block_end, need_end)
                block_tags.append(t)
            else:
                out.append(_ReadBlock(fc, unit, block_start, block_end - block_start, block_tags))
                block_start = t.address
                block_end = need_end
                block_tags = [t]
        out.append(_ReadBlock(fc, unit, block_start, block_end - block_start, block_tags))
    return out

class TagPoller:
    def __init__(self, plc: PLCClient, cfg: DemoConfig) -> None:
        self.plc = plc
        self.cfg = cfg
        self._last_values: Dict[str, Union[bool, int, float]] = {}
        self._last_publish_ts: float = 0.0

    @staticmethod
    def _changed(a: Any, b: Any, eps: float) -> bool:
        if a is None or b is None:
            return True
        if isinstance(a, float) or isinstance(b, float):
            try:
                return abs(float(a) - float(b)) > eps
            except Exception:
                return True
        return a != b

    async def poll_once(self, tags: List[Tag]) -> Dict[str, Union[bool, int, float]]:
        result: Dict[str, Union[bool, int, float]] = {}
        blocks = _group_tags(tags)
        for blk in blocks:
            if blk.fc in (FC.COILS, FC.DISCRETE):
                raw = await self.plc.read_bits(blk.fc, blk.start, blk.count, unit_id=blk.unit_id)
            else:
                raw = await self.plc.read_regs(blk.fc, blk.start, blk.count, unit_id=blk.unit_id)
            for t in blk.tags:
                off = t.address - blk.start
                if t.datatype == DataType.BOOL:
                    val = decode_value(t, [raw[off]])
                else:
                    regs = raw[off : off + t.count]
                    val = decode_value(t, regs)
                result[t.name] = val
        return result

    async def run(self, pub_cb: Optional[callable] = None) -> None:
        """
        Main polling loop. Calls pub_cb(changed_payload) on change or periodic interval.
        """
        backoff = self.cfg.reconnect_base_s
        while True:
            try:
                t0 = time.perf_counter()
                values = await self.poll_once(self.cfg.tags)
                now = time.time()
                changed: Dict[str, Any] = {}
                for k, v in values.items():
                    if self._changed(self._last_values.get(k), v, self.cfg.float_epsilon):
                        changed[k] = v
                        self._last_values[k] = v
                force = (now - self._last_publish_ts) >= self.cfg.publish_every_s
                if changed or force:
                    payload = {
                        "ts_unix": now,
                        "unit_id": self.cfg.unit_id,
                        "values": (self._last_values if force and not changed else changed),
                    }
                    if pub_cb:
                        await pub_cb(payload)
                    self._last_publish_ts = now
                # successful iteration, reset backoff
                backoff = self.cfg.reconnect_base_s
                dt = (time.perf_counter() - t0)
                sleep_left = max(0.0, self.cfg.poll_interval_s - dt)
                await asyncio.sleep(sleep_left)
            except (ConnectionError, OSError, ModbusException) as e:
                LOG.warning("PLC poll error: %r; reconnecting in %.2fs", e, backoff)
                await self.plc.close()
                await asyncio.sleep(backoff)
                try:
                    await self.plc.connect()
                except Exception as ee:
                    LOG.error("PLC reconnect failed: %r", ee)
                backoff = min(self.cfg.reconnect_max_s, backoff * 2.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.exception("Unexpected polling error: %r", e)
                await asyncio.sleep(self.cfg.poll_interval_s)

# ---------------------------
# Kafka command handler
# ---------------------------

class CommandServer:
    """
    Consumes commands from Kafka topic and executes writes to PLC:
    message schema (JSON):
    {
      "op": "write_coil" | "write_register",
      "address": 0,
      "unit_id": 1,             # optional, defaults to cfg.unit_id
      "value": true | 123
    }
    """
    def __init__(self, plc: PLCClient, cfg: DemoConfig, kafka) -> None:
        self.plc = plc
        self.cfg = cfg
        self.kafka = kafka

    async def start(self) -> None:
        if not KafkaAdapter or not self.kafka:
            return
        # Note: KafkaAdapter.consume runs forever; we spawn it as a task.
        async def handler(msg) -> None:
            try:
                data = j_loads(msg.value or b"{}")
                op = str(data.get("op", "")).lower()
                address = int(data.get("address"))
                unit_id = int(data.get("unit_id", self.cfg.unit_id))
                if op == "write_coil":
                    val = bool(data.get("value"))
                    await self._safe_write(self.plc.write_coil, address, val, unit_id)
                elif op == "write_register":
                    val = int(data.get("value"))
                    if not (0 <= val <= 0xFFFF):
                        raise ValueError("value must be 0..65535 for write_register")
                    await self._safe_write(self.plc.write_register, address, val, unit_id)
                else:
                    LOG.warning("Unknown command op: %r", op)
            except Exception as e:
                LOG.warning("Command processing failed: %r", e)

        await self.kafka.start_consumer([self.cfg.kafka_topic_cmd])
        await self.kafka.consume([self.cfg.kafka_topic_cmd], handler)

    async def _safe_write(self, fn, address: int, value: Any, unit_id: int) -> None:
        try:
            await fn(address, value, unit_id=unit_id)
            LOG.info("Command executed: %s addr=%s val=%s unit=%s", fn.__name__, address, value, unit_id)
        except Exception as e:
            LOG.warning("Command failed: %s addr=%s err=%r", fn.__name__, address, e)

# ---------------------------
# Config loading
# ---------------------------

def load_tags_from_file(path: str) -> List[Tag]:
    with open(path, "rb") as f:
        data = json.load(f)
    tags: List[Tag] = []
    for item in data:
        tags.append(
            Tag(
                name=item["name"],
                fc=FC(int(item["fc"])) if isinstance(item["fc"], int) else FC[item["fc"].upper()],
                address=int(item["address"]),
                count=int(item.get("count", 1)),
                datatype=DataType[item["datatype"].upper()],
                scale=float(item.get("scale", 1.0)),
                offset=float(item.get("offset", 0.0)),
                endian=Endian[item.get("endian", "BIG").upper()],
                word_order=WordOrder[item.get("word_order", "MSW_FIRST").lower()],
                unit_id=int(item.get("unit_id", 1)),
            )
        )
    return tags

def default_tags(unit_id: int) -> List[Tag]:
    # Reasonable demo mapping; adjust to your PLC
    return [
        Tag("pump_run", FC.COILS, address=0, count=1, datatype=DataType.BOOL, unit_id=unit_id),
        Tag("alarm", FC.DISCRETE, address=1, count=1, datatype=DataType.BOOL, unit_id=unit_id),
        Tag("motor_rpm", FC.HOLDING, address=100, count=2, datatype=DataType.FLOAT32, unit_id=unit_id,
            endian=Endian.BIG, word_order=WordOrder.MSW_FIRST, scale=1.0),
        Tag("pressure_bar", FC.INPUT, address=200, count=1, datatype=DataType.UINT16, unit_id=unit_id, scale=0.01),
        Tag("temp_c", FC.INPUT, address=201, count=1, datatype=DataType.INT16, unit_id=unit_id, scale=0.1),
    ]

def build_config_from_args() -> DemoConfig:
    p = argparse.ArgumentParser(description="Industrial Modbus TCP demo with Kafka bridge")
    p.add_argument("--plc-host", default=os.getenv("PLC_HOST", "127.0.0.1"))
    p.add_argument("--plc-port", type=int, default=int(os.getenv("PLC_PORT", "502")))
    p.add_argument("--unit-id", type=int, default=int(os.getenv("PLC_UNIT_ID", "1")))
    p.add_argument("--poll-interval", type=float, default=float(os.getenv("POLL_INTERVAL", "0.5")))
    p.add_argument("--publish-every", type=float, default=float(os.getenv("PUBLISH_EVERY", "5.0")))
    p.add_argument("--float-eps", type=float, default=float(os.getenv("FLOAT_EPS", "1e-6")))
    p.add_argument("--kafka-bootstrap", default=os.getenv("KAFKA_BOOTSTRAP"))
    p.add_argument("--kafka-topic-out", default=os.getenv("KAFKA_TOPIC_OUT", "plc.telemetry"))
    p.add_argument("--kafka-topic-cmd", default=os.getenv("KAFKA_TOPIC_CMD", "plc.commands"))
    p.add_argument("--kafka-client-id", default=os.getenv("KAFKA_CLIENT_ID", "plc_modbus_demo"))
    p.add_argument("--kafka-group-id", default=os.getenv("KAFKA_GROUP_ID", "plc_modbus_demo"))
    p.add_argument("--tags-file", default=os.getenv("TAGS_FILE"))
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    args = p.parse_args()

    cfg = DemoConfig()
    cfg.plc_host = args.plc_host
    cfg.plc_port = args.plc_port
    cfg.unit_id = args.unit_id
    cfg.poll_interval_s = args.poll_interval
    cfg.publish_every_s = args.publish_every
    cfg.float_epsilon = args.float_eps
    cfg.kafka_bootstrap = args.kafka_bootstrap
    cfg.kafka_topic_out = args.kafka_topic_out
    cfg.kafka_topic_cmd = args.kafka_topic_cmd
    cfg.kafka_client_id = args.kafka_client_id
    cfg.kafka_group_id = args.kafka_group_id
    cfg.log_level = getattr(logging, str(args.log_level).upper(), logging.INFO)
    cfg.tags = load_tags_from_file(args.tags_file) if args.tags_file else default_tags(cfg.unit_id)
    return cfg

# ---------------------------
# Main
# ---------------------------

async def main_async(cfg: DemoConfig) -> None:
    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    LOG.info("Starting PLC Modbus demo with config: host=%s port=%s unit=%s kafka=%s",
             cfg.plc_host, cfg.plc_port, cfg.unit_id, bool(cfg.kafka_bootstrap))

    # PLC
    plc = PLCClient(cfg.plc_host, cfg.plc_port, cfg.unit_id)
    await plc.connect()

    # Kafka (optional)
    kafka = None
    if cfg.kafka_bootstrap and KafkaAdapter and KafkaConfig:
        kcfg = KafkaConfig(
            bootstrap_servers=cfg.kafka_bootstrap,
            client_id=cfg.kafka_client_id,
            group_id=cfg.kafka_group_id,
            enable_auto_commit=False,
        )
        kafka = KafkaAdapter(kcfg)
        await kafka.start_producer()
    else:
        kafka = _NoKafka()

    # Publisher callback
    async def publish(payload: Dict[str, Any]) -> None:
        if isinstance(kafka, _NoKafka):
            LOG.info("Telemetry: %s", payload)
        else:
            await kafka.send(cfg.kafka_topic_out, payload, key="telemetry")

    poller = TagPoller(plc, cfg)

    # Kafka command consumer (optional)
    cmd_server = CommandServer(plc, cfg, kafka if not isinstance(kafka, _NoKafka) else None)

    # Graceful shutdown
    stop_event = asyncio.Event()

    def _signal_handler():
        LOG.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _signal_handler)
        except NotImplementedError:
            # Windows fallback
            signal.signal(s, lambda *_: _signal_handler())

    tasks = []
    tasks.append(asyncio.create_task(poller.run(publish)))
    if not isinstance(kafka, _NoKafka):
        tasks.append(asyncio.create_task(cmd_server.start()))

    await stop_event.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    # Cleanup
    await plc.close()
    if not isinstance(kafka, _NoKafka):
        await kafka.close()

def main() -> None:
    cfg = build_config_from_args()
    try:
        asyncio.run(main_async(cfg))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
