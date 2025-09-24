# physical-integration-core/physical_integration/protocols/zigbee_matter.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union

LOG = logging.getLogger("physical_integration.protocols")

# -----------------------------
# Опциональные зависимости
# -----------------------------
# Zigbee (zigpy/bellows/zigpy-deconz и т.п.)
try:
    import zigpy  # type: ignore
    from zigpy.application import ControllerApplication  # type: ignore
except Exception:  # pragma: no cover
    zigpy = None
    ControllerApplication = None

# Matter (Python Controller)
try:
    # Python Matter SDK может устанавливаться как 'chip' или 'matter'
    from chip.clusters import Objects as Clusters  # type: ignore
    from chip.FabricAdmin import FabricAdmin  # type: ignore
    from chip.CertificateAuthority import CertificateAuthorityManager  # type: ignore
    from chip.ChipDeviceCtrl import ChipDeviceCtrl  # type: ignore
except Exception:  # pragma: no cover
    Clusters = None
    FabricAdmin = None
    CertificateAuthorityManager = None
    ChipDeviceCtrl = None

# Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None


# -----------------------------
# Исключения
# -----------------------------
class ProtocolError(Exception):
    pass


class NotAvailableError(ProtocolError):
    """Поднимается, если в окружении нет нужного SDK."""


class CommissioningError(ProtocolError):
    pass


class AttributeErrorProtocol(ProtocolError):
    pass


# -----------------------------
# Метрики (если есть prometheus_client)
# -----------------------------
if Histogram and Counter:  # pragma: no cover
    MET_REQ_LAT = Histogram(
        "proto_request_latency_seconds",
        "Protocol request latency",
        ["stack", "op"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
    )
    MET_REQ_ERRS = Counter("proto_request_errors_total", "Protocol errors", ["stack", "op"])
    MET_EVENTS = Counter("proto_events_total", "Protocol emitted events", ["stack", "type"])
else:
    MET_REQ_LAT = MET_REQ_ERRS = MET_EVENTS = None  # type: ignore


def _metric_time(stack: str, op: str):
    class _T:
        def __enter__(self):  # noqa: D401
            self.t = time.perf_counter()

        def __exit__(self, exc_type, exc, tb):
            if MET_REQ_LAT:
                MET_REQ_LAT.labels(stack, op).observe(time.perf_counter() - self.t)
            if exc and MET_REQ_ERRS:
                MET_REQ_ERRS.labels(stack, op).inc()

    return _T()


# -----------------------------
# Вспомогательные утилиты
# -----------------------------
def _jittered_backoff(retry: int, base: float = 0.2, cap: float = 5.0) -> float:
    """Экспоненциальная задержка с джиттером."""
    exp = min(cap, base * (2 ** retry))
    return random.uniform(0, exp)


def _uuid() -> str:
    return str(uuid.uuid4())


@dataclass
class EndpointCluster:
    endpoint: int
    cluster_id: int
    cluster_name: Optional[str] = None


@dataclass
class DeviceDescriptor:
    device_id: str  # внутренний UUID
    stack: str      # "zigbee" | "matter"
    address: str    # zigbee: EUI64 hex; matter: nodeId int/hex
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    endpoints: List[EndpointCluster] = field(default_factory=list)
    rssi: Optional[int] = None
    lqi: Optional[int] = None
    last_seen_ts: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class AttrRef:
    endpoint: int
    cluster: Union[int, str]
    attribute: Union[int, str]


@dataclass
class CommandRef:
    endpoint: int
    cluster: Union[int, str]
    command: Union[int, str]
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    type: str  # "device.join", "attr.changed", "commissioned", ...
    device: DeviceDescriptor
    payload: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class TwinSink(abc.ABC):
    """Куда отдавать события и статусы для цифрового двойника."""

    @abc.abstractmethod
    async def upsert_twin(self, device: DeviceDescriptor) -> None:
        ...

    @abc.abstractmethod
    async def publish_event(self, event: Event) -> None:
        ...

    @abc.abstractmethod
    async def update_attr(self, device: DeviceDescriptor, attr: AttrRef, value: Any) -> None:
        ...


class LoggingTwinSink(TwinSink):
    async def upsert_twin(self, device: DeviceDescriptor) -> None:
        LOG.info("Twin upsert: %s %s", device.stack, device.address)

    async def publish_event(self, event: Event) -> None:
        if MET_EVENTS:
            MET_EVENTS.labels(event.device.stack, event.type).inc()
        LOG.info("Event: %s %s payload=%s", event.type, event.device.address, event.payload)

    async def update_attr(self, device: DeviceDescriptor, attr: AttrRef, value: Any) -> None:
        LOG.info("Attr: %s %s %s=%s", device.stack, device.address, attr, value)


# -----------------------------
# Хранилище секретов (просто/безопасно)
# -----------------------------
class SecretStore:
    def __init__(self, base_path: Optional[str] = None) -> None:
        self.base_path = Path(base_path or os.getenv("PROTO_SECRETS_DIR", "/var/run/physical-integration/secrets"))

    def get(self, key: str) -> Optional[str]:
        # 1) ENV, 2) файл
        env_key = os.getenv(key)
        if env_key:
            return env_key
        p = self.base_path / key
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
        return None


# -----------------------------
# Простой файловый кеш устройств
# -----------------------------
class JSONCache:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def load(self) -> Dict[str, Any]:
        async with self._lock:
            if not self.path.exists():
                return {}
            with contextlib.suppress(Exception):
                return json.loads(self.path.read_text(encoding="utf-8"))
            return {}

    async def save(self, data: Dict[str, Any]) -> None:
        async with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)


# -----------------------------
# Базовый драйвер протокола
# -----------------------------
class ProtocolDriver(abc.ABC):
    def __init__(self, sink: TwinSink, rate_limit_per_device: int = 4) -> None:
        self._sink = sink
        self._started = False
        self._device_limits: Dict[str, asyncio.Semaphore] = {}
        self._cache = JSONCache(os.getenv("PROTO_CACHE_FILE", "/var/run/physical-integration/devices.json"))

    def _limiter(self, device_key: str) -> asyncio.Semaphore:
        sem = self._device_limits.get(device_key)
        if not sem:
            sem = self._device_limits[device_key] = asyncio.Semaphore(4)
        return sem

    @abc.abstractmethod
    async def start(self) -> None:
        ...

    @abc.abstractmethod
    async def stop(self) -> None:
        ...

    @abc.abstractmethod
    async def commission(self, **kwargs: Any) -> DeviceDescriptor:
        ...

    @abc.abstractmethod
    async def read_attribute(self, device: DeviceDescriptor, ref: AttrRef) -> Any:
        ...

    @abc.abstractmethod
    async def write_attribute(self, device: DeviceDescriptor, ref: AttrRef, value: Any) -> None:
        ...

    @abc.abstractmethod
    async def send_command(self, device: DeviceDescriptor, cmd: CommandRef) -> Any:
        ...

    @abc.abstractmethod
    async def subscribe(self, device: DeviceDescriptor, refs: List[AttrRef]) -> None:
        ...

    async def _emit(self, ev: Event) -> None:
        await self._sink.publish_event(ev)

    async def _upsert(self, d: DeviceDescriptor) -> None:
        await self._sink.upsert_twin(d)


# -----------------------------
# Zigbee Driver (zigpy)
# -----------------------------
class ZigbeeDriver(ProtocolDriver):
    """Контроллер Zigbee через zigpy. Поддерживает join, атрибуты, команды и подписки."""

    def __init__(self, sink: TwinSink, *, radio_device: Optional[str] = None, app_config: Optional[Dict[str, Any]] = None):
        super().__init__(sink)
        self._radio = radio_device or os.getenv("ZIGBEE_RADIO", "/dev/ttyUSB0")
        self._app_config = app_config or {}
        self._app = None
        self._tasks: List[asyncio.Task] = []
        if ControllerApplication is None:
            raise NotAvailableError("zigpy is not available in this environment")

    async def start(self) -> None:
        if self._started:
            return
        LOG.info("Starting Zigbee on %s", self._radio)
        with _metric_time("zigbee", "start"):
            # Минимальный пример инициализации контроллера:
            self._app = await ControllerApplication.new(self._app_config, auto_form=True)  # type: ignore
            self._started = True
        # Подписка на события устройств (зависит от стека; тут псевдокод)
        self._tasks.append(asyncio.create_task(self._device_watcher()))

    async def stop(self) -> None:
        if not self._started:
            return
        LOG.info("Stopping Zigbee")
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        with contextlib.suppress(Exception):
            if self._app:
                await self._app.shutdown()  # type: ignore
        self._started = False

    async def commission(self, *, permit_seconds: int = 60) -> DeviceDescriptor:
        if not self._started:
            raise ProtocolError("Driver not started")
        with _metric_time("zigbee", "commission"):
            LOG.info("Permit join for %ss", permit_seconds)
            # Разрешаем присоединение
            await self._app.permit(permit_seconds)  # type: ignore
            # В реальности нужно слушать событие device_joined; тут — упрощенный поллинг
            deadline = time.time() + permit_seconds + 5
            while time.time() < deadline:
                # Скан локальной БД устройств zigpy
                for dev in self._app.devices.values():  # type: ignore
                    desc = _zigbee_descriptor(dev)
                    await self._upsert(desc)
                    await self._emit(Event("device.join", desc, {}))
                    return desc
                await asyncio.sleep(2)
            raise CommissioningError("No device joined within permit window")

    async def read_attribute(self, device: DeviceDescriptor, ref: AttrRef) -> Any:
        with _metric_time("zigbee", "read"):
            if not self._app:
                raise ProtocolError("App not ready")
            dev = _zig_find(self._app, device.address)  # type: ignore
            if not dev:
                raise ProtocolError("Device not found")
            # zigpy API примеры (псевдокод, конкретная реализация зависит от стека/радио):
            cluster = dev.endpoints[ref.endpoint].in_clusters.get(_to_cluster_id(ref.cluster))  # type: ignore
            val = await cluster.read_attributes([_to_attr_id(ref.attribute)])  # type: ignore
            await self._sink.update_attr(device, ref, val)
            return val

    async def write_attribute(self, device: DeviceDescriptor, ref: AttrRef, value: Any) -> None:
        with _metric_time("zigbee", "write"):
            dev = _zig_find(self._app, device.address)  # type: ignore
            cluster = dev.endpoints[ref.endpoint].out_clusters.get(_to_cluster_id(ref.cluster))  # type: ignore
            await cluster.write_attributes({_to_attr_id(ref.attribute): value})  # type: ignore

    async def send_command(self, device: DeviceDescriptor, cmd: CommandRef) -> Any:
        with _metric_time("zigbee", "command"):
            dev = _zig_find(self._app, device.address)  # type: ignore
            cluster = dev.endpoints[cmd.endpoint].out_clusters.get(_to_cluster_id(cmd.cluster))  # type: ignore
            # В реальных стеках обычно есть методы команд по имени/ID
            res = await cluster.command(_to_cmd_id(cmd.command), *cmd.args, **cmd.kwargs)  # type: ignore
            return res

    async def subscribe(self, device: DeviceDescriptor, refs: List[AttrRef]) -> None:
        # Подписки реализуются уровнями ZCL reporting/bind; здесь сохраняем минималистично
        with _metric_time("zigbee", "subscribe"):
            LOG.info("Subscribe zigbee %s: %s", device.address, refs)
            # В проде: configure reporting для каждого атрибута
            return

    async def _device_watcher(self) -> None:
        """Простая фоновая задача мониторинга устройств."""
        try:
            while True:
                try:
                    for dev in list(self._app.devices.values()):  # type: ignore
                        desc = _zigbee_descriptor(dev)
                        await self._upsert(desc)
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    LOG.warning("Zigbee watcher error: %s", ex, exc_info=False)
                    await asyncio.sleep(2)
        except asyncio.CancelledError:
            return


def _zig_find(app: Any, ieee_hex: str) -> Any:
    for d in app.devices.values():  # type: ignore
        try:
            if str(d.ieee).replace(":", "").lower() == ieee_hex.replace(":", "").lower():
                return d
        except Exception:
            continue
    return None


def _zigbee_descriptor(dev: Any) -> DeviceDescriptor:
    try:
        ieee_hex = str(dev.ieee).replace(":", "").lower()  # type: ignore
    except Exception:
        ieee_hex = "unknown"
    endpoints: List[EndpointCluster] = []
    try:
        for ep_id, ep in dev.endpoints.items():  # type: ignore
            for cl in getattr(ep, "in_clusters", {}).values():  # type: ignore
                endpoints.append(EndpointCluster(endpoint=ep_id, cluster_id=int(cl.cluster_id), cluster_name=getattr(cl, "name", None)))
            for cl in getattr(ep, "out_clusters", {}).values():  # type: ignore
                endpoints.append(EndpointCluster(endpoint=ep_id, cluster_id=int(cl.cluster_id), cluster_name=getattr(cl, "name", None)))
    except Exception:
        pass
    desc = DeviceDescriptor(
        device_id=_uuid(),
        stack="zigbee",
        address=ieee_hex,
        vendor_id=getattr(dev, "manufacturer", None) or None,  # типы могут не совпасть, оставим None
        product_id=getattr(dev, "model", None) or None,
        endpoints=endpoints,
        rssi=getattr(dev, "rssi", None),
        lqi=getattr(dev, "lqi", None),
        labels={"network": "zigbee"},
    )
    return desc


def _to_cluster_id(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(x, 0)


def _to_attr_id(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(x, 0)


def _to_cmd_id(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(x, 0)


# -----------------------------
# Matter Driver (Python Controller)
# -----------------------------
class MatterDriver(ProtocolDriver):
    """Контроллер Matter: commissioning по Setup Code/QR, read/write/subscribe, команды."""

    def __init__(self, sink: TwinSink, *, storage_dir: Optional[str] = None):
        super().__init__(sink)
        if ChipDeviceCtrl is None or FabricAdmin is None or CertificateAuthorityManager is None:
            raise NotAvailableError("Matter Python Controller is not available in this environment")
        self._storage_dir = Path(storage_dir or os.getenv("MATTER_STORAGE", "/var/lib/physical-integration/matter"))
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._cam = CertificateAuthorityManager(self._storage_dir)  # type: ignore
        self._admin = self._cam.NewCertificateAuthority().NewFabricAdmin(vendorId=0xFFF1, fabricId=1)  # type: ignore
        self._ctrl: Optional[ChipDeviceCtrl] = None
        self._subs_tasks: Dict[str, asyncio.Task] = {}

    async def start(self) -> None:
        if self._started:
            return
        LOG.info("Starting Matter controller")
        with _metric_time("matter", "start"):
            self._ctrl = self._admin.NewController(nodeId=1)  # type: ignore
            self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        LOG.info("Stopping Matter controller")
        for t in self._subs_tasks.values():
            t.cancel()
        self._subs_tasks.clear()
        with contextlib.suppress(Exception):
            if self._ctrl:
                self._ctrl.Shutdown()  # type: ignore
        self._started = False

    async def commission(self, *, setup_code: Optional[str] = None, discriminator: Optional[int] = None, ip: Optional[str] = None) -> DeviceDescriptor:
        if not self._ctrl:
            raise ProtocolError("Controller not started")
        with _metric_time("matter", "commission"):
            if not setup_code:
                raise CommissioningError("setup_code is required for Matter commissioning")
            node_id = random.randrange(0x10000, 0xFFFFFFF0)
            # Синхронный вызов SDK — оборачиваем в executor
            loop = asyncio.get_running_loop()
            ok = await loop.run_in_executor(None, lambda: self._ctrl.CommissionWithCode(setup_code, nodeid=node_id))  # type: ignore
            if ok != 0:
                raise CommissioningError(f"Matter commission failed: code={ok}")
            desc = await self._describe_node(node_id)
            await self._upsert(desc)
            await self._emit(Event("device.commissioned", desc, {"node_id": node_id}))
            return desc

    async def _describe_node(self, node_id: int) -> DeviceDescriptor:
        # Чтение базовых атрибутов Descriptor/BasicInformation
        endpoints: List[EndpointCluster] = []
        try:
            # Пример опроса endpoint 0
            endpoints.append(EndpointCluster(endpoint=0, cluster_id=29, cluster_name="Descriptor"))
            endpoints.append(EndpointCluster(endpoint=0, cluster_id=40, cluster_name="BasicInformation"))
        except Exception:
            pass
        desc = DeviceDescriptor(
            device_id=_uuid(),
            stack="matter",
            address=str(node_id),
            labels={"network": "matter"},
        )
        desc.endpoints = endpoints
        return desc

    async def read_attribute(self, device: DeviceDescriptor, ref: AttrRef) -> Any:
        if not self._ctrl:
            raise ProtocolError("Controller not started")
        with _metric_time("matter", "read"):
            loop = asyncio.get_running_loop()
            # SDK предоставляет ReadAttribute(nodeid, endpoint, cluster, attribute)
            res = await loop.run_in_executor(None, lambda: self._ctrl.ReadAttribute(int(device.address), ref.endpoint, _to_m_cluster(ref.cluster), _to_m_attr(ref.attribute)))  # type: ignore
            await self._sink.update_attr(device, ref, res)
            return res

    async def write_attribute(self, device: DeviceDescriptor, ref: AttrRef, value: Any) -> None:
        if not self._ctrl:
            raise ProtocolError("Controller not started")
        with _metric_time("matter", "write"):
            loop = asyncio.get_running_loop()
            code = await loop.run_in_executor(None, lambda: self._ctrl.WriteAttribute(int(device.address), ref.endpoint, _to_m_cluster(ref.cluster), _to_m_attr(ref.attribute), value))  # type: ignore
            if code != 0:
                raise AttributeErrorProtocol(f"Matter write failed: {code}")

    async def send_command(self, device: DeviceDescriptor, cmd: CommandRef) -> Any:
        if not self._ctrl:
            raise ProtocolError("Controller not started")
        with _metric_time("matter", "command"):
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(None, lambda: self._ctrl.SendCommand(int(device.address), cmd.endpoint, _to_m_cluster(cmd.cluster), _to_m_cmd(cmd.command), *cmd.args))  # type: ignore
            return res

    async def subscribe(self, device: DeviceDescriptor, refs: List[AttrRef]) -> None:
        if not self._ctrl:
            raise ProtocolError("Controller not started")
        key = f"{device.address}"
        if key in self._subs_tasks:
            return
        self._subs_tasks[key] = asyncio.create_task(self._loop_subscribe(device, refs))

    async def _loop_subscribe(self, device: DeviceDescriptor, refs: List[AttrRef]) -> None:
        """Простая подписка: периодический read (fallback, если нет SDK подписок)."""
        try:
            retry = 0
            while True:
                try:
                    for ref in refs:
                        val = await self.read_attribute(device, ref)
                        await self._sink.update_attr(device, ref, val)
                    await asyncio.sleep(5)
                    retry = 0
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    delay = _jittered_backoff(retry)
                    LOG.warning("Matter subscribe loop error: %s (retry in %.2fs)", ex, delay)
                    await asyncio.sleep(delay)
                    retry += 1
        except asyncio.CancelledError:
            return


def _to_m_cluster(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(str(x), 0)


def _to_m_attr(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(str(x), 0)


def _to_m_cmd(x: Union[int, str]) -> int:
    return int(x) if isinstance(x, int) else int(str(x), 0)


# -----------------------------
# Protocol Manager: единая точка входа
# -----------------------------
class ProtocolManager:
    """Единая фасадная обертка над Zigbee и Matter с общим sink и жизненным циклом."""

    def __init__(self, *, enable_zigbee: bool = True, enable_matter: bool = True, sink: Optional[TwinSink] = None) -> None:
        self.sink = sink or LoggingTwinSink()
        self.zigbee: Optional[ZigbeeDriver] = None
        self.matter: Optional[MatterDriver] = None
        self.enable_zigbee = enable_zigbee
        self.enable_matter = enable_matter

        if enable_zigbee:
            with contextlib.suppress(NotAvailableError):
                self.zigbee = ZigbeeDriver(self.sink)
        if enable_matter:
            with contextlib.suppress(NotAvailableError):
                self.matter = MatterDriver(self.sink)

    async def start(self) -> None:
        if self.zigbee:
            await self.zigbee.start()
        if self.matter:
            await self.matter.start()

    async def stop(self) -> None:
        if self.matter:
            await self.matter.stop()
        if self.zigbee:
            await self.zigbee.stop()

    # Комиссионирование
    async def commission_zigbee(self, **kwargs: Any) -> DeviceDescriptor:
        if not self.zigbee:
            raise NotAvailableError("Zigbee driver not available")
        return await self.zigbee.commission(**kwargs)

    async def commission_matter(self, **kwargs: Any) -> DeviceDescriptor:
        if not self.matter:
            raise NotAvailableError("Matter driver not available")
        return await self.matter.commission(**kwargs)

    # Универсальные операции
    async def read(self, device: DeviceDescriptor, ref: AttrRef) -> Any:
        if device.stack == "zigbee":
            if not self.zigbee:
                raise NotAvailableError("Zigbee driver not available")
            return await self.zigbee.read_attribute(device, ref)
        elif device.stack == "matter":
            if not self.matter:
                raise NotAvailableError("Matter driver not available")
            return await self.matter.read_attribute(device, ref)
        else:
            raise ProtocolError(f"Unknown stack {device.stack}")

    async def write(self, device: DeviceDescriptor, ref: AttrRef, value: Any) -> None:
        if device.stack == "zigbee":
            if not self.zigbee:
                raise NotAvailableError("Zigbee driver not available")
            return await self.zigbee.write_attribute(device, ref, value)
        elif device.stack == "matter":
            if not self.matter:
                raise NotAvailableError("Matter driver not available")
            return await self.matter.write_attribute(device, ref, value)
        else:
            raise ProtocolError(f"Unknown stack {device.stack}")

    async def command(self, device: DeviceDescriptor, cmd: CommandRef) -> Any:
        if device.stack == "zigbee":
            if not self.zigbee:
                raise NotAvailableError("Zigbee driver not available")
            return await self.zigbee.send_command(device, cmd)
        elif device.stack == "matter":
            if not self.matter:
                raise NotAvailableError("Matter driver not available")
            return await self.matter.send_command(device, cmd)
        else:
            raise ProtocolError(f"Unknown stack {device.stack}")

    async def subscribe(self, device: DeviceDescriptor, refs: List[AttrRef]) -> None:
        if device.stack == "zigbee":
            if not self.zigbee:
                raise NotAvailableError("Zigbee driver not available")
            return await self.zigbee.subscribe(device, refs)
        elif device.stack == "matter":
            if not self.matter:
                raise NotAvailableError("Matter driver not available")
            return await self.matter.subscribe(device, refs)
        else:
            raise ProtocolError(f"Unknown stack {device.stack}")


# -----------------------------
# Пример минимальной инициализации (локальный тест)
# -----------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    async def _main():
        mgr = ProtocolManager(enable_zigbee=False, enable_matter=False, sink=LoggingTwinSink())
        # В этой среде SDK могут отсутствовать; запуск только каркаса
        await mgr.start()
        print("ProtocolManager started (no active drivers).")
        await asyncio.sleep(1)
        await mgr.stop()

    asyncio.run(_main())
