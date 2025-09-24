# physical-integration-core/physical_integration/edge/agent.py
"""
Edge Agent for Physical Integration Core.

Функции:
- Загрузка и горячая перезагрузка профиля устройства (YAML)
- Калибровки и нормализация единиц измерения
- Плагинные источники данных (сенсоры), агрегатор, батчирование
- Надежные публикации в MQTT (TLS/mTLS/OAuth2) через physical_integration.protocols.mqtt_client
- Heartbeat и обработка команд (идемпотентные ACK/NACK)
- Метрики Prometheus и структурные логи
- Корректное завершение, ротация сертификатов, backoff

Зависимости (Python >= 3.10):
  pyyaml>=6
  prometheus_client>=0.19
  orjson>=3.9 (опционально)
  asyncio-mqtt>=0.16
  httpx>=0.27 (опционально, если OAuth2)

Переменные окружения (основные):
  PIC_AGENT_PROFILE=/etc/pic/device_profile.yaml
  PIC_AGENT_SAMPLING_SEC=10
  PIC_AGENT_BATCH_MAX=100
  PIC_AGENT_METRICS_PORT=9094
  PIC_AGENT_DEVICE_ID=xt200-<uuid>      # иначе из профиля
  PIC_AGENT_TWIN_NAME=twin/<id>         # если используется
  PIC_AGENT_HEARTBEAT_SEC=30
  PIC_AGENT_TIMEZONE=UTC

  # См. также переменные PIC_MQTT_* в mqtt_client.py
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import glob
import hashlib
import json
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import yaml
from prometheus_client import Counter, Histogram, Gauge, Summary, start_http_server

# MQTT client abstraction
from physical_integration.protocols.mqtt_client import (
    MqttClient,
    MqttSettings,
    PublishMessage,
)

# ---------- Быстрый JSON ----------
try:
    import orjson  # type: ignore

    def jdumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY).decode()

    def jloads(b: bytes) -> Any:
        return orjson.loads(b)
except Exception:  # pragma: no cover
    import json as _json

    def jdumps(obj: Any) -> str:
        return _json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def jloads(b: bytes) -> Any:
        return _json.loads(b.decode("utf-8"))


# =============== Логи ===============
LOG = logging.getLogger("pic.edge.agent")
if not LOG.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO if os.getenv("PIC_DEBUG", "false").lower() != "true" else logging.DEBUG)

# =============== Метрики ===============
AGENT_READY = Gauge("edge_agent_ready", "Agent readiness (1=ready,0=not)")
AGENT_SAMPLES = Counter("edge_samples_total", "Total sensor samples", ["sensor_id"])
AGENT_PUBLISHED = Counter("edge_published_total", "Published telemetry messages", ["topic"])
AGENT_DROPPED = Counter("edge_dropped_total", "Dropped telemetry messages", ["reason"])
AGENT_HEARTBEAT = Counter("edge_heartbeat_total", "Heartbeats sent")
AGENT_CAL_ERRORS = Counter("edge_calibration_errors_total", "Calibration errors", ["sensor_id"])
AGENT_CMD_TOTAL = Counter("edge_commands_total", "Commands processed", ["type", "status"])
AGENT_PROFILE_RELOADS = Counter("edge_profile_reloads_total", "Profile reloads")
AGENT_PUBLISH_LAT = Histogram("edge_publish_latency_seconds", "Publish latency", buckets=(0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))
AGENT_SAMPLE_LAT = Histogram("edge_sample_latency_seconds", "Sampling latency", buckets=(0.001,0.005,0.01,0.025,0.05,0.1,0.25,0.5,1))

# =============== Конфигурация агента ===============
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)

@dataclass
class AgentConfig:
    profile_path: Path
    sampling_sec: float = float(_env("PIC_AGENT_SAMPLING_SEC", "10"))
    batch_max: int = int(_env("PIC_AGENT_BATCH_MAX", "100"))
    metrics_port: int = int(_env("PIC_AGENT_METRICS_PORT", "9094"))
    device_id: Optional[str] = _env("PIC_AGENT_DEVICE_ID")  # fallback из профиля
    twin_name: Optional[str] = _env("PIC_AGENT_TWIN_NAME")  # twin/{id}
    heartbeat_sec: float = float(_env("PIC_AGENT_HEARTBEAT_SEC", "30"))
    timezone: str = _env("PIC_AGENT_TIMEZONE", "UTC")
    # темы MQTT (переопределяются профилем при наличии)
    topic_pub_telemetry: Optional[str] = _env("PIC_AGENT_TOPIC_TELEMETRY")  # например sensors/{deviceId}/telemetry
    topic_pub_events: Optional[str] = _env("PIC_AGENT_TOPIC_EVENTS")
    topic_sub_commands: Optional[str] = _env("PIC_AGENT_TOPIC_COMMANDS")   # commands/{deviceId}
    # файлы для ротации сертификатов (наблюдение mtime)
    cert_watch_glob: Optional[str] = _env("PIC_AGENT_CERT_GLOB")  # например /etc/pki/devices/*

    @staticmethod
    def load() -> "AgentConfig":
        p = _env("PIC_AGENT_PROFILE", "/etc/pic/device_profile.yaml")
        return AgentConfig(profile_path=Path(p))


# =============== Загрузка профиля и калибровки ===============
@dataclass
class SensorProfile:
    id: str
    name: str
    unit: str
    calibration: Dict[str, Any]  # CalibrationSpec-подобная структура
    normalization_to: Optional[str] = None  # "K" и т.п.

@dataclass
class DeviceProfile:
    device_id: str
    twin_name: Optional[str]
    telemetry_topic: str
    alerts_topic: Optional[str]
    commands_topic: str
    sensors: Dict[str, SensorProfile]

def _coalesce_topic(env_val: Optional[str], profile_val: Optional[str]) -> Optional[str]:
    return env_val or profile_val

def load_device_profile(path: Path, overrides: AgentConfig) -> DeviceProfile:
    with path.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    m = doc.get("metadata", {})
    conn = (doc.get("connectivity") or {})
    mqtt = (conn.get("mqtt") or {})
    topics = (mqtt.get("topics") or {})
    pub = (topics.get("pub") or {})
    sub = (topics.get("sub") or {})

    device_id = overrides.device_id or (doc.get("provisioning", {}).get("identifiers", {}).get("deviceId")) or m.get("name")
    if not device_id:
        raise RuntimeError("device_id is not defined in env or profile")

    telemetry_topic = _coalesce_topic(overrides.topic_pub_telemetry, pub.get("telemetry")) or f"sensors/{device_id}/telemetry"
    alerts_topic = _coalesce_topic(overrides.topic_pub_events, pub.get("events"))
    commands_topic = _coalesce_topic(overrides.topic_sub_commands, sub.get("commands")) or f"commands/{device_id}"
    twin_name = overrides.twin_name or doc.get("metadata", {}).get("name") or None

    caps = (doc.get("capabilities") or {}).get("sensors") or []
    sensors: Dict[str, SensorProfile] = {}
    for s in caps:
        sid = str(s.get("id"))
        sensors[sid] = SensorProfile(
            id=sid,
            name=s.get("name") or sid,
            unit=s.get("unit") or "",
            calibration=s.get("calibration") or {"mode": "none"},
            normalization_to=(s.get("normalization") or {}).get("to"),
        )

    return DeviceProfile(
        device_id=device_id,
        twin_name=twin_name,
        telemetry_topic=telemetry_topic,
        alerts_topic=alerts_topic,
        commands_topic=commands_topic,
        sensors=sensors,
    )

# =============== Калибровочный движок ===============
class CalibrationError(Exception):
    pass

class CalibrationEngine:
    """
    Поддержка стратегий: identity, linear(a,b), two-point, polynomial, piecewise_linear, lookup_table
    Синтаксис совместим с device_profile.example.yaml (см. ранее).
    """
    def __init__(self, mapping: Dict[str, Dict[str, Any]]) -> None:
        self._m = mapping  # sensor_id -> spec

    def apply(self, sensor_id: str, value: float) -> float:
        spec = (self._m.get(sensor_id) or {})
        mode = str(spec.get("mode") or spec.get("strategy") or "none")
        if mode in ("none", "identity"):
            return float(value)
        try:
            if mode == "linear":
                a = float(spec["a"]); b = float(spec["b"])
                return a * value + b
            if mode in ("two_point", "two-point"):
                x1 = float(spec["points"][0]["input"] if "points" in spec else spec["x1"])
                y1 = float(spec["points"][0]["output"] if "points" in spec else spec["y1"])
                x2 = float(spec["points"][1]["input"] if "points" in spec else spec["x2"])
                y2 = float(spec["points"][1]["output"] if "points" in spec else spec["y2"])
                if x2 == x1:
                    raise CalibrationError("two_point requires x1 != x2")
                return y1 + (value - x1) * (y2 - y1) / (x2 - x1)
            if mode == "polynomial":
                coeffs = list(spec["coefficients"])
                if len(coeffs) > 7:
                    raise CalibrationError("polynomial degree must be <=6")
                y = 0.0
                for i, c in enumerate(coeffs):
                    y += float(c) * (value ** i)
                return float(y)
            if mode == "piecewise_linear":
                pts = [(float(p[0]), float(p[1])) for p in (spec["points"] if isinstance(spec["points"][0], (list, tuple)) else [(p["input"], p["output"]) for p in spec["points"]])]
                pts = sorted(pts, key=lambda t: t[0])
                if value <= pts[0][0]:
                    (x0,y0),(x1,y1) = pts[0], pts[1]
                elif value >= pts[-1][0]:
                    (x0,y0),(x1,y1) = pts[-2], pts[-1]
                else:
                    lo, hi = 0, len(pts)-1
                    while lo+1 < hi:
                        mid = (lo+hi)//2
                        if value >= pts[mid][0]:
                            lo = mid
                        else:
                            hi = mid
                    (x0,y0),(x1,y1) = pts[lo], pts[lo+1]
                if x1 == x0: return float(y0)
                return y0 + (value - x0) * (y1 - y0) / (x1 - x0)
            if mode == "lookup_table":
                tbl = spec["table"]
                key = str(value)
                if key in tbl:
                    return float(tbl[key])
                on_miss = spec.get("on_miss", "error")
                if on_miss == "identity":
                    return value
                if on_miss == "nearest":
                    pairs = [(float(k), float(v)) for k,v in tbl.items()]
                    nearest = min(pairs, key=lambda kv: abs(kv[0]-value))
                    return float(nearest[1])
                raise CalibrationError(f"value {value} not in lookup_table")
        except CalibrationError:
            raise
        except Exception as e:
            raise CalibrationError(str(e))

# =============== Нормализация единиц (минимальная) ===============
def normalize_unit(sensor_unit: str, to_unit: Optional[str], value: float) -> float:
    if not to_unit or sensor_unit == to_unit:
        return value
    # Примеры: C->K, K->C, C->F, Pa->kPa, etc.
    if sensor_unit == "C" and to_unit == "K":
        return value + 273.15
    if sensor_unit == "K" and to_unit == "C":
        return value - 273.15
    if sensor_unit == "Pa" and to_unit == "kPa":
        return value / 1000.0
    if sensor_unit == "kPa" and to_unit == "Pa":
        return value * 1000.0
    # По умолчанию — без изменений
    return value

# =============== Плагины сенсоров ===============
class SensorPlugin:
    """
    Базовый интерфейс плагина сенсора.
    Реализуйте sample() и верните словарь {sensor_id: float}.
    """
    def __init__(self, profile: DeviceProfile) -> None:
        self.profile = profile

    async def setup(self) -> None:
        pass

    async def sample(self) -> Dict[str, float]:
        raise NotImplementedError

    async def close(self) -> None:
        pass

class RandomSensor(SensorPlugin):
    """
    Демонстрационный плагин — выдаёт значения для всех сенсоров из профиля.
    В реальном деплое замените на OPC UA / Modbus / драйверы железа.
    """
    def __init__(self, profile: DeviceProfile, jitter: float = 0.2) -> None:
        super().__init__(profile)
        self._j = float(jitter)
        import random
        self._rnd = random

    async def sample(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for sid, s in self.profile.sensors.items():
            base = {
                "C": 25.0,
                "%": 50.0,
                "kPa": 101.3,
                "Pa": 101300.0,
            }.get(s.unit, 1.0)
            out[sid] = base + (self._rnd.random() - 0.5) * 2 * self._j * base
        await asyncio.sleep(0)  # точка переключения
        return out

# =============== Агенты и пайплайн ===============
class EdgeAgent:
    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self.profile: Optional[DeviceProfile] = None
        self.cal: Optional[CalibrationEngine] = None
        self._mqtt: Optional[MqttClient] = None
        self._plugins: List[SensorPlugin] = []
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task] = []
        self._profile_mtime: float = 0.0
        self._cert_mtimes: Dict[Path, float] = {}
        self._idem_cmd: Dict[str, float] = {}  # id -> ts
        self._idem_ttl = 600.0

    # ---------- Lifecycle ----------
    async def start(self) -> None:
        # Метрики
        if self.cfg.metrics_port:
            start_http_server(self.cfg.metrics_port)
            LOG.info("metrics_http_started port=%d", self.cfg.metrics_port)

        # Профиль и MQTT
        await self._load_profile(initial=True)
        self._mqtt = MqttClient(MqttSettings())
        self._mqtt.set_message_handler(self._on_mqtt_message)

        # Задачи
        self._tasks = [
            asyncio.create_task(self._mqtt.run_forever(), name="mqtt"),
            asyncio.create_task(self._sampler_loop(), name="sampler"),
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._profile_watch_loop(), name="profile_watch"),
            asyncio.create_task(self._cert_watch_loop(), name="cert_watch"),
        ]
        AGENT_READY.set(1.0)
        LOG.info("edge_agent_started device_id=%s twin=%s", self.profile.device_id if self.profile else "-", self.profile.twin_name if self.profile else "-")  # type: ignore

    async def stop(self) -> None:
        self._stop.set()
        AGENT_READY.set(0.0)
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(Exception):
                await t
        if self._mqtt:
            await self._mqtt.stop()
        for p in self._plugins:
            with contextlib.suppress(Exception):
                await p.close()
        LOG.info("edge_agent_stopped")

    # ---------- Профиль / калибровки ----------
    async def _load_profile(self, initial: bool = False) -> None:
        prof = load_device_profile(self.cfg.profile_path, self.cfg)
        self.profile = prof
        # Калибровки: сенсор -> spec
        cal_map = {sid: s.calibration for sid, s in prof.sensors.items() if s.calibration}
        self.cal = CalibrationEngine(cal_map)
        self._profile_mtime = self.cfg.profile_path.stat().st_mtime
        # Инициализация плагинов
        for p in self._plugins:
            with contextlib.suppress(Exception):
                await p.close()
        self._plugins = [RandomSensor(prof)]
        for p in self._plugins:
            await p.setup()
        AGENT_PROFILE_RELOADS.inc()
        if initial:
            LOG.info("profile_loaded device_id=%s telemetry_topic=%s commands_topic=%s sensors=%d",
                     prof.device_id, prof.telemetry_topic, prof.commands_topic, len(prof.sensors))
        else:
            LOG.info("profile_reloaded")

    async def _profile_watch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                mt = self.cfg.profile_path.stat().st_mtime
                if mt != self._profile_mtime:
                    await self._load_profile()
                await asyncio.sleep(2.0)
            except FileNotFoundError:
                LOG.warning("profile_not_found path=%s", self.cfg.profile_path)
                await asyncio.sleep(5.0)
            except Exception as e:
                LOG.exception("profile_watch_error %s", e)
                await asyncio.sleep(2.0)

    # ---------- Ротация сертификатов ----------
    async def _cert_watch_loop(self) -> None:
        glob_pat = self.cfg.cert_watch_glob
        if not glob_pat:
            return
        while not self._stop.is_set():
            changed = False
            for fp in glob.glob(glob_pat):
                p = Path(fp)
                try:
                    mt = p.stat().st_mtime
                except FileNotFoundError:
                    continue
                prev = self._cert_mtimes.get(p)
                if prev is None:
                    self._cert_mtimes[p] = mt
                elif mt != prev:
                    self._cert_mtimes[p] = mt
                    changed = True
            if changed and self._mqtt:
                LOG.info("certificates_changed -> reconnect MQTT")
                await self._mqtt.stop()  # run_forever перезапустится внешним supervisorом или процессом
            await asyncio.sleep(5.0)

    # ---------- Сбор и публикация ----------
    async def _sampler_loop(self) -> None:
        assert self.profile is not None and self.cal is not None
        sampling = max(0.1, self.cfg.sampling_sec)
        while not self._stop.is_set():
            started = time.perf_counter()
            batch: List[Dict[str, Any]] = []
            try:
                # Сбор данных со всех плагинов
                samples: Dict[str, float] = {}
                for p in self._plugins:
                    part = await p.sample()
                    samples.update(part)
                # Калибровки и нормализация
                for sid, raw in samples.items():
                    AGENT_SAMPLES.labels(sid).inc()
                    try:
                        val = self.cal.apply(sid, float(raw))
                    except Exception as e:
                        AGENT_CAL_ERRORS.labels(sid).inc()
                        LOG.warning("calibration_error sensor=%s err=%s", sid, e)
                        val = float(raw)
                    sp = self.profile.sensors.get(sid)
                    if sp:
                        val = normalize_unit(sp.unit, sp.normalization_to, val)
                    env = {
                        "twin_name": self.profile.twin_name,
                        "stream": sid,
                        "event_id": uuid.uuid4().hex,
                        "ts": time.time(),
                        "sequence": None,
                        "partition_key": self.profile.device_id,
                        "schema_uri": None,
                        "content_type": "application/json",
                        "attributes": {"deviceId": self.profile.device_id, "sensor": sid},
                        "payload": {"value": val, "unit": sp.normalization_to or sp.unit if sp else None},
                    }
                    batch.append(env)
                    if len(batch) >= self.cfg.batch_max:
                        await self._publish_batch(batch)
                        batch = []
                if batch:
                    await self._publish_batch(batch)
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.exception("sampling_error %s", e)
            finally:
                AGENT_SAMPLE_LAT.observe(time.perf_counter() - started)
                await asyncio.sleep(max(0.0, sampling - (time.perf_counter() - started)))

    async def _publish_batch(self, envs: List[Dict[str, Any]]) -> None:
        if not envs or not self._mqtt or not self.profile:
            return
        topic = self.profile.telemetry_topic
        payload = {"envelopes": envs}
        msg = PublishMessage.json(topic, payload, qos=1, retain=False)
        started = time.perf_counter()
        await self._mqtt.publish(msg)
        AGENT_PUBLISHED.labels(topic).inc()
        AGENT_PUBLISH_LAT.observe(time.perf_counter() - started)

    # ---------- Heartbeat ----------
    async def _heartbeat_loop(self) -> None:
        if not self.profile:
            return
        hb_sec = max(5.0, self.cfg.heartbeat_sec)
        topic = f"status/{self.profile.device_id}"
        while not self._stop.is_set():
            try:
                payload = {"status": "online", "ts": time.time(), "device_id": self.profile.device_id}
                if self._mqtt:
                    await self._mqtt.publish(PublishMessage.json(topic, payload, qos=1, retain=True))
                    AGENT_HEARTBEAT.inc()
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.warning("heartbeat_error %s", e)
            await asyncio.sleep(hb_sec)

    # ---------- Обработка входящих MQTT сообщений (команды) ----------
    async def _on_mqtt_message(self, topic: str, obj: Any, props: Dict[str, Any]) -> None:
        # Подписки указываются через PIC_MQTT_SUBSCRIBE: "commands/<deviceId>:1"
        # Ожидаемый формат команды:
        # { "type":"command", "id":"...", "command":"setpoint.write", "params":{...}, "priority":"NORMAL" }
        if not self.profile:
            return
        if topic != self.profile.commands_topic and not topic.endswith(f"/{self.profile.device_id}"):
            return
        try:
            cmd = obj if isinstance(obj, dict) else {}
            cid = cmd.get("id") or uuid.uuid4().hex
            ctype = str(cmd.get("command") or cmd.get("type") or "unknown")
            # идемпотентность
            now = time.time()
            for k, ts in list(self._idem_cmd.items()):
                if now - ts > self._idem_ttl:
                    self._idem_cmd.pop(k, None)
            if cid in self._idem_cmd:
                AGENT_CMD_TOTAL.labels(ctype, "duplicate").inc()
                return
            self._idem_cmd[cid] = now

            # Выполнение
            status = "COMPLETED"
            message = "ok"
            if ctype == "setpoint.write":
                # пример: params: {"sensor":"temp","value":23.5}
                p = cmd.get("params", {})
                LOG.info("cmd_setpoint sensor=%s value=%s", p.get("sensor"), p.get("value"))
                # В реальном драйвере — запись в актуатор
            elif ctype == "relay.switch":
                LOG.info("cmd_relay state=%s", cmd.get("params", {}).get("state"))
            elif ctype == "ota.update":
                LOG.info("cmd_ota_update channel=%s", cmd.get("params", {}).get("channel"))
                # В реальном окружении — запуск OTA-агента
            else:
                status = "REJECTED"; message = "unknown command"

            # ACK в канал событий (если задан), иначе — в команды/acks
            ack_topic = self.profile.alerts_topic or f"events/{self.profile.device_id}"
            ack = {
                "type": "command_result",
                "id": cid,
                "status": status,
                "message": message,
                "ts": time.time(),
            }
            if self._mqtt:
                await self._mqtt.publish(PublishMessage.json(ack_topic, ack, qos=1, retain=False))
            AGENT_CMD_TOTAL.labels(ctype, status.lower()).inc()
        except Exception as e:
            LOG.exception("command_error %s", e)
            AGENT_CMD_TOTAL.labels("unknown", "error").inc()

# =============== Точка входа ===============
async def _run() -> None:
    cfg = AgentConfig.load()
    agent = EdgeAgent(cfg)

    loop = asyncio.get_running_loop()
    stop_ev = asyncio.Event()

    def _graceful(*_: Any) -> None:
        LOG.info("signal_received -> stopping...")
        loop.create_task(agent.stop())
        stop_ev.set()

    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _graceful)

    await agent.start()
    await stop_ev.wait()

if __name__ == "__main__":
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
