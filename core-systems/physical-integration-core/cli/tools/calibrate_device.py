#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import os
import random
import signal
import sys
import time
import typing as t
from dataclasses import dataclass
from pathlib import Path

# -------- Опциональные зависимости (аккуратно деградируем) --------
try:
    import yaml  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyYAML is required: pip install pyyaml") from e

try:
    from jsonschema import Draft7Validator  # type: ignore
except Exception:  # pragma: no cover
    Draft7Validator = None  # type: ignore

# Serial CAN (совместимо с ранее предложенным serial_can.py)
try:
    from physical_integration.protocols.serial_can import SerialSLCANTransport, CANFrame, SerialCANConfig  # type: ignore
except Exception:
    SerialSLCANTransport = None  # type: ignore
    CANFrame = None  # type: ignore
    SerialCANConfig = None  # type: ignore

# Публикация результатов (опционально)
try:
    from physical_integration.adapters.datafabric_adapter import (
        DataFabricAdapter, DataFabricConfig, BackendKind, KafkaConfig, AvroConfig
    )  # type: ignore
except Exception:
    DataFabricAdapter = None  # type: ignore

# Метрики (no-op fallback)
try:
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def set(self, *_): return
    Counter = Gauge = _Noop  # type: ignore


# ================================
# Журналирование
# ================================

def jlog(level: str, msg: str, **kw) -> None:
    rec = {"ts": dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z", "level": level, "msg": msg}
    if kw:
        rec.update(kw)
    print(json.dumps(rec, ensure_ascii=False))


# ================================
# YAML схема рецепта
# ================================

CALIBRATION_SCHEMA: dict = {
    "type": "object",
    "required": ["schema_version", "device", "steps"],
    "properties": {
        "schema_version": {"type": "string", "enum": ["1.0"]},
        "idempotency_key": {"type": "string"},
        "device": {
            "type": "object",
            "required": ["driver"],
            "properties": {
                "driver": {"type": "string", "enum": ["mock", "serial_can"]},
                "port": {"type": "string"},
                "baudrate": {"type": "integer", "minimum": 9600},
                "bitrate_preset": {"type": "integer", "minimum": 0, "maximum": 8},
                "device_id": {"type": "string"},
                "stable_tolerance": {"type": "number", "minimum": 0},
                "stable_window": {"type": "integer", "minimum": 1},
                "read_timeout_s": {"type": "number", "minimum": 0.01},
            },
            "additionalProperties": False
        },
        "limits": {
            "type": "object",
            "properties": {
                "temperature_c": {"type": "array", "minItems": 2, "maxItems": 2},
                "supply_v": {"type": "array", "minItems": 2, "maxItems": 2}
            },
            "additionalProperties": True
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["op"],
                "properties": {
                    "name": {"type": "string"},
                    "op": {"type": "string", "enum": [
                        "set_register", "send_can", "wait", "measure", "adjust_gain",
                        "write_calibration", "save_eeprom", "assert_range"
                    ]},
                    "register": {"type": "string"},
                    "value": {"type": ["integer", "number", "string"]},
                    "mask": {"type": "integer"},
                    "duration_ms": {"type": "integer", "minimum": 0},
                    "measure": {
                        "type": "object",
                        "required": ["signal", "samples", "avg"],
                        "properties": {
                            "signal": {"type": "string"},
                            "samples": {"type": "integer", "minimum": 1},
                            "avg": {"type": "boolean"},
                            "timeout_s": {"type": "number", "minimum": 0.01}
                        },
                        "additionalProperties": False
                    },
                    "target": {"type": "number"},
                    "tolerance": {"type": "number", "minimum": 0},
                    "max_iters": {"type": "integer", "minimum": 1},
                    "gain_step": {"type": "number"},
                    "can_id": {"type": "integer"},
                    "can_data_hex": {"type": "string", "pattern": "^[0-9A-Fa-f]*$"},
                    "min": {"type": "number"},
                    "max": {"type": "number"},
                },
                "additionalProperties": False
            }
        }
    },
    "additionalProperties": False,
}


# ================================
# Драйверы устройств
# ================================

class BaseDevice:
    async def open(self): ...
    async def close(self): ...
    async def set_register(self, reg: str, value: int, mask: int | None = None) -> None: ...
    async def send_can(self, can_id: int, payload: bytes) -> None: ...
    async def measure(self, signal: str, timeout_s: float) -> float: ...
    async def write_calibration(self) -> None: ...
    async def save_eeprom(self) -> None: ...
    async def read_env(self) -> dict: ...


class MockDevice(BaseDevice):
    def __init__(self, device_id: str = "MOCK-0001") -> None:
        self.device_id = device_id
        self._opened = False
        self._state: dict[str, float] = {"gain": 1.0, "offset": 0.0, "temp_c": 25.0, "supply_v": 12.1}

    async def open(self):
        self._opened = True
        await asyncio.sleep(0.05)

    async def close(self):
        self._opened = False

    async def set_register(self, reg: str, value: int, mask: int | None = None) -> None:
        if reg == "GAIN":
            self._state["gain"] = float(value)
        elif reg == "OFFSET":
            self._state["offset"] = float(value)
        await asyncio.sleep(0.01)

    async def send_can(self, can_id: int, payload: bytes) -> None:
        await asyncio.sleep(0.005)

    async def measure(self, signal: str, timeout_s: float) -> float:
        # простая модель измерения
        base = 100.0 * self._state.get("gain", 1.0) + self._state.get("offset", 0.0)
        noise = random.uniform(-0.5, 0.5)
        if signal == "photodiode":
            return base + noise
        if signal == "temp_c":
            return self._state["temp_c"] + random.uniform(-0.1, 0.1)
        if signal == "supply_v":
            return self._state["supply_v"] + random.uniform(-0.01, 0.01)
        return base + noise

    async def write_calibration(self) -> None:
        await asyncio.sleep(0.02)

    async def save_eeprom(self) -> None:
        await asyncio.sleep(0.05)

    async def read_env(self) -> dict:
        return {"device_id": self.device_id, "fw": "v0.0-mock", "temp_c": self._state["temp_c"], "supply_v": self._state["supply_v"]}


class SerialCanDevice(BaseDevice):
    def __init__(self, port: str, baudrate: int = 115200, preset: int | None = None, read_timeout_s: float = 1.0) -> None:
        if SerialSLCANTransport is None:
            raise RuntimeError("serial_can driver is unavailable (install serial dependencies)")
        assert SerialCANConfig is not None and CANFrame is not None
        self.cfg = SerialCANConfig(port=port, baudrate=baudrate, bitrate_preset=preset)
        self.tr = SerialSLCANTransport(self.cfg)
        self.read_timeout_s = read_timeout_s

    async def open(self):
        await self.tr.start()
        await asyncio.sleep(0.1)

    async def close(self):
        await self.tr.stop()

    async def set_register(self, reg: str, value: int, mask: int | None = None) -> None:
        # протокол примера: CAN id 0x100, payload: [cmd=0x01, reg_id, value_lo, value_hi]
        reg_map = {"GAIN": 0x01, "OFFSET": 0x02}
        rid = reg_map.get(reg, 0x00)
        val = int(value) & 0xFFFF
        payload = bytes([0x01, rid, val & 0xFF, (val >> 8) & 0xFF])
        await self.send_can(0x100, payload)

    async def send_can(self, can_id: int, payload: bytes) -> None:
        frame = CANFrame(id=can_id, data=payload, is_extended=False, is_remote=False)  # type: ignore
        await self.tr.send(frame)

    async def measure(self, signal: str, timeout_s: float) -> float:
        # протокол примера: запрос/ответ на id 0x200/0x201
        sig_map = {"photodiode": 0x10, "temp_c": 0x20, "supply_v": 0x30}
        code = sig_map.get(signal, 0x10)
        await self.send_can(0x200, bytes([0x02, code]))
        # ожидание ответа: для простоты слушаем очередь транспорта
        try:
            fut = asyncio.get_event_loop().create_future()

            def cb(frame):
                if frame.id == 0x201 and len(frame.data) >= 4:
                    val = int.from_bytes(frame.data[:4], "little", signed=False)
                    fut.set_result(val / 1000.0)

            self.tr.add_subscriber(cb)
            return await asyncio.wait_for(fut, timeout=timeout_s)
        except asyncio.TimeoutError:
            raise TimeoutError("measurement timeout")

    async def write_calibration(self) -> None:
        await self.send_can(0x100, bytes([0x03]))

    async def save_eeprom(self) -> None:
        await self.send_can(0x100, bytes([0x04]))

    async def read_env(self) -> dict:
        # возвращаем минимальный набор
        return {"device_id": f"CAN:{self.cfg.port}", "fw": "unknown"}


# ================================
# Исполнитель рецептов
# ================================

@dataclass
class CalibContext:
    recipe: dict
    device: BaseDevice
    stable_tol: float
    stable_window: int
    out_dir: Path
    hmac_secret: str | None
    df_adapter: t.Any | None
    start_ts_ms: int


def _validate_recipe(recipe: dict) -> None:
    if Draft7Validator is None:
        # Минимальная проверка без jsonschema
        if recipe.get("schema_version") != "1.0":
            raise ValueError("schema_version must be '1.0'")
        if "device" not in recipe or "steps" not in recipe:
            raise ValueError("recipe requires 'device' and 'steps'")
        return
    Draft7Validator(CALIBRATION_SCHEMA).validate(recipe)


async def _measure_stable(dev: BaseDevice, signal: str, n: int, tol: float, timeout_s: float) -> tuple[float, list[float]]:
    vals: list[float] = []
    deadline = time.time() + timeout_s
    while time.time() < deadline and len(vals) < n:
        v = await dev.measure(signal, timeout_s=timeout_s)
        vals.append(v)
        if len(vals) >= 2 and abs(vals[-1] - vals[-2]) > tol:
            # нестабильно — начнем окно заново
            vals = [vals[-1]]
        await asyncio.sleep(0.02)
    if len(vals) < n:
        raise TimeoutError(f"stable window not reached for {signal}")
    avg = sum(vals) / len(vals)
    return avg, vals


async def run_steps(ctx: CalibContext) -> dict:
    dev = ctx.device
    recipe = ctx.recipe
    res: dict = {
        "schema_version": "1.0",
        "recipe_idempotency_key": recipe.get("idempotency_key"),
        "device": {},
        "limits_ok": True,
        "steps": [],
        "started_at": ctx.start_ts_ms,
        "finished_at": None,
        "ok": False,
    }

    # окружение устройства
    env = await dev.read_env()
    res["device"] = env

    # проверка пределов, если заданы
    limits = recipe.get("limits") or {}
    if "temperature_c" in limits:
        tavg, _ = await _measure_stable(dev, "temp_c", n=ctx.stable_window, tol=ctx.stable_tol, timeout_s=5.0)
        lo, hi = limits["temperature_c"]
        res["limits_ok"] = res["limits_ok"] and (lo <= tavg <= hi)
        res.setdefault("env", {})["temp_c"] = tavg
    if "supply_v" in limits:
        vavg, _ = await _measure_stable(dev, "supply_v", n=ctx.stable_window, tol=ctx.stable_tol, timeout_s=5.0)
        lo, hi = limits["supply_v"]
        res["limits_ok"] = res["limits_ok"] and (lo <= vavg <= hi)
        res.setdefault("env", {})["supply_v"] = vavg
    if not res["limits_ok"]:
        jlog("error", "limits_check_failed", env=res.get("env", {}))
        res["finished_at"] = int(time.time() * 1000)
        return res

    # выполнение шагов
    for idx, st in enumerate(recipe["steps"], 1):
        step_rec: dict = {"idx": idx, "name": st.get("name") or st["op"], "op": st["op"], "ok": False}
        try:
            op = st["op"]
            if op == "wait":
                await asyncio.sleep((st.get("duration_ms") or 0) / 1000.0)
            elif op == "set_register":
                await dev.set_register(st["register"], int(st["value"]), st.get("mask"))
            elif op == "send_can":
                can_id = int(st["can_id"])
                payload = bytes.fromhex(st.get("can_data_hex", ""))
                await dev.send_can(can_id, payload)
            elif op == "measure":
                m = st["measure"]
                if recipe["device"].get("stable_window"):
                    avg, series = await _measure_stable(dev, m["signal"], n=ctx.stable_window, tol=ctx.stable_tol, timeout_s=m.get("timeout_s", 2.0))
                    step_rec["value"] = avg
                    step_rec["series"] = series
                else:
                    vals = []
                    for _ in range(int(m["samples"])):
                        vals.append(await dev.measure(m["signal"], m.get("timeout_s", 2.0)))
                        await asyncio.sleep(0.01)
                    step_rec["value"] = sum(vals) / len(vals) if m.get("avg", True) else vals[-1]
                    step_rec["series"] = vals
            elif op == "adjust_gain":
                target = float(st["target"])
                tol = float(st.get("tolerance", 0.5))
                max_iters = int(st.get("max_iters", 10))
                gain_step = float(st.get("gain_step", 0.1))
                cur_gain = 1.0
                await dev.set_register("GAIN", int(cur_gain))
                for it in range(max_iters):
                    val = await dev.measure("photodiode", timeout_s=2.0)
                    err = target - val
                    step_rec.setdefault("iters", []).append({"iter": it + 1, "val": val, "err": err, "gain": cur_gain})
                    if abs(err) <= tol:
                        break
                    cur_gain += gain_step if err > 0 else -gain_step
                    cur_gain = max(0.0, cur_gain)
                    await dev.set_register("GAIN", int(cur_gain))
                    await asyncio.sleep(0.05)
                step_rec["final_gain"] = cur_gain
            elif op == "write_calibration":
                await dev.write_calibration()
            elif op == "save_eeprom":
                await dev.save_eeprom()
            elif op == "assert_range":
                minv = float(st["min"]); maxv = float(st["max"])
                sig = st.get("measure", {}).get("signal", "photodiode")
                v = await dev.measure(sig, timeout_s=2.0)
                if not (minv <= v <= maxv):
                    raise ValueError(f"value {v} not in [{minv}, {maxv}]")
                step_rec["value"] = v
            else:
                raise ValueError(f"unsupported op: {op}")

            step_rec["ok"] = True
            jlog("info", "step_ok", idx=idx, name=step_rec["name"], op=st["op"])
        except Exception as e:
            step_rec["error"] = str(e)
            jlog("error", "step_failed", idx=idx, name=step_rec["name"], op=st["op"], error=str(e))
            res["steps"].append(step_rec)
            res["finished_at"] = int(time.time() * 1000)
            return res

        res["steps"].append(step_rec)

    res["finished_at"] = int(time.time() * 1000)
    res["ok"] = True
    return res


# ================================
# Подпись и сохранение результатов
# ================================

def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sign_result(result: dict, secret: str | None) -> dict:
    if not secret:
        return result
    mac = hmac.new(secret.encode("utf-8"), _canonical(result), hashlib.sha256).hexdigest()
    result = dict(result)
    result["signature"] = {"alg": "HMAC-SHA256", "value": mac}
    return result

def save_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ================================
# Обвязка CLI
# ================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Device calibration CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    prun = sub.add_parser("run", help="Запустить калибровку по рецепту")
    prun.add_argument("--recipe", required=True, help="Путь к YAML рецепту")
    prun.add_argument("--results-dir", default="./cal_results", help="Каталог для результатов")
    prun.add_argument("--dry-run", action="store_true", help="Не посылать команды устройству")
    prun.add_argument("--df-kafka", help="Bootstrap servers для публикации результатов в Kafka (опционально)")
    prun.add_argument("--df-topic", default="calibration.results", help="Топик для публикации")
    prun.add_argument("--hmac-secret", help="Секрет для HMAC подписи результата")
    prun.add_argument("--timeout-s", type=float, default=600, help="Глобальный таймаут выполнения")

    psim = sub.add_parser("simulate", help="Симуляция рецепта на MockDevice")
    psim.add_argument("--recipe", required=True)
    psim.add_argument("--results-dir", default="./cal_results")

    pver = sub.add_parser("verify", help="Проверка рецепта без выполнения")
    pver.add_argument("--recipe", required=True)

    psch = sub.add_parser("schema", help="Вывести JSON-схему рецепта",)
    plist = sub.add_parser("list-serial", help="Показать доступные serial-порты (best-effort)")
    return p


def load_recipe(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        recipe = yaml.safe_load(f)  # type: ignore
    if not isinstance(recipe, dict):
        raise ValueError("recipe must be a mapping")
    _validate_recipe(recipe)
    return recipe


async def make_device(recipe: dict, dry_run: bool = False) -> BaseDevice:
    devcfg = recipe["device"]
    if devcfg["driver"] == "mock" or dry_run:
        return MockDevice(device_id=devcfg.get("device_id", "MOCK-0001"))
    if devcfg["driver"] == "serial_can":
        if SerialSLCANTransport is None:
            raise RuntimeError("serial_can driver is not available")
        port = devcfg.get("port") or "/dev/ttyACM0"
        baud = int(devcfg.get("baudrate", 115200))
        preset = devcfg.get("bitrate_preset")
        read_timeout_s = float(devcfg.get("read_timeout_s", 1.0))
        return SerialCanDevice(port, baud, preset, read_timeout_s)
    raise ValueError(f"unsupported driver: {devcfg['driver']}")


async def publish_result_df(result: dict, bootstrap: str, topic: str) -> None:
    if DataFabricAdapter is None:
        jlog("warn", "datafabric_adapter_not_available")
        return
    cfg = DataFabricConfig(
        backend=BackendKind.kafka,
        kafka=KafkaConfig(bootstrap_servers=bootstrap, topic=topic, acks="all", enable_idempotence=True),
        avro=AvroConfig(schema_path=None, validate=False),  # публикуем JSON
    )
    adapter = DataFabricAdapter(cfg)
    await adapter.start()
    try:
        await adapter.publish(result, headers={"type": "calibration_result"})
        await asyncio.sleep(0.1)
    finally:
        await adapter.stop()


# ================================
# Выполнение команд
# ================================

async def cmd_run(args: argparse.Namespace) -> int:
    recipe = load_recipe(args.recipe)
    device = await make_device(recipe, dry_run=args.dry_run)
    out_dir = Path(args.results_dir)
    stable_tol = float(recipe.get("device", {}).get("stable_tolerance", 0.2))
    stable_window = int(recipe.get("device", {}).get("stable_window", 3))
    start_ts_ms = int(time.time() * 1000)

    df_adapter = None  # публикацию делаем отдельной функцией по завершении
    ctx = CalibContext(
        recipe=recipe,
        device=device,
        stable_tol=stable_tol,
        stable_window=stable_window,
        out_dir=out_dir,
        hmac_secret=args.hmac_secret,
        df_adapter=df_adapter,
        start_ts_ms=start_ts_ms,
    )

    # таймаут и корректное завершение
    stop = asyncio.Event()

    def _sig(*_):
        stop.set()

    loop = asyncio.get_event_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, _sig)
        loop.add_signal_handler(signal.SIGTERM, _sig)
    except NotImplementedError:
        pass

    await device.open()
    try:
        task = asyncio.create_task(run_steps(ctx))
        done, pending = await asyncio.wait({task, stop.wait()}, timeout=args.timeout_s, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            result = task.result()
        else:
            for p in pending:
                p.cancel()
            jlog("error", "calibration_timeout")
            result = {"ok": False, "error": "timeout", "started_at": start_ts_ms, "finished_at": int(time.time() * 1000)}
    finally:
        await device.close()

    # подпись и сохранение
    signed = sign_result(result, args.hmac_secret)
    save_jsonl(out_dir / "results.jsonl", signed)
    jlog("info", "result_saved", path=str((out_dir / "results.jsonl").resolve()), ok=signed.get("ok", False))

    # публикация (если задан bootstrap)
    if args.df_kafka:
        try:
            await publish_result_df(signed, args.df_kafka, args.df_topic)
            jlog("info", "result_published", topic=args.df_topic, bootstrap=args.df_kafka)
        except Exception as e:
            jlog("error", "publish_failed", error=str(e))

    # отдельный файл последнего результата
    with (out_dir / "last_result.json").open("w", encoding="utf-8") as f:
        json.dump(signed, f, ensure_ascii=False, indent=2)

    return 0 if signed.get("ok") else 1


async def cmd_simulate(args: argparse.Namespace) -> int:
    recipe = load_recipe(args.recipe)
    recipe = dict(recipe)
    recipe["device"] = dict(recipe["device"], driver="mock")
    args.dry_run = True
    return await cmd_run(args)


def cmd_verify(args: argparse.Namespace) -> int:
    recipe = load_recipe(args.recipe)
    jlog("info", "recipe_ok", device=recipe["device"]["driver"], steps=len(recipe["steps"]))
    return 0


def cmd_schema(_: argparse.Namespace) -> int:
    print(json.dumps(CALIBRATION_SCHEMA, ensure_ascii=False, indent=2))
    return 0


def cmd_list_serial(_: argparse.Namespace) -> int:
    try:
        import serial.tools.list_ports as lp  # type: ignore
    except Exception:
        jlog("warn", "pyserial_not_available")
        return 0
    ports = [{"device": p.device, "desc": p.description, "hwid": p.hwid} for p in lp.comports()]
    print(json.dumps(ports, ensure_ascii=False, indent=2))
    return 0


# ================================
# Entry point
# ================================

def main() -> int:
    ap = build_argparser()
    args = ap.parse_args()
    if args.cmd == "run":
        return asyncio.run(cmd_run(args))
    if args.cmd == "simulate":
        return asyncio.run(cmd_simulate(args))
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "schema":
        return cmd_schema(args)
    if args.cmd == "list-serial":
        return cmd_list_serial(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
