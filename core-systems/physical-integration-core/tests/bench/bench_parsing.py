# tests/bench/bench_parsing.py
# Промышленный бенчмарк парсинга/нормализации телеметрии.
from __future__ import annotations

import hashlib
import json
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------- Опциональные JSON парсеры ----------
try:
    import orjson  # type: ignore
    _HAS_ORJSON = True
except Exception:
    _HAS_ORJSON = False

try:
    import ujson  # type: ignore
    _HAS_UJSON = True
except Exception:
    _HAS_UJSON = False

# ---------- Опциональная JSON Schema ----------
try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:
    _HAS_JSONSCHEMA = False

try:
    import fastjsonschema  # type: ignore
    _HAS_FASTJSONSCHEMA = True
except Exception:
    _HAS_FASTJSONSCHEMA = False

# ---------- Импорт нормализатора из проекта ----------
try:
    from physical_integration.telemetry.normalizer import (
        TelemetryNormalizer,
        NormalizationSpec,
        UnitRule,
    )
    _HAS_NORMALIZER = True
except Exception:
    _HAS_NORMALIZER = False

# ---------- Генерация детерминированного датасета ----------
@dataclass(frozen=True)
class BenchConfig:
    n_messages: int = int(os.getenv("PIC_BENCH_N", "5000"))
    n_devices: int = int(os.getenv("PIC_BENCH_DEVICES", "200"))
    pressure_unit: str = os.getenv("PIC_BENCH_PRESSURE_UNIT", "kPa")  # "kPa" или "bar"
    seed: int = int(os.getenv("PIC_BENCH_SEED", "42"))

def _gen_payload(i: int, cfg: BenchConfig) -> Dict[str, Any]:
    # device_id равномерно по пулу устройств
    dev_id = f"dev-{i % cfg.n_devices:05d}"
    # псевдослучайные величины с небольшими «шумами»
    base_temp = 20.0 + (i % 50) * 0.1
    base_pres_kpa = 100.0 + (i % 200) * 0.5
    online = (i % 13) != 0
    # единицы давления
    if cfg.pressure_unit == "bar":
        pressure = base_pres_kpa / 100.0  # 1 bar = 100 kPa
    else:
        pressure = base_pres_kpa
    return {
        "device_id": dev_id,
        "ts": int(time.time() * 1000) - (i % 100) * 1000,  # ms
        "payload": {
            "tempC": round(base_temp + random.random() * 0.5, 3),
            "pressure": round(pressure, 3),
            "online": online,
            "secret": "redact-me",
        },
        "credentials": {"token": "SHOULD_BE_REDACTED"},
        "topic": f"factory/line-{(i % 7)+1}/sensor/{dev_id}",
        "env": "bench",
    }

def make_dataset(cfg: Optional[BenchConfig] = None) -> Tuple[List[bytes], List[Dict[str, Any]]]:
    cfg = cfg or BenchConfig()
    random.seed(cfg.seed)
    records: List[Dict[str, Any]] = [_gen_payload(i, cfg) for i in range(cfg.n_messages)]
    # bytes для json.loads/from bytes
    raw_bytes: List[bytes] = [json.dumps(rec, ensure_ascii=False).encode("utf-8") for rec in records]
    return raw_bytes, records

# ---------- Помощники ----------
def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ---------- Pytest-бенчи (если запускается через pytest) ----------
if "PYTEST_CURRENT_TEST" in os.environ:
    # Требуем pytest-benchmark для запуска как тестов‑бенчей
    import pytest  # type: ignore
    pytest.importorskip("pytest_benchmark", reason="pytest-benchmark not installed")

    @pytest.fixture(scope="session")
    def bench_cfg() -> BenchConfig:
        return BenchConfig()

    @pytest.fixture(scope="session")
    def dataset(bench_cfg):
        raw_bytes, records = make_dataset(bench_cfg)
        return raw_bytes, records

    @pytest.fixture(scope="session")
    def normalizer_and_spec():
        if not _HAS_NORMALIZER:
            pytest.skip("TelemetryNormalizer not available")
        spec = NormalizationSpec(
            name="bench",
            device_id_path="$.device_id",
            ts_field_path="$.ts",
            required_paths=["$.payload"],
            ts_tolerance_seconds=86400,
            metrics_map={"temperature_c": "$.payload.tempC", "pressure_kpa": "$.payload.pressure", "online": "$.payload.online"},
            metrics_units={"temperature_c": "C", "pressure_kpa": "kPa"},
            redact_paths=["$.credentials", "$.payload.secret"],
            tags={"source": "bench", "topic": "{topic}", "env": "{env}"},
            unit_rules=[UnitRule("bar", "kPa", 100.0)],
            severity="INFO",
            type="TELEMETRY",
        )
        norm = TelemetryNormalizer()
        norm.register_unit_rules(spec.unit_rules)
        return norm, spec

    @pytest.mark.benchmark(group="json.loads")
    def test_json_std_loads(benchmark, dataset):
        raw_bytes, _ = dataset
        def _run():
            out = []
            for b in raw_bytes:
                out.append(json.loads(b))
            return out
        result = benchmark(_run)
        assert isinstance(result[0], dict)

    @pytest.mark.benchmark(group="json.loads")
    def test_json_orjson_loads(benchmark, dataset):
        if not _HAS_ORJSON:
            import pytest
            pytest.skip("orjson not installed")
        raw_bytes, _ = dataset
        def _run():
            out = []
            for b in raw_bytes:
                out.append(orjson.loads(b))
            return out
        result = benchmark(_run)
        assert isinstance(result[0], dict)

    @pytest.mark.benchmark(group="json.loads")
    def test_json_ujson_loads(benchmark, dataset):
        if not _HAS_UJSON:
            import pytest
            pytest.skip("ujson not installed")
        raw_bytes, _ = dataset
        def _run():
            out = []
            for b in raw_bytes:
                out.append(ujson.loads(b))
            return out
        result = benchmark(_run)
        assert isinstance(result[0], dict)

    @pytest.mark.benchmark(group="normalize")
    def test_normalizer_full_pipeline(benchmark, dataset, normalizer_and_spec):
        raw_bytes, records = dataset
        norm, spec = normalizer_and_spec
        ctx = {"topic": "factory/line-1/sensor/*", "env": "bench", "source": "pytest"}
        def _run():
            ok = 0
            for rec in records:
                env, dlq = norm.normalize(rec, spec, ctx)
                if dlq is None:
                    ok += 1
            return ok
        ok_count = benchmark(_run)
        assert ok_count == len(records)

    @pytest.mark.benchmark(group="schema")
    def test_jsonschema_validation(benchmark, dataset):
        if not _HAS_JSONSCHEMA:
            import pytest
            pytest.skip("jsonschema not installed")
        raw_bytes, records = dataset
        schema = {
            "type": "object",
            "required": ["device_id", "ts", "payload"],
            "properties": {
                "device_id": {"type": "string"},
                "ts": {"type": "number"},
                "payload": {
                    "type": "object",
                    "required": ["tempC", "pressure", "online"],
                    "properties": {
                        "tempC": {"type": "number"},
                        "pressure": {"type": "number"},
                        "online": {"type": "boolean"},
                    },
                },
            },
            "additionalProperties": True,
        }
        validator = jsonschema.Draft202012Validator(schema)  # type: ignore
        def _run():
            cnt = 0
            for rec in records:
                errs = list(validator.iter_errors(rec))
                if not errs:
                    cnt += 1
            return cnt
        cnt = benchmark(_run)
        assert cnt == len(records)

    @pytest.mark.benchmark(group="schema")
    def test_fastjsonschema_validation(benchmark, dataset):
        if not _HAS_FASTJSONSCHEMA:
            import pytest
            pytest.skip("fastjsonschema not installed")
        _, records = dataset
        schema = {
            "type": "object",
            "required": ["device_id", "ts", "payload"],
            "properties": {
                "device_id": {"type": "string"},
                "ts": {"type": "number"},
                "payload": {
                    "type": "object",
                    "required": ["tempC", "pressure", "online"],
                    "properties": {
                        "tempC": {"type": "number"},
                        "pressure": {"type": "number"},
                        "online": {"type": "boolean"},
                    },
                },
            },
            "additionalProperties": True,
        }
        compiled = fastjsonschema.compile(schema)  # type: ignore
        def _run():
            cnt = 0
            for rec in records:
                compiled(rec)
                cnt += 1
            return cnt
        cnt = benchmark(_run)
        assert cnt == len(records)

    @pytest.mark.benchmark(group="hashing")
    def test_content_hash_sha256(benchmark, dataset):
        _, records = dataset
        def _run():
            s = 0
            for rec in records:
                h = _sha256_hex(_canonical_json(rec))
                if h:
                    s += 1
            return s
        n = benchmark(_run)
        assert n == len(records)

    @pytest.mark.benchmark(group="encoding")
    def test_canonical_json_encoding(benchmark, dataset):
        _, records = dataset
        def _run():
            bytes_total = 0
            for rec in records:
                j = _canonical_json(rec)
                bytes_total += len(j)
            return bytes_total
        total = benchmark(_run)
        assert total > 0

# ---------- Самостоятельный запуск (без pytest) ----------
def _duration_ns(f, *args, **kwargs) -> Tuple[int, Any]:
    t0 = time.perf_counter_ns()
    res = f(*args, **kwargs)
    t1 = time.perf_counter_ns()
    return t1 - t0, res

def _bench_loop(name: str, fn, loops: int = 1) -> Tuple[float, Any]:
    # Возвращает среднюю длительность на цикл (сек) и результат
    times = []
    result = None
    for _ in range(loops):
        dt_ns, result = _duration_ns(fn)
        times.append(dt_ns / 1e9)
    avg = statistics.mean(times)
    print(f"{name:32s}  {avg:9.6f}s")
    return avg, result

def main():
    # Параметры из окружения/CLI
    n = int(os.getenv("PIC_BENCH_N", "20000"))
    cfg = BenchConfig(n_messages=n)
    raw_bytes, records = make_dataset(cfg)
    print(f"Dataset: {len(records)} messages, devices={cfg.n_devices}, unit={cfg.pressure_unit}")

    # JSON parsers
    def run_std():
        out = []
        for b in raw_bytes:
            out.append(json.loads(b))
        return len(out)

    def run_orjson():
        if not _HAS_ORJSON:
            return 0
        out = []
        for b in raw_bytes:
            out.append(orjson.loads(b))
        return len(out)

    def run_ujson():
        if not _HAS_UJSON:
            return 0
        out = []
        for b in raw_bytes:
            out.append(ujson.loads(b))
        return len(out)

    _bench_loop("json.loads (stdlib)", run_std, loops=1)
    if _HAS_ORJSON:
        _bench_loop("orjson.loads", run_orjson, loops=1)
    else:
        print("orjson.loads".ljust(32), "  skipped")
    if _HAS_UJSON:
        _bench_loop("ujson.loads", run_ujson, loops=1)
    else:
        print("ujson.loads".ljust(32), "  skipped")

    # Normalizer (если доступен)
    if _HAS_NORMALIZER:
        norm = TelemetryNormalizer()
        spec = NormalizationSpec(
            name="bench",
            device_id_path="$.device_id",
            ts_field_path="$.ts",
            required_paths=["$.payload"],
            ts_tolerance_seconds=86400,
            metrics_map={"temperature_c": "$.payload.tempC", "pressure_kpa": "$.payload.pressure", "online": "$.payload.online"},
            metrics_units={"temperature_c": "C", "pressure_kpa": "kPa"},
            redact_paths=["$.credentials", "$.payload.secret"],
            tags={"source": "bench", "topic": "{topic}", "env": "{env}"},
            unit_rules=[UnitRule("bar", "kPa", 100.0)],
            severity="INFO",
            type="TELEMETRY",
        )
        norm.register_unit_rules(spec.unit_rules)
        ctx = {"topic": "factory/*", "env": "bench", "source": "cli"}

        def run_norm():
            ok = 0
            for rec in records:
                env, dlq = norm.normalize(rec, spec, ctx)
                ok += (1 if dlq is None else 0)
            return ok

        _bench_loop("TelemetryNormalizer.normalize", run_norm, loops=1)
    else:
        print("TelemetryNormalizer.normalize".ljust(32), "  skipped")

    # JSON Schema
    if _HAS_JSONSCHEMA:
        schema = {
            "type": "object",
            "required": ["device_id", "ts", "payload"],
            "properties": {
                "device_id": {"type": "string"},
                "ts": {"type": "number"},
                "payload": {
                    "type": "object",
                    "required": ["tempC", "pressure", "online"],
                    "properties": {
                        "tempC": {"type": "number"},
                        "pressure": {"type": "number"},
                        "online": {"type": "boolean"},
                    },
                },
            },
            "additionalProperties": True,
        }
        validator = jsonschema.Draft202012Validator(schema)  # type: ignore
        def run_schema_std():
            cnt = 0
            for rec in records:
                if not list(validator.iter_errors(rec)):
                    cnt += 1
            return cnt
        _bench_loop("jsonschema.validate", run_schema_std, loops=1)
    else:
        print("jsonschema.validate".ljust(32), "  skipped")

    if _HAS_FASTJSONSCHEMA:
        schema = {
            "type": "object",
            "required": ["device_id", "ts", "payload"],
            "properties": {
                "device_id": {"type": "string"},
                "ts": {"type": "number"},
                "payload": {
                    "type": "object",
                    "required": ["tempC", "pressure", "online"],
                    "properties": {
                        "tempC": {"type": "number"},
                        "pressure": {"type": "number"},
                        "online": {"type": "boolean"},
                    },
                },
            },
            "additionalProperties": True,
        }
        compiled = fastjsonschema.compile(schema)  # type: ignore
        def run_schema_fast():
            cnt = 0
            for rec in records:
                compiled(rec)
                cnt += 1
            return cnt
        _bench_loop("fastjsonschema.validate", run_schema_fast, loops=1)
    else:
        print("fastjsonschema.validate".ljust(32), "  skipped")

    # Canonical JSON + SHA256
    def run_canonical():
        s = 0
        for rec in records:
            j = _canonical_json(rec)
            h = _sha256_hex(j)
            s += 1 if h else 0
        return s
    _bench_loop("canonical_json + sha256", run_canonical, loops=1)

if __name__ == "__main__":
    main()
