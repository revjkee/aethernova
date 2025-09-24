# engine/cli/tools/loadgen.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import json
import logging
import math
import os
import random
import signal
import string
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple, Union

# Опциональная телеметрия
with contextlib.suppress(Exception):
    from engine.telemetry.profiling import profile_block  # type: ignore
    _HAS_PROF = True
if not "profile_block" in globals():
    def profile_block(name: Optional[str] = None, config: Optional[Any] = None):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()
    _HAS_PROF = False

# Опциональные клиенты
try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:
    _HAS_HTTPX = False

try:
    import websockets  # type: ignore
    _HAS_WS = True
except Exception:
    _HAS_WS = False

LOG = logging.getLogger(__name__)
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

# =========================
# Конфигурации
# =========================

@dataclass(frozen=True)
class LoadGenConfig:
    name: str = "loadgen"
    duration_sec: float = 30.0
    warmup_sec: float = 3.0
    ramp_up_sec: float = 0.0
    ramp_down_sec: float = 0.0

    # Модель нагрузки
    model: str = "open"  # open | closed
    target_rps: float = 100.0               # для open
    max_concurrency: int = 1000            # ограничение задач
    users: int = 100                        # для closed
    think_time_ms: Tuple[int, int] = (10, 30)

    # Дистрибуция интервалов для open
    arrival: str = "poisson"  # poisson | uniform

    # Сеть и таймауты
    request_timeout_sec: float = 5.0
    retry_attempts: int = 1
    backoff_base_ms: int = 50
    backoff_cap_ms: int = 500

    # Поведение событий
    payload_bytes: int = 200
    keyspace: int = 1000
    allow_errors: bool = False  # если False, исключения учитываются и поднимаются после теста

    # Метрики и вывод
    report_interval_sec: float = 2.0
    export_json: Optional[str] = None  # путь к файлу с итоговым отчетом
    tag: str = "default"

    # Синк
    sink: str = "memory"  # memory | http | ws | custom
    sink_endpoint: Optional[str] = None
    sink_headers: Dict[str, str] = field(default_factory=dict)

    # Сценарий
    scenario: str = "random"  # random | scripted
    script: Optional[str] = None  # путь к json со списком событий

    # Завершение
    graceful_shutdown_sec: float = 5.0

    @staticmethod
    def from_env(prefix: str = "LOADGEN") -> "LoadGenConfig":
        def _get(k: str, d: Optional[str] = None) -> Optional[str]:
            v = os.getenv(f"{prefix}_{k}")
            return v if v is not None else d
        def _getf(k: str, d: float) -> float:
            v = _get(k)
            return float(v) if v is not None else d
        def _geti(k: str, d: int) -> int:
            v = _get(k)
            return int(v) if v is not None else d
        def _getb(k: str, d: bool) -> bool:
            v = _get(k)
            return v.lower() in ("1","true","yes","on") if v is not None else d

        return LoadGenConfig(
            name=_get("NAME", "loadgen") or "loadgen",
            duration_sec=_getf("DURATION", 30.0),
            warmup_sec=_getf("WARMUP", 3.0),
            ramp_up_sec=_getf("RAMP_UP", 0.0),
            ramp_down_sec=_getf("RAMP_DOWN", 0.0),
            model=_get("MODEL", "open") or "open",
            target_rps=_getf("RPS", 100.0),
            max_concurrency=_geti("MAX_CONC", 1000),
            users=_geti("USERS", 100),
            request_timeout_sec=_getf("TIMEOUT", 5.0),
            retry_attempts=_geti("RETRIES", 1),
            backoff_base_ms=_geti("BACKOFF_BASE", 50),
            backoff_cap_ms=_geti("BACKOFF_CAP", 500),
            payload_bytes=_geti("PAYLOAD_BYTES", 200),
            keyspace=_geti("KEYSPACE", 1000),
            allow_errors=_getb("ALLOW_ERRORS", False),
            report_interval_sec=_getf("REPORT_INT", 2.0),
            export_json=_get("EXPORT_JSON"),
            tag=_get("TAG", "default") or "default",
            sink=_get("SINK", "memory") or "memory",
            sink_endpoint=_get("ENDPOINT"),
            scenario=_get("SCENARIO", "random") or "random",
            script=_get("SCRIPT"),
        )

# =========================
# События и сценарии
# =========================

@dataclass
class Event:
    type: str
    key: str
    payload: Dict[str, Any]
    ts: float = field(default_factory=lambda: time.time())

class BaseScenario(abc.ABC):
    @abc.abstractmethod
    async def next_event(self) -> Event:
        ...

    async def on_result(self, ev: Event, ok: bool, status: int, latency_ms: float) -> None:
        return

class RandomScenario(BaseScenario):
    def __init__(self, cfg: LoadGenConfig):
        self.cfg = cfg
        self._rnd = random.Random(1337)

    def _rand_key(self) -> str:
        return f"k{self._rnd.randint(1, max(1, self.cfg.keyspace))}"

    def _rand_payload(self) -> Dict[str, Any]:
        size = self.cfg.payload_bytes
        # простая псевдослучайная строка
        s = "".join(self._rnd.choice(string.ascii_letters + string.digits) for _ in range(min(1024, size)))
        return {"msg": s, "n": self._rnd.randint(0, 1_000_000)}

    async def next_event(self) -> Event:
        t = self._rnd.random()
        etype = "move" if t < 0.4 else "shoot" if t < 0.7 else "loot"
        return Event(type=etype, key=self._rand_key(), payload=self._rand_payload())

class ScriptedScenario(BaseScenario):
    def __init__(self, script_path: str):
        self._events: List[Event] = []
        data = json.loads(Path(script_path).read_text(encoding="utf-8"))
        for item in data:
            self._events.append(Event(type=item["type"], key=item["key"], payload=item.get("payload", {})))
        self._i = 0

    async def next_event(self) -> Event:
        if not self._events:
            return Event(type="noop", key="noop", payload={})
        e = self._events[self._i % len(self._events)]
        self._i += 1
        return Event(type=e.type, key=e.key, payload=dict(e.payload))

# =========================
# Синки
# =========================

class BaseSink(abc.ABC):
    @abc.abstractmethod
    async def send(self, event: Event, timeout: float) -> Tuple[bool, int]:
        ...

    async def close(self) -> None:
        return

class InMemorySink(BaseSink):
    def __init__(self):
        self.storage: List[Event] = []

    async def send(self, event: Event, timeout: float) -> Tuple[bool, int]:
        self.storage.append(event)
        return True, 200

class HttpSink(BaseSink):
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None):
        if not _HAS_HTTPX:
            raise RuntimeError("httpx is not installed")
        self._client = httpx.AsyncClient(base_url=endpoint, headers=headers, timeout=None)

    async def send(self, event: Event, timeout: float) -> Tuple[bool, int]:
        try:
            with profile_block("loadgen.http.send"):
                r = await self._client.post("/", json=dataclasses.asdict(event), timeout=timeout)
            return (200 <= r.status_code < 300), r.status_code
        except Exception:
            return False, 0

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await self._client.aclose()

class WsSink(BaseSink):
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None):
        if not _HAS_WS:
            raise RuntimeError("websockets is not installed")
        self.endpoint = endpoint
        self.headers = headers or {}
        self._conn = None

    async def _ensure(self):
        if self._conn is None:
            self._conn = await websockets.connect(self.endpoint, extra_headers=self.headers)

    async def send(self, event: Event, timeout: float) -> Tuple[bool, int]:
        try:
            await self._ensure()
            with profile_block("loadgen.ws.send"):
                await asyncio.wait_for(self._conn.send(json.dumps(dataclasses.asdict(event))), timeout=timeout)
            return True, 101
        except Exception:
            return False, 0

    async def close(self) -> None:
        if self._conn:
            with contextlib.suppress(Exception):
                await self._conn.close()
            self._conn = None

# =========================
# Метрики
# =========================

class LatencyHistogram:
    def __init__(self, lowest_ms: float = 0.1, highest_ms: float = 60_000.0, precision: int = 3):
        self.lowest = lowest_ms
        self.highest = highest_ms
        self.precision = precision
        self._buckets: Dict[int, int] = {}
        self._count = 0
        self._sum_ms = 0.0
        self._min = float("inf")
        self._max = 0.0

    def _idx(self, v_ms: float) -> int:
        v = max(self.lowest, min(self.highest, v_ms))
        # логарифмическая сетка
        scale = 10 ** self.precision
        return int(math.log10(v + 1.0) * scale)

    def observe(self, v_ms: float) -> None:
        self._count += 1
        self._sum_ms += v_ms
        self._min = min(self._min, v_ms)
        self._max = max(self._max, v_ms)
        self._buckets[self._idx(v_ms)] = self._buckets.get(self._idx(v_ms), 0) + 1

    def quantile(self, q: float) -> float:
        if self._count == 0:
            return 0.0
        target = int(self._count * q)
        acc = 0
        for idx in sorted(self._buckets):
            acc += self._buckets[idx]
            if acc >= target:
                # обратная логарифмическая аппроксимация
                return (10 ** (idx / (10 ** self.precision))) - 1.0
        return self._max

    def summary(self) -> Dict[str, Any]:
        avg = self._sum_ms / self._count if self._count else 0.0
        return {
            "count": self._count,
            "min_ms": self._min if self._count else 0.0,
            "avg_ms": avg,
            "p50_ms": self.quantile(0.50),
            "p90_ms": self.quantile(0.90),
            "p99_ms": self.quantile(0.99),
            "max_ms": self._max,
        }

@dataclass
class Metrics:
    ok: int = 0
    err: int = 0
    codes: Dict[int, int] = field(default_factory=dict)
    latency: LatencyHistogram = field(default_factory=LatencyHistogram)
    start_t: float = field(default_factory=lambda: time.time())
    _last_report_t: float = field(default_factory=lambda: time.time())
    _last_ok: int = 0
    _last_err: int = 0

    def observe(self, ok: bool, code: int, latency_ms: float) -> None:
        if ok:
            self.ok += 1
        else:
            self.err += 1
        self.codes[code] = self.codes.get(code, 0) + 1
        self.latency.observe(latency_ms)

    def snapshot(self, tag: str) -> Dict[str, Any]:
        now = time.time()
        dt = now - self._last_report_t
        delta_ok = self.ok - self._last_ok
        delta_err = self.err - self._last_err
        self._last_report_t = now
        self._last_ok = self.ok
        self._last_err = self.err
        summ = self.latency.summary()
        return {
            "tag": tag,
            "uptime_sec": now - self.start_t,
            "ok": self.ok,
            "err": self.err,
            "rps": (delta_ok + delta_err) / dt if dt > 0 else 0.0,
            "codes": dict(sorted(self.codes.items())),
            "latency": summ,
        }

# =========================
# Планировщик нагрузки
# =========================

class LoadGenerator:
    def __init__(self, cfg: LoadGenConfig, scenario: BaseScenario, sink: BaseSink):
        self.cfg = cfg
        self.scenario = scenario
        self.sink = sink
        self.metrics = Metrics()
        self._stop = asyncio.Event()
        self._errors: List[str] = []
        self._semaphore = asyncio.Semaphore(self.cfg.max_concurrency)

    async def run(self) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)

        async def reporter():
            while not self._stop.is_set():
                await asyncio.sleep(max(0.5, self.cfg.report_interval_sec))
                snap = self.metrics.snapshot(self.cfg.tag)
                LOG.info("stats tag=%s rps=%.1f ok=%s err=%s p50=%.1f p90=%.1f p99=%.1f",
                         snap["tag"], snap["rps"], snap["ok"], snap["err"],
                         snap["latency"]["p50_ms"], snap["latency"]["p90_ms"], snap["latency"]["p99_ms"])

        rep_task = asyncio.create_task(reporter())

        start = time.time()
        end = start + self.cfg.duration_sec + self.cfg.warmup_sec + self.cfg.ramp_up_sec + self.cfg.ramp_down_sec

        producers: List[asyncio.Task] = []
        try:
            if self.cfg.model == "open":
                producers.append(asyncio.create_task(self._run_open(end)))
            else:
                producers.append(asyncio.create_task(self._run_closed(end)))

            await asyncio.wait_for(self._stop.wait(), timeout=end - time.time())
        except asyncio.TimeoutError:
            pass
        finally:
            self._stop.set()
            for t in producers:
                t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*producers, return_exceptions=True)
            rep_task.cancel()
            with contextlib.suppress(Exception):
                await rep_task
            with contextlib.suppress(Exception):
                await self.sink.close()

        result = {
            "config": dataclasses.asdict(self.cfg),
            "metrics": self.metrics.snapshot(self.cfg.tag),
            "errors": list(self._errors),
        }
        if self.cfg.export_json:
            Path(self.cfg.export_json).parent.mkdir(parents=True, exist_ok=True)
            Path(self.cfg.export_json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        if self._errors and not self.cfg.allow_errors:
            raise RuntimeError("Load test finished with errors")
        return result

    # Открытая модель нагрузки
    async def _run_open(self, end_ts: float) -> None:
        while not self._stop.is_set() and time.time() < end_ts:
            tgt = self._current_rps()
            dt = self._next_interval(tgt)
            await asyncio.sleep(dt)
            asyncio.create_task(self._issue_one())

    # Закрытая модель нагрузки
    async def _run_closed(self, end_ts: float) -> None:
        async def user_loop(uid: int):
            rnd = random.Random(uid * 7919)
            while not self._stop.is_set() and time.time() < end_ts:
                await self._issue_one()
                tt = rnd.uniform(self.cfg.think_time_ms[0], self.cfg.think_time_ms[1]) / 1000.0
                await asyncio.sleep(tt)
        tasks = [asyncio.create_task(user_loop(i)) for i in range(self.cfg.users)]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    def _current_rps(self) -> float:
        # RPS с учетом ramp
        t = time.time()
        start = self.metrics.start_t
        rel = t - start
        rps = self.cfg.target_rps
        if rel < self.cfg.warmup_sec:
            return max(1.0, rps * 0.1)
        rel -= self.cfg.warmup_sec
        if self.cfg.ramp_up_sec > 0 and rel < self.cfg.ramp_up_sec:
            return max(1.0, rps * (rel / self.cfg.ramp_up_sec))
        rel -= self.cfg.ramp_up_sec
        if self.cfg.ramp_down_sec > 0 and time.time() > (start + self.cfg.warmup_sec + self.cfg.ramp_up_sec + self.cfg.duration_sec):
            # линейный спад
            past = time.time() - (start + self.cfg.warmup_sec + self.cfg.ramp_up_sec + self.cfg.duration_sec)
            frac = max(0.0, 1.0 - min(1.0, past / self.cfg.ramp_down_sec))
            return max(1.0, rps * frac)
        return rps

    def _next_interval(self, rps: float) -> float:
        if rps <= 0:
            return 0.1
        if self.cfg.arrival == "poisson":
            # экспоненциальное распределение интервалов
            return random.expovariate(rps)
        # равномерный тактинг
        return 1.0 / rps

    async def _issue_one(self) -> None:
        async with self._semaphore:
            ev = await self.scenario.next_event()
            attempt = 0
            t0 = time.perf_counter()
            ok = False
            code = 0
            while True:
                attempt += 1
                try:
                    with profile_block("loadgen.send"):
                        done, code = await asyncio.wait_for(self.sink.send(ev, self.cfg.request_timeout_sec),
                                                           timeout=self.cfg.request_timeout_sec)
                    ok = done
                    break
                except Exception as e:
                    if attempt > max(1, self.cfg.retry_attempts + 1):
                        self._errors.append(str(e))
                        ok = False
                        break
                    # backoff
                    b = min(self.cfg.backoff_cap_ms, self.cfg.backoff_base_ms * (2 ** (attempt - 1)))
                    await asyncio.sleep(random.uniform(b * 0.5, b * 1.5) / 1000.0)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self.metrics.observe(ok, code, latency_ms)
            with contextlib.suppress(Exception):
                await self.scenario.on_result(ev, ok, code, latency_ms)

# =========================
# Фабрики
# =========================

def build_scenario(cfg: LoadGenConfig) -> BaseScenario:
    if cfg.scenario == "scripted":
        if not cfg.script:
            raise ValueError("script path required for scripted scenario")
        return ScriptedScenario(cfg.script)
    return RandomScenario(cfg)

def build_sink(cfg: LoadGenConfig) -> BaseSink:
    if cfg.sink == "memory":
        return InMemorySink()
    if cfg.sink == "http":
        if not cfg.sink_endpoint:
            raise ValueError("sink_endpoint required for http sink")
        return HttpSink(cfg.sink_endpoint, cfg.sink_headers)
    if cfg.sink == "ws":
        if not cfg.sink_endpoint:
            raise ValueError("sink_endpoint required for ws sink")
        return WsSink(cfg.sink_endpoint, cfg.sink_headers)
    raise ValueError("unknown sink")

# =========================
# CLI для прямого запуска
# =========================

def _parse_args(argv: Optional[List[str]] = None) -> Dict[str, Any]:
    import argparse
    p = argparse.ArgumentParser(prog="engine-loadgen", description="Engine event load generator")
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--warmup", type=float, default=None)
    p.add_argument("--rps", type=float, default=None)
    p.add_argument("--model", choices=["open","closed"], default=None)
    p.add_argument("--users", type=int, default=None)
    p.add_argument("--sink", choices=["memory","http","ws"], default=None)
    p.add_argument("--endpoint", default=None)
    p.add_argument("--scenario", choices=["random","scripted"], default=None)
    p.add_argument("--script", default=None)
    p.add_argument("--export", default=None)
    p.add_argument("--tag", default=None)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)
    cfg = LoadGenConfig.from_env()
    # override
    def ov(v, cur): return v if v is not None else cur
    cfg = dataclasses.replace(
        cfg,
        duration_sec=ov(args.duration, cfg.duration_sec),
        warmup_sec=ov(args.warmup, cfg.warmup_sec),
        target_rps=ov(args.rps, cfg.target_rps),
        model=ov(args.model, cfg.model),
        users=ov(args.users, cfg.users),
        sink=ov(args.sink, cfg.sink),
        sink_endpoint=ov(args.endpoint, cfg.sink_endpoint),
        scenario=ov(args.scenario, cfg.scenario),
        script=ov(args.script, cfg.script),
        export_json=ov(args.export, cfg.export_json),
        tag=ov(args.tag, cfg.tag),
    )
    if args.verbose:
        LOG.setLevel(logging.DEBUG)
    return dataclasses.asdict(cfg)

async def _amain(cfg_dict: Dict[str, Any]) -> int:
    cfg = LoadGenConfig(**cfg_dict)
    scenario = build_scenario(cfg)
    sink = build_sink(cfg)
    lg = LoadGenerator(cfg, scenario, sink)
    res = await lg.run()
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0

def main(argv: Optional[List[str]] = None) -> int:
    cfg = _parse_args(argv)
    return asyncio.run(_amain(cfg))

if __name__ == "__main__":
    sys.exit(main())
