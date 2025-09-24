# SPDX-License-Identifier: Apache-2.0
"""
Omnimind Core — Bench: Tool Invoker

Назначение:
  Универсальный бенч-харнесс для измерения производительности слоя вызова инструментов.
  Поддерживает три типа инвокеров:
    1) python:<module>:<callable>        — прямой вызов Python-функции (sync/async)
    2) http:<POST URL>                   — HTTP POST с JSON-пейлоадом
    3) proc:<shell command>              — подпроцесс, JSON -> stdin, JSON <- stdout

Сценарии:
  - Задаются через JSON/YAML файл или генерируются по умолчанию.
  - Каждый сценарий — набор запросов (tool, input), вес, ожидания (expect).
  - Валидация: dotted-path в ответе должен удовлетворять оператору сравнения.

Нагрузочная модель:
  - Warmup (без учёта в метриках), затем основная фаза.
  - Конкурентность через Semaphore; Target RPS с планированием отправок по времени.
  - Таймауты, ретраи с экспоненциальным бэк-оффом (для HTTP/подпроцесса).
  - Статистика: count, rps, mean, median, p50/p90/p95/p99, max, stddev, error_rate.
  - Опциональный профилинг CPU/RSS (если установлен psutil).

Вывод:
  - Человекочитаемая сводка в stdout.
  - JSON-отчёт + CSV трейс в ./_bench_out/tool_invoker_<ts>/.

Зависимости:
  - Стандартная библиотека.
  - Опционально: pyyaml (для YAML), httpx (для HTTP), psutil (для системных метрик).
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import dataclasses
import importlib
import io
import json
import math
import os
import random
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# --------- Опциональные зависимости (подключаются лениво) --------- #
def _maybe_import_httpx():
    try:
        import httpx  # type: ignore
        return httpx
    except Exception:
        return None

def _maybe_import_yaml():
    try:
        import yaml  # type: ignore
        return yaml
    except Exception:
        return None

def _maybe_import_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except Exception:
        return None


# --------------------------- Модель данных --------------------------- #

@dataclass
class BenchConfig:
    mode: str                              # 'python', 'http', 'proc'
    target: str                            # module:function | URL | command
    duration_s: int = 30
    warmup_s: int = 5
    ramp_s: int = 0
    concurrency: int = 8
    rps: float = 100.0                     # целевой RPS
    timeout_s: float = 10.0
    retries: int = 1
    retry_backoff_base: float = 0.2
    retry_backoff_max: float = 2.0
    random_seed: int = 42
    out_dir: Path = Path("./_bench_out")
    scenario_file: Optional[Path] = None
    headers: Dict[str, str] = field(default_factory=dict)  # для HTTP
    extra_env: Dict[str, str] = field(default_factory=dict)
    psutil: bool = False                   # включить профилинг psutil
    name: str = "tool-invoker"

@dataclass
class RequestItem:
    tool: str
    input: Dict[str, Any]
    weight: float = 1.0
    expect: Optional[Dict[str, Any]] = None  # {"path":"result.status","op":"eq","value":"ok"}

@dataclass
class Scenario:
    name: str = "default"
    requests: List[RequestItem] = field(default_factory=list)

@dataclass
class Sample:
    ok: bool
    ts_start: float
    ts_end: float
    latency_ms: float
    ttfb_ms: Optional[float] = None
    code: Optional[int] = None
    error: Optional[str] = None
    tool: Optional[str] = None

@dataclass
class Summary:
    count: int
    errors: int
    rps: float
    mean_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    std_ms: float
    error_rate: float
    duration_s: float


# --------------------------- Утилиты сценариев --------------------------- #

def load_scenario(path: Optional[Path]) -> Scenario:
    if not path:
        # дефолтный сценарий
        return Scenario(
            name="default",
            requests=[
                RequestItem(tool="echo", input={"text": "hello"}, weight=1.0,
                            expect={"path": "status", "op": "in", "value": ["ok", 200]}),
            ],
        )
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        y = _maybe_import_yaml()
        if not y:
            raise RuntimeError("Для YAML сценариев требуется пакет pyyaml")
        data = y.safe_load(text)
    else:
        data = json.loads(text)
    reqs: List[RequestItem] = []
    for r in (data.get("requests") or []):
        reqs.append(RequestItem(
            tool=r.get("tool", "echo"),
            input=r.get("input", {}),
            weight=float(r.get("weight", 1.0)),
            expect=r.get("expect"),
        ))
    return Scenario(name=data.get("name", "scenario"), requests=reqs)


def choose_request(scn: Scenario, rnd: random.Random) -> RequestItem:
    weights = [max(0.0, r.weight) for r in scn.requests]
    total = sum(weights) or 1.0
    acc = 0.0
    pick = rnd.random() * total
    for r, w in zip(scn.requests, weights):
        acc += w
        if pick <= acc:
            return r
    return scn.requests[-1]


# --------------------------- Валидация ответа --------------------------- #

def dotted_get(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        elif isinstance(cur, (list, tuple)):
            try:
                idx = int(part)
                cur = cur[idx]
            except Exception:
                return None
        else:
            return None
    return cur

def check_expect(resp: Any, expect: Optional[Dict[str, Any]]) -> bool:
    if not expect:
        return True
    path = expect.get("path")
    op = (expect.get("op") or "eq").lower()
    val = expect.get("value")
    got = dotted_get(resp, path) if path else resp
    try:
        if op == "eq":
            return got == val
        if op == "ne":
            return got != val
        if op == "in":
            return got in val  # type: ignore
        if op == "ge":
            return got >= val
        if op == "le":
            return got <= val
        if op == "gt":
            return got > val
        if op == "lt":
            return got < val
        return False
    except Exception:
        return False


# --------------------------- Инвокеры --------------------------- #

class BaseInvoker:
    async def invoke(self, tool: str, payload: Dict[str, Any], timeout_s: float) -> Tuple[bool, Any, Optional[int], Optional[float]]:
        """
        Возвращает (ok, response_obj, status_code, ttfb_ms)
        """
        raise NotImplementedError

class PythonInvoker(BaseInvoker):
    def __init__(self, target: str):
        # target = "package.module:function"
        if ":" not in target:
            raise ValueError("python target must be 'module:function'")
        mod, fn = target.split(":", 1)
        self._callable = getattr(importlib.import_module(mod), fn)

    async def invoke(self, tool: str, payload: Dict[str, Any], timeout_s: float) -> Tuple[bool, Any, Optional[int], Optional[float]]:
        async def _call():
            res = self._callable(tool=tool, payload=payload)
            if asyncio.iscoroutine(res):
                res = await res  # type: ignore
            return res
        try:
            res = await asyncio.wait_for(_call(), timeout=timeout_s)
            return True, res, 200, None
        except Exception as e:
            return False, {"error": str(e)}, 500, None

class HttpInvoker(BaseInvoker):
    def __init__(self, url: str, headers: Optional[Mapping[str, str]] = None):
        self.url = url
        self.headers = dict(headers or {})
        self.httpx = _maybe_import_httpx()
        if not self.httpx:
            raise RuntimeError("Для режима http требуется httpx")

    async def invoke(self, tool: str, payload: Dict[str, Any], timeout_s: float) -> Tuple[bool, Any, Optional[int], Optional[float]]:
        # Синхронный httpx.Client через to_thread, чтобы не тащить httpx.AsyncClient
        def _do():
            with self.httpx.Client(timeout=timeout_s) as client:  # type: ignore[attr-defined]
                t0 = time.perf_counter()
                resp = client.post(self.url, headers=self.headers, json={"tool": tool, "input": payload})
                ttfb_ms = (time.perf_counter() - t0) * 1000
                data = None
                try:
                    data = resp.json()
                except Exception:
                    data = {"text": resp.text}
                ok = 200 <= resp.status_code < 300
                return ok, data, int(resp.status_code), float(ttfb_ms)

        return await asyncio.to_thread(_do)

class ProcInvoker(BaseInvoker):
    def __init__(self, cmdline: str, extra_env: Optional[Mapping[str, str]] = None):
        self.cmdline = cmdline
        self.env = os.environ.copy()
        if extra_env:
            self.env.update({str(k): str(v) for k, v in extra_env.items()})

    async def invoke(self, tool: str, payload: Dict[str, Any], timeout_s: float) -> Tuple[bool, Any, Optional[int], Optional[float]]:
        # stdin -> JSON {"tool":..., "input":...}, stdout <- JSON
        data = json.dumps({"tool": tool, "input": payload}, ensure_ascii=False).encode("utf-8")
        proc = await asyncio.create_subprocess_shell(
            self.cmdline,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        try:
            t0 = time.perf_counter()
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=data), timeout=timeout_s)
            ttfb_ms = (time.perf_counter() - t0) * 1000.0
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return False, {"error": "timeout"}, 599, None
        txt = stdout.decode("utf-8", "ignore")
        try:
            val = json.loads(txt) if txt.strip() else {}
        except Exception:
            val = {"stdout": txt, "stderr": stderr.decode("utf-8", "ignore")}
        ok = proc.returncode == 0
        return ok, val, 0 if ok else proc.returncode, ttfb_ms


# --------------------------- Планировщик нагрузки --------------------------- #

def _sleep_until(target_ts: float):
    now = time.perf_counter()
    delay = target_ts - now
    if delay > 0:
        time.sleep(delay)

async def run_phase(name: str, cfg: BenchConfig, scn: Scenario, inv: BaseInvoker, duration_s: int, collect: bool, rnd: random.Random, sem: asyncio.Semaphore, results: List[Sample]):
    """
    Планирование по целевому RPS: равномерно распределяем старты запросов по времени.
    """
    start = time.perf_counter()
    end = start + duration_s
    next_ts = start
    interval = 1.0 / max(0.001, cfg.rps)
    idx = 0

    async def one_call(tool: str, payload: Dict[str, Any], expect: Optional[Dict[str, Any]]):
        ts0 = time.perf_counter()
        ttfb_ms = None
        code = None
        ok = False
        err = None
        try:
            async with sem:
                # ретраи только для http/proc (сетевые)
                attempts = cfg.retries + 1
                for attempt in range(attempts):
                    ok, resp, code, ttfb_ms = await inv.invoke(tool, payload, cfg.timeout_s)
                    passed = ok and check_expect(resp, expect)
                    if passed:
                        ok = True
                        break
                    # решаем, ретраить ли
                    if attempt < cfg.retries and (code in (408, 409, 429, 500, 502, 503, 504) or not ok):
                        backoff = min(cfg.retry_backoff_max, cfg.retry_backoff_base * (2 ** attempt)) * (0.7 + 0.6 * rnd.random())
                        await asyncio.sleep(backoff)
                        continue
                    else:
                        ok = False
                        err = f"bad_resp code={code} expect={expect} resp={str(resp)[:200]}"
                        break
        except Exception as e:
            ok = False
            err = str(e)
        finally:
            ts1 = time.perf_counter()
            if collect:
                results.append(Sample(
                    ok=ok,
                    ts_start=ts0,
                    ts_end=ts1,
                    latency_ms=(ts1 - ts0) * 1000.0,
                    ttfb_ms=ttfb_ms,
                    code=code,
                    error=err,
                    tool=tool,
                ))

    while True:
        now = time.perf_counter()
        if now >= end:
            break
        # планирование следующего старта
        target_ts = next_ts
        next_ts += interval
        idx += 1

        # выбираем запрос
        req = choose_request(scn, rnd)

        # учитываем ramp: линейно наращиваем rps
        if cfg.ramp_s > 0:
            elapsed = now - start
            ramp_factor = min(1.0, elapsed / cfg.ramp_s)
            if rnd.random() > ramp_factor:
                # пропускаем слот, имитируя меньший RPS
                await asyncio.sleep(min(interval, 0.01))
                continue

        # точная подача старта
        await asyncio.to_thread(_sleep_until, target_ts)
        asyncio.create_task(one_call(req.tool, dict(req.input), req.expect))

    # дождаться завершения всех задач в семафоре
    while sem._value != cfg.concurrency:  # грубая проверка, чтобы не оставлять подвисших
        await asyncio.sleep(0.01)


# --------------------------- Подсчет метрик и вывод --------------------------- #

def summarize(samples: List[Sample], window_s: float) -> Summary:
    if not samples:
        return Summary(0, 0, 0.0, 0, 0, 0, 0, 0, 0, 0.0, window_s)
    lat = [s.latency_ms for s in samples]
    lat_sorted = sorted(lat)
    count = len(lat_sorted)
    errors = sum(1 for s in samples if not s.ok)
    def q(p: float) -> float:
        if not lat_sorted:
            return 0.0
        k = (len(lat_sorted) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(lat_sorted[int(k)])
        d0, d1 = lat_sorted[f], lat_sorted[c]
        return float(d0 + (d1 - d0) * (k - f))
    return Summary(
        count=count,
        errors=errors,
        rps=count / window_s if window_s > 0 else 0.0,
        mean_ms=float(statistics.fmean(lat_sorted)),
        p50_ms=q(0.50),
        p90_ms=q(0.90),
        p95_ms=q(0.95),
        p99_ms=q(0.99),
        max_ms=float(max(lat_sorted)),
        std_ms=float(statistics.pstdev(lat_sorted) if len(lat_sorted) > 1 else 0.0),
        error_rate=errors / count if count else 0.0,
        duration_s=window_s,
    )


def print_summary(title: str, s: Summary):
    print(f"\n== {title} ==")
    print(f"count={s.count} errors={s.errors} error_rate={s.error_rate:.3f}")
    print(f"rps={s.rps:.2f} mean={s.mean_ms:.2f}ms p50={s.p50_ms:.2f}ms p90={s.p90_ms:.2f}ms p95={s.p95_ms:.2f}ms p99={s.p99_ms:.2f}ms max={s.max_ms:.2f}ms std={s.std_ms:.2f}ms")


def export_reports(out_dir: Path, cfg: BenchConfig, samples: List[Sample], warmup: List[Sample], warmup_s: int, duration_s: int):
    ts = int(time.time())
    run_dir = out_dir / f"tool_invoker_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "config": dataclasses.asdict(cfg),
        "timestamp": ts,
        "samples": len(samples),
        "warmup_samples": len(warmup),
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    # Сырые события
    with (run_dir / "trace.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ok", "ts_start", "ts_end", "latency_ms", "ttfb_ms", "code", "error", "tool"])
        for s in samples:
            w.writerow([int(s.ok), f"{s.ts_start:.6f}", f"{s.ts_end:.6f}", f"{s.latency_ms:.3f}", f"{(s.ttfb_ms or 0.0):.3f}", s.code if s.code is not None else "", s.error or "", s.tool or ""])
    # Summary JSON
    summ = summarize(samples, duration_s)
    (run_dir / "summary.json").write_text(json.dumps(dataclasses.asdict(summ), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nArtifacts: {run_dir}")


# --------------------------- psutil-профилинг (опц.) --------------------------- #

@contextlib.asynccontextmanager
async def maybe_psutil_profiler(enabled: bool):
    if not enabled:
        yield None
        return
    psutil = _maybe_import_psutil()
    if not psutil:
        print("WARN: psutil not installed; system profiling disabled")
        yield None
        return
    proc = psutil.Process(os.getpid())
    start_cpu = proc.cpu_times()
    start_mem = proc.memory_info()
    t0 = time.time()
    try:
        yield proc
    finally:
        t1 = time.time()
        end_cpu = proc.cpu_times()
        end_mem = proc.memory_info()
        cpu_user = end_cpu.user - start_cpu.user
        cpu_sys = end_cpu.system - start_cpu.system
        rss_mb = end_mem.rss / (1024 * 1024)
        print(f"\n[psutil] cpu_user={cpu_user:.3f}s cpu_sys={cpu_sys:.3f}s rss={rss_mb:.1f}MB wall={t1 - t0:.2f}s")


# --------------------------- Основной запуск --------------------------- #

async def main_async(cfg: BenchConfig):
    random.seed(cfg.random_seed)
    rnd = random.Random(cfg.random_seed)
    scn = load_scenario(cfg.scenario_file)
    # Выбор инвокера
    if cfg.mode == "python":
        inv: BaseInvoker = PythonInvoker(cfg.target)
    elif cfg.mode == "http":
        inv = HttpInvoker(cfg.target, headers=cfg.headers)
    elif cfg.mode == "proc":
        inv = ProcInvoker(cfg.target, extra_env=cfg.extra_env)
    else:
        raise SystemExit(f"unknown mode: {cfg.mode}")

    sem = asyncio.Semaphore(cfg.concurrency)
    warmup_samples: List[Sample] = []
    run_samples: List[Sample] = []

    print(f"Scenario: {scn.name} ({len(scn.requests)} requests)")
    print(f"Mode={cfg.mode} target={cfg.target} duration={cfg.duration_s}s warmup={cfg.warmup_s}s ramp={cfg.ramp_s}s rps={cfg.rps} conc={cfg.concurrency}")

    # Warmup
    if cfg.warmup_s > 0:
        async with maybe_psutil_profiler(False):
            await run_phase("warmup", cfg, scn, inv, cfg.warmup_s, collect=True, rnd=rnd, sem=sem, results=warmup_samples)
        print_summary("WARMUP", summarize(warmup_samples, cfg.warmup_s))

    # Основная фаза
    async with maybe_psutil_profiler(cfg.psutil):
        t0 = time.perf_counter()
        await run_phase("run", cfg, scn, inv, cfg.duration_s, collect=True, rnd=rnd, sem=sem, results=run_samples)
        t1 = time.perf_counter()
    summary = summarize(run_samples, t1 - t0)
    print_summary("RUN", summary)

    # Экспорт
    export_reports(cfg.out_dir, cfg, run_samples, warmup_samples, cfg.warmup_s, cfg.duration_s)

def parse_args(argv: List[str]) -> BenchConfig:
    import argparse

    p = argparse.ArgumentParser(description="Omnimind Tool Invoker Benchmark")
    p.add_argument("--mode", choices=["python", "http", "proc"], required=True)
    p.add_argument("--target", required=True, help="python: module:function | http: URL | proc: shell command")
    p.add_argument("--duration", type=int, default=int(os.getenv("OMNI_BENCH_DURATION", "30")))
    p.add_argument("--warmup", type=int, default=int(os.getenv("OMNI_BENCH_WARMUP", "5")))
    p.add_argument("--ramp", type=int, default=int(os.getenv("OMNI_BENCH_RAMP", "0")))
    p.add_argument("--concurrency", type=int, default=int(os.getenv("OMNI_BENCH_CONC", "8")))
    p.add_argument("--rps", type=float, default=float(os.getenv("OMNI_BENCH_RPS", "100")))
    p.add_argument("--timeout", type=float, default=float(os.getenv("OMNI_BENCH_TIMEOUT", "10.0")))
    p.add_argument("--retries", type=int, default=int(os.getenv("OMNI_BENCH_RETRIES", "1")))
    p.add_argument("--seed", type=int, default=int(os.getenv("OMNI_BENCH_SEED", "42")))
    p.add_argument("--scenario", type=Path, help="JSON/YAML сценарий")
    p.add_argument("--out", type=Path, default=Path(os.getenv("OMNI_BENCH_OUT", "./_bench_out")))
    p.add_argument("--header", action="append", default=[], help="HTTP header k=v (multi)")
    p.add_argument("--env", dest="env_kv", action="append", default=[], help="Extra env for proc k=v (multi)")
    p.add_argument("--psutil", action="store_true", help="Включить системный профилинг (если установлен)")
    p.add_argument("--name", default=os.getenv("OMNI_BENCH_NAME", "tool-invoker"))

    args = p.parse_args(argv)

    headers = {}
    for h in args.header:
        if "=" not in h:
            continue
        k, v = h.split("=", 1)
        headers[k.strip()] = v.strip()
    extra_env = {}
    for e in args.env_kv:
        if "=" not in e:
            continue
        k, v = e.split("=", 1)
        extra_env[k.strip()] = v.strip()

    return BenchConfig(
        mode=args.mode,
        target=args.target,
        duration_s=args.duration,
        warmup_s=args.warmup,
        ramp_s=args.ramp,
        concurrency=args.concurrency,
        rps=args.rps,
        timeout_s=args.timeout,
        retries=args.retries,
        random_seed=args.seed,
        out_dir=args.out,
        scenario_file=args.scenario,
        headers=headers,
        extra_env=extra_env,
        psutil=args.psutil,
        name=args.name,
    )

def main():
    cfg = parse_args(sys.argv[1:])
    # Обработка SIGINT/SIGTERM для корректного выхода
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = asyncio.Event()

    def _stop(*_):
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            loop.add_signal_handler(sig, _stop)

    try:
        loop.run_until_complete(main_async(cfg))
    finally:
        loop.close()

if __name__ == "__main__":
    main()
