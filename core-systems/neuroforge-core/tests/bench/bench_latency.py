# neuroforge-core/tests/bench/bench_latency.py
# -*- coding: utf-8 -*-
"""
NeuroForge Bench - Latency/Throughput Benchmark (industrial-grade)

Назначение:
  Бенчмарк инференса для раннеров NeuroForge (HF text-generation, ONNX).
  Параллелизм достигается независимыми репликами раннера (по числу воркеров).

Возможности:
  - Источники: JSONL или синтетика
  - Warmup и стабилизация
  - Реплики раннеров для безопасного параллелизма
  - p50/p90/p95/p99, throughput, детализация по батчу и элементу
  - Экспорт отчёта в JSON и сырых измерений в CSV
  - Опциональные системные метрики (CPU/RAM/GPU) — «мягкие» зависимости

Примеры:
  # HF LLM с JSONL
  python bench_latency.py \
    --runner hf-text-generation --model-id meta-llama/Llama-3.1-8B-Instruct \
    --input data/prompts.jsonl --warmup-batches 2 \
    --batch-size 4 --workers 1 --max-batches 50 --seed 42 \
    --report bench.json --raw-csv raw.csv

  # HF LLM с синтетическим вводом
  python bench_latency.py \
    --runner hf-text-generation --model-id meta-llama/Llama-3.1-8B-Instruct \
    --synthetic 1000 --prompt-len 32 --batch-size 8 --workers 1

  # ONNX с синтетикой по форме входа модели
  python bench_latency.py \
    --runner onnx --onnx-model models/encoder.onnx \
    --synthetic 2000 --batch-size 16 --workers 2 --warmup-batches 3 \
    --report onnx_bench.json

Зависимости:
  - стандартные библиотеки
  - ваши раннеры: cli.tools.run_infer (HFTextGenRunner, OnnxRunner)
  - опционально: psutil, pynvml (если установлены — добавляются системные метрики)
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import queue
import random
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

# Логи: structlog -> fallback
try:
    import structlog

    def _configure_logging():
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer() if os.getenv("DEV_LOG", "0") == "1"
                else structlog.processors.JSONRenderer(),
            ]
        )
        return structlog.get_logger("neuroforge.bench")

    log = _configure_logging()
except Exception:
    import logging

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("neuroforge.bench")

# Импортируем раннеры проекта
# Структура: neuroforge-core/cli/tools/run_infer.py
import sys
ROOT = Path(__file__).resolve().parents[2]  # .../neuroforge-core
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import cli.tools.run_infer as ri  # noqa: E402

# Опциональные метрики системы
try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # type: ignore

try:
    import pynvml  # type: ignore
    pynvml_available = True
except Exception:
    pynvml_available = False


# ---------------------- Утилиты ----------------------
def _now_ms() -> float:
    return time.perf_counter() * 1000.0

def _percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    arr = sorted(values)
    k = (len(arr) - 1) * (q / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(arr[int(k)])
    d0 = arr[f] * (c - k)
    d1 = arr[c] * (k - f)
    return float(d0 + d1)

def _set_seed(seed: Optional[int]):
    if seed is None:
        return
    try:
        import numpy as np  # noqa: F401
    except Exception:
        pass
    ri._set_seed(seed)
    random.seed(seed)


# ---------------------- Источники данных ----------------------
def _read_jsonl(path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def _synthetic_hf(total: int, prompt_len: int) -> Iterator[Dict[str, Any]]:
    for i in range(total):
        prompt = "x" * prompt_len
        yield {"id": str(i), "prompt": prompt}

def _synthetic_onnx_from_session(sess, total: int) -> Iterator[Dict[str, Any]]:
    # По входам модели строим нули/случайный тензор формы [1, ...]
    import numpy as np
    inputs = sess.get_inputs()
    first_name = inputs[0].name if inputs else "input"
    # Фиксируем разумную форму по плейсхолдерам None/символам
    shape = [1]
    if inputs and hasattr(inputs[0], "shape"):
        for d in inputs[0].shape[1:]:
            shape.append(int(d) if isinstance(d, int) and d > 0 else 16)
    else:
        shape = [1, 16]
    for i in range(total):
        arr = np.random.rand(*shape).astype(np.float32)
        yield {"id": str(i), "input": arr}


# ---------------------- Метрики ----------------------
@dataclass
class Sample:
    batch_ms: float
    per_item_ms: float
    size: int

@dataclass
class SysSample:
    cpu_percent: Optional[float] = None
    mem_percent: Optional[float] = None
    gpu_util: Optional[float] = None
    gpu_mem: Optional[float] = None

@dataclass
class Report:
    runner: str
    model: Optional[str]
    onnx_model: Optional[str]
    batch_size: int
    workers: int
    warmup_batches: int
    total_batches: int
    total_items: int
    total_time_ms: float
    batch_p50_ms: float
    batch_p90_ms: float
    batch_p95_ms: float
    batch_p99_ms: float
    item_p50_ms: float
    item_p90_ms: float
    item_p95_ms: float
    item_p99_ms: float
    throughput_rps: float
    system: Optional[SysSample] = None


# ---------------------- Воркеры ----------------------
class RunnerWorker(threading.Thread):
    def __init__(self, runner: ri.BaseRunner, q: "queue.Queue[List[Dict[str, Any]]]", results: List[Sample], lock: threading.Lock):
        super().__init__(daemon=True)
        self.runner = runner
        self.q = q
        self.results = results
        self.lock = lock
        self._stopped = threading.Event()

    def run(self):
        while not self._stopped.is_set():
            try:
                batch = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                t0 = _now_ms()
                out = self.runner.infer_batch(batch)
                t1 = _now_ms()
                dt = t1 - t0
                size = len(batch)
                per_item = dt / max(1, size)
                with self.lock:
                    self.results.append(Sample(batch_ms=dt, per_item_ms=per_item, size=size))
            except Exception as e:
                log.error("worker_infer_error", error=str(e))
            finally:
                self.q.task_done()

    def stop(self):
        self._stopped.set()


# ---------------------- Системные метрики ----------------------
def _collect_system_metrics() -> SysSample:
    cpu = mem = gpu_util = gpu_mem = None
    if psutil:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
        except Exception:
            pass
    if pynvml_available:
        try:
            pynvml.nvmlInit()
            h = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(h)
            meminfo = pynvml.nvmlDeviceGetMemoryInfo(h)
            gpu_util = float(util.gpu)
            gpu_mem = float(meminfo.used) / (1024 * 1024)
            pynvml.nvmlShutdown()
        except Exception:
            pass
    return SysSample(cpu_percent=cpu, mem_percent=mem, gpu_util=gpu_util, gpu_mem=gpu_mem)


# ---------------------- Основной бенч ----------------------
def bench(
    runner_name: str,
    model_id: Optional[str],
    onnx_path: Optional[str],
    batch_size: int,
    workers: int,
    warmup_batches: int,
    max_batches: Optional[int],
    input_path: Optional[str],
    synthetic_total: Optional[int],
    prompt_len: int,
    seed: Optional[int],
) -> Tuple[Report, List[Sample]]:
    _set_seed(seed)

    # Создаём реплики раннеров (по числу воркеров)
    replicas: List[ri.BaseRunner] = []
    for i in range(workers):
        if runner_name == ri.HFTextGenRunner.name:
            if not model_id:
                raise SystemExit("--model-id обязателен для hf-text-generation")
            r = ri.HFTextGenRunner(
                model_id=model_id,
                device=os.getenv("NEUROFORGE_DEVICE", "cpu"),
                dtype=os.getenv("NEUROFORGE_DTYPE", "float32"),
                max_new_tokens=int(os.getenv("NEUROFORGE_MAX_NEW_TOKENS", "64")),
                temperature=float(os.getenv("NEUROFORGE_TEMPERATURE", "0.7")),
                top_p=float(os.getenv("NEUROFORGE_TOP_P", "0.95")),
                top_k=int(os.getenv("NEUROFORGE_TOP_K", "0")),
                do_sample=not bool(int(os.getenv("NEUROFORGE_GREEDY", "0"))),
                trust_remote_code=bool(int(os.getenv("NEUROFORGE_TRUST_RC", "0"))),
            )
        elif runner_name == ri.OnnxRunner.name:
            if not onnx_path:
                raise SystemExit("--onnx-model обязателен для onnx")
            providers = os.getenv("NEUROFORGE_ORT_PROVIDERS")
            providers = [x.strip() for x in providers.split(",")] if providers else None
            r = ri.OnnxRunner(
                model_path=onnx_path,
                intra_op=int(os.getenv("NEUROFORGE_ORT_INTRA", "0")) or None,
                inter_op=int(os.getenv("NEUROFORGE_ORT_INTER", "0")) or None,
                providers=providers,
                prefer_float32=bool(int(os.getenv("NEUROFORGE_PREFER_F32", "1"))),
            )
        else:
            raise SystemExit(f"Неизвестный раннер: {runner_name}")
        r.load()
        replicas.append(r)

    # Warmup
    for r in replicas:
        try:
            r.warmup(batch_size=batch_size)
        except Exception as e:
            log.warning("warmup_failed", error=str(e))
    log.info("warmup_done", batches=warmup_batches, batch_size=batch_size, workers=workers)

    # Источник данных
    if input_path:
        iterator = _read_jsonl(input_path)
    else:
        if runner_name == ri.HFTextGenRunner.name:
            total = synthetic_total or 1000
            iterator = _synthetic_hf(total=total, prompt_len=prompt_len)
        else:
            # для ONNX: используем сессию первой реплики
            total = synthetic_total or 1000
            sess = replicas[0]._sess if hasattr(replicas[0], "_sess") else None
            if sess is None:
                # Если сессия скрыта/недоступна — создадим простую форму
                def _fallback(total_):
                    import numpy as np
                    for i in range(total_):
                        yield {"id": str(i), "input": np.random.rand(1, 16).astype(np.float32)}
                iterator = _fallback(total)
            else:
                iterator = _synthetic_onnx_from_session(sess, total=total)

    # Очередь батчей и воркеры
    q_batches: "queue.Queue[List[Dict[str, Any]]]" = queue.Queue(maxsize=workers * 2)
    results: List[Sample] = []
    lock = threading.Lock()
    workers_thr: List[RunnerWorker] = [RunnerWorker(replicas[i], q_batches, results, lock) for i in range(workers)]
    for w in workers_thr:
        w.start()

    # Генерация батчей и выдача в очередь
    total_batches = 0
    total_items = 0
    t_start = _now_ms()

    def _emit_batches():
        nonlocal total_batches, total_items
        batch: List[Dict[str, Any]] = []
        for row in iterator:
            batch.append(row)
            if len(batch) >= batch_size:
                q_batches.put(batch)
                total_batches += 1
                total_items += len(batch)
                batch = []
                if max_batches is not None and total_batches >= max_batches:
                    break
        if batch and (max_batches is None or total_batches < max_batches):
            q_batches.put(batch)
            total_batches += 1
            total_items += len(batch)

    _emit_batches()
    q_batches.join()
    for w in workers_thr:
        w.stop()
    for w in workers_thr:
        w.join()

    total_time_ms = _now_ms() - t_start

    batch_lat = [s.batch_ms for s in results]
    item_lat = [s.per_item_ms for s in results]

    report = Report(
        runner=runner_name,
        model=model_id,
        onnx_model=onnx_path,
        batch_size=batch_size,
        workers=workers,
        warmup_batches=warmup_batches,
        total_batches=total_batches,
        total_items=total_items,
        total_time_ms=round(total_time_ms, 3),
        batch_p50_ms=round(median(batch_lat) if batch_lat else 0.0, 3),
        batch_p90_ms=round(_percentile(batch_lat, 90.0), 3),
        batch_p95_ms=round(_percentile(batch_lat, 95.0), 3),
        batch_p99_ms=round(_percentile(batch_lat, 99.0), 3),
        item_p50_ms=round(median(item_lat) if item_lat else 0.0, 3),
        item_p90_ms=round(_percentile(item_lat, 90.0), 3),
        item_p95_ms=round(_percentile(item_lat, 95.0), 3),
        item_p99_ms=round(_percentile(item_lat, 99.0), 3),
        throughput_rps=round(1000.0 * (total_items or 1) / (total_time_ms or 1.0), 3),
        system=_collect_system_metrics(),
    )
    return report, results


# ---------------------- CLI ----------------------
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NeuroForge Inference Benchmark")
    p.add_argument("--runner", required=True, choices=[ri.HFTextGenRunner.name, ri.OnnxRunner.name])
    p.add_argument("--model-id", default=None, help="HF model id для hf-text-generation")
    p.add_argument("--onnx-model", default=None, help="Путь к .onnx модели для onnx")
    p.add_argument("--input", default=None, help="JSONL вход; если не задан, используется синтетика")
    p.add_argument("--synthetic", type=int, default=None, help="Количество синтетических элементов, если нет --input")
    p.add_argument("--prompt-len", type=int, default=32, help="Длина синтетического промпта для HF")
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--workers", type=int, default=1, help="Число реплик раннера и воркеров")
    p.add_argument("--warmup-batches", type=int, default=1)
    p.add_argument("--max-batches", type=int, default=None)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--report", default=None, help="Путь для JSON-отчёта")
    p.add_argument("--raw-csv", default=None, help="Путь для экспорта сырых измерений (CSV)")
    return p

def main():
    args = build_argparser().parse_args()

    if args.runner == ri.HFTextGenRunner.name and not (args.model_id or os.getenv("NEUROFORGE_MODEL_ID")) and not args.input and not args.synthetic:
        log.error("hf_requires_model_or_synthetic", hint="--model-id или --synthetic обязателен")
        raise SystemExit(2)

    model_id = args.model_id or os.getenv("NEUROFORGE_MODEL_ID")
    onnx_path = args.onnx_model or os.getenv("NEUROFORGE_ONNX_MODEL")

    report, samples = bench(
        runner_name=args.runner,
        model_id=model_id,
        onnx_path=onnx_path,
        batch_size=max(1, args.batch_size),
        workers=max(1, args.workers),
        warmup_batches=max(0, args.warmup_batches),
        max_batches=args.max_batches,
        input_path=args.input,
        synthetic_total=args.synthetic,
        prompt_len=max(1, args.prompt_len),
        seed=args.seed,
    )

    # Лог-итог
    log.info(
        "bench_done",
        runner=report.runner,
        model=report.model or report.onnx_model,
        items=report.total_items,
        batches=report.total_batches,
        time_ms=report.total_time_ms,
        p50_ms=report.item_p50_ms,
        p95_ms=report.item_p95_ms,
        rps=report.throughput_rps,
        cpu=getattr(report.system, "cpu_percent", None) if report.system else None,
        gpu=getattr(report.system, "gpu_util", None) if report.system else None,
    )

    # Экспорт отчёта
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, ensure_ascii=False, indent=2)

    # Экспорт raw
    if args.raw_csv:
        Path(args.raw_csv).parent.mkdir(parents=True, exist_ok=True)
        with open(args.raw_csv, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["batch_ms", "per_item_ms", "size"])
            for s in samples:
                w.writerow([round(s.batch_ms, 6), round(s.per_item_ms, 6), s.size])

if __name__ == "__main__":
    main()
