# neuroforge-core/cli/tools/run_infer.py
# -*- coding: utf-8 -*-
"""
NeuroForge - Unified Inference CLI (industrial-grade)

Назначение:
  Единый инструмент запуска инференса для разных бэкендов (HF text-generation, ONNX Runtime).
  Архитектура плагинов позволяет добавлять новые раннеры без изменения ядра.

Зависимости (опциональные по раннерам):
  - structlog (рекомендуется) или стандартный logging
  - pydantic>=1
  - transformers, torch (для HFTextGenRunner)
  - onnxruntime (для OnnxRunner)
  - numpy

Вход (JSONL):
  HF text-generation:
    {"id":"1", "prompt":"Hello, world"}
  ONNX:
    вариант A: {"id":"1","input":[[1.0,2.0,...]]}
    вариант B: {"id":"2","inputs":{"input_ids":[...], "mask":[...]}}

Выход (JSONL):
  {"id":"1","result":<model_output>,"meta":{"latency_ms":...}}

Примеры:
  # HF LLM:
  python run_infer.py \
    --runner hf-text-generation --model-id meta-llama/Llama-3.1-8B-Instruct \
    --input data/prompts.jsonl --output out.jsonl \
    --batch-size 4 --max-new-tokens 64 --device cuda --dtype float16 --seed 42

  # ONNX:
  python run_infer.py \
    --runner onnx --onnx-model models/encoder.onnx \
    --input data/onnx_inputs.jsonl --output out.jsonl \
    --batch-size 16 --intra-op 1 --inter-op 1

Лицензия: Internal / Proprietary (адаптируйте при необходимости)
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

# ---------- Logging (structlog -> fallback) ----------
try:
    import structlog

    def _configure_logging() -> Any:
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
        return structlog.get_logger("neuroforge.run_infer")

    log = _configure_logging()
except Exception:
    import logging

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("neuroforge.run_infer")

# ---------- Utils ----------
def _now_ms() -> float:
    return time.perf_counter() * 1000.0

def _read_jsonl(path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def _write_jsonl(path: Optional[Union[str, Path]], item: Dict[str, Any]) -> None:
    s = json.dumps(item, ensure_ascii=False)
    if path is None or str(path) == "-":
        print(s, flush=True)
    else:
        with open(path, "a", encoding="utf-8") as f:
            f.write(s + "\n")

def _chunks(it: Iterable[Any], n: int) -> Iterator[List[Any]]:
    batch: List[Any] = []
    for x in it:
        batch.append(x)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch

def _set_seed(seed: Optional[int]) -> None:
    if seed is None:
        return
    try:
        import random, numpy as np
        random.seed(seed)
        np.random.seed(seed)
        try:
            import torch
            torch.manual_seed(seed)
            torch.cuda.manual_seed_all(seed)
            torch.use_deterministic_algorithms(False)
        except Exception:
            pass
    except Exception:
        pass

# ---------- Runner API ----------
class BaseRunner:
    name: str = "base"

    def load(self) -> None:
        raise NotImplementedError

    def warmup(self, batch_size: int) -> None:
        """Optional warmup to stabilize kernels/caches."""
        return

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Any]:
        """Takes a list of input dicts; returns a list of model outputs."""
        raise NotImplementedError

    def close(self) -> None:
        return

# ---------- HF Text Generation Runner ----------
class HFTextGenRunner(BaseRunner):
    """
    Requirements: transformers, torch
    Input rows must contain: "prompt": str
    """
    name = "hf-text-generation"

    def __init__(
        self,
        model_id: str,
        device: str = "cpu",
        dtype: str = "float32",
        max_new_tokens: int = 64,
        temperature: float = 0.7,
        top_p: float = 0.95,
        top_k: int = 0,
        do_sample: bool = True,
        trust_remote_code: bool = False,
        revision: Optional[str] = None,
        compile_model: bool = False,
    ) -> None:
        self.model_id = model_id
        self.device = device
        self.dtype = dtype
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.top_k = top_k
        self.do_sample = do_sample
        self.trust_remote_code = trust_remote_code
        self.revision = revision
        self.compile_model = compile_model

        self._tokenizer = None
        self._model = None
        self._torch = None

    def load(self) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as e:
            raise RuntimeError(
                "HFTextGenRunner requires 'transformers' and 'torch' to be installed"
            ) from e

        self._torch = torch
        dtype_map = {
            "float32": torch.float32,
            "float16": torch.float16,
            "bfloat16": torch.bfloat16,
        }
        if self.dtype not in dtype_map:
            raise ValueError(f"Unsupported dtype: {self.dtype}")

        log.info("hf_load_start", model_id=self.model_id, device=self.device, dtype=self.dtype)
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_id, trust_remote_code=self.trust_remote_code, revision=self.revision
        )
        self._model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=dtype_map[self.dtype],
            trust_remote_code=self.trust_remote_code,
            revision=self.revision,
        )
        if self.device == "cuda":
            if not torch.cuda.is_available():
                raise RuntimeError("CUDA is not available but device=cuda was requested")
            self._model = self._model.to("cuda")
        elif self.device == "cpu":
            pass
        else:
            # поддержка mps/other, если доступно
            self._model = self._model.to(self.device)

        if self.compile_model:
            try:
                self._model = torch.compile(self._model)  # type: ignore
                log.info("hf_compile_success")
            except Exception as ce:
                log.warning("hf_compile_failed", error=str(ce))

        self._model.eval()
        log.info("hf_load_done")

    def warmup(self, batch_size: int) -> None:
        if self._model is None or self._tokenizer is None:
            return
        prompts = ["warmup"] * batch_size
        toks = self._tokenizer(prompts, return_tensors="pt", padding=True, truncation=True)
        if self.device == "cuda":
            toks = {k: v.to("cuda") for k, v in toks.items()}
        with self._torch.inference_mode():
            _ = self._model.generate(
                **toks,
                max_new_tokens=1,
                do_sample=False,
                pad_token_id=self._tokenizer.eos_token_id,
            )

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Any]:
        if self._model is None or self._tokenizer is None or self._torch is None:
            raise RuntimeError("Runner is not loaded")

        prompts: List[str] = []
        ids: List[Any] = []
        for row in batch:
            if "prompt" not in row:
                raise ValueError("HFTextGenRunner expects key 'prompt' in each input row")
            prompts.append(str(row["prompt"]))
            ids.append(row.get("id"))

        toks = self._tokenizer(prompts, return_tensors="pt", padding=True, truncation=True)
        if self.device == "cuda":
            toks = {k: v.to("cuda") for k, v in toks.items()}

        gen_cfg = dict(
            max_new_tokens=self.max_new_tokens,
            do_sample=self.do_sample,
            temperature=self.temperature,
            top_p=self.top_p,
        )
        if self.top_k and self.top_k > 0:
            gen_cfg["top_k"] = self.top_k

        with self._torch.inference_mode():
            out = self._model.generate(
                **toks,
                **gen_cfg,
                pad_token_id=self._tokenizer.eos_token_id,
            )

        texts = self._tokenizer.batch_decode(out, skip_special_tokens=True)
        return texts

# ---------- ONNX Runner ----------
class OnnxRunner(BaseRunner):
    """
    Requirements: onnxruntime, numpy
    Inputs:
      - either {"input":[...]} OR {"inputs":{"name1":[...], "name2":[...]}}
    """
    name = "onnx"

    def __init__(
        self,
        model_path: str,
        intra_op: Optional[int] = None,
        inter_op: Optional[int] = None,
        providers: Optional[List[str]] = None,
        prefer_float32: bool = True,
    ) -> None:
        self.model_path = model_path
        self.intra_op = intra_op
        self.inter_op = inter_op
        self.providers = providers
        self.prefer_float32 = prefer_float32

        self._ort = None
        self._np = None
        self._sess = None
        self._input_names: Optional[List[str]] = None
        self._output_names: Optional[List[str]] = None

    def load(self) -> None:
        try:
            import onnxruntime as ort
            import numpy as np
        except Exception as e:
            raise RuntimeError("OnnxRunner requires 'onnxruntime' and 'numpy'") from e

        self._ort = ort
        self._np = np

        so = ort.SessionOptions()
        if self.intra_op is not None:
            so.intra_op_num_threads = int(self.intra_op)
        if self.inter_op is not None:
            so.inter_op_num_threads = int(self.inter_op)

        if self.providers:
            providers = self.providers
        else:
            # Автовыбор: CUDA EP если доступен, иначе CPU
            providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        try:
            self._sess = ort.InferenceSession(self.model_path, sess_options=so, providers=providers)
        except Exception as e:
            raise RuntimeError(f"Failed to create ORT session for {self.model_path}: {e}") from e

        self._input_names = [x.name for x in self._sess.get_inputs()]
        self._output_names = [x.name for x in self._sess.get_outputs()]
        log.info("onnx_load_done", inputs=self._input_names, outputs=self._output_names, providers=self._sess.get_providers())

    def warmup(self, batch_size: int) -> None:
        if self._sess is None or self._np is None:
            return
        feeds = {}
        for inp in self._sess.get_inputs():
            shape = [d if isinstance(d, int) and d > 0 else 1 for d in inp.shape]
            shape[0] = max(1, batch_size)
            dt = self._to_numpy_dtype(inp.type)
            feeds[inp.name] = self._np.zeros(shape, dtype=dt)
        _ = self._sess.run(self._output_names, feeds)

    def _to_numpy_dtype(self, onnx_type: str) -> Any:
        np = self._np
        mapping = {
            "tensor(float)": np.float32,
            "tensor(float16)": np.float16,
            "tensor(bfloat16)": np.float16 if self.prefer_float32 is False else np.float32,
            "tensor(int32)": np.int32,
            "tensor(int64)": np.int64,
        }
        return mapping.get(onnx_type, np.float32)

    def _prepare_feeds(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if self._sess is None or self._np is None:
            raise RuntimeError("Runner is not loaded")
        if "inputs" in row and isinstance(row["inputs"], dict):
            feeds = {}
            for k, v in row["inputs"].items():
                feeds[k] = self._np.asarray(v)
            return feeds
        elif "input" in row:
            # single-input models: map to first input name
            if not self._input_names:
                raise RuntimeError("Input names are unknown")
            data = self._np.asarray(row["input"])
            return {self._input_names[0]: data}
        else:
            raise ValueError("ONNX input must contain 'input' or 'inputs'")

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Any]:
        # Сконкатенировать по batch-ось: поддерживаем словари фидов
        if self._sess is None or self._np is None:
            raise RuntimeError("Runner is not loaded")
        # Собираем список фидов и конкатенируем по ключам
        feed_list = [self._prepare_feeds(row) for row in batch]
        merged: Dict[str, Any] = {}
        for k in self._input_names or []:
            arrays = [f[k] for f in feed_list if k in f]
            if not arrays:
                continue
            merged[k] = self._np.concatenate(arrays, axis=0) if arrays[0].ndim > 0 else self._np.array(arrays)
        outputs = self._sess.run(self._output_names, merged)
        # Разбить по batch-ось
        bsz = (next(iter(merged.values())).shape[0]) if merged else len(batch)
        result: List[Any] = []
        for i in range(bsz):
            item_out = {}
            for name, arr in zip(self._output_names or [], outputs):
                item_out[name] = arr[i].tolist() if hasattr(arr, "shape") else arr
            result.append(item_out)
        return result

# ---------- Runner Registry ----------
@dataclass
class RunnerSpec:
    name: str
    cls: Any

RUNNERS: Dict[str, RunnerSpec] = {
    HFTextGenRunner.name: RunnerSpec(HFTextGenRunner.name, HFTextGenRunner),
    OnnxRunner.name: RunnerSpec(OnnxRunner.name, OnnxRunner),
}

def get_runner(name: str) -> RunnerSpec:
    spec = RUNNERS.get(name)
    if not spec:
        raise KeyError(f"Unknown runner: {name}. Available: {list(RUNNERS.keys())}")
    return spec

# ---------- Core Infer Loop ----------
@dataclass
class Metrics:
    latencies_ms: List[float]
    total_rows: int
    total_time_ms: float

    def p50(self) -> float:
        return median(self.latencies_ms) if self.latencies_ms else 0.0

    def p95(self) -> float:
        if not self.latencies_ms:
            return 0.0
        arr = sorted(self.latencies_ms)
        idx = min(len(arr) - 1, math.ceil(0.95 * len(arr)) - 1)
        return float(arr[idx])

    def throughput_rps(self) -> float:
        if self.total_time_ms <= 0:
            return 0.0
        return 1000.0 * self.total_rows / self.total_time_ms

def run_infer(
    runner: BaseRunner,
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]],
    batch_size: int,
    warmup_batches: int,
    max_batches: Optional[int],
) -> Metrics:
    latencies: List[float] = []
    total_rows = 0
    t0 = _now_ms()

    # Warmup
    if warmup_batches > 0:
        try:
            runner.warmup(batch_size)
            log.info("warmup_done", batches=warmup_batches, batch_size=batch_size)
        except Exception as e:
            log.warning("warmup_failed", error=str(e))

    processed_batches = 0
    for batch in _chunks(_read_jsonl(input_path), batch_size):
        if max_batches is not None and processed_batches >= max_batches:
            break
        processed_batches += 1

        start = _now_ms()
        try:
            outputs = runner.infer_batch(batch)
        except Exception as e:
            # Логируем и продолжаем; каждый элемент помечаем ошибкой
            log.error("infer_batch_failed", error=str(e), tb=traceback.format_exc())
            outputs = [{"error": str(e)} for _ in batch]
        end = _now_ms()
        lat = end - start
        latencies.append(lat)

        # выводим результаты построчно, сохраняя id если был
        for row, out in zip(batch, outputs):
            rec_id = row.get("id")
            meta = {"latency_ms": lat}
            _write_jsonl(output_path, {"id": rec_id, "result": out, "meta": meta})

        total_rows += len(batch)

    total_time_ms = _now_ms() - t0
    return Metrics(latencies, total_rows, total_time_ms)

# ---------- CLI ----------
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NeuroForge Unified Inference CLI")
    p.add_argument("--runner", required=True, choices=list(RUNNERS.keys()), help="Which runner to use")
    p.add_argument("--input", required=True, help="Path to JSONL input")
    p.add_argument("--output", default="-", help="Path to JSONL output or '-' for stdout")
    p.add_argument("--batch-size", type=int, default=int(os.getenv("NEUROFORGE_BATCH_SIZE", "4")))
    p.add_argument("--warmup-batches", type=int, default=int(os.getenv("NEUROFORGE_WARMUP", "1")))
    p.add_argument("--max-batches", type=int, default=None)
    p.add_argument("--seed", type=int, default=None)

    # HF runner options
    p.add_argument("--model-id", default=os.getenv("NEUROFORGE_MODEL_ID", None))
    p.add_argument("--device", default=os.getenv("NEUROFORGE_DEVICE", "cpu"), help="cpu|cuda|mps|... for HF")
    p.add_argument("--dtype", default=os.getenv("NEUROFORGE_DTYPE", "float32"), help="float32|float16|bfloat16 for HF")
    p.add_argument("--max-new-tokens", type=int, default=int(os.getenv("NEUROFORGE_MAX_NEW_TOKENS", "64")))
    p.add_argument("--temperature", type=float, default=float(os.getenv("NEUROFORGE_TEMPERATURE", "0.7")))
    p.add_argument("--top-p", type=float, default=float(os.getenv("NEUROFORGE_TOP_P", "0.95")))
    p.add_argument("--top-k", type=int, default=int(os.getenv("NEUROFORGE_TOP_K", "0")))
    p.add_argument("--no-sample", action="store_true", help="Disable sampling for HF (greedy)")
    p.add_argument("--trust-remote-code", action="store_true")
    p.add_argument("--revision", default=None)
    p.add_argument("--compile", action="store_true", help="torch.compile for HF")

    # ONNX options
    p.add_argument("--onnx-model", default=os.getenv("NEUROFORGE_ONNX_MODEL", None))
    p.add_argument("--intra-op", type=int, default=None)
    p.add_argument("--inter-op", type=int, default=None)
    p.add_argument("--providers", default=None, help="Comma-separated ORT providers, e.g. CUDAExecutionProvider,CPUExecutionProvider")
    p.add_argument("--prefer-float32", action="store_true", help="Map bfloat16->float32 for safety")

    return p

def main() -> None:
    args = build_argparser().parse_args()
    _set_seed(args.seed)

    # Prepare runner
    if args.runner == HFTextGenRunner.name:
        if not args.model_id:
            log.error("missing_model_id", hint="--model-id must be provided for hf-text-generation")
            sys.exit(2)
        runner: BaseRunner = HFTextGenRunner(
            model_id=args.model_id,
            device=args.device,
            dtype=args.dtype,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
            top_k=args.top_k,
            do_sample=not args.no_sample,
            trust_remote_code=args.trust_remote_code,
            revision=args.revision,
            compile_model=args.compile,
        )
    elif args.runner == OnnxRunner.name:
        if not args.onnx_model:
            log.error("missing_onnx_model", hint="--onnx-model must be provided for onnx runner")
            sys.exit(2)
        providers = None
        if args.providers:
            providers = [x.strip() for x in args.providers.split(",") if x.strip()]
        runner = OnnxRunner(
            model_path=args.onnx_model,
            intra_op=args.intra_op,
            inter_op=args.inter_op,
            providers=providers,
            prefer_float32=args.prefer_float32,
        )
    else:
        log.error("unknown_runner", name=args.runner)
        sys.exit(2)

    # Load runner
    try:
        runner.load()
    except Exception as e:
        log.error("runner_load_failed", error=str(e))
        sys.exit(3)

    # Ensure output path is empty or stdout
    out_path: Optional[str] = args.output
    if out_path not in (None, "-", ""):
        # создаём директорию и очищаем файл
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text("", encoding="utf-8")

    try:
        metrics = run_infer(
            runner=runner,
            input_path=args.input,
            output_path=None if args.output == "-" else args.output,
            batch_size=max(1, int(args.batch_size)),
            warmup_batches=max(0, int(args.warmup_batches)),
            max_batches=args.max_batches,
        )
    except KeyboardInterrupt:
        log.warning("interrupted_by_user")
        sys.exit(130)
    except Exception as e:
        log.error("infer_failed", error=str(e), tb=traceback.format_exc())
        sys.exit(4)
    finally:
        try:
            runner.close()
        except Exception as e:
            log.warning("runner_close_failed", error=str(e))

    # Final report
    report = {
        "rows": metrics.total_rows,
        "time_ms": round(metrics.total_time_ms, 3),
        "p50_ms": round(metrics.p50(), 3),
        "p95_ms": round(metrics.p95(), 3),
        "throughput_rps": round(metrics.throughput_rps(), 3),
    }
    log.info("infer_done", **report)

if __name__ == "__main__":
    main()
