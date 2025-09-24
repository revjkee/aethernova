#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Neuroforge Quickstart Inference CLI (industrial-grade)

Features:
- Config loading: YAML/JSON/TOML (+ overrides via --set and ENV NEUROFORGE_*).
- Engines: PyTorch (TorchScript) and ONNX Runtime (optional deps, graceful errors).
- Device/precision/threads: cpu/cuda, fp32/fp16/bf16 (as applicable), intra/inter op threads.
- IO: JSONL input (stdin or file), JSONL atomic output, per-item error capture.
- Batching, warmup, max-requests limit, throughput benchmark with synthetic data.
- Signals: SIGINT/SIGTERM → graceful stop.
- Determinism: base random seed; thread control for torch where applicable.

Input format (JSON Lines):
  {"id": "opt-1", "tensor": [[...], [...], ...]}  # list/nd-array-like numeric payload

Output format (JSON Lines):
  {"id": "...", "output": [...], "engine": "torch|onnx", "latency_ms": 1.23}
  {"id": "...", "error": "message", "engine": "torch|onnx"}

Note:
- Torch engine expects TorchScript file (.pt/.ts) producing tensor output.
- ONNX engine expects standard ONNX model; first input is used by default.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import io
import json
import logging
import os
import queue
import random
import signal
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ---------- Optional deps (graceful if absent) ----------
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:
    import tomllib  # type: ignore[attr-defined]
except Exception:
    tomllib = None  # type: ignore

# Engines (optional)
try:
    import numpy as np  # type: ignore
except Exception:
    np = None  # type: ignore

try:
    import torch  # type: ignore
except Exception:
    torch = None  # type: ignore

try:
    import onnxruntime as ort  # type: ignore
except Exception:
    ort = None  # type: ignore


# ---------- Logging ----------
def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("neuroforge.infer")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S")
        h.setFormatter(fmt)
        logger.addHandler(h)
    return logger


# ---------- Config helpers ----------
def deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_update(dst[k], v)  # type: ignore[index]
        else:
            dst[k] = v
    return dst


def parse_literal(val: str) -> Any:
    low = val.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    # int/float
    try:
        if val.strip().isdigit() or (val.strip().startswith("-") and val.strip()[1:].isdigit()):
            return int(val.strip())
        if any(c in val for c in (".", "e", "E")):
            return float(val)
    except Exception:
        pass
    # JSON
    if (val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]")):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


def parse_set_overrides(items: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for it in items:
        if "=" not in it:
            raise ValueError(f"Invalid --set '{it}', expected key.path=value")
        key, raw = it.split("=", 1)
        cur = out
        parts = key.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = parse_literal(raw)
    return out


def env_overrides(prefix: str = "NEUROFORGE_") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in os.environ.items():
        if not k.startswith(prefix):
            continue
        key = k[len(prefix) :].lower().replace("__", ".")
        cur = out
        parts = key.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = parse_literal(v)
    return out


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    suf = path.suffix.lower()
    data = path.read_bytes()
    if suf in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML not installed for YAML config")
        return yaml.safe_load(data) or {}
    if suf == ".json":
        return json.loads(data.decode("utf-8"))
    if suf == ".toml":
        if tomllib is None:
            raise RuntimeError("tomllib (Py3.11+) not available for TOML config")
        return tomllib.loads(data.decode("utf-8"))
    raise RuntimeError(f"Unsupported config format: {suf}")


# ---------- IO: JSONL reader/writer (atomic) ----------
class JsonlWriter:
    """
    Atomic JSONL writer: writes to .tmp and renames on close().
    """
    def __init__(self, path: Optional[Path], ensure_ascii: bool = False):
        self.path = path
        self.ensure_ascii = ensure_ascii
        self._fh: Optional[io.TextIOBase] = None
        self._tmp_path: Optional[Path] = None
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
            os.close(tmp_fd)
            self._tmp_path = Path(tmp_name)
            self._fh = open(self._tmp_path, "w", encoding="utf-8", newline="\n")
        else:
            self._fh = sys.stdout  # not atomic for stdout

    def write_obj(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=self.ensure_ascii)
        assert self._fh is not None
        self._fh.write(line + "\n")

    def flush(self) -> None:
        if self._fh and self._fh is not sys.stdout:
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())  # type: ignore[attr-defined]
            except Exception:
                pass

    def close(self) -> None:
        if self._fh is None:
            return
        if self._fh is not sys.stdout:
            try:
                self._fh.flush()
                try:
                    os.fsync(self._fh.fileno())  # type: ignore[attr-defined]
                except Exception:
                    pass
            finally:
                self._fh.close()
            if self.path and self._tmp_path:
                os.replace(self._tmp_path, self.path)
        self._fh = None


def iter_jsonl(path: Optional[Path]) -> Iterator[Dict[str, Any]]:
    fh = sys.stdin if path is None else open(path, "r", encoding="utf-8")
    try:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                yield obj
            except Exception as e:
                yield {"error": f"invalid_json: {e}", "line": raw}
    finally:
        if fh is not sys.stdin:
            fh.close()


# ---------- Engines interface ----------
class BaseInferencer:
    """
    Interface for inference engines.
    """
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger

    def prepare(self) -> None:
        """Load model and allocate resources."""
        raise NotImplementedError

    def warmup(self, sample: Any) -> None:
        """Optional warmup with sample batch."""
        pass

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run inference for a batch of input objects. Returns list of outputs (JSON-serializable)."""
        raise NotImplementedError

    def close(self) -> None:
        """Free resources."""
        pass


class TorchInferencer(BaseInferencer):
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        super().__init__(cfg, logger)
        if torch is None:
            raise RuntimeError("PyTorch is not installed")
        self.model = None
        self.device = None
        self.precision = str(self.cfg.get("precision", "fp32")).lower()
        self._dtype = None

    def prepare(self) -> None:
        path = Path(self.cfg["model"]["path"])
        device = self.cfg.get("device", "cpu")
        threads = int(self.cfg.get("threads", 0) or 0)
        if threads > 0:
            torch.set_num_threads(threads)
        if device == "cuda" and torch.cuda.is_available():
            self.device = torch.device("cuda")
        else:
            self.device = torch.device("cpu")

        # dtype
        if self.precision == "fp16":
            self._dtype = torch.float16
        elif self.precision == "bf16":
            # bf16 mainly for recent GPUs/CPUs
            self._dtype = torch.bfloat16
        else:
            self._dtype = torch.float32

        # Load TorchScript
        self.model = torch.jit.load(str(path), map_location=self.device)
        self.model.eval()
        self.logger.info("Torch model loaded: %s on %s (%s)", path, self.device, self._dtype)

    def _to_tensor(self, arr: Any):
        t = torch.as_tensor(arr)
        if self._dtype is not None:
            t = t.to(self._dtype)
        return t.to(self.device)

    def warmup(self, sample: Any) -> None:
        if self.model is None:
            return
        with torch.no_grad():
            _ = self.model(self._to_tensor(sample))

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self.model is None:
            raise RuntimeError("Model not prepared")
        xs = []
        ids = []
        for obj in batch:
            ids.append(obj.get("id"))
            xs.append(obj.get("tensor"))
        x = self._to_tensor(xs)
        t0 = time.perf_counter()
        with torch.no_grad():
            y = self.model(x)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        # Support single tensor or tuple/list of tensors
        def to_py(o):
            if isinstance(o, torch.Tensor):
                return o.detach().to("cpu").float().tolist()
            if isinstance(o, (list, tuple)):
                return [to_py(i) for i in o]
            return o
        y_py = to_py(y)
        out = []
        for i, _id in enumerate(ids):
            yi = y_py[i] if isinstance(y_py, list) and len(y_py) == len(ids) else y_py
            out.append({"id": _id, "output": yi, "engine": "torch", "latency_ms": latency_ms})
        return out


class OnnxInferencer(BaseInferencer):
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        super().__init__(cfg, logger)
        if ort is None or np is None:
            raise RuntimeError("onnxruntime and numpy are required for ONNX engine")
        self.sess: Optional[Any] = None
        self.input_name: Optional[str] = None
        self.output_names: List[str] = []

    def prepare(self) -> None:
        model_path = Path(self.cfg["model"]["path"])
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        intra = int(self.cfg.get("threads", 0) or 0)
        inter = int(self.cfg.get("threads_inter", 0) or 0)
        if intra > 0:
            so.intra_op_num_threads = intra
        if inter > 0:
            so.inter_op_num_threads = inter
        providers = self.cfg.get("providers") or ["CUDAExecutionProvider", "CPUExecutionProvider"]
        # Filter by availability
        avail = ort.get_available_providers()
        use = [p for p in providers if p in avail]
        if not use:
            use = ["CPUExecutionProvider"]
        self.sess = ort.InferenceSession(str(model_path), sess_options=so, providers=use)
        self.input_name = self.sess.get_inputs()[0].name  # simple case
        self.output_names = [o.name for o in self.sess.get_outputs()]
        self.logger.info("ONNX model loaded: %s providers=%s", model_path, use)

    def warmup(self, sample: Any) -> None:
        if self.sess is None:
            return
        x = np.asarray(sample, dtype=np.float32)
        self.sess.run(self.output_names, {self.input_name: x})

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self.sess is None or self.input_name is None:
            raise RuntimeError("Session not prepared")
        xs = []
        ids = []
        for obj in batch:
            ids.append(obj.get("id"))
            xs.append(obj.get("tensor"))
        x = np.asarray(xs, dtype=np.float32)
        t0 = time.perf_counter()
        outs = self.sess.run(self.output_names, {self.input_name: x})
        latency_ms = (time.perf_counter() - t0) * 1000.0
        # If single output, unwrap
        if len(outs) == 1:
            outs = outs[0]
        result = []
        for i, _id in enumerate(ids):
            yi = outs[i].tolist() if hasattr(outs, "__getitem__") and len(outs) == len(ids) else (
                [o[i].tolist() for o in outs] if isinstance(outs, list) else outs
            )
            result.append({"id": _id, "output": yi, "engine": "onnx", "latency_ms": latency_ms})
        return result


# ---------- Engine factory ----------
def make_engine(cfg: Dict[str, Any], logger: logging.Logger) -> BaseInferencer:
    engine = str(cfg.get("engine", "torch")).lower()
    if engine == "torch":
        return TorchInferencer(cfg, logger)
    if engine == "onnx":
        return OnnxInferencer(cfg, logger)
    raise ValueError(f"Unknown engine: {engine}")


# ---------- Inference runner ----------
@dataclasses.dataclass
class RunState:
    stop: bool = False
    processed: int = 0


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    try:
        import numpy as _np  # type: ignore
        _np.random.seed(seed)
    except Exception:
        pass
    if torch is not None:
        try:
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
        except Exception:
            pass


def do_infer(cfg: Dict[str, Any], logger: logging.Logger) -> int:
    set_seed(int(cfg.get("seed", 42)))
    state = RunState()

    # Signals
    def on_signal(signum, frame):
        logger.warning("Signal %s received -> will stop after current batch", signum)
        state.stop = True

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, on_signal)
        except Exception:
            pass

    # Engine
    eng = make_engine(cfg, logger)
    eng.prepare()

    # Warmup
    warm = cfg.get("warmup", {})
    if warm and warm.get("enabled", True):
        sample_shape = warm.get("sample_shape") or cfg.get("input", {}).get("shape")
        if sample_shape and np is not None:
            sample = (np.random.rand(*sample_shape)).astype("float32").tolist()
            try:
                eng.warmup(sample)
                logger.info("Warmup completed (shape=%s)", sample_shape)
            except Exception as e:
                logger.warning("Warmup failed: %s", e)

    # IO
    inp_path = Path(cfg["input"]["path"]).expanduser() if cfg.get("input", {}).get("path") else None
    out_path = Path(cfg["output"]["path"]).expanduser() if cfg.get("output", {}).get("path") else None
    writer = JsonlWriter(out_path, ensure_ascii=False)

    batch_size = int(cfg.get("batch_size", 1))
    limit = cfg.get("limit")  # optional max items
    batch: List[Dict[str, Any]] = []
    t_start = time.perf_counter()

    try:
        for obj in iter_jsonl(inp_path):
            if state.stop:
                break
            # If parser error yielded {"error": ...,"line":...}
            if "error" in obj and "tensor" not in obj:
                writer.write_obj({"id": obj.get("id"), "error": obj["error"]})
                continue
            if "tensor" not in obj:
                writer.write_obj({"id": obj.get("id"), "error": "missing_tensor"})
                continue
            if "id" not in obj:
                obj["id"] = f"item-{state.processed + len(batch)}"

            batch.append(obj)
            if len(batch) >= batch_size:
                _run_batch(eng, batch, writer, logger)
                state.processed += len(batch)
                batch.clear()
                if limit and state.processed >= int(limit):
                    break

        # tail
        if not state.stop and batch:
            _run_batch(eng, batch, writer, logger)
            state.processed += len(batch)

        elapsed = time.perf_counter() - t_start
        if state.processed > 0:
            logger.info("Done: %d items, %.2fs, %.2f it/s",
                        state.processed, elapsed, state.processed / max(elapsed, 1e-9))
        return 0
    finally:
        try:
            eng.close()
        except Exception:
            pass
        writer.close()


def _run_batch(eng: BaseInferencer, batch: List[Dict[str, Any]], writer: JsonlWriter, logger: logging.Logger) -> None:
    try:
        results = eng.infer_batch(batch)
        for r in results:
            writer.write_obj(r)
    except Exception as e:
        # Per-item error reporting
        logger.exception("Batch failed: %s", e)
        for obj in batch:
            writer.write_obj({"id": obj.get("id"), "error": f"batch_failed: {e}"})


# ---------- Benchmark ----------
def run_benchmark(cfg: Dict[str, Any], logger: logging.Logger) -> int:
    if np is None:
        logger.error("numpy is required for benchmark")
        return 2
    # Prepare engine
    eng = make_engine(cfg, logger)
    eng.prepare()
    # Build synthetic batch
    shape = cfg.get("input", {}).get("shape")
    if not shape:
        logger.error("benchmark requires input.shape in config")
        return 2
    batch_size = int(cfg.get("batch_size", 1))
    steps = int(cfg.get("benchmark", {}).get("steps", 50))
    warmup_steps = int(cfg.get("benchmark", {}).get("warmup_steps", 5))
    sample = (np.random.rand(batch_size, *shape).astype("float32")).tolist()
    eng.warmup(sample)

    # Measure
    latencies = []
    for i in range(warmup_steps + steps):
        t0 = time.perf_counter()
        batch = [{"id": f"bench-{i}-{j}", "tensor": sample[j]} for j in range(batch_size)]
        try:
            eng.infer_batch(batch)
        except Exception as e:
            logger.error("Benchmark batch failed: %s", e)
            return 3
        if i >= warmup_steps:
            latencies.append((time.perf_counter() - t0) * 1000.0)

    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)
    ips = (batch_size * steps) / (sum(latencies) / 1000.0)
    report = {
        "engine": cfg.get("engine", "torch"),
        "batch_size": batch_size,
        "steps": steps,
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "items_per_sec": round(ips, 2),
        "time_utc": dt.datetime.utcnow().isoformat() + "Z",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    try:
        eng.close()
    except Exception:
        pass
    return 0


def _percentile(arr: List[float], pct: float) -> float:
    if not arr:
        return 0.0
    s = sorted(arr)
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


# ---------- CLI ----------
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="neuroforge-infer",
        description="Neuroforge Quickstart Inference CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              # From file to file (JSONL):
              neuroforge-infer run --config cfg.yaml --set output.path=out.jsonl

              # From STDIN to STDOUT:
              cat input.jsonl | neuroforge-infer run --config cfg.yaml

              # Minimal config inline:
              neuroforge-infer run --set engine=onnx --set model.path=model.onnx --set input.path=input.jsonl --set output.path=out.jsonl

              # Benchmark (requires input.shape):
              neuroforge-infer bench --set engine=onnx --set model.path=model.onnx --set input.shape='[64,128]' --set batch_size=8
            """
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(a: argparse.ArgumentParser) -> None:
        a.add_argument("--config", type=str, help="Path to config (.yaml/.yml/.json/.toml)")
        a.add_argument("--set", nargs="*", default=[], metavar="KEY=VAL", help="Override config values")
        a.add_argument("--env-prefix", type=str, default="NEUROFORGE_", help="ENV prefix for overrides")
        a.add_argument("--log-level", type=str, default="INFO", help="Logging level")

    prun = sub.add_parser("run", help="Run inference from JSONL")
    add_common(prun)

    pbench = sub.add_parser("bench", help="Benchmark inference")
    add_common(pbench)

    return p


def build_config(args: argparse.Namespace) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    base = load_config(Path(args.config)) if args.config else {}
    deep_update(cfg, base)
    deep_update(cfg, env_overrides(prefix=args.env_prefix))
    if args.set:
        deep_update(cfg, parse_set_overrides(args.set))

    # Sensible defaults
    cfg.setdefault("engine", "torch")
    cfg.setdefault("model", {}).setdefault("path", "model.pt")
    cfg.setdefault("input", {}).setdefault("path", None)   # None → stdin
    cfg.setdefault("output", {}).setdefault("path", None)  # None → stdout
    cfg.setdefault("batch_size", 1)
    cfg.setdefault("seed", 42)
    cfg.setdefault("warmup", {"enabled": True})
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_cli()
    args = parser.parse_args(argv)
    logger = setup_logging(level=args.log_level)
    try:
        cfg = build_config(args)
    except Exception as e:
        logger.error("Config error: %s", e)
        return 2

    if args.cmd == "bench":
        return run_benchmark(cfg, logger)
    if args.cmd == "run":
        return do_infer(cfg, logger)
    logger.error("Unknown command: %s", args.cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
