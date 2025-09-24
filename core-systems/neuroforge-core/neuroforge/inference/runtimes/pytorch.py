# File: neuroforge-core/neuroforge/inference/runtimes/pytorch.py
from __future__ import annotations

import contextlib
import functools
import importlib
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

try:
    import torch
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyTorch is required for neuroforge PyTorchRuntime") from e

# ----------------------------- Опциональные зависимости -----------------------------
try:
    from pydantic import BaseModel, Field, validator
    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *a, **k: None  # type: ignore
    _HAS_PYDANTIC = False

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False
    def Counter(*a, **k): return None  # type: ignore
    def Histogram(*a, **k): return None  # type: ignore
    def Gauge(*a, **k): return None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

log = logging.getLogger(__name__)

# ----------------------------- Исключения -----------------------------
class ModelLoadError(RuntimeError):
    pass

class InferenceError(RuntimeError):
    pass

class InferenceTimeoutError(TimeoutError):
    pass

# ----------------------------- Конфигурация -----------------------------
PrecisionT = Literal["fp32", "fp16", "bf16", "int8"]
DevicePrefT = Literal["auto", "cuda", "rocm", "mps", "cpu"]

if _HAS_PYDANTIC:
    class RuntimeConfig(BaseModel):
        model_path: str = Field(..., description="Путь к сохраненной модели, .pt/.pth/.pt2, Python модулю, либо torchscript")
        entrypoint: Optional[str] = Field(None, description="Имя фабрики/функции в модуле (если model_path это python-модуль)")
        device_preference: DevicePrefT = Field("auto")
        precision: PrecisionT = Field("fp32")
        allow_compile: bool = Field(True, description="torch.compile если доступно")
        compile_mode: Literal["default", "reduce-overhead", "max-autotune"] = Field("reduce-overhead")
        enable_autocast: bool = Field(True)
        deterministic: bool = Field(False)
        seed: Optional[int] = Field(1337)
        quantize_dynamic: bool = Field(False, description="Динамическая int8 квантизация nn.LSTM/nn.Linear")
        max_batch_size: int = Field(1, ge=1)
        max_concurrency: int = Field(8, ge=1)
        inference_timeout_s: float = Field(30.0, gt=0)
        warmup_runs: int = Field(1, ge=0)
        enable_metrics: bool = Field(True)
        enable_otel: bool = Field(True)
        gradient_disabled: bool = Field(True)
        cpu_fallback_on_oom: bool = Field(True)
        memory_fraction: Optional[float] = Field(None, ge=0.0, le=1.0, description="torch.cuda.set_per_process_memory_fraction")
        extra: Dict[str, Any] = Field(default_factory=dict)

        @validator("precision")
        def _check_precision(cls, v: PrecisionT) -> PrecisionT:
            return v
else:
    @dataclass
    class RuntimeConfig:  # type: ignore[no-redef]
        model_path: str = ""
        entrypoint: Optional[str] = None
        device_preference: DevicePrefT = "auto"
        precision: PrecisionT = "fp32"
        allow_compile: bool = True
        compile_mode: Literal["default", "reduce-overhead", "max-autotune"] = "reduce-overhead"
        enable_autocast: bool = True
        deterministic: bool = False
        seed: Optional[int] = 1337
        quantize_dynamic: bool = False
        max_batch_size: int = 1
        max_concurrency: int = 8
        inference_timeout_s: float = 30.0
        warmup_runs: int = 1
        enable_metrics: bool = True
        enable_otel: bool = True
        gradient_disabled: bool = True
        cpu_fallback_on_oom: bool = True
        memory_fraction: Optional[float] = None
        extra: Dict[str, Any] = field(default_factory=dict)

# ----------------------------- Метрики -----------------------------
_INF_COUNTER = Counter("nf_infer_total", "Total inference calls", ["status"]) if _HAS_PROM else None
_INF_LAT = Histogram("nf_infer_latency_seconds", "Inference end-to-end latency", buckets=(0.005,0.01,0.02,0.05,0.1,0.2,0.5,1,2,5)) if _HAS_PROM else None
_LOAD_LAT = Histogram("nf_model_load_seconds", "Model load time seconds") if _HAS_PROM else None
_ACTIVE = Gauge("nf_infer_active", "Active concurrent inference") if _HAS_PROM else None

def _otel_span(name: str):
    if not _HAS_OTEL:
        return contextlib.nullcontext()
    tracer = trace.get_tracer(__name__)  # type: ignore
    return tracer.start_as_current_span(name)  # type: ignore

# ----------------------------- Вспомогательное -----------------------------
def _detect_device(pref: DevicePrefT) -> torch.device:
    if pref in ("cuda", "rocm"):
        if torch.cuda.is_available():
            return torch.device("cuda")
    if pref == "mps":
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():  # type: ignore
            return torch.device("mps")
    if pref == "auto":
        if torch.cuda.is_available():
            return torch.device("cuda")
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():  # type: ignore
            return torch.device("mps")
    return torch.device("cpu")

def _dtype_for_precision(precision: PrecisionT, device: torch.device) -> Optional[torch.dtype]:
    if precision == "fp32":
        return torch.float32
    if precision == "bf16":
        # bf16 доступен на современных GPU/CPU AVX512-BF16; если нет — будем использовать autocast
        return torch.bfloat16
    if precision == "fp16":
        return torch.float16 if device.type in ("cuda", "mps") else None
    if precision == "int8":
        return torch.float32  # вычисления на fp32, веса могут быть квантованы динамически
    return torch.float32

def _compile_if_available(model: torch.nn.Module, mode: str) -> torch.nn.Module:
    comp = getattr(torch, "compile", None)
    if comp is None:  # torch < 2.0
        return model
    try:
        return comp(model, mode=mode)  # type: ignore
    except Exception as e:
        log.warning("torch.compile failed: %s", e)
        return model

def _maybe_quantize_dynamic(model: torch.nn.Module) -> torch.nn.Module:
    qd = getattr(torch.ao.quantization, "quantize_dynamic", None)
    if qd is None:  # older torch
        return model
    try:
        return qd(model, {torch.nn.Linear, torch.nn.LSTM}, dtype=torch.qint8)  # type: ignore
    except Exception as e:
        log.warning("dynamic quantization failed: %s", e)
        return model

# ----------------------------- Интерфейс препроцессинга -----------------------------
PreFn = Callable[[Any], Dict[str, Any]]
PostFn = Callable[[Any], Any]

@dataclass
class IOHandlers:
    preprocess: Optional[PreFn] = None
    postprocess: Optional[PostFn] = None

# ----------------------------- Рантайм -----------------------------
class PyTorchRuntime:
    """
    Производственный рантайм с:
    - безопасной загрузкой модели (scripted/trace/state_dict/модуль),
    - управлением устройством и dtype,
    - опциональным torch.compile, autocast,
    - квантизацией dynamic int8,
    - тайм-аутами, метриками, OOM-ретраями и CPU-fallback,
    - потокобезопасной конкуренцией и батчингом,
    - прогревом.

    Использование:
        cfg = RuntimeConfig(model_path="models/my_model.pt", device_preference="auto", precision="bf16")
        rt = PyTorchRuntime(cfg, io=IOHandlers(preprocess=prep_fn, postprocess=post_fn))
        rt.load()
        out = rt.infer({"x": np_array})  # или уже подготовленный dict через preprocess
    """

    def __init__(self, config: RuntimeConfig, io: Optional[IOHandlers] = None):
        self.cfg = config
        self.io = io or IOHandlers()
        self._device = _detect_device(self.cfg.device_preference)
        self._dtype = _dtype_for_precision(self.cfg.precision, self._device)
        self._model: Optional[torch.nn.Module] = None
        self._model_lock = threading.RLock()
        self._infer_sem = threading.Semaphore(self.cfg.max_concurrency)
        self._loaded = False
        self._closed = False

        if self.cfg.seed is not None:
            torch.manual_seed(int(self.cfg.seed))
            try:
                torch.cuda.manual_seed_all(int(self.cfg.seed))  # type: ignore
            except Exception:
                pass

        if self.cfg.deterministic:
            try:
                torch.use_deterministic_algorithms(True)
            except Exception:
                os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"

        if self._device.type == "cuda" and self.cfg.memory_fraction:
            try:
                torch.cuda.set_per_process_memory_fraction(self.cfg.memory_fraction)  # type: ignore
            except Exception as e:
                log.warning("unable to set memory fraction: %s", e)

        log.info("pytorch.runtime.init device=%s precision=%s", self._device, self.cfg.precision)

    # ------------------------- Загрузка/выгрузка -------------------------
    def load(self) -> None:
        if self._loaded:
            return
        with self._model_lock:
            if self._loaded:
                return
            t0 = time.perf_counter()
            if _HAS_PROM and _LOAD_LAT:
                timer = _LOAD_LAT.time()
            else:
                timer = contextlib.nullcontext()
            with timer, _otel_span("nf.model.load"):
                self._model = self._load_model_impl(self.cfg.model_path, self.cfg.entrypoint)
                self._model.eval()
                self._model.to(self._device)
                if self.cfg.quantize_dynamic:
                    self._model = _maybe_quantize_dynamic(self._model)
                if self.cfg.allow_compile:
                    self._model = _compile_if_available(self._model, self.cfg.compile_mode)
                # Прогрев
                for i in range(self.cfg.warmup_runs):
                    with self._autocast_ctx(), torch.inference_mode():
                        try:
                            dummy = self._make_warmup_sample()
                            self._invoke(self._model, dummy)
                        except Exception as e:
                            log.debug("warmup run %d failed: %s", i, e)
                            break
            self._loaded = True
            log.info("pytorch.runtime.loaded in %.3fs", time.perf_counter() - t0)

    def unload(self) -> None:
        with self._model_lock:
            self._loaded = False
            self._model = None
            if self._device.type == "cuda":
                with contextlib.suppress(Exception):
                    torch.cuda.empty_cache()  # type: ignore
            self._closed = True
            log.info("pytorch.runtime.unloaded")

    # ------------------------- Инференс -------------------------
    def infer(
        self,
        inputs: Any,
        *,
        timeout_s: Optional[float] = None,
        skip_preprocess: bool = False,
        skip_postprocess: bool = False,
    ) -> Any:
        """
        Синхронный батч/единичный инференс.
        inputs: произвольная структура; если задан preprocess — будет преобразована в dict тензоров.
        """
        if not self._loaded:
            self.load()

        deadline = time.time() + (timeout_s or self.cfg.inference_timeout_s)
        acquired = self._infer_sem.acquire(timeout=max(0.0, deadline - time.time()))
        if not acquired:
            self._record_metrics("timeout")
            raise InferenceTimeoutError("acquire semaphore timed out")

        if _HAS_PROM and _ACTIVE:
            _ACTIVE.inc()
        if _HAS_PROM and _INF_LAT:
            lat_ctx = _INF_LAT.time()
        else:
            lat_ctx = contextlib.nullcontext()

        with lat_ctx, _otel_span("nf.infer"):
            try:
                payload = inputs if skip_preprocess or self.io.preprocess is None else self.io.preprocess(inputs)
                if not isinstance(payload, dict):
                    raise InferenceError("preprocess must return dict[str, Tensor-like]")

                prepared = self._prepare_tensors(payload)
                out = self._infer_with_retries(prepared, deadline=deadline)
                result = out if skip_postprocess or self.io.postprocess is None else self.io.postprocess(out)
                self._record_metrics("ok")
                return result
            except InferenceTimeoutError:
                self._record_metrics("timeout")
                raise
            except torch.cuda.OutOfMemoryError as e:
                self._record_metrics("oom")
                raise InferenceError(f"CUDA OOM: {e}") from e
            except Exception as e:
                self._record_metrics("error")
                raise InferenceError(str(e)) from e
            finally:
                if _HAS_PROM and _ACTIVE:
                    _ACTIVE.dec()
                self._infer_sem.release()

    def infer_batch(self, batch: Sequence[Any], **kwargs) -> List[Any]:
        results: List[Any] = []
        for item in batch:
            results.append(self.infer(item, **kwargs))
        return results

    # ------------------------- Внутренние операции -------------------------
    def _infer_with_retries(self, tensors: Dict[str, torch.Tensor], *, deadline: float) -> Any:
        # 1: нормальный проход
        try:
            return self._forward(tensors, deadline=deadline)
        except torch.cuda.OutOfMemoryError as e:
            log.warning("oom on %s, attempt to recover: %s", self._device, e)

            # 2: очистка и понижение прецизионности
            self._clear_cuda()
            lowered = False
            if self.cfg.precision in ("fp32", "bf16") and self._device.type == "cuda":
                self._dtype = torch.float16
                lowered = True
                log.info("retry with fp16 autocast due to OOM")

            try:
                return self._forward(tensors, deadline=deadline)
            except torch.cuda.OutOfMemoryError:
                # 3: CPU fallback
                if self.cfg.cpu_fallback_on_oom and self._device.type != "cpu":
                    log.warning("fallback to CPU due to repeated OOM")
                    self._move_to_device(torch.device("cpu"))
                    return self._forward(tensors, deadline=deadline)
                raise

    def _forward(self, tensors: Dict[str, torch.Tensor], *, deadline: float) -> Any:
        remaining = max(0.0, deadline - time.time())
        if remaining <= 0:
            raise InferenceTimeoutError("deadline exceeded before forward")

        with self._deadline_guard(remaining), self._autocast_ctx(), torch.inference_mode() if self.cfg.gradient_disabled else contextlib.nullcontext():
            return self._invoke(self._model, tensors)

    def _invoke(self, model: Optional[torch.nn.Module], tensors: Dict[str, torch.Tensor]) -> Any:
        if model is None:
            raise InferenceError("model is not loaded")
        return model(**tensors) if self._expects_kwargs(model) else model(*tensors.values())

    # ------------------------- Утилиты -------------------------
    def _prepare_tensors(self, payload: Dict[str, Any]) -> Dict[str, torch.Tensor]:
        out: Dict[str, torch.Tensor] = {}
        for k, v in payload.items():
            if isinstance(v, torch.Tensor):
                t = v
            elif hasattr(torch, "as_tensor"):
                t = torch.as_tensor(v)  # numpy/sequence -> tensor
            else:
                raise InferenceError(f"unsupported input type for key {k}")
            if self._dtype is not None and t.dtype.is_floating_point:
                t = t.to(self._dtype)
            out[k] = t.to(self._device, non_blocking=True)
        return out

    def _autocast_ctx(self):
        if not self.cfg.enable_autocast:
            return contextlib.nullcontext()
        if self._device.type == "cuda":
            return torch.cuda.amp.autocast(dtype=self._dtype or torch.float16)  # type: ignore
        if self._device.type == "cpu" and self._dtype == torch.bfloat16:
            # CPU autocast bf16
            return torch.cpu.amp.autocast(dtype=torch.bfloat16)  # type: ignore
        if self._device.type == "mps":
            # MPS autocast управляется dtype тензоров; контекст вернем пустой
            return contextlib.nullcontext()
        return contextlib.nullcontext()

    def _deadline_guard(self, seconds: float):
        return _DeadlineContext(seconds)

    def _expects_kwargs(self, model: torch.nn.Module) -> bool:
        sig = getattr(model, "__signature__", None)
        if sig:
            return any(p.kind.name in ("VAR_KEYWORD",) for p in sig.parameters.values()) or any(
                p.kind.name in ("KEYWORD_ONLY",) for p in sig.parameters.values()
            )
        # эвристика: если forward принимает **kwargs
        fwd = getattr(model, "forward", None)
        return getattr(fwd, "__code__", None).co_flags & 0x08 == 0x08 if fwd and getattr(fwd, "__code__", None) else False

    def _clear_cuda(self) -> None:
        if self._device.type == "cuda":
            with contextlib.suppress(Exception):
                torch.cuda.empty_cache()  # type: ignore
                torch.cuda.ipc_collect()  # type: ignore

    def _move_to_device(self, dev: torch.device) -> None:
        with self._model_lock:
            if self._model is not None:
                self._model.to(dev)
            self._device = dev
            log.info("model moved to device=%s", dev)
            self._clear_cuda()

    def _make_warmup_sample(self) -> Dict[str, torch.Tensor]:
        # Базовый warmup: один тензор 1x1 (настраивайте под свою модель через config.extra)
        shape = self.cfg.extra.get("warmup_shape", [1, 1])
        key = self.cfg.extra.get("warmup_key", "x")
        t = torch.randn(*shape, dtype=self._dtype or torch.float32, device=self._device)
        return {key: t}

    # ------------------------- Загрузка модели -------------------------
    def _load_model_impl(self, path: str, entrypoint: Optional[str]) -> torch.nn.Module:
        """
        Поддерживаемые варианты:
          1) torchscript файл (.pt/.pth) -> torch.jit.load
          2) checkpoint state_dict -> ожидается модульный путь + entrypoint, возвращающий nn.Module
          3) python-модуль 'pkg.subpkg:factory' или модуль + entrypoint
        """
        if ":" in path and (entrypoint is None):
            # Формат module:callable
            mod_name, func = path.split(":", 1)
            entrypoint = func
            path = mod_name

        if os.path.isfile(path):
            ext = os.path.splitext(path)[1].lower()
            if ext in (".pt", ".pth", ".ts"):
                with _otel_span("nf.model.load.torchscript"):
                    model = torch.jit.load(path, map_location="cpu")
                    return model
            else:
                # бинарный checkpoint state_dict
                sd = torch.load(path, map_location="cpu")
                if not entrypoint:
                    raise ModelLoadError("entrypoint must be provided to construct nn.Module from state_dict file")
                factory = self._resolve_callable(entrypoint, module= None)
                model = factory(self.cfg.extra) if self._accepts_single(factory) else factory(**self.cfg.extra)
                if hasattr(model, "load_state_dict"):
                    missing, unexpected = model.load_state_dict(sd, strict=False)
                    if missing or unexpected:
                        log.warning("state_dict mismatch missing=%s unexpected=%s", missing, unexpected)
                return model

        # Python модуль
        factory = self._resolve_callable(entrypoint, module=path)
        with _otel_span("nf.model.build"):
            model = factory(self.cfg.extra) if self._accepts_single(factory) else factory(**self.cfg.extra)
        return model

    def _resolve_callable(self, entrypoint: Optional[str], module: Optional[str]) -> Callable[..., torch.nn.Module]:
        if not entrypoint:
            raise ModelLoadError("entrypoint is required when model_path is not a torchscript file")
        if module:
            mod = importlib.import_module(module)
            fn = getattr(mod, entrypoint, None)
        else:
            # entrypoint как "pkg.mod:factory" уже разобран выше; здесь просто из текущего пространства
            parts = entrypoint.split(".")
            if len(parts) > 1:
                mod = importlib.import_module(".".join(parts[:-1]))
                fn = getattr(mod, parts[-1], None)
            else:
                fn = globals().get(entrypoint)
        if not callable(fn):
            raise ModelLoadError(f"cannot resolve factory/entrypoint: {module}:{entrypoint}")
        return fn  # type: ignore

    def _accepts_single(self, fn: Callable[..., Any]) -> bool:
        try:
            import inspect
            sig = inspect.signature(fn)
            return len(sig.parameters) == 1 and next(iter(sig.parameters.values())).kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.POSITIONAL_ONLY,
            )
        except Exception:
            return False

    # ------------------------- Метрики -------------------------
    def _record_metrics(self, status: str) -> None:
        if not (_HAS_PROM and self.cfg.enable_metrics):
            return
        if _INF_COUNTER:
            try:
                _INF_COUNTER.labels(status=status).inc()
            except Exception:
                pass

# ----------------------------- Deadline context -----------------------------
class _DeadlineContext:
    def __init__(self, seconds: float):
        self.seconds = seconds
        self._t0 = None  # type: Optional[float]

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc is None:
            return False
        # Не перехватываем исключения; Deadline управляется на верхнем уровне
        return False

# ----------------------------- Фабрики -----------------------------
def from_env() -> PyTorchRuntime:
    """
    Удобная фабрика из ENV.
      NF_MODEL_PATH, NF_ENTRYPOINT, NF_DEVICE, NF_PRECISION, NF_ALLOW_COMPILE, NF_TIMEOUT_S и т.д.
    """
    cfg = RuntimeConfig(
        model_path=os.getenv("NF_MODEL_PATH", ""),
        entrypoint=os.getenv("NF_ENTRYPOINT"),
        device_preference=os.getenv("NF_DEVICE", "auto"),  # type: ignore
        precision=os.getenv("NF_PRECISION", "fp32"),       # type: ignore
        allow_compile=os.getenv("NF_ALLOW_COMPILE", "true").lower() == "true",
        compile_mode=os.getenv("NF_COMPILE_MODE", "reduce-overhead"),  # type: ignore
        enable_autocast=os.getenv("NF_AUTocast", "true").lower() == "true",
        deterministic=os.getenv("NF_DETERMINISTIC", "false").lower() == "true",
        seed=int(os.getenv("NF_SEED", "1337")),
        quantize_dynamic=os.getenv("NF_QDYN", "false").lower() == "true",
        max_batch_size=int(os.getenv("NF_MAX_BATCH", "1")),
        max_concurrency=int(os.getenv("NF_MAX_CONCURRENCY", "8")),
        inference_timeout_s=float(os.getenv("NF_TIMEOUT_S", "30")),
        warmup_runs=int(os.getenv("NF_WARMUP", "1")),
        enable_metrics=os.getenv("NF_METRICS", "true").lower() == "true",
        enable_otel=os.getenv("NF_OTEL", "true").lower() == "true",
        gradient_disabled=os.getenv("NF_NO_GRAD", "true").lower() == "true",
        cpu_fallback_on_oom=os.getenv("NF_CPU_FALLBACK", "true").lower() == "true",
        memory_fraction=float(os.getenv("NF_MEMORY_FRACTION", "0") or 0) or None,
        extra=_parse_json_env("NF_EXTRA_JSON"),
    )
    rt = PyTorchRuntime(cfg)
    rt.load()
    return rt

def _parse_json_env(name: str) -> Dict[str, Any]:
    raw = os.getenv(name)
    if not raw:
        return {}
    try:
        import json
        return json.loads(raw)
    except Exception:
        log.warning("failed to parse %s", name)
        return {}

# ----------------------------- Пример интеграции -----------------------------
# def build_model(extra: Dict[str, Any]) -> torch.nn.Module:
#     class M(torch.nn.Module):
#         def __init__(self, out_dim: int = 10):
#             super().__init__()
#             self.l = torch.nn.Linear(32, out_dim)
#         def forward(self, x: torch.Tensor) -> torch.Tensor:
#             return self.l(x)
#     return M(out_dim=extra.get("out_dim", 10))
#
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     cfg = RuntimeConfig(model_path="your.package.models", entrypoint="build_model", precision="bf16")
#     rt = PyTorchRuntime(cfg)
#     rt.load()
#     import numpy as np
#     x = {"x": torch.randn(1, 32)}
#     y = rt.infer(x, skip_preprocess=True, skip_postprocess=True)
#     print(y.shape)
