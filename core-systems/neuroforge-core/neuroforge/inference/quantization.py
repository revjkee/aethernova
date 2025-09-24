# neuroforge-core/neuroforge/inference/quantization.py
from __future__ import annotations

import contextlib
import dataclasses
import enum
import gc
import io
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, Union

# ---------- ЛОГИРОВАНИЕ ----------

log = logging.getLogger("neuroforge.quantization")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    log.addHandler(_h)
log.setLevel(logging.INFO)

# ---------- ИСКЛЮЧЕНИЯ ----------

class QuantizationError(Exception): ...
class MissingDependencyError(QuantizationError): ...
class ExportError(QuantizationError): ...
class CalibrationError(QuantizationError): ...

# ---------- ОПЦИОНАЛЬНЫЕ ЗАВИСИМОСТИ ----------

with contextlib.suppress(Exception):
    import torch  # type: ignore

def _ensure_torch() -> Any:
    if "torch" not in globals():
        raise MissingDependencyError("PyTorch is required")
    return globals()["torch"]

def _has_ao() -> bool:
    try:
        import torch.ao.quantization as _  # type: ignore
        return True
    except Exception:
        return False

def _torch_version_tuple() -> Tuple[int, int]:
    t = _ensure_torch()
    vs = t.__version__.split(".")
    return int(vs[0]), int(vs[1])

# ---------- ПУБЛИЧНЫЕ ТИПЫ ----------

class Method(str, enum.Enum):
    DYNAMIC_INT8 = "dynamic-int8"
    STATIC_PTQ_INT8 = "static-ptq-int8"
    QAT_INT8 = "qat-int8"
    BNB_INT8 = "bnb-int8"
    BNB_4BIT = "bnb-4bit"

class Backend(str, enum.Enum):
    FBGEMM = "fbgemm"   # x86/AVX2
    QNNPACK = "qnnpack" # ARM

@dataclass
class PTQConfig:
    backend: Backend = Backend.FBGEMM
    per_channel: bool = True
    symmetric: bool = True
    fuse_modules: bool = True
    observers: str = "default"  # "default" | "reduced_range"
    calibrate_steps: int = 256  # кол-во батчей для калибровки
    example_inputs: Optional[Tuple[Any, ...]] = None  # для FX path (инкапсуляция graph)
    use_fx: bool = True  # предпочтительно FX-путь на torch>=1.13

@dataclass
class DynamicConfig:
    # Квантовать Linear/LSTM/Conv по умолчанию
    modules: Tuple[Any, ...] = dataclasses.field(default_factory=lambda: ())

@dataclass
class QATConfig:
    backend: Backend = Backend.FBGEMM
    fuse_modules: bool = True

@dataclass
class BitsAndBytesConfig:
    # Для Transformers + bitsandbytes
    compute_dtype: str = "float16"  # "float16" | "bfloat16"
    quant_type: str = "nf4"  # "nf4" | "fp4" (для 4bit)
    use_double_quant: bool = True
    torch_dtype_override: Optional[str] = None  # если хотим переопределить torch_dtype

@dataclass
class QuantizationConfig:
    method: Method
    ptq: PTQConfig = dataclasses.field(default_factory=PTQConfig)
    dynamic: DynamicConfig = dataclasses.field(default_factory=DynamicConfig)
    qat: QATConfig = dataclasses.field(default_factory=QATConfig)
    bnb: BitsAndBytesConfig = dataclasses.field(default_factory=BitsAndBytesConfig)

# ---------- ВСПОМОГАТЕЛЬНОЕ ----------

def _set_backend(backend: Backend) -> None:
    t = _ensure_torch()
    if not _has_ao():
        raise MissingDependencyError("torch.ao.quantization is required")
    if backend == Backend.FBGEMM:
        if hasattr(t.backends, "quantized") and hasattr(t.backends.quantized, "engine"):
            t.backends.quantized.engine = "fbgemm"
    elif backend == Backend.QNNPACK:
        if hasattr(t.backends, "quantized") and hasattr(t.backends.quantized, "engine"):
            t.backends.quantized.engine = "qnnpack"

def _model_size_bytes(model: Any) -> int:
    t = _ensure_torch()
    total = 0
    for p in model.state_dict().values():
        total += p.nelement() * p.element_size()
    # грубо добавим буферы
    for b in getattr(model, "_buffers", {}).values() if hasattr(model, "_buffers") else []:
        if b is not None:
            total += b.nelement() * b.element_size()
    return total

def human_bytes(n: int) -> str:
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.2f} {u}"
        n /= 1024.0
    return f"{n:.2f} PB"

def measure_latency(model: Any, build_input: Callable[[], Tuple[Any, ...]], iters: int = 50, warmup: int = 10, device: Optional[str] = None) -> float:
    t = _ensure_torch()
    if device is None:
        device = "cpu"
    model = model.to(device)
    model.eval()
    with t.no_grad():
        # warmup
        for _ in range(max(0, warmup)):
            _ = model(*build_input())
        # measure
        t0 = time.perf_counter()
        for _ in range(max(1, iters)):
            _ = model(*build_input())
        t1 = time.perf_counter()
    return (t1 - t0) * 1000.0 / max(1, iters)

# ---------- ОСНОВНОЙ КЛАСС ----------

class Quantizer:
    """
    Унифицированный интерфейс для квантования моделей.
    """

    @staticmethod
    def dynamic_int8(model: Any, cfg: DynamicConfig) -> Any:
        t = _ensure_torch()
        if not _has_ao():
            raise MissingDependencyError("torch.ao.quantization is required")
        # Если модули не заданы — квантовать Linear/LSTM по умолчанию
        modules = cfg.modules or (t.nn.Linear, t.nn.LSTM)
        log.info("Applying dynamic int8 quantization to modules: %s", [m.__name__ for m in modules])
        qmodel = t.quantization.quantize_dynamic(
            model,
            {m for m in modules},
            dtype=t.qint8
        )
        return qmodel

    @staticmethod
    def static_ptq_int8(
        model: Any,
        cfg: PTQConfig,
        calibrator: Callable[[int], Iterable[Tuple[Tuple[Any, ...], Optional[Any]]]]
    ) -> Any:
        """
        calibrator(step) -> iterable of (inputs, targets?) for калибровки на step
        Пример calibrator: lambda step: dataloader (игнорирует аргумент).
        """
        t = _ensure_torch()
        if not _has_ao():
            raise MissingDependencyError("torch.ao.quantization is required")
        _set_backend(cfg.backend)

        model.eval()
        ver_major, ver_minor = _torch_version_tuple()

        # Выбор qconfig
        import torch.ao.quantization as ao  # type: ignore
        if cfg.observers == "reduced_range" and hasattr(ao, "qconfig"):
            qcfg = ao.qconfig.default_per_channel_qconfig if cfg.per_channel else ao.qconfig.default_qconfig
        else:
            qcfg = ao.get_default_qconfig(str(cfg.backend.value))
            if cfg.per_channel and hasattr(ao, "get_default_qconfig"):
                # Попытаемся переключить на per-channel, если доступно
                with contextlib.suppress(Exception):
                    qcfg = ao.qconfig.default_per_channel_qconfig

        # Fusion (eager)
        if cfg.fuse_modules:
            with contextlib.suppress(Exception):
                # Популярные последовательности
                fuse_list = _infer_fuse_list(model)
                if fuse_list:
                    log.info("Fusing modules: %s", fuse_list)
                    t.quantization.fuse_modules(model, fuse_list, inplace=True)

        # Путь FX предпочтителен на новых torch
        use_fx = bool(cfg.use_fx and (ver_major > 1 or (ver_major == 1 and ver_minor >= 13)))
        if use_fx:
            with contextlib.suppress(Exception):
                from torch.ao.quantization import get_default_qconfig  # type: ignore
                from torch.ao.quantization.quantize_fx import prepare_fx, convert_fx  # type: ignore
                qconf = get_default_qconfig(str(cfg.backend.value))
                if cfg.per_channel:
                    with contextlib.suppress(Exception):
                        from torch.ao.quantization.qconfig import default_per_channel_qconfig  # type: ignore
                        qconf = default_per_channel_qconfig
                log.info("Preparing FX graph for PTQ (backend=%s, per_channel=%s)", cfg.backend.value, cfg.per_channel)
                example_inputs = cfg.example_inputs if cfg.example_inputs is not None else _default_example_inputs(model)
                prepared = prepare_fx(model, {"": qconf}, example_inputs=example_inputs)
                _run_calibration_fx(prepared, calibrator, steps=cfg.calibrate_steps)
                qmodel = convert_fx(prepared)
                return qmodel

        # Eager mode (совместимость)
        log.info("Preparing Eager PTQ (backend=%s, per_channel=%s)", cfg.backend.value, cfg.per_channel)
        model.qconfig = qcfg
        ao.prepare(model, inplace=True)  # type: ignore
        _run_calibration_eager(model, calibrator, steps=cfg.calibrate_steps)
        qmodel = ao.convert(model, inplace=False)  # type: ignore
        return qmodel

    @staticmethod
    def qat_int8_prepare(model: Any, cfg: QATConfig) -> Any:
        """
        Подготовка модели к QAT (fake-quant). Обучение выполняется отдельно.
        """
        t = _ensure_torch()
        if not _has_ao():
            raise MissingDependencyError("torch.ao.quantization is required")
        _set_backend(cfg.backend)

        import torch.ao.quantization as ao  # type: ignore
        model.train()
        if cfg.fuse_modules:
            with contextlib.suppress(Exception):
                fuse_list = _infer_fuse_list(model)
                if fuse_list:
                    log.info("Fusing modules for QAT: %s", fuse_list)
                    t.quantization.fuse_modules(model, fuse_list, inplace=True)

        qconfig = ao.get_default_qat_qconfig(str(cfg.backend.value))
        model.qconfig = qconfig
        ao.prepare_qat(model, inplace=True)  # type: ignore
        log.info("QAT prepared; run your training loop, then convert()")
        return model

    @staticmethod
    def qat_convert(model: Any) -> Any:
        import torch.ao.quantization as ao  # type: ignore
        model.eval()
        qmodel = ao.convert(model.eval(), inplace=False)  # type: ignore
        return qmodel

    # ---------- BitsAndBytes / Transformers ----------

    @staticmethod
    def load_transformer_bnb(
        model_name_or_path: str,
        method: Method,
        cfg: BitsAndBytesConfig,
        device_map: Union[str, Dict[str, int]] = "auto",
    ) -> Any:
        """
        Загружает модель Transformers c bitsandbytes 8bit/4bit.
        """
        if method not in (Method.BNB_INT8, Method.BNB_4BIT):
            raise QuantizationError("Method must be BNB_INT8 or BNB_4BIT for this loader")

        try:
            from transformers import AutoModelForCausalLM  # type: ignore
        except Exception as e:
            raise MissingDependencyError("transformers is required") from e
        try:
            import bitsandbytes as bnb  # noqa: F401
        except Exception as e:
            raise MissingDependencyError("bitsandbytes is required") from e

        from transformers import BitsAndBytesConfig as HF_BNB_Config  # type: ignore
        import torch as t  # type: ignore

        dtype = {"float16": t.float16, "bfloat16": t.bfloat16}[cfg.compute_dtype]
        hf_bnb = None
        if method == Method.BNB_INT8:
            hf_bnb = HF_BNB_Config(load_in_8bit=True)
        else:
            hf_bnb = HF_BNB_Config(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=dtype,
                bnb_4bit_use_double_quant=cfg.use_double_quant,
                bnb_4bit_quant_type=cfg.quant_type,
            )

        torch_dtype = dtype if cfg.torch_dtype_override is None else {"float16": t.float16, "bfloat16": t.bfloat16}[cfg.torch_dtype_override]
        model = AutoModelForCausalLM.from_pretrained(
            model_name_or_path,
            device_map=device_map,
            quantization_config=hf_bnb,
            torch_dtype=torch_dtype,
        )
        return model

    # ---------- Экспорт и отчеты ----------

    @staticmethod
    def export_torchscript(model: Any, example_inputs: Tuple[Any, ...], out_path: Union[str, Path]) -> Path:
        t = _ensure_torch()
        model.eval()
        try:
            traced = t.jit.trace(model, example_inputs, strict=False)
            t.jit.save(traced, str(out_path))
        except Exception as e:
            raise ExportError(f"TorchScript export failed: {e}") from e
        log.info("TorchScript saved to %s", out_path)
        return Path(out_path)

    @staticmethod
    def report(model_fp32: Any, model_quant: Any, build_input: Callable[[], Tuple[Any, ...]]) -> Dict[str, Any]:
        """
        Возвращает сравнение размеров и латентности (CPU).
        """
        size_fp32 = _model_size_bytes(model_fp32)
        size_q = _model_size_bytes(model_quant)
        lat_fp32 = measure_latency(model_fp32, build_input)
        lat_q = measure_latency(model_quant, build_input)
        gain_size = size_fp32 / max(1, size_q)
        gain_lat = lat_fp32 / max(1e-9, lat_q)
        out = {
            "size_fp32_bytes": size_fp32,
            "size_quant_bytes": size_q,
            "size_reduction_x": gain_size,
            "latency_fp32_ms": lat_fp32,
            "latency_quant_ms": lat_q,
            "latency_speedup_x": gain_lat,
            "size_fp32_human": human_bytes(size_fp32),
            "size_quant_human": human_bytes(size_q),
        }
        log.info("Report: %s", out)
        return out

# ---------- ВНУТРЕННИЕ ХЕЛПЕРЫ ----------

def _infer_fuse_list(model: Any) -> List[List[str]]:
    """
    Эвристика для fusion в eager-mode: ищет шаблоны Conv/BN/ReLU и Linear/ReLU
    Возвращает список цепочек для torch.quantization.fuse_modules.
    """
    import torch.nn as nn  # type: ignore
    fuse = []

    def walk(prefix: str, m: nn.Module):
        prev_name = None
        prev_type = None
        for name, child in m.named_children():
            full = f"{prefix}.{name}" if prefix else name
            walk(full, child)
            # пары Linear + ReLU
            if isinstance(child, nn.ReLU) and prev_type in (nn.Linear, nn.Conv2d):
                fuse.append([f"{prefix}.{prev_name}" if prefix else prev_name, full])
            prev_name, prev_type = name, type(child)

        # тройки Conv + BN + ReLU
        names = list(m._modules.keys())
        for i in range(len(names) - 2):
            a, b, c = names[i], names[i+1], names[i+2]
            A = m._modules[a]; B = m._modules[b]; C = m._modules[c]
            if isinstance(A, nn.Conv2d) and isinstance(B, nn.BatchNorm2d) and isinstance(C, nn.ReLU):
                fuse.append([f"{prefix}.{a}" if prefix else a,
                             f"{prefix}.{b}" if prefix else b,
                             f"{prefix}.{c}" if prefix else c])

    walk("", model)
    # Убрать дубликаты
    uniq = []
    seen = set()
    for item in fuse:
        key = tuple(item)
        if key not in seen:
            uniq.append(item)
            seen.add(key)
    return uniq

def _default_example_inputs(model: Any) -> Tuple[Any, ...]:
    """
    Пытается угадать форму входа. В проде лучше передавать явно через PTQConfig.example_inputs.
    """
    t = _ensure_torch()
    # Эвристика: ищем первый Linear/Conv чтобы определить размер
    import torch.nn as nn  # type: ignore
    for m in model.modules():
        if isinstance(m, nn.Linear):
            in_f = m.in_features
            return (t.randn(1, in_f),)
        if isinstance(m, nn.Conv2d):
            c = m.in_channels
            k = m.kernel_size
            # предположим квадрат 224
            return (t.randn(1, c, 224, 224),)
    # fallback
    return (t.randn(1, 16),)

def _run_calibration_eager(model: Any, calibrator: Callable[[int], Iterable[Tuple[Tuple[Any, ...], Optional[Any]]]], steps: int) -> None:
    t = _ensure_torch()
    model.eval()
    with t.inference_mode():
        it = calibrator(0)
        count = 0
        for inputs, _ in it:
            _ = model(*inputs)
            count += 1
            if count >= steps:
                break
    if count == 0:
        raise CalibrationError("Calibration produced zero batches")

def _run_calibration_fx(model_prepared: Any, calibrator: Callable[[int], Iterable[Tuple[Tuple[Any, ...], Optional[Any]]]], steps: int) -> None:
    # prepared FX-модель прогоняем так же, как обычную
    _run_calibration_eager(model_prepared, calibrator, steps)

# ---------- ПРИМЕР ИСПОЛЬЗОВАНИЯ (докстринг) ----------

"""
Пример статического PTQ:

    from neuroforge.inference.quantization import Quantizer, QuantizationConfig, Method, PTQConfig, measure_latency

    cfg = QuantizationConfig(
        method=Method.STATIC_PTQ_INT8,
        ptq=PTQConfig(backend=Backend.FBGEMM, per_channel=True, calibrate_steps=200)
    )

    def calibrator(_):
        # возвращает iterable из (inputs, targets)
        for xb, yb in calib_loader:
            yield (xb.to("cpu"),), yb

    qmodel = Quantizer.static_ptq_int8(model_cpu, cfg.ptq, calibrator)

    report = Quantizer.report(model_cpu, qmodel, build_input=lambda: (torch.randn(1, in_features),))
    print(report)

Пример динамического квантования:

    qmodel = Quantizer.dynamic_int8(model_cpu, DynamicConfig())

BitsAndBytes 4-bit:

    model = Quantizer.load_transformer_bnb("meta-llama/Llama-2-7b-hf", Method.BNB_4BIT,
                                           BitsAndBytesConfig(compute_dtype="bfloat16", quant_type="nf4"))

Экспорт TorchScript:

    Quantizer.export_torchscript(qmodel, example_inputs=(torch.randn(1, in_features),), out_path="model.ts")
"""
