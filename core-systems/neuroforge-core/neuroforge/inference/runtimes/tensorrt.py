# neuroforge/inference/runtimes/tensorrt.py
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np

# -----------------------------
# Логирование
# -----------------------------
LOG = logging.getLogger("neuroforge.trt")
if not LOG.handlers:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="ts=%(asctime)s lvl=%(levelname)s logger=%(name)s msg=%(message)s",
    )

# -----------------------------
# Импорт TensorRT
# -----------------------------
try:
    import tensorrt as trt
except Exception as e:  # pragma: no cover
    raise ImportError("Пакет 'tensorrt' не найден. Установите NVIDIA TensorRT Python bindings.") from e


# -----------------------------
# CUDA backend: cuda-python (cudart) или PyCUDA
# -----------------------------
class _CudaError(RuntimeError):
    pass


class _CudaApi:
    """
    Унифицированная абстракция CUDA: память, копирования, стримы.
    Предпочтительно использует cuda-python (cudart), фолбэк — PyCUDA.
    """

    def __init__(self) -> None:
        self.backend = None  # "cudart" | "pycuda"
        self._init_backend()

    def _init_backend(self) -> None:
        # cuda-python (cudart)
        try:
            from cuda import cudart  # type: ignore

            self.backend = "cudart"
            self.cudart = cudart
            # Инициализация контекста на текущем устройстве
            _check = self.cudart.cudaFree(0)[0]
            if _check != self.cudart.cudaError_t.cudaSuccess:
                raise _CudaError(f"cudaFree(0) failed: {_check}")
            return
        except Exception:
            pass

        # PyCUDA
        try:
            import pycuda.autoinit  # noqa: F401  # type: ignore
            import pycuda.driver as cuda  # type: ignore

            self.backend = "pycuda"
            self.cuda = cuda
            return
        except Exception:
            pass

        raise ImportError(
            "Не найдено ни 'cuda-python' (cudart), ни 'pycuda'. "
            "Установите 'cuda-python' (рекомендовано) или 'pycuda'."
        )

    # ----- Стримы -----
    def stream_create(self) -> Any:
        if self.backend == "cudart":
            s_ptr = ctypes.c_void_p()
            res = self.cudart.cudaStreamCreate(ctypes.byref(s_ptr))[0]
            if res != self.cudart.cudaError_t.cudaSuccess:
                raise _CudaError(f"cudaStreamCreate failed: {res}")
            return s_ptr
        else:
            return self.cuda.Stream()

    def stream_destroy(self, stream: Any) -> None:
        if self.backend == "cudart":
            self.cudart.cudaStreamDestroy(stream)
        else:
            del stream

    def stream_synchronize(self, stream: Any) -> None:
        if self.backend == "cudart":
            self.cudart.cudaStreamSynchronize(stream)
        else:
            stream.synchronize()

    # ----- Память -----
    def malloc(self, nbytes: int) -> int:
        if nbytes <= 0:
            raise _CudaError("malloc: nbytes must be > 0")
        if self.backend == "cudart":
            dptr = ctypes.c_void_p()
            res = self.cudart.cudaMalloc(ctypes.byref(dptr), nbytes)[0]
            if res != self.cudart.cudaError_t.cudaSuccess:
                raise _CudaError(f"cudaMalloc failed: {res}")
            return int(ctypes.cast(dptr, ctypes.c_void_p).value or 0)
        else:
            # PyCUDA возвращает объект DeviceAllocation, нам нужен int ptr
            d = self.cuda.mem_alloc(nbytes)
            return int(int(d))  # __int__ -> ptr value

    def free(self, dptr: int) -> None:
        if self.backend == "cudart":
            self.cudart.cudaFree(ctypes.c_void_p(dptr))
        else:
            # PyCUDA освобождает при GC; прямого free по ptr нет. Игнорируем.
            pass

    def memcpy_htod_async(self, dptr: int, h_src: np.ndarray, stream: Any) -> None:
        if not h_src.flags["C_CONTIGUOUS"]:
            h_src = np.ascontiguousarray(h_src)
        nbytes = h_src.nbytes
        if self.backend == "cudart":
            res = self.cudart.cudaMemcpyAsync(
                ctypes.c_void_p(dptr),
                h_src.ctypes.data_as(ctypes.c_void_p),
                nbytes,
                self.cudart.cudaMemcpyKind.cudaMemcpyHostToDevice,
                stream,
            )[0]
            if res != self.cudart.cudaError_t.cudaSuccess:
                raise _CudaError(f"cudaMemcpyAsync HtoD failed: {res}")
        else:
            self.cuda.memcpy_htod_async(dptr, h_src, stream)

    def memcpy_dtoh_async(self, h_dst: np.ndarray, dptr: int, stream: Any) -> None:
        if not h_dst.flags["C_CONTIGUOUS"]:
            raise _CudaError("dst host array must be contiguous")
        nbytes = h_dst.nbytes
        if self.backend == "cudart":
            res = self.cudart.cudaMemcpyAsync(
                h_dst.ctypes.data_as(ctypes.c_void_p),
                ctypes.c_void_p(dptr),
                nbytes,
                self.cudart.cudaMemcpyKind.cudaMemcpyDeviceToHost,
                stream,
            )[0]
            if res != self.cudart.cudaError_t.cudaSuccess:
                raise _CudaError(f"cudaMemcpyAsync DtoH failed: {res}")
        else:
            self.cuda.memcpy_dtoh_async(h_dst, dptr, stream)


_CUDA = _CudaApi()  # создаём один раз


# -----------------------------
# Конфиг сборки/рантайма TRT
# -----------------------------
@dataclass
class ProfileShape:
    min: Tuple[int, ...]
    opt: Tuple[int, ...]
    max: Tuple[int, ...]


@dataclass
class TensorRTConfig:
    # Общие
    max_workspace_size_mb: int = 2048
    fp16: bool = True
    int8: bool = False
    strict_types: bool = False
    builder_optimization_level: int = 3  # 0..5
    tactic_sources: Optional[int] = None  # trt.TacticSource битовая маска или None
    sparse_weights: bool = False
    refittable: bool = False
    safety: bool = False  # для safety runtime

    # DLA (опционально для Jetson/NVIDIA)
    dla_core: Optional[int] = None  # None = GPU

    # Динамические формы
    profiles: Dict[str, ProfileShape] = field(default_factory=dict)  # input_name -> ProfileShape

    # Параметры INT8
    calibrator_cache: Optional[Path] = None  # путь к кэшу калибратора
    calibrator_batch_size: int = 8

    # Рантайм
    num_contexts: int = 2  # пул execution context
    num_streams: int = 2   # пул CUDA stream
    enable_profiling: bool = False
    enable_reflection: bool = False  # печать схемы биндингов при старте

    # Ограничения сообщений (страховка)
    max_input_bytes: Optional[int] = None
    max_output_bytes: Optional[int] = None

    def to_hash(self) -> str:
        data = {
            "fp16": self.fp16,
            "int8": self.int8,
            "strict_types": self.strict_types,
            "opt_level": self.builder_optimization_level,
            "tactics": int(self.tactic_sources or 0),
            "sparse": self.sparse_weights,
            "refit": self.refittable,
            "safety": self.safety,
            "dla": self.dla_core,
            "profiles": {k: {"min": v.min, "opt": v.opt, "max": v.max} for k, v in self.profiles.items()},
            "calib_bs": self.calibrator_batch_size,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


# -----------------------------
# TRT Logger (интеграция с Python logging)
# -----------------------------
class _TrtLogger(trt.ILogger):
    def __init__(self, level: int = trt.Logger.WARNING) -> None:
        super().__init__()
        self.level = level

    def log(self, severity: trt.ILogger.Severity, msg: str) -> None:  # type: ignore[override]
        if severity <= trt.ILogger.Severity.ERROR:
            LOG.error(f"trt: {msg}")
        elif severity == trt.ILogger.Severity.WARNING:
            LOG.warning(f"trt: {msg}")
        elif severity == trt.ILogger.Severity.INFO:
            LOG.info(f"trt: {msg}")
        else:
            LOG.debug(f"trt: {msg}")


# -----------------------------
# INT8 калибратор (Entropy2)
# -----------------------------
class EntropyCalibrator(trt.IInt8EntropyCalibrator2):
    """
    Калибратор INT8. Ожидает callable data_fn(batch_size) -> Dict[input_name, np.ndarray]
    с согласованными формами и dtype np.float32/np.float16/np.int8/np.int32.
    """
    def __init__(
        self,
        input_names: Sequence[str],
        batch_size: int,
        data_fn: Callable[[int], Optional[Dict[str, np.ndarray]]],
        cache_file: Optional[Path] = None,
    ):
        super().__init__()
        self.input_names = list(input_names)
        self.batch_size = batch_size
        self.data_fn = data_fn
        self.cache_file = cache_file
        self.device_ptrs: Dict[str, int] = {}
        self.last_batch: Optional[Dict[str, np.ndarray]] = None

    def get_batch_size(self) -> int:  # type: ignore[override]
        return self.batch_size

    def get_batch(self, names: Sequence[str]) -> Optional[List[int]]:  # type: ignore[override]
        batch = self.data_fn(self.batch_size)
        if batch is None:
            LOG.info("INT8 calibration finished (no more batches).")
            return None

        # Выделяем/копируем
        addrs: List[int] = []
        for name in names:
            arr = batch[name]
            if not isinstance(arr, np.ndarray):
                raise TypeError("Calibrator input must be numpy.ndarray")
            if name not in self.device_ptrs or arr.nbytes > self._nbytes_of(name):
                # realloc
                if name in self.device_ptrs:
                    _CUDA.free(self.device_ptrs[name])
                self.device_ptrs[name] = _CUDA.malloc(arr.nbytes)
            _CUDA.memcpy_htod_async(self.device_ptrs[name], arr, _CalibStream.stream)
            addrs.append(self.device_ptrs[name])
        _CUDA.stream_synchronize(_CalibStream.stream)
        self.last_batch = batch
        return addrs

    def read_calibration_cache(self) -> Optional[bytes]:  # type: ignore[override]
        if self.cache_file and self.cache_file.is_file():
            LOG.info(f"Using INT8 calibration cache: {self.cache_file}")
            return self.cache_file.read_bytes()
        return None

    def write_calibration_cache(self, cache: bytes) -> None:  # type: ignore[override]
        if self.cache_file:
            LOG.info(f"Writing INT8 calibration cache: {self.cache_file}")
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_bytes(cache)

    def _nbytes_of(self, name: str) -> int:
        # crude helper: we do not track sizes; allocate exact each time
        return self.last_batch[name].nbytes if self.last_batch and name in self.last_batch else 0


class _CalibStream:
    stream = _CUDA.stream_create()


# -----------------------------
# Вспомогательные типы
# -----------------------------
@dataclass
class BindingInfo:
    index: int
    name: str
    is_input: bool
    dtype: np.dtype
    format: trt.TensorFormat
    shape: Tuple[int, ...]  # с динамикой (-1)


# -----------------------------
# TensorRT Runtime
# -----------------------------
class TensorRTRuntime:
    """
    Вариант промышленного рантайма TensorRT:
      - build_engine_from_onnx() / load_engine()
      - динамические формы и профили
      - INT8 калибровка / FP16
      - пул execution-context’ов и CUDA-стримов
      - батчинг и асинхронная передача
      - warmup() и health()
    """

    def __init__(self, cfg: TensorRTConfig) -> None:
        self.cfg = cfg
        self.trt_logger = _TrtLogger(trt.Logger.INFO)
        self.runtime = trt.Runtime(self.trt_logger)
        if cfg.safety:
            self.runtime = trt.Runtime(self.trt_logger)  # placeholder; safety runtime для некоторых платформ

        self.engine: Optional[trt.ICudaEngine] = None
        self.bindings: Dict[str, BindingInfo] = {}
        self._context_pool: "queue.Queue[trt.IExecutionContext]" = queue.Queue()
        self._stream_pool: "queue.Queue[Any]" = queue.Queue()
        self._allocation_lock = threading.Lock()  # защита при возможной переразметке биндингов
        self._device_buffers: Dict[Tuple[int, int], int] = {}  # (binding_index, bytes) -> dptr

    # ---------- BUILD / LOAD ----------

    def build_engine_from_onnx(
        self,
        onnx_path: Union[str, Path],
        *,
        int8_data_fn: Optional[Callable[[int], Optional[Dict[str, np.ndarray]]]] = None,
        plan_out: Optional[Union[str, Path]] = None,
    ) -> trt.ICudaEngine:
        """
        Собирает engine из ONNX с учётом конфигурации. При int8=True ожидает data_fn.
        """
        onnx_path = Path(onnx_path)
        assert onnx_path.is_file(), f"ONNX not found: {onnx_path}"

        LOG.info(f"Building TensorRT engine from ONNX: {onnx_path}")
        builder = trt.Builder(self.trt_logger)
        network_flags = 1 << int(trt.NetworkDefinitionCreationFlag.EXPLICIT_BATCH)
        network = builder.create_network(network_flags)
        parser = trt.OnnxParser(network, self.trt_logger)

        with onnx_path.open("rb") as f:
            if not parser.parse(f.read()):
                for i in range(parser.num_errors):
                    LOG.error("ONNX parse error: %s", parser.get_error(i))
                raise RuntimeError("ONNX parse failed")

        config = builder.create_builder_config()
        config.max_workspace_size = self.cfg.max_workspace_size_mb * 1024 * 1024
        config.set_memory_pool_limit(trt.MemoryPoolType.WORKSPACE, config.max_workspace_size)
        config.builder_optimization_level = int(self.cfg.builder_optimization_level)

        if self.cfg.tactic_sources is not None:
            config.set_tactic_sources(self.cfg.tactic_sources)

        if self.cfg.fp16 and builder.platform_has_fast_fp16:
            config.set_flag(trt.BuilderFlag.FP16)

        if self.cfg.strict_types:
            config.set_flag(trt.BuilderFlag.STRICT_TYPES)

        if self.cfg.sparse_weights:
            config.set_flag(trt.BuilderFlag.SPARSE_WEIGHTS)

        if self.cfg.refittable:
            config.set_flag(trt.BuilderFlag.REFIT)

        if self.cfg.dla_core is not None:
            config.default_device_type = trt.DeviceType.DLA
            config.DLA_core = int(self.cfg.dla_core)
            config.set_flag(trt.BuilderFlag.GPU_FALLBACK)

        # INT8
        calibrator = None
        if self.cfg.int8:
            if not builder.platform_has_fast_int8:
                LOG.warning("INT8 requested but platform_has_fast_int8=False")
            config.set_flag(trt.BuilderFlag.INT8)
            if int8_data_fn is None:
                raise ValueError("INT8 requires int8_data_fn for calibration")
            in_names = [network.get_input(i).name for i in range(network.num_inputs)]
            calibrator = EntropyCalibrator(
                input_names=in_names,
                batch_size=self.cfg.calibrator_batch_size,
                data_fn=int8_data_fn,
                cache_file=self.cfg.calibrator_cache,
            )
            config.int8_calibrator = calibrator

        # Optimization profiles
        if self.cfg.profiles:
            profile = builder.create_optimization_profile()
            for inp_name, shp in self.cfg.profiles.items():
                profile.set_shape(inp_name, shp.min, shp.opt, shp.max)
                LOG.info("Profile for %s: min=%s opt=%s max=%s", inp_name, shp.min, shp.opt, shp.max)
            config.add_optimization_profile(profile)

        # Build
        engine_bytes = builder.build_serialized_network(network, config)
        if engine_bytes is None:
            raise RuntimeError("Failed to build serialized engine")
        engine = self.runtime.deserialize_cuda_engine(engine_bytes)
        if engine is None:
            raise RuntimeError("Failed to deserialize built engine")
        self._set_engine(engine)

        # Save plan
        if plan_out:
            plan_out = Path(plan_out)
            plan_out.parent.mkdir(parents=True, exist_ok=True)
            plan_out.write_bytes(bytes(engine_bytes))
            LOG.info(f"Engine plan saved: {plan_out}")

        return engine

    def load_engine(self, plan_path: Union[str, Path]) -> trt.ICudaEngine:
        plan_path = Path(plan_path)
        assert plan_path.is_file(), f"Engine plan not found: {plan_path}"
        LOG.info(f"Loading TensorRT engine: {plan_path}")
        engine = self.runtime.deserialize_cuda_engine(plan_path.read_bytes())
        if engine is None:
            raise RuntimeError("Failed to deserialize engine from file")
        self._set_engine(engine)
        return engine

    def _set_engine(self, engine: trt.ICudaEngine) -> None:
        self.engine = engine
        self.bindings = self._inspect_bindings(engine)
        if self.cfg.enable_reflection:
            self._print_bindings()
        self._init_pools()

    def _inspect_bindings(self, engine: trt.ICudaEngine) -> Dict[str, BindingInfo]:
        infos: Dict[str, BindingInfo] = {}
        for idx in range(engine.num_bindings):
            name = engine.get_binding_name(idx)
            is_input = engine.binding_is_input(idx)
            dtype = np.dtype(self._trt_dtype_to_numpy(engine.get_binding_dtype(idx)))
            fmt = engine.get_binding_format(idx)
            shape = tuple(engine.get_binding_shape(idx))
            infos[name] = BindingInfo(index=idx, name=name, is_input=is_input, dtype=dtype, format=fmt, shape=shape)
        return infos

    def _trt_dtype_to_numpy(self, dt: trt.DataType) -> Any:
        mapping = {
            trt.DataType.FLOAT: np.float32,
            trt.DataType.HALF: np.float16,
            trt.DataType.INT8: np.int8,
            trt.DataType.INT32: np.int32,
            trt.DataType.BOOL: np.bool_,
        }
        if dt not in mapping:
            raise TypeError(f"Unsupported TRT dtype: {dt}")
        return mapping[dt]

    def _print_bindings(self) -> None:
        for b in self.bindings.values():
            LOG.info("binding name=%s idx=%d in=%s dtype=%s shape=%s format=%s",
                     b.name, b.index, b.is_input, b.dtype, b.shape, b.format)

    # ---------- CONTEXT / STREAM POOLS ----------

    def _init_pools(self) -> None:
        assert self.engine is not None
        while not self._context_pool.empty():
            self._context_pool.get_nowait()

        while not self._stream_pool.empty():
            s = self._stream_pool.get_nowait()
            with contextlib.suppress(Exception):
                _CUDA.stream_destroy(s)

        for _ in range(self.cfg.num_contexts):
            ctx = self.engine.create_execution_context()
            if ctx is None:
                raise RuntimeError("Failed to create execution context")
            self._context_pool.put(ctx)

        for _ in range(self.cfg.num_streams):
            self._stream_pool.put(_CUDA.stream_create())

    @contextlib.contextmanager
    def _borrow_ctx_stream(self, timeout: float = 10.0):
        try:
            ctx = self._context_pool.get(timeout=timeout)
            stream = self._stream_pool.get(timeout=timeout)
            yield ctx, stream
        finally:
            if "ctx" in locals():
                self._context_pool.put(ctx)
            if "stream" in locals():
                self._stream_pool.put(stream)

    # ---------- INFERENCE ----------

    def _ensure_binding_shapes(self, ctx: trt.IExecutionContext, inputs: Mapping[str, np.ndarray]) -> None:
        """
        Устанавливает binding shapes для динамических входов.
        """
        assert self.engine is not None
        for name, arr in inputs.items():
            if name not in self.bindings:
                raise KeyError(f"Unknown input: {name}")
            b = self.bindings[name]
            if not b.is_input:
                raise ValueError(f"{name} is not an input")
            # Если shape динамический, выставим фактический
            shape = tuple(int(x) for x in arr.shape)
            if -1 in b.shape or any(dim == -1 for dim in b.shape):
                ok = ctx.set_binding_shape(b.index, shape)
                if not ok:
                    raise RuntimeError(f"Failed to set binding shape for {name} -> {shape}")
            else:
                # Проверка на совпадение статической формы
                if tuple(arr.shape) != b.shape:
                    raise ValueError(f"Static shape mismatch for {name}: expected {b.shape}, got {arr.shape}")

    def _bytes_required(self, name: str, ctx: trt.IExecutionContext) -> int:
        b = self.bindings[name]
        shape = tuple(ctx.get_binding_shape(b.index))
        return int(np.prod(shape)) * b.dtype.itemsize

    def _alloc_or_get(self, binding_idx: int, nbytes: int) -> int:
        key = (binding_idx, nbytes)
        with self._allocation_lock:
            if key in self._device_buffers:
                return self._device_buffers[key]
            dptr = _CUDA.malloc(nbytes)
            self._device_buffers[key] = dptr
            return dptr

    def infer(
        self,
        inputs: Mapping[str, np.ndarray],
        *,
        output_names: Optional[Sequence[str]] = None,
        synchronize: bool = True,
    ) -> Dict[str, np.ndarray]:
        """
        Синхронный инференс для одного запроса. Возвращает словарь output_name->np.ndarray.
        """
        assert self.engine is not None
        with self._borrow_ctx_stream() as (ctx, stream):
            # 1) Установка форм
            self._ensure_binding_shapes(ctx, inputs)

            # 2) Подготовка биндингов
            bindings: List[int] = [0] * self.engine.num_bindings
            # Входы: копируем HtoD
            for name, arr in inputs.items():
                b = self.bindings[name]
                if self.cfg.max_input_bytes and arr.nbytes > self.cfg.max_input_bytes:
                    raise ValueError(f"Input {name} too large: {arr.nbytes} > {self.cfg.max_input_bytes}")
                dptr = self._alloc_or_get(b.index, arr.nbytes)
                _CUDA.memcpy_htod_async(dptr, arr.astype(b.dtype, copy=False), stream)
                bindings[b.index] = dptr

            # Выходы: выделяем буферы
            outputs: Dict[str, np.ndarray] = {}
            fetch_names = output_names or [n for n, bi in self.bindings.items() if not bi.is_input]
            for name in fetch_names:
                b = self.bindings[name]
                nbytes = self._bytes_required(name, ctx)
                if self.cfg.max_output_bytes and nbytes > self.cfg.max_output_bytes:
                    raise ValueError(f"Output {name} too large: {nbytes} > {self.cfg.max_output_bytes}")
                dptr = self._alloc_or_get(b.index, nbytes)
                bindings[b.index] = dptr
                # Подготовим host buffer
                shape = tuple(ctx.get_binding_shape(b.index))
                outputs[name] = np.empty(shape, dtype=b.dtype)

            # 3) Запуск
            ok = ctx.execute_async_v2(bindings=bindings, stream_handle=int(self._stream_handle(stream)))
            if not ok:
                raise RuntimeError("execute_async_v2 returned False")

            # 4) Копирование DtoH
            for name in outputs:
                b = self.bindings[name]
                dptr = bindings[b.index]
                _CUDA.memcpy_dtoh_async(outputs[name], dptr, stream)

            if synchronize:
                _CUDA.stream_synchronize(stream)

            return outputs

    def _stream_handle(self, stream: Any) -> int:
        if _CUDA.backend == "cudart":
            return int(ctypes.cast(stream, ctypes.c_void_p).value or 0)
        else:
            return int(stream.handle)  # PyCUDA

    # ---------- BATCHING / WARMUP / HEALTH ----------

    def batched_infer(
        self,
        batch_inputs: Sequence[Mapping[str, np.ndarray]],
        *,
        output_names: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, np.ndarray]]:
        """
        Последовательный запуск множества запросов (микро-батч). Управляет пулом контекстов/стримов.
        Возвращает список результатов в исходном порядке.
        """
        results: List[Optional[Dict[str, np.ndarray]]] = [None] * len(batch_inputs)
        exceptions: List[Optional[BaseException]] = [None] * len(batch_inputs)

        def worker(i: int, inp: Mapping[str, np.ndarray]):
            try:
                results[i] = self.infer(inp, output_names=output_names, synchronize=True)
            except BaseException as e:
                exceptions[i] = e

        threads: List[threading.Thread] = []
        for i, inp in enumerate(batch_inputs):
            t = threading.Thread(target=worker, args=(i, inp), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        # Поднимаем первую ошибку
        for e in exceptions:
            if e:
                raise e
        return [r for r in results if r is not None]  # type: ignore

    def warmup(self, n_runs: int = 3) -> None:
        """
        Тёплый старт: формирует фиктивные входы по 'opt' профилям и прогревает engine.
        """
        if not self.cfg.profiles:
            LOG.info("Warmup skipped: no dynamic profiles configured")
            return
        fake_inputs: Dict[str, np.ndarray] = {}
        for name, p in self.cfg.profiles.items():
            b = self.bindings.get(name)
            if not b:
                continue
            shape = tuple(p.opt)
            fake_inputs[name] = np.zeros(shape, dtype=b.dtype)
        for i in range(n_runs):
            _ = self.infer(fake_inputs, synchronize=True)
        LOG.info("Warmup done: %d runs", n_runs)

    def health(self) -> Dict[str, Any]:
        """
        Простая проверка здоровья рантайма.
        """
        return {
            "engine": bool(self.engine),
            "contexts": self._context_pool.qsize(),
            "streams": self._stream_pool.qsize(),
            "bindings": list(self.bindings.keys()),
            "config_hash": self.cfg.to_hash(),
        }

    # ---------- Утилиты кэширования/хеша ----------

    @staticmethod
    def build_cache_key(onnx_path: Union[str, Path], cfg: TensorRTConfig) -> str:
        onnx_path = Path(onnx_path)
        h = hashlib.sha256()
        h.update(onnx_path.read_bytes())
        h.update(cfg.to_hash().encode())
        return h.hexdigest()[:24]

    # ---------- Удобные конструкторы ----------

    @classmethod
    def build_or_load(
        cls,
        onnx_path: Union[str, Path],
        plan_dir: Union[str, Path],
        cfg: TensorRTConfig,
        *,
        int8_data_fn: Optional[Callable[[int], Optional[Dict[str, np.ndarray]]]] = None,
    ) -> "TensorRTRuntime":
        """
        Строит или загружает engine согласно хешу конфигурации и онтологии.
        """
        plan_dir = Path(plan_dir)
        plan_dir.mkdir(parents=True, exist_ok=True)
        key = cls.build_cache_key(onnx_path, cfg)
        plan_path = plan_dir / f"{Path(onnx_path).stem}-{key}.plan"

        rt = cls(cfg)
        if plan_path.is_file():
            rt.load_engine(plan_path)
            LOG.info(f"Loaded engine from cache: {plan_path.name}")
        else:
            rt.build_engine_from_onnx(onnx_path, int8_data_fn=int8_data_fn, plan_out=plan_path)
            LOG.info(f"Built engine and cached as: {plan_path.name}")
        return rt


# -----------------------------
# Пример использования (докстринг)
# -----------------------------
__doc__ = """
Пример:
    from neuroforge.inference.runtimes.tensorrt import TensorRTConfig, ProfileShape, TensorRTRuntime
    cfg = TensorRTConfig(
        fp16=True,
        int8=False,
        profiles={
            "input_ids": ProfileShape(min=(1, 8), opt=(4, 128), max=(8, 256)),
            "attention_mask": ProfileShape(min=(1, 8), opt=(4, 128), max=(8, 256)),
        },
        num_contexts=4,
        num_streams=4,
    )
    rt = TensorRTRuntime.build_or_load("model.onnx", "./engines", cfg)
    rt.warmup()

    # Единичный запуск:
    outputs = rt.infer({
        "input_ids": np.random.randint(0, 100, (4, 128), dtype=np.int32),
        "attention_mask": np.ones((4, 128), dtype=np.int32),
    })
    print({k: v.shape for k, v in outputs.items()})
"""
