# neuroforge-core/neuroforge/inference/runtimes/onnxruntime.py
from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import numpy as np

try:
    import onnxruntime as ort  # type: ignore
except Exception as exc:  # pragma: no cover
    raise RuntimeError("onnxruntime is required for this runtime") from exc

try:
    import torch  # type: ignore
    _HAS_TORCH = True
except Exception:  # pragma: no cover
    _HAS_TORCH = False

log = logging.getLogger("neuroforge.ort")


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

@dataclass
class OnnxRuntimeConfig:
    model_path: Optional[str] = None              # путь к .onnx
    model_bytes: Optional[bytes] = None           # альтернатива: байтовый буфер
    providers: Optional[List[str]] = None         # явный список EP, если None — autodetect
    device_id: int = 0                            # GPU device id для CUDA/TensorRT
    inter_op_threads: Optional[int] = None        # параллелизм графов
    intra_op_threads: Optional[int] = None        # параллелизм операторов
    graph_optimization: str = "all"               # disabled|basic|extended|all
    execution_mode: str = "sequential"            # sequential|parallel
    enable_cpu_mem_arena: bool = True
    enable_mem_pattern: bool = True
    execution_order: Optional[str] = None         # e.g. "priority"
    extra_session_kv: Dict[str, Any] = field(default_factory=dict)  # дополнительные опции
    enable_profiling: bool = False
    profile_output_prefix: str = "ort-profile"
    session_log_severity: int = 2                 # 0-4 (verbose..fatal), 2=warning
    session_log_verbosity: int = 0
    session_logid: str = "neuroforge-ort"
    enable_io_binding: bool = True
    warmup_runs: int = 0                          # если >0 — выполнить холостые прогоны (нужны примеры)
    warmup_example_fn: Optional[Callable[[Sequence[ort.NodeArg]], Dict[str, np.ndarray]]] = None
    run_timeout_ms: Optional[int] = None          # таймаут на один вызов
    # Динамический микробатчинг
    dynamic_batching: bool = False
    max_batch_size: int = 32
    batch_window_ms: int = 2                      # окно в миллисекундах для сборки batch
    # Наблюдаемость (хук)
    metrics_hook: Optional[Callable[[str, Dict[str, str], float], None]] = None  # (event, labels, latency_s)


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

_OPT_LEVELS = {
    "disabled": ort.GraphOptimizationLevel.ORT_DISABLE_ALL,
    "basic": ort.GraphOptimizationLevel.ORT_ENABLE_BASIC,
    "extended": ort.GraphOptimizationLevel.ORT_ENABLE_EXTENDED,
    "all": ort.GraphOptimizationLevel.ORT_ENABLE_ALL,
}

_EXEC_MODES = {
    "sequential": ort.ExecutionMode.ORT_SEQUENTIAL,
    "parallel": ort.ExecutionMode.ORT_PARALLEL,
}


def _available_providers() -> List[str]:
    try:
        return list(ort.get_available_providers())
    except Exception:  # pragma: no cover
        return ["CPUExecutionProvider"]


def _autodetect_providers(device_id: int) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
    avail = set(_available_providers())
    provider_options: Dict[str, Dict[str, Any]] = {}

    order: List[str] = []

    # TensorRT (если есть) обычно ставим первым
    if "TensorrtExecutionProvider" in avail:
        order.append("TensorrtExecutionProvider")
        provider_options["TensorrtExecutionProvider"] = {
            "device_id": device_id,
            "trt_max_workspace_size": 1 << 30,      # 1 GiB по умолчанию
            "trt_fp16_enable": True,
            "trt_engine_cache_enable": True,
        }

    # CUDA
    if "CUDAExecutionProvider" in avail:
        order.append("CUDAExecutionProvider")
        provider_options["CUDAExecutionProvider"] = {
            "device_id": device_id,
            "arena_extend_strategy": "kSameAsRequested",
            "cudnn_conv_algo_search": "EXHAUSTIVE",
            "do_copy_in_default_stream": True,
        }

    # DirectML (Windows)
    if "DmlExecutionProvider" in avail:
        order.append("DmlExecutionProvider")

    # CPU всегда в конце
    order.append("CPUExecutionProvider")

    # Отфильтровать отстутствующие (на всякий случай)
    order = [p for p in order if p in avail]
    return order, provider_options


def _to_numpy(x: Any) -> np.ndarray:
    if isinstance(x, np.ndarray):
        return x
    if _HAS_TORCH and isinstance(x, torch.Tensor):
        # переносим на CPU без градиента
        return x.detach().to("cpu").contiguous().numpy()
    # список/скаляр -> ndarray
    return np.asarray(x)


def _concat_batch(inputs_list: List[Mapping[str, np.ndarray]]) -> Dict[str, np.ndarray]:
    """Склейка батча по первой оси. Требуется одинаковый набор ключей и совместимые формы."""
    if not inputs_list:
        return {}
    keys = inputs_list[0].keys()
    out: Dict[str, List[np.ndarray]] = {k: [] for k in keys}
    for item in inputs_list:
        if item.keys() != keys:
            raise ValueError("Inconsistent input keys across batch")
        for k in keys:
            out[k].append(item[k])
    return {k: np.concatenate(v, axis=0) for k, v in out.items()}


# --------------------------------------------------------------------------------------
# Dynamic micro-batching
# --------------------------------------------------------------------------------------

class _BatchRequest:
    __slots__ = ("inputs", "future", "deadline")
    def __init__(self, inputs: Mapping[str, np.ndarray], timeout_s: Optional[float]) -> None:
        self.inputs = {k: _to_numpy(v) for k, v in inputs.items()}
        self.future: asyncio.Future[Mapping[str, np.ndarray]] = asyncio.get_event_loop().create_future()
        self.deadline = time.perf_counter() + (timeout_s or 3600.0)


class _DynamicBatcher:
    def __init__(self, runner: "OnnxRuntimeRunner", max_batch: int, window_ms: int):
        self.runner = runner
        self.max_batch = max_batch
        self.window_ms = window_ms
        self._queue: asyncio.Queue[_BatchRequest] = asyncio.Queue()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping = False

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task
            self._task = None

    async def enqueue(self, req: _BatchRequest) -> asyncio.Future[Mapping[str, np.ndarray]]:
        await self._queue.put(req)
        return req.future

    async def _run(self) -> None:
        loop = asyncio.get_event_loop()
        while not self._stopping:
            req = await self._queue.get()
            batch: List[_BatchRequest] = [req]
            t0 = loop.time()
            # собираем в окно
            while len(batch) < self.max_batch:
                wait_left = self.window_ms / 1000.0 - (loop.time() - t0)
                if wait_left <= 0:
                    break
                try:
                    nxt = await asyncio.wait_for(self._queue.get(), timeout=max(0.0, wait_left))
                    batch.append(nxt)
                except asyncio.TimeoutError:
                    break

            # инференс
            try:
                merged = _concat_batch([b.inputs for b in batch])
                outputs = await self.runner._infer_async_internal(merged)  # batched outputs
                # Теперь разделяем обратно по первой оси
                # Наивное разбиение: делим по размерам исходных мини-батчей
                sizes = [list(b.inputs.values())[0].shape[0] for b in batch]
                cum = np.cumsum([0] + sizes)
                split_out: List[Dict[str, np.ndarray]] = []
                for i in range(len(batch)):
                    piece: Dict[str, np.ndarray] = {}
                    for name, val in outputs.items():
                        piece[name] = val[cum[i]:cum[i+1]]
                    split_out.append(piece)
                # резолвим futures
                for b, o in zip(batch, split_out):
                    if not b.future.done():
                        b.future.set_result(o)
            except Exception as exc:
                for b in batch:
                    if not b.future.done():
                        b.future.set_exception(exc)


# --------------------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------------------

class OnnxRuntimeRunner:
    """
    Промышленный рантайм-обёртка над onnxruntime.InferenceSession с:
      - автодетектом EP (TensorRT/CUDA/CPU),
      - тонкими SessionOptions,
      - синхронным/асинхронным инференсом,
      - IO Binding (по желанию),
      - динамическим микробатчингом,
      - warmup и профайлингом,
      - безопасным shutdown.
    """

    def __init__(self, cfg: OnnxRuntimeConfig) -> None:
        self.cfg = cfg
        self._session: Optional[ort.InferenceSession] = None
        self._providers: List[str] = []
        self._provider_options: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._loop = asyncio.get_event_loop()
        self._batcher: Optional[_DynamicBatcher] = None

    # ---------------- Lifecycle ----------------

    def start(self) -> None:
        with self._lock:
            if self._session is not None:
                return
            so = ort.SessionOptions()

            so.graph_optimization_level = _OPT_LEVELS.get(self.cfg.graph_optimization.lower(), ort.GraphOptimizationLevel.ORT_ENABLE_ALL)
            so.execution_mode = _EXEC_MODES.get(self.cfg.execution_mode.lower(), ort.ExecutionMode.ORT_SEQUENTIAL)
            so.enable_cpu_mem_arena = self.cfg.enable_cpu_mem_arena
            so.enable_mem_pattern = self.cfg.enable_mem_pattern
            so.log_severity_level = self.cfg.session_log_severity
            so.log_verbosity_level = self.cfg.session_log_verbosity
            so.logid = self.cfg.session_logid

            if self.cfg.inter_op_threads:
                so.inter_op_num_threads = int(self.cfg.inter_op_threads)
            if self.cfg.intra_op_threads:
                so.intra_op_num_threads = int(self.cfg.intra_op_threads)
            if self.cfg.execution_order:
                try:
                    so.execution_order = self.cfg.execution_order  # type: ignore[attr-defined]
                except Exception:
                    pass
            if self.cfg.enable_profiling:
                so.enable_profiling = True
                so.profile_file_prefix = self.cfg.profile_output_prefix

            # Дополнительные опции (best effort)
            for k, v in (self.cfg.extra_session_kv or {}).items():
                with contextlib.suppress(Exception):
                    setattr(so, k, v)

            # Providers
            if self.cfg.providers:
                prov = list(self.cfg.providers)
                prov_opts_map = {}
            else:
                prov, prov_opts_map = _autodetect_providers(self.cfg.device_id)

            prov_opts: List[Dict[str, Any]] = [prov_opts_map.get(p, {}) for p in prov]

            # Создаём сессию
            if self.cfg.model_bytes is not None:
                self._session = ort.InferenceSession(self.cfg.model_bytes, sess_options=so, providers=prov, provider_options=prov_opts)
            elif self.cfg.model_path:
                self._session = ort.InferenceSession(self.cfg.model_path, sess_options=so, providers=prov, provider_options=prov_opts)
            else:
                raise ValueError("Either model_path or model_bytes must be provided")

            self._providers = prov
            self._provider_options = prov_opts
            log.info("ORT session created; providers=%s", self._providers)

            # Warmup (если указана функция генерации примера)
            if self.cfg.warmup_runs > 0 and self.cfg.warmup_example_fn:
                try:
                    example = self.cfg.warmup_example_fn(self._session.get_inputs())
                    for i in range(int(self.cfg.warmup_runs)):
                        _ = self._run_once(example)  # sync warmup
                    log.info("ORT warmup completed: %d runs", int(self.cfg.warmup_runs))
                except Exception as exc:
                    log.warning("ORT warmup skipped: %s", exc)

            # Динамический батчинг
            if self.cfg.dynamic_batching:
                self._batcher = _DynamicBatcher(self, self.cfg.max_batch_size, self.cfg.batch_window_ms)
                # запускаем в текущем loop, если он жив
                if self._loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._batcher.start(), self._loop)
                else:
                    self._loop.run_until_complete(self._batcher.start())

    def stop(self) -> None:
        with self._lock:
            # стоп батчера
            if self._batcher:
                if self._loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._batcher.stop(), self._loop).result(timeout=1)
                else:
                    self._loop.run_until_complete(self._batcher.stop())
                self._batcher = None
            # выгружаем сессию
            if self._session is not None:
                try:
                    if self.cfg.enable_profiling:
                        try:
                            path = self._session.end_profiling()
                            log.info("ORT profile saved: %s", path)
                        except Exception:
                            pass
                finally:
                    self._session = None
                    log.info("ORT session disposed")

    # ---------------- Metadata ----------------

    @property
    def ready(self) -> bool:
        return self._session is not None

    def inputs(self) -> List[ort.NodeArg]:
        self._ensure_ready()
        return list(self._session.get_inputs())  # type: ignore[union-attr]

    def outputs(self) -> List[ort.NodeArg]:
        self._ensure_ready()
        return list(self._session.get_outputs())  # type: ignore[union-attr]

    def model_metadata(self) -> Dict[str, Any]:
        self._ensure_ready()
        md = self._session.get_modelmeta()  # type: ignore[union-attr]
        return {
            "producer": md.producer_name,
            "version": md.version,
            "graph_name": md.graph_name,
            "domain": md.domain,
            "description": md.description,
            "custom_metadata": dict(md.custom_metadata_map),
            "providers": self._providers,
        }

    # ---------------- Inference API ----------------

    def infer(
        self,
        inputs: Mapping[str, Any],
        output_names: Optional[Sequence[str]] = None,
        timeout_ms: Optional[int] = None,
        use_io_binding: Optional[bool] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Синхронный вызов. inputs: name -> ndarray/torch.Tensor/список.
        """
        self._ensure_ready()
        t0 = time.perf_counter()

        try:
            if self.cfg.dynamic_batching:
                # В sync-режиме динамический батчинг нецелесообразен: вызываем напрямую
                result = self._run_once(_to_numpy_dict(inputs), output_names, timeout_ms, use_io_binding)
            else:
                result = self._run_once(_to_numpy_dict(inputs), output_names, timeout_ms, use_io_binding)
            return result
        finally:
            self._metric("infer.sync", {}, time.perf_counter() - t0)

    async def infer_async(
        self,
        inputs: Mapping[str, Any],
        output_names: Optional[Sequence[str]] = None,
        timeout_ms: Optional[int] = None,
        use_io_binding: Optional[bool] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Асинхронный вызов. При включённом динамическом батчинге — отправляет запрос в микробатчер.
        """
        self._ensure_ready()
        t0 = time.perf_counter()
        try:
            if self.cfg.dynamic_batching:
                # enqueue into batcher; по завершении получим мапу выходов
                assert self._batcher is not None
                req = _BatchRequest(_to_numpy_dict(inputs), (timeout_ms or self.cfg.run_timeout_ms or 0) / 1000.0 or None)
                fut = await self._batcher.enqueue(req)
                outputs = await asyncio.wait_for(fut, timeout=(timeout_ms or self.cfg.run_timeout_ms or 0) / 1000.0 if (timeout_ms or self.cfg.run_timeout_ms) else None)
                # если нужны конкретные выходы — отфильтруем
                if output_names:
                    outputs = {k: v for k, v in outputs.items() if k in set(output_names)}
                return outputs
            else:
                # обычный путь: в thread-пуле
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None,
                    lambda: self._run_once(_to_numpy_dict(inputs), output_names, timeout_ms, use_io_binding),
                )
        finally:
            self._metric("infer.async", {}, time.perf_counter() - t0)

    # ---------------- Internal helpers ----------------

    def _run_once(
        self,
        np_inputs: Mapping[str, np.ndarray],
        output_names: Optional[Sequence[str]] = None,
        timeout_ms: Optional[int] = None,
        use_io_binding: Optional[bool] = None,
    ) -> Dict[str, np.ndarray]:
        sess = self._session
        assert sess is not None

        run_opts = ort.RunOptions()
        eff_timeout = timeout_ms if timeout_ms is not None else self.cfg.run_timeout_ms
        if eff_timeout and eff_timeout > 0:
            run_opts.add_run_config_entry("cpu.ep.timeout", str(int(eff_timeout)))
            run_opts.add_run_config_entry("cuda.ep.timeout", str(int(eff_timeout)))
        # Отмена через run_opts (best-effort): run_log_verbosity_level, termination. Ограничимся таймаутом.

        # IO Binding?
        use_binding = self.cfg.enable_io_binding if use_io_binding is None else use_io_binding
        if use_binding and hasattr(sess, "io_binding"):
            try:
                io_bind = sess.io_binding()
                # В качестве простого варианта — биндим CPU входы; с CUDA можно указать device_type="cuda"
                for name, arr in np_inputs.items():
                    assert isinstance(arr, np.ndarray), "inputs must be numpy arrays at binding stage"
                    io_bind.bind_input(
                        name=name,
                        device_type="cpu",
                        device_id=0,
                        element_type=arr.dtype,
                        shape=arr.shape,
                        buffer_ptr=arr.ctypes.data,
                    )
                # Выходы — по именам графа
                out_names = [o.name for o in sess.get_outputs()] if output_names is None else list(output_names)
                for name in out_names:
                    io_bind.bind_output(name)
                sess.run_with_iobinding(io_bind, run_options=run_opts)
                outputs = {}
                for out in io_bind.get_outputs():
                    # out — IOBinding buffer; преобразуем в numpy
                    # На новых версиях ORT есть asarray(); fallback — np.frombuffer
                    try:
                        arr = out.asarray()  # type: ignore[attr-defined]
                    except Exception:
                        # CPU buffer
                        arr = np.frombuffer(out.buffer_ptr(), dtype=out.element_type()).reshape(out.shape())  # type: ignore[attr-defined]
                    outputs[out.name] = arr  # type: ignore[attr-defined]
                return outputs
            except Exception as exc:
                log.debug("IO Binding failed, falling back to session.run: %s", exc)

        # Обычный путь
        feed = {k: v for k, v in np_inputs.items()}
        out_names = None if output_names is None else list(output_names)
        out_list = sess.run(out_names, feed, run_options=run_opts)
        # Нормализуем в dict[name] -> ndarray
        names = [o.name for o in sess.get_outputs()] if out_names is None else out_names
        return {n: out for n, out in zip(names, out_list)}

    async def _infer_async_internal(self, np_inputs: Mapping[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Внутренний помощник для батчера: всегда использует стандартный sync вызов в пуле."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._run_once(np_inputs, None, self.cfg.run_timeout_ms, None))

    def _ensure_ready(self) -> None:
        if self._session is None:
            raise RuntimeError("ONNX Runtime session is not initialized; call start() first")

    def _metric(self, event: str, labels: Dict[str, str], latency_s: float) -> None:
        if self.cfg.metrics_hook:
            with contextlib.suppress(Exception):
                self.cfg.metrics_hook(event, labels, latency_s)


# --------------------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------------------

def create_runner_from_env(model_path: Optional[str] = None, model_bytes: Optional[bytes] = None) -> OnnxRuntimeRunner:
    """
    Удобный конструктор: читает настройки из ENV и создаёт готовый раннер.
    """
    providers_env = os.getenv("ORT_PROVIDERS")
    providers = [p.strip() for p in providers_env.split(",")] if providers_env else None
    cfg = OnnxRuntimeConfig(
        model_path=model_path,
        model_bytes=model_bytes,
        providers=providers,
        device_id=int(os.getenv("ORT_DEVICE_ID", "0")),
        inter_op_threads=int(os.getenv("ORT_INTER_OP", "0") or 0) or None,
        intra_op_threads=int(os.getenv("ORT_INTRA_OP", "0") or 0) or None,
        graph_optimization=os.getenv("ORT_OPT_LEVEL", "all"),
        execution_mode=os.getenv("ORT_EXEC_MODE", "sequential"),
        enable_cpu_mem_arena=os.getenv("ORT_CPU_ARENA", "true").lower() == "true",
        enable_mem_pattern=os.getenv("ORT_MEM_PATTERN", "true").lower() == "true",
        execution_order=os.getenv("ORT_EXEC_ORDER") or None,
        enable_profiling=os.getenv("ORT_PROFILE", "false").lower() == "true",
        profile_output_prefix=os.getenv("ORT_PROFILE_PREFIX", "ort-profile"),
        session_log_severity=int(os.getenv("ORT_LOG_SEVERITY", "2")),
        session_log_verbosity=int(os.getenv("ORT_LOG_VERBOSITY", "0")),
        session_logid=os.getenv("ORT_LOG_ID", "neuroforge-ort"),
        enable_io_binding=os.getenv("ORT_IO_BINDING", "true").lower() == "true",
        run_timeout_ms=int(os.getenv("ORT_TIMEOUT_MS", "0") or 0) or None,
        dynamic_batching=os.getenv("ORT_DYN_BATCH", "false").lower() == "true",
        max_batch_size=int(os.getenv("ORT_MAX_BATCH", "32")),
        batch_window_ms=int(os.getenv("ORT_BATCH_WINDOW_MS", "2")),
    )
    return OnnxRuntimeRunner(cfg)


# --------------------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------------------

def _to_numpy_dict(inputs: Mapping[str, Any]) -> Dict[str, np.ndarray]:
    return {k: _to_numpy(v) for k, v in inputs.items()}
