# neuroforge-core/neuroforge/serving/server.py
# Neuroforge Serving: Production-grade inference HTTP server with batching, metrics, health, and hot reload.
from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, root_validator

# Optional deps
try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:
    import onnxruntime as ort  # type: ignore
except Exception:  # pragma: no cover
    ort = None  # type: ignore

try:
    import torch  # type: ignore
except Exception:  # pragma: no cover
    torch = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore
    def generate_latest():  # type: ignore
        return b""
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


# -------------------------------
# Settings
# -------------------------------

@dataclass
class Settings:
    # Model
    model_type: str = os.getenv("NF_MODEL_TYPE", "onnx")  # onnx|torchscript|python
    model_uri: str = os.getenv("NF_MODEL_URI", "")        # path/to/model.onnx | .pt | module:function
    model_version: str = os.getenv("NF_MODEL_VERSION", "v1")
    device: str = os.getenv("NF_DEVICE", "auto")          # auto|cpu|cuda
    # Batching
    enable_batching: bool = os.getenv("NF_BATCHING", "true").lower() == "true"
    max_batch_size: int = int(os.getenv("NF_BATCH_MAX_SIZE", "32"))
    max_batch_latency_ms: int = int(os.getenv("NF_BATCH_MAX_LATENCY_MS", "10"))
    # Runtime
    inference_timeout_s: float = float(os.getenv("NF_INFER_TIMEOUT_S", "10"))
    concurrency_limit: int = int(os.getenv("NF_CONCURRENCY", "4"))
    # HTTP
    host: str = os.getenv("NF_HOST", "0.0.0.0")
    port: int = int(os.getenv("NF_PORT", "8080"))
    cors_origins: Tuple[str, ...] = tuple(
        [o for o in os.getenv("NF_CORS_ORIGINS", "").split(",") if o.strip()]
    )
    # Metrics/Tracing
    enable_metrics: bool = os.getenv("NF_METRICS", "true").lower() == "true"
    service_name: str = os.getenv("NF_SERVICE_NAME", "neuroforge-serving")
    # Reload
    allow_reload: bool = os.getenv("NF_ALLOW_RELOAD", "true").lower() == "true"
    # Config file (yaml)
    config_path: Optional[str] = os.getenv("NF_SERVING_CONFIG")

    @classmethod
    def load(cls) -> "Settings":
        s = cls()
        if s.config_path and yaml:
            try:
                with open(s.config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                # Overlay known keys if present
                for k in cfg.keys():
                    if hasattr(s, k):
                        setattr(s, k, cfg[k])
            except Exception:
                pass
        return s


S = Settings.load()


# -------------------------------
# Logging & request id
# -------------------------------

LOG = logging.getLogger("neuroforge.serving")
_log_level = os.getenv("NF_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}',
    stream=sys.stdout,
)

def request_id(req: Request) -> str:
    return (
        req.headers.get("x-request-id")
        or req.headers.get("x-correlation-id")
        or f"{int(time.time()*1e6):x}"
    )


# -------------------------------
# Runners
# -------------------------------

class RunnerError(Exception):
    pass


class BaseRunner:
    name: str = "base"

    async def load(self) -> None:
        raise NotImplementedError

    async def predict_batch(self, batch: List[Any], params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """Must return list of predictions aligned with input batch."""
        raise NotImplementedError

    async def warmup(self) -> None:
        """Optional warmup; default no-op."""
        return


class ONNXRuntimeRunner(BaseRunner):
    name = "onnx"

    def __init__(self, model_uri: str, device: str = "auto"):
        if ort is None:
            raise RunnerError("onnxruntime is not installed")
        self.uri = model_uri
        self.device = device
        self.sess = None

    async def load(self) -> None:
        providers = ["CPUExecutionProvider"]
        if self.device in ("cuda", "auto"):
            if "CUDAExecutionProvider" in ort.get_available_providers():
                providers = [ "CUDAExecutionProvider", "CPUExecutionProvider" ]
        self.sess = ort.InferenceSession(self.uri, providers=providers)  # type: ignore
        inputs = [i.name for i in self.sess.get_inputs()]  # sanity
        LOG.info('onnx model loaded uri="%s" inputs=%s', self.uri, inputs)

    async def predict_batch(self, batch: List[Any], params: Optional[Dict[str, Any]] = None) -> List[Any]:
        if self.sess is None:
            raise RunnerError("model not loaded")
        # Accept either list of dict(inputs) or list of arrays -> assign to first input
        if len(self.sess.get_inputs()) == 1:
            in_name = self.sess.get_inputs()[0].name
            arr = _to_numpy(batch)
            outputs = self.sess.run(None, {in_name: arr})
        else:
            # each element should be dict of inputs for multi-input models
            if not isinstance(batch[0], dict):
                raise RunnerError("multi-input ONNX expects instances as dicts")
            # Stack per input name
            feed = {}
            for inp in self.sess.get_inputs():
                feed[inp.name] = _to_numpy([inst[inp.name] for inst in batch])
            outputs = self.sess.run(None, feed)
        # If single output => return flattened list; else map as dict per sample
        out_names = [o.name for o in self.sess.get_outputs()]
        if len(out_names) == 1:
            arr = outputs[0]
            return _from_numpy(arr)
        # multiple outputs
        results = []
        for i in range(len(batch)):
            item = {}
            for j, name in enumerate(out_names):
                item[name] = _slice_output(outputs[j], i)
            results.append(item)
        return results

    async def warmup(self) -> None:
        try:
            if len(self.sess.get_inputs()) == 1:  # type: ignore
                in_name = self.sess.get_inputs()[0].name  # type: ignore
                shape = _fallback_shape(self.sess.get_inputs()[0].shape)  # type: ignore
                dummy = np.zeros(shape, dtype=_fallback_dtype(self.sess.get_inputs()[0].type)) if np else None  # type: ignore
                if dummy is not None:
                    _ = self.sess.run(None, {in_name: dummy})  # type: ignore
        except Exception:
            pass


class TorchScriptRunner(BaseRunner):
    name = "torchscript"

    def __init__(self, model_uri: str, device: str = "auto"):
        if torch is None:
            raise RunnerError("torch is not installed")
        self.uri = model_uri
        self.device = torch.device("cuda" if (device in ("cuda", "auto") and torch.cuda.is_available()) else "cpu")
        self.module = None

    async def load(self) -> None:
        self.module = torch.jit.load(self.uri, map_location=self.device)
        self.module.eval()
        LOG.info('torchscript model loaded uri="%s" device=%s', self.uri, self.device)

    async def predict_batch(self, batch: List[Any], params: Optional[Dict[str, Any]] = None) -> List[Any]:
        if self.module is None:
            raise RunnerError("model not loaded")
        with torch.no_grad():
            # Convert to tensor batch; assume single tensor input
            tens = _to_tensor(batch, device=self.device)
            out = self.module(tens)
            return _from_tensor(out)


class PythonFunctionRunner(BaseRunner):
    name = "python"

    def __init__(self, callable_uri: str):
        # module:function
        if ":" not in callable_uri:
            raise RunnerError("python runner expects 'module:function' in NF_MODEL_URI")
        mod, fn = callable_uri.split(":", 1)
        self.mod_name = mod
        self.fn_name = fn
        self.fn = None

    async def load(self) -> None:
        mod = importlib.import_module(self.mod_name)
        fn = getattr(mod, self.fn_name, None)
        if not callable(fn):
            raise RunnerError(f"callable {self.mod_name}:{self.fn_name} not found")
        self.fn = fn
        LOG.info('python function loaded "%s:%s"', self.mod_name, self.fn_name)

    async def predict_batch(self, batch: List[Any], params: Optional[Dict[str, Any]] = None) -> List[Any]:
        if self.fn is None:
            raise RunnerError("callable not loaded")
        # fn should accept list[Any], optional params, and return list[Any]
        out = self.fn(batch, params or {})
        if not isinstance(out, list):
            raise RunnerError("python function must return list")
        return out


# -------------------------------
# Batch queue and worker
# -------------------------------

class _Work:
    __slots__ = ("data", "params", "future", "enq_time")
    def __init__(self, data: Any, params: Optional[Dict[str, Any]]):
        self.data = data
        self.params = params
        self.future: asyncio.Future = asyncio.get_event_loop().create_future()
        self.enq_time = time.time()

class Batcher:
    def __init__(self, runner_getter, max_size: int, max_latency_ms: int, timeout_s: float, concurrency: int):
        self._q: asyncio.Queue[_Work] = asyncio.Queue()
        self._runner_getter = runner_getter
        self._max = max_size
        self._lat = max_latency_ms / 1000.0
        self._timeout = timeout_s
        self._sem = asyncio.Semaphore(concurrency)
        self._task: Optional[asyncio.Task] = None
        self._running = asyncio.Event()

    async def start(self):
        self._running.set()
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._running.clear()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def submit(self, data: Any, params: Optional[Dict[str, Any]]) -> Any:
        work = _Work(data, params)
        await self._q.put(work)
        return await asyncio.wait_for(work.future, timeout=self._timeout)

    async def _loop(self):
        while self._running.is_set():
            try:
                first = await asyncio.wait_for(self._q.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            batch = [first]
            start = first.enq_time
            # coalesce
            while len(batch) < self._max:
                wait_left = max(0.0, self._lat - (time.time() - start))
                if wait_left <= 0:
                    break
                try:
                    nxt = await asyncio.wait_for(self._q.get(), timeout=wait_left)
                    batch.append(nxt)
                except asyncio.TimeoutError:
                    break

            # run batch
            asyncio.create_task(self._run_batch(batch))

    async def _run_batch(self, items: List[_Work]):
        async with self._sem:
            try:
                runner = self._runner_getter()
                payload, params = _merge_batch(items)
                preds = await asyncio.wait_for(runner.predict_batch(payload, params), timeout=self._timeout)
                if not isinstance(preds, list) or len(preds) != len(items):
                    raise RunnerError("runner returned unexpected output shape")
                for it, out in zip(items, preds):
                    _set_future(it.future, out)
            except Exception as e:
                for it in items:
                    _set_future_exc(it.future, e)


def _merge_batch(items: List[_Work]) -> Tuple[List[Any], Dict[str, Any]]:
    payload = [w.data for w in items]
    # Merge params shallowly: last wins
    merged: Dict[str, Any] = {}
    for w in items:
        if w.params:
            merged.update(w.params)
    return payload, merged


def _set_future(fut: asyncio.Future, value: Any) -> None:
    if not fut.done():
        fut.set_result(value)

def _set_future_exc(fut: asyncio.Future, exc: Exception) -> None:
    if not fut.done():
        fut.set_exception(exc)


# -------------------------------
# I/O schema
# -------------------------------

class PredictRequest(BaseModel):
    # Either provide instances (batched) or a single "inputs"
    instances: Optional[List[Any]] = None
    inputs: Optional[Any] = None
    parameters: Optional[Dict[str, Any]] = None

    @root_validator
    def _one_of(cls, values):
        if values.get("instances") is None and values.get("inputs") is None:
            raise ValueError("either 'instances' or 'inputs' must be provided")
        return values

class PredictResponse(BaseModel):
    model: str
    version: str
    took_ms: float
    predictions: List[Any]

class DescribeResponse(BaseModel):
    model: str
    version: str
    runner: str
    device: str
    batching: Dict[str, Any]


# -------------------------------
# Metrics (optional)
# -------------------------------

if S.enable_metrics and Counter and Histogram and Gauge:
    MET_REQ = Counter("nf_serving_requests_total", "Total HTTP requests", ["path", "method", "code"])
    MET_LAT = Histogram("nf_serving_request_latency_seconds", "Request latency", ["path", "method"])
    MET_INF = Histogram("nf_serving_infer_latency_seconds", "Inference latency", ["runner"])
    MET_ERR = Counter("nf_serving_errors_total", "Errors", ["type"])
    MET_READY = Gauge("nf_serving_ready", "Readiness (1/0)")
else:
    MET_REQ = MET_LAT = MET_INF = MET_ERR = MET_READY = None  # type: ignore


def _metrics_count(req: Request, code: int, start: float):
    if MET_REQ and MET_LAT:
        path = req.scope.get("path", "")
        MET_REQ.labels(path=path, method=req.method, code=str(code)).inc()
        MET_LAT.labels(path=path, method=req.method).observe(max(0.0, time.time() - start))


# -------------------------------
# Scope check (integration with AuthMiddleware)
# -------------------------------

def _require_scope(req: Request, scope: str) -> None:
    p = getattr(req.state, "principal", None)
    has = getattr(p, "has_scope", None)
    if callable(has) and has(scope):
        return
    raise HTTPException(status_code=403, detail="Missing required scope")


# -------------------------------
# App lifecycle
# -------------------------------

app = FastAPI(title="Neuroforge Serving", version="1.0.0")

if S.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(S.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

router = APIRouter(prefix="/v1")

_runner_lock = asyncio.Lock()
_runner: Optional[BaseRunner] = None
_batcher: Optional[Batcher] = None
_ready: bool = False


def _select_runner() -> BaseRunner:
    if _runner is None:
        raise RuntimeError("runner not initialized")
    return _runner


async def _init_runner() -> None:
    global _runner, _batcher, _ready
    async with _runner_lock:
        _ready = False
        _runner = await _build_runner(S)
        await _runner.load()
        await _runner.warmup()
        _batcher = Batcher(lambda: _runner, S.max_batch_size, S.max_batch_latency_ms, S.inference_timeout_s, S.concurrency_limit)
        if S.enable_batching:
            await _batcher.start()
        _ready = True
        if MET_READY:
            MET_READY.set(1.0)
        LOG.info("serving ready model=%s version=%s runner=%s", S.model_uri, S.model_version, _runner.name)


async def _shutdown_runner() -> None:
    global _batcher, _ready
    _ready = False
    if MET_READY:
        MET_READY.set(0.0)
    if _batcher:
        with contextlib.suppress(Exception):
            await _batcher.stop()
        _batcher = None


async def _build_runner(cfg: Settings) -> BaseRunner:
    t = cfg.model_type.lower().strip()
    if t == "onnx":
        return ONNXRuntimeRunner(cfg.model_uri, cfg.device)
    if t == "torchscript":
        return TorchScriptRunner(cfg.model_uri, cfg.device)
    if t == "python":
        return PythonFunctionRunner(cfg.model_uri)
    raise RunnerError(f"unknown model_type: {cfg.model_type}")


@app.on_event("startup")
async def on_startup():
    await _init_runner()
    # graceful shutdown signals (uvicorn handles SIGTERM, but add safety)
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(Exception):
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(_on_signal(s)))


@app.on_event("shutdown")
async def on_shutdown():
    await _shutdown_runner()


async def _on_signal(sig):
    LOG.warning("received signal %s, starting graceful shutdown", sig)
    await _shutdown_runner()


# -------------------------------
# Health & metrics
# -------------------------------

@app.get("/healthz/live", include_in_schema=False)
async def live():
    return {"status": "ok"}

@app.get("/healthz/ready", include_in_schema=False)
async def ready():
    return {"status": "ready" if _ready else "starting", "ready": _ready}

@app.get("/metrics", include_in_schema=False)
async def metrics():
    if not (S.enable_metrics and Counter):
        return Response(content=b"", media_type=CONTENT_TYPE_LATEST)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# -------------------------------
# Describe & reload
# -------------------------------

@router.get("/models/describe", response_model=DescribeResponse)
async def describe():
    device = S.device
    runner = _select_runner()
    return DescribeResponse(
        model=S.model_uri,
        version=S.model_version,
        runner=runner.name,
        device=device,
        batching={
            "enabled": bool(S.enable_batching),
            "max_batch_size": S.max_batch_size,
            "max_batch_latency_ms": S.max_batch_latency_ms,
        },
    )

@router.post("/models/reload", status_code=204)
async def reload_model(req: Request, body: Dict[str, Any] = Body(default=None)):
    if not S.allow_reload:
        raise HTTPException(status_code=403, detail="Reload disabled")
    # Require admin scope if middleware is present
    with contextlib.suppress(Exception):
        _require_scope(req, "serving:admin")
    # Allow overriding subset of settings at runtime
    await _shutdown_runner()
    if body:
        # limited overrides
        for k in ("model_type", "model_uri", "model_version", "device"):
            if k in body and hasattr(S, k):
                setattr(S, k, body[k])
    await _init_runner()
    return Response(status_code=204)


# -------------------------------
# Predict endpoints
# -------------------------------

@router.post("/predict", response_model=PredictResponse)
async def predict(req: Request, payload: PredictRequest):
    started = time.time()
    rid = request_id(req)
    if not _ready:
        raise HTTPException(status_code=503, detail="Model not ready")

    runner = _select_runner()
    params = payload.parameters or {}

    # Build batch (compat: if instances absent, wrap inputs)
    if payload.instances is not None:
        batch = payload.instances
    else:
        batch = [payload.inputs]

    try:
        if S.enable_batching and _batcher:
            preds = await _batcher.submit(batch, params)
        else:
            # Direct call without queuing
            with _infer_timer(runner.name):
                preds = await asyncio.wait_for(runner.predict_batch(batch, params), timeout=S.inference_timeout_s)
        took_ms = (time.time() - started) * 1000.0
        resp = PredictResponse(
            model=S.model_uri,
            version=S.model_version,
            took_ms=round(took_ms, 3),
            predictions=preds,
        )
        return resp
    except asyncio.TimeoutError:
        if MET_ERR:
            MET_ERR.labels(type="timeout").inc()
        LOG.warning('timeout infer rid=%s', rid)
        raise HTTPException(status_code=504, detail="Inference timeout")
    except RunnerError as e:
        if MET_ERR:
            MET_ERR.labels(type="runner").inc()
        LOG.error('runner error rid=%s err=%s', rid, str(e))
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        if MET_ERR:
            MET_ERR.labels(type="internal").inc()
        LOG.exception('internal error rid=%s', rid)
        raise HTTPException(status_code=500, detail="Internal error")
    finally:
        _metrics_count(req, 200, started)


# Batch variant accepting list of requests; replies aligned
class BatchPredictRequest(BaseModel):
    requests: List[PredictRequest]

class BatchPredictResponse(BaseModel):
    results: List[PredictResponse]

@router.post("/batchPredict", response_model=BatchPredictResponse)
async def batch_predict(req: Request, body: BatchPredictRequest):
    started = time.time()
    if not _ready:
        raise HTTPException(status_code=503, detail="Model not ready")

    results: List[PredictResponse] = []
    for item in body.requests:
        # Execute sequentially here; batching inside Batcher will coalesce them anyway
        res = await predict(req, item)
        results.append(res)
    _metrics_count(req, 200, started)
    return BatchPredictResponse(results=results)


# -------------------------------
# Helpers: numpy/torch conversions and timers
# -------------------------------

def _to_numpy(batch: List[Any]):
    if np is None:
        raise RunnerError("numpy is required for onnxruntime inputs")
    arr = np.asarray(batch)
    return arr

def _from_numpy(arr):
    if hasattr(arr, "tolist"):
        return [x for x in arr.tolist()]
    return list(arr)

def _slice_output(arr, i: int):
    # Handles numpy or python lists
    try:
        return arr[i].tolist() if hasattr(arr, "tolist") else arr[i]
    except Exception:
        # fall back for scalar outputs
        return arr

def _fallback_shape(shape: Iterable[Any]) -> Tuple[int, ...]:
    # Replace dynamic dims with 1
    shp: List[int] = []
    for d in list(shape):
        if isinstance(d, int) and d > 0:
            shp.append(d)
        else:
            shp.append(1)
    return tuple(shp)

def _fallback_dtype(onnx_type: str) -> Any:
    if np is None:
        return None
    mapping = {
        "tensor(float)": np.float32,
        "tensor(double)": np.float64,
        "tensor(float16)": np.float16,
        "tensor(int64)": np.int64,
        "tensor(int32)": np.int32,
        "tensor(bool)": np.bool_,
    }
    return mapping.get(onnx_type, np.float32)

def _to_tensor(batch: List[Any], device) -> "torch.Tensor":
    if torch is None:
        raise RunnerError("torch is required for torchscript inputs")
    return torch.as_tensor(batch, device=device)

@contextlib.contextmanager
def _infer_timer(runner_name: str):
    start = time.time()
    try:
        yield
    finally:
        if MET_INF:
            MET_INF.labels(runner=runner_name).observe(max(0.0, time.time() - start))


# -------------------------------
# Mount router
# -------------------------------

app.include_router(router, prefix="/v1")


# -------------------------------
# Entrypoint (uvicorn)
# -------------------------------

def main():
    # uvicorn neuroforge.serving.server:app --host 0.0.0.0 --port 8080
    import uvicorn
    uvicorn.run("neuroforge.serving.server:app", host=S.host, port=S.port, reload=False, log_level=_log_level.lower())

if __name__ == "__main__":
    main()
