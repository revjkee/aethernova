import time
import threading
import contextvars
import logging
import uuid
from typing import Callable, Dict, Optional, Any
from prometheus_client import Summary, Gauge

# === Метрики Prometheus ===
LATENCY_SUMMARY = Summary("genesis_latency_seconds", "Latency measurement in seconds", ["operation", "component", "zone"])
ACTIVE_LATENCY_GAUGE = Gauge("genesis_latency_active", "Currently active latency spans", ["component"])

# === Контекст запроса ===
_latency_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("latency_context", default={})

# === Логгер ===
logger = logging.getLogger("latency_tracker")
logger.setLevel(logging.INFO)

# === Уровни зон в архитектуре ===
DEFAULT_ZONE = "core"

class LatencySpan:
    def __init__(self, operation: str, component: str, zone: str = DEFAULT_ZONE):
        self.operation = operation
        self.component = component
        self.zone = zone
        self.start_time = time.perf_counter()
        self.trace_id = str(uuid.uuid4())
        self.context = {
            "operation": operation,
            "component": component,
            "zone": zone,
            "trace_id": self.trace_id,
            "timestamp": time.time()
        }
        ACTIVE_LATENCY_GAUGE.labels(component=component).inc()
        logger.debug(f"[{self.trace_id}] Begin latency span: {operation} in {component}/{zone}")

    def finish(self, extra_context: Optional[Dict[str, Any]] = None):
        duration = time.perf_counter() - self.start_time
        LATENCY_SUMMARY.labels(operation=self.operation, component=self.component, zone=self.zone).observe(duration)
        ACTIVE_LATENCY_GAUGE.labels(component=self.component).dec()
        merged = self.context.copy()
        if extra_context:
            merged.update(extra_context)
        merged["duration_sec"] = round(duration, 6)
        logger.info(f"[{self.trace_id}] Latency: {merged}")
        return merged

def track_latency(operation: str, component: str, zone: str = DEFAULT_ZONE):
    """ Декоратор для автотрекинга задержек функций """
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            span = LatencySpan(operation=operation, component=component, zone=zone)
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                span.finish()
        return wrapper
    return decorator

def set_latency_context(**kwargs):
    ctx = _latency_context.get().copy()
    ctx.update(kwargs)
    _latency_context.set(ctx)

def get_latency_context() -> Dict[str, Any]:
    return _latency_context.get()

def start_background_latency_probe(name: str, interval_sec: int, probe_func: Callable[[], float]):
    """ Запускает фоновый трекер, измеряющий задержки по интервалу """
    def probe_loop():
        while True:
            try:
                delay = probe_func()
                LATENCY_SUMMARY.labels(operation=name, component="background_probe", zone="system").observe(delay)
                logger.info(f"[PROBE] {name} = {round(delay, 4)}s")
            except Exception as e:
                logger.error(f"[PROBE_ERROR] {name}: {e}")
            time.sleep(interval_sec)
    threading.Thread(target=probe_loop, daemon=True).start()
