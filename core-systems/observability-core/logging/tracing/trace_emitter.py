import time
import uuid
import logging
import json
import threading
from contextlib import contextmanager
from typing import Optional, Dict, Any

from monitoring.logging.tracing.trace_context import TraceContext
from monitoring.logging.tracing.span_sampler import should_sample_span
from monitoring.logging.latency.latency_tracker import track_latency  # трекаем latency внутри спана
from monitoring.alerting.receivers.webhook_dispatcher import dispatch_span_event  # опциональная отправка в алертер

logger = logging.getLogger("trace_emitter")
logger.setLevel(logging.INFO)

TRACE_EXPORTERS = {
    "console": True,
    "tempo": True,
    "file": "/var/log/teslaai/traces.log",
    "webhook": True
}

def generate_span_id() -> str:
    return uuid.uuid4().hex

def get_current_timestamp_ns() -> int:
    return int(time.time() * 1e9)

class TraceEmitter:
    def __init__(self, trace_context: Optional[TraceContext] = None):
        self.trace_context = trace_context or TraceContext()

    def emit_span(self, name: str, attributes: Dict[str, Any], status: str = "OK"):
        if not should_sample_span(name):
            return

        span_id = generate_span_id()
        parent_id = self.trace_context.current_span_id or None
        trace_id = self.trace_context.trace_id or generate_span_id()

        start_time_ns = get_current_timestamp_ns()
        duration_ns = attributes.pop("duration_ns", None) or 0

        span = {
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_id,
            "name": name,
            "start_time_ns": start_time_ns,
            "duration_ns": duration_ns,
            "status": status,
            "attributes": attributes
        }

        self._export_span(span)
        self.trace_context.set_span(span_id, trace_id)

    def _export_span(self, span: dict):
        try:
            if TRACE_EXPORTERS["console"]:
                logger.info(f"[SPAN] {json.dumps(span, ensure_ascii=False)}")
            if TRACE_EXPORTERS["file"]:
                with open(TRACE_EXPORTERS["file"], "a") as f:
                    f.write(json.dumps(span) + "\n")
            if TRACE_EXPORTERS["webhook"]:
                dispatch_span_event(span)
            if TRACE_EXPORTERS["tempo"]:
                # отправка в OTLP/Tempo может быть реализована отдельно через otel_collector
                pass
        except Exception as e:
            logger.error(f"[TRACE_EMITTER] Failed to export span: {e}")

@contextmanager
def traced_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    context = TraceContext.get_thread_context()
    emitter = TraceEmitter(context)
    start_time = time.time()
    attributes = attributes or {}

    try:
        yield
        duration = int((time.time() - start_time) * 1e9)
        attributes["duration_ns"] = duration
        emitter.emit_span(name, attributes, status="OK")
    except Exception as e:
        duration = int((time.time() - start_time) * 1e9)
        attributes["duration_ns"] = duration
        attributes["error"] = str(e)
        emitter.emit_span(name, attributes, status="ERROR")
        raise

def emit_manual_span(name: str, attributes: Dict[str, Any], status: str = "OK"):
    context = TraceContext.get_thread_context()
    emitter = TraceEmitter(context)
    emitter.emit_span(name, attributes, status=status)

def start_background_heartbeat_trace(name: str, interval_sec: int = 60):
    def heartbeat():
        context = TraceContext()
        emitter = TraceEmitter(context)
        while True:
            emitter.emit_span(name, {"heartbeat": True}, status="OK")
            time.sleep(interval_sec)

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
