import contextvars
import uuid
from typing import Optional, Dict, Any

# Контекст переменных для текущего запроса или цепочки вызовов
_context_request_id = contextvars.ContextVar("latency_request_id", default=None)
_context_trace_id = contextvars.ContextVar("latency_trace_id", default=None)
_context_span_id = contextvars.ContextVar("latency_span_id", default=None)
_context_metadata = contextvars.ContextVar("latency_metadata", default={})


def set_latency_context(
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
):
    """ Установка контекста задержек для текущего запроса. """
    if request_id:
        _context_request_id.set(request_id)
    if trace_id:
        _context_trace_id.set(trace_id)
    if span_id:
        _context_span_id.set(span_id)
    if metadata:
        _context_metadata.set(metadata)


def clear_latency_context():
    """ Очистка контекста для завершённого запроса. """
    _context_request_id.set(None)
    _context_trace_id.set(None)
    _context_span_id.set(None)
    _context_metadata.set({})


def get_latency_context() -> Dict[str, Any]:
    """ Получение текущего latency-контекста. """
    return {
        "request_id": _context_request_id.get() or _generate_request_id(),
        "trace_id": _context_trace_id.get() or _generate_trace_id(),
        "span_id": _context_span_id.get() or _generate_span_id(),
        "metadata": _context_metadata.get(),
    }


def _generate_request_id() -> str:
    """ Генерация нового request_id, если не установлен. """
    rid = f"req-{uuid.uuid4().hex[:16]}"
    _context_request_id.set(rid)
    return rid


def _generate_trace_id() -> str:
    """ Генерация trace_id (обычно 16/32 символов UUID). """
    tid = uuid.uuid4().hex
    _context_trace_id.set(tid)
    return tid


def _generate_span_id() -> str:
    """ Генерация нового span_id (для вложенных вызовов). """
    sid = uuid.uuid4().hex[:16]
    _context_span_id.set(sid)
    return sid
