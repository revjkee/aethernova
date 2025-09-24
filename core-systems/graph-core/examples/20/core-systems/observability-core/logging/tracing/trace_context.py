import uuid
import contextvars
from typing import Dict, Optional

# Контекст текущей трассировки, безопасный для асинхронного исполнения
_trace_context_var = contextvars.ContextVar("trace_context", default={})

# Ключи по W3C + расширения Genesis
TRACE_KEYS = {
    "trace_id": "trace-id",
    "span_id": "span-id",
    "parent_span_id": "parent-id",
    "ai_tag": "x-ai-tag",
    "trust_level": "x-trust-lvl"
}


def generate_trace_id() -> str:
    return uuid.uuid4().hex


def generate_span_id() -> str:
    return uuid.uuid4().hex[:16]


def start_trace_context(ai_tag: Optional[str] = None, trust_level: str = "trusted") -> Dict[str, str]:
    """
    Инициализирует новый контекст трассировки
    """
    context = {
        "trace-id": generate_trace_id(),
        "span-id": generate_span_id(),
        "parent-id": "",
        "x-ai-tag": ai_tag or "none",
        "x-trust-lvl": trust_level
    }
    _trace_context_var.set(context)
    return context


def inject_trace_context(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Добавляет текущий trace-контекст в HTTP-заголовки или RPC-метаданные
    """
    ctx = _trace_context_var.get()
    for key, header in TRACE_KEYS.items():
        if header in ctx:
            headers[header] = ctx[header]
    return headers


def extract_trace_context(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Извлекает trace-контекст из HTTP-заголовков или gRPC metadata
    """
    extracted = {}
    for key, header in TRACE_KEYS.items():
        if header in headers:
            extracted[header] = headers[header]
    if "trace-id" not in extracted:
        extracted["trace-id"] = generate_trace_id()
    if "span-id" not in extracted:
        extracted["span-id"] = generate_span_id()
    _trace_context_var.set(extracted)
    return extracted


def get_current_context() -> Dict[str, str]:
    return _trace_context_var.get()


def get_trace_id() -> str:
    return _trace_context_var.get().get("trace-id", "unknown")


def get_span_id() -> str:
    return _trace_context_var.get().get("span-id", "unknown")


def get_ai_tag() -> str:
    return _trace_context_var.get().get("x-ai-tag", "none")


def get_trust_level() -> str:
    return _trace_context_var.get().get("x-trust-lvl", "unverified")
