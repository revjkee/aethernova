# observability/dashboards/middlewares/context_injector.py

import logging
import contextvars
from typing import Optional


# Контекстные переменные для трассировки и пользователя
trace_id_var = contextvars.ContextVar("trace_id", default=None)
user_id_var = contextvars.ContextVar("user_id", default=None)
span_id_var = contextvars.ContextVar("span_id", default=None)
environment_var = contextvars.ContextVar("environment", default="production")
tactic_var = contextvars.ContextVar("tactic", default=None)
technique_id_var = contextvars.ContextVar("technique_id", default=None)
signal_var = contextvars.ContextVar("signal", default=None)


class ContextInjector(logging.Filter):
    """
    Лог-фильтр для внедрения контекста из contextvars в лог-записи.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = trace_id_var.get()
        record.user_id = user_id_var.get()
        record.span_id = span_id_var.get()
        record.environment = environment_var.get()
        record.tactic = tactic_var.get()
        record.technique_id = technique_id_var.get()
        record.signal = signal_var.get()
        return True


def set_context(
    trace_id: Optional[str] = None,
    user_id: Optional[str] = None,
    span_id: Optional[str] = None,
    environment: Optional[str] = None,
    tactic: Optional[str] = None,
    technique_id: Optional[str] = None,
    signal: Optional[str] = None,
):
    if trace_id:
        trace_id_var.set(trace_id)
    if user_id:
        user_id_var.set(user_id)
    if span_id:
        span_id_var.set(span_id)
    if environment:
        environment_var.set(environment)
    if tactic:
        tactic_var.set(tactic)
    if technique_id:
        technique_id_var.set(technique_id)
    if signal:
        signal_var.set(signal)


def clear_context():
    """
    Очищает все переменные контекста.
    """
    trace_id_var.set(None)
    user_id_var.set(None)
    span_id_var.set(None)
    environment_var.set("production")
    tactic_var.set(None)
    technique_id_var.set(None)
    signal_var.set(None)
