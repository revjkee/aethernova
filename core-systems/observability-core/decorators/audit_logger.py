import functools
import logging
import inspect
from datetime import datetime
from typing import Callable, Any, Dict, Optional

from contextvars import ContextVar

from config import settings
from core.security import get_current_user_id, get_request_id
from utils.time import utc_now

logger = logging.getLogger("audit")

# Контекст для хранения переменных на время запроса
audit_context: ContextVar[Dict[str, Any]] = ContextVar("audit_context", default={})

def set_audit_context(**kwargs):
    context = audit_context.get().copy()
    context.update(kwargs)
    audit_context.set(context)

def get_audit_context() -> Dict[str, Any]:
    return audit_context.get()

def audit_log(action: str, resource: Optional[str] = None):
    """
    Декоратор для логирования действий в формате аудита:
    - кто (user_id)
    - что (action)
    - над чем (resource)
    - когда (timestamp)
    - дополнительные поля: IP, request_id, RBAC роль, результат
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            user_id = await get_current_user_id()
            request_id = get_request_id()
            timestamp = utc_now().isoformat()
            role = get_audit_context().get("role", "unknown")
            ip = get_audit_context().get("ip", "unknown")
            method_name = func.__name__
            module_name = func.__module__

            # Параметры функции в человекочитаемом виде
            bound_args = inspect.signature(func).bind(*args, **kwargs)
            bound_args.apply_defaults()
            params = dict(bound_args.arguments)

            try:
                result = await func(*args, **kwargs)
                outcome = "success"
                return result
            except Exception as e:
                outcome = "error"
                raise e
            finally:
                logger.info({
                    "type": "audit",
                    "timestamp": timestamp,
                    "user_id": user_id,
                    "role": role,
                    "ip": ip,
                    "action": action,
                    "resource": resource,
                    "function": f"{module_name}.{method_name}",
                    "params": {k: str(v) for k, v in params.items()},
                    "request_id": request_id,
                    "result": outcome
                })
        return wrapper
    return decorator
