# keyvault/agent_sdk/decorators.py

import functools
import asyncio
import logging
from typing import Callable, Optional

from keyvault.agent_sdk.agent_keyvault_client import AgentKeyVaultClient
from keyvault.audit.audit_logger import log_access_event
from keyvault.core.signing_engine import sign_action_payload

logger = logging.getLogger("agent_decorators")
logger.setLevel(logging.INFO)


def requires_secret(secret_name: str,
                    param_name: str = "secret_value",
                    raise_on_fail: bool = True):
    """
    Декоратор, автоматически извлекающий секрет из KeyVault и подставляющий его как аргумент.
    Используется в агентных действиях.
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            client: Optional[AgentKeyVaultClient] = kwargs.get("kv_client")
            if not client:
                logger.error("KeyVault client not provided in kwargs")
                if raise_on_fail:
                    raise RuntimeError("Missing KeyVault client")
                return await func(*args, **kwargs)

            secret = await client.get_secret(secret_name)
            if not secret:
                logger.warning(f"Failed to retrieve secret: {secret_name}")
                if raise_on_fail:
                    raise PermissionError(f"Access denied to secret: {secret_name}")
                return await func(*args, **kwargs)

            kwargs[param_name] = secret["value"]
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def signed_action(action_name: Optional[str] = None,
                  audit: bool = True,
                  attach_signature: bool = True):
    """
    Декоратор, создающий подпись действия агента и, опционально, логирующий его.
    Может использоваться с внешними аудиторскими или ZK-подтверждающими системами.
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            agent_id = kwargs.get("agent_id", "unknown-agent")
            payload = {
                "function": func.__name__,
                "action": action_name or func.__name__,
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items() if k != "kv_client"},
            }

            signature = sign_action_payload(payload, agent_id)
            if attach_signature:
                kwargs["action_signature"] = signature

            if audit:
                log_access_event(
                    actor_id=agent_id,
                    resource_id=payload["action"],
                    action="agent_action_signed",
                    success=True,
                    metadata={"signature": signature}
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
