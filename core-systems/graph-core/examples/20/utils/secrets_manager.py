# utils/secrets_manager.py

import os
import hvac
from functools import lru_cache
from typing import Optional
from utils.logger import logger

VAULT_ENABLED = os.getenv("VAULT_ENABLED", "false").lower() == "true"
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

if VAULT_ENABLED:
    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        if not client.is_authenticated():
            raise ConnectionError("Vault authentication failed.")
    except Exception as e:
        logger.error(f"[Vault] Initialization failed: {e}")
        client = None
else:
    client = None


class SecretRetrievalError(Exception):
    pass


@lru_cache(maxsize=None)
def get_secret(path: str, key: str, version: Optional[int] = None, fallback_env: Optional[str] = None) -> str:
    """
    Получение секрета из Vault (или ENV fallback).

    Args:
        path (str): путь к секрету в Vault (например, "kv/data/myapp")
        key (str): ключ внутри секрета
        version (int, optional): версия секрета (Vault KV v2)
        fallback_env (str, optional): ключ ENV как fallback

    Returns:
        str: значение секрета

    Raises:
        SecretRetrievalError
    """
    # fallback через ENV если Vault отключён
    if not client or not client.is_authenticated():
        val = os.getenv(fallback_env or key)
        if val is None:
            raise SecretRetrievalError(f"[Fallback] Secret not found in env: {fallback_env or key}")
        logger.warning(f"[Fallback] Using env var: {fallback_env or key}")
        return val

    try:
        read_args = {"path": path}
        if version is not None:
            read_args["version"] = version

        result = client.secrets.kv.v2.read_secret_version(**read_args)
        value = result["data"]["data"].get(key)

        if value is None:
            raise SecretRetrievalError(f"[Vault] Key '{key}' not found at path '{path}'")

        logger.debug(f"[Vault] Secret fetched from: {path} key={key}")
        return value

    except Exception as e:
        raise SecretRetrievalError(f"[Vault] Failed to retrieve secret: {e}")
