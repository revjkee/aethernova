# keyvault/access/ephemeral_token_engine.py

import time
import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any

from keyvault.core.secret_manager import store_ephemeral_token, revoke_ephemeral_token, retrieve_token_metadata
from keyvault.utils.device_fingerprint import get_device_id
from keyvault.utils.geoip import resolve_ip_zone
from keyvault.audit.token_logger import log_token_event


class TokenValidationError(Exception):
    pass


class EphemeralTokenEngine:
    def __init__(self, secret_salt: str):
        self.secret_salt = secret_salt.encode()

    def generate_token(self,
                       actor_id: str,
                       resource_id: str,
                       action: str,
                       ttl_seconds: int = 300,
                       context: Optional[Dict[str, Any]] = None) -> str:
        """
        Генерация короткоживущего токена доступа для указанного действия и ресурса.
        """
        issued_at = int(time.time())
        expires_at = issued_at + ttl_seconds
        context = context or {}

        payload = {
            "actor_id": actor_id,
            "resource_id": resource_id,
            "action": action,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "ip_zone": resolve_ip_zone(context.get("ip_address", "")),
            "device_id": get_device_id(),
            "fingerprint": context.get("browser_fingerprint", "")
        }

        # Хэширование токена с HMAC
        raw = f"{actor_id}:{resource_id}:{action}:{issued_at}:{expires_at}"
        token = hmac.new(self.secret_salt, raw.encode(), hashlib.sha3_256).hexdigest()

        # Хранилище метаданных
        store_ephemeral_token(token, payload)

        log_token_event(actor_id, "issued", token, payload)
        return token

    def verify_token(self, token: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Проверка подлинности и срока действия токена.
        """
        context = context or {}
        payload = retrieve_token_metadata(token)
        now = int(time.time())

        if not payload:
            raise TokenValidationError("Токен не найден или уже отозван.")

        if now > payload["expires_at"]:
            raise TokenValidationError("Срок действия токена истёк.")

        if payload["device_id"] != get_device_id():
            raise TokenValidationError("Устройство не соответствует оригиналу.")

        if payload["ip_zone"] != resolve_ip_zone(context.get("ip_address", "")):
            raise TokenValidationError("IP зона изменилась, доступ запрещён.")

        if payload["fingerprint"] and payload["fingerprint"] != context.get("browser_fingerprint", ""):
            raise TokenValidationError("Нарушена целостность отпечатка клиента.")

        log_token_event(payload["actor_id"], "verified", token, payload)
        return payload

    def revoke_token(self, token: str):
        """
        Принудительный отзыв токена (например, при компрометации).
        """
        revoke_ephemeral_token(token)
        log_token_event("system", "revoked", token, reason="manual revocation")
