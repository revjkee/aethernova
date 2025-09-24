# message-brokers/adapters/secure_middleware.py

import time
import hmac
import hashlib
import logging
import gnupg
import os
from typing import Dict, Any, Callable, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("secure_middleware")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [SECURE-MW] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

gpg = gnupg.GPG(gnupghome=os.getenv("GPG_HOME", "~/.gnupg"))


class MiddlewareSettings(BaseModel):
    hmac_secret: str
    allowed_roles: Optional[list] = Field(default_factory=lambda: ["admin", "system", "supervisor"])
    gpg_required: bool = True
    trace_enabled: bool = True
    max_delay_sec: int = 30
    replay_protection: bool = True


class SecureMessage(BaseModel):
    message_id: str
    timestamp: float
    sender_id: str
    role: str
    payload: Dict[str, Any]
    hmac_signature: Optional[str]
    gpg_signature: Optional[str]

    def compute_hmac(self, secret: str) -> str:
        raw = f"{self.message_id}{self.timestamp}{self.sender_id}"
        return hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

    def verify_hmac(self, secret: str) -> bool:
        if not self.hmac_signature:
            return False
        expected = self.compute_hmac(secret)
        return hmac.compare_digest(expected, self.hmac_signature)

    def verify_gpg(self) -> bool:
        if not self.gpg_signature:
            return False
        signed_payload = f"{self.message_id}:{self.sender_id}:{self.timestamp}"
        verified = gpg.verify_data(self.gpg_signature, signed_payload.encode())
        return verified.valid


class SecureMiddleware:
    def __init__(self, settings: MiddlewareSettings):
        self.settings = settings
        self.replay_cache = {}

    def _is_expired(self, msg: SecureMessage) -> bool:
        now = time.time()
        delay = abs(now - msg.timestamp)
        return delay > self.settings.max_delay_sec

    def _is_replayed(self, msg: SecureMessage) -> bool:
        if msg.message_id in self.replay_cache:
            return True
        self.replay_cache[msg.message_id] = time.time()
        # Trim old entries
        self.replay_cache = {
            k: v for k, v in self.replay_cache.items() if time.time() - v < 300
        }
        return False

    def _trace(self, msg: SecureMessage):
        trace_data = {
            "trace_event": "secure_msg_pass",
            "message_id": msg.message_id,
            "sender": msg.sender_id,
            "role": msg.role,
            "timestamp": msg.timestamp,
        }
        logger.info(f"[TRACE] {trace_data}")

    def process(self, msg: SecureMessage, callback: Callable[[Dict[str, Any]], None]):
        if msg.role not in self.settings.allowed_roles:
            logger.warning(f"[BLOCKED] Unauthorized role: {msg.role}")
            return

        if self.settings.replay_protection and self._is_replayed(msg):
            logger.warning(f"[REPLAY ATTEMPT] message_id: {msg.message_id}")
            return

        if self._is_expired(msg):
            logger.warning(f"[EXPIRED] message_id: {msg.message_id}")
            return

        if not msg.verify_hmac(self.settings.hmac_secret):
            logger.warning(f"[HMAC FAIL] message_id: {msg.message_id}")
            return

        if self.settings.gpg_required and not msg.verify_gpg():
            logger.warning(f"[GPG FAIL] message_id: {msg.message_id}")
            return

        if self.settings.trace_enabled:
            self._trace(msg)

        try:
            callback(msg.payload)
        except Exception as e:
            logger.error(f"[HANDLER ERROR] Failed to process message {msg.message_id}: {e}")
