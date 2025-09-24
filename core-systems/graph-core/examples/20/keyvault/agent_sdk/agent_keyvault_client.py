# keyvault/agent_sdk/agent_keyvault_client.py

import aiohttp
import asyncio
import base64
import logging
from typing import Optional, Dict, Any

from keyvault.utils.device_fingerprint import get_device_id
from keyvault.utils.context_utils import get_current_context_hash
from keyvault.core.signing_engine import sign_payload_cli
from keyvault.config.vault_config_loader import get_sdk_config

logger = logging.getLogger("agent_sdk_client")
logger.setLevel(logging.INFO)

class AgentKeyVaultClient:
    def __init__(self, agent_id: str, jwt_token: str):
        self.agent_id = agent_id
        self.jwt_token = jwt_token
        self.config = get_sdk_config()
        self.api_url = self.config["api_url"]
        self.session = aiohttp.ClientSession()
        self.headers = self._build_headers()

    def _build_headers(self) -> Dict[str, str]:
        context_hash = get_current_context_hash(self.agent_id)
        signature = base64.b64encode(sign_payload_cli(self.jwt_token.encode())).decode()

        return {
            "Authorization": f"Bearer {self.jwt_token}",
            "X-Agent-Signature": signature,
            "X-Device-Fingerprint": get_device_id(),
            "X-Context-Hash": context_hash,
            "X-Client-Version": "TeslaAI-AgentSDK/1.0"
        }

    async def create_secret(self, key: str, value: str, scope: str = "global", metadata: Optional[Dict] = None) -> bool:
        payload = {
            "key": key,
            "value": value,
            "scope": scope,
            "metadata": metadata or {"created_by": self.agent_id}
        }

        async with self.session.post(f"{self.api_url}/secret/create", headers=self.headers, json=payload) as resp:
            if resp.status == 201:
                logger.info(f"[{self.agent_id}] Секрет создан: {key}")
                return True
            else:
                err = await resp.text()
                logger.warning(f"[{self.agent_id}] Ошибка создания: {resp.status} {err}")
                return False

    async def get_secret(self, key: str) -> Optional[Dict[str, Any]]:
        payload = {"key": key}
        async with self.session.post(f"{self.api_url}/secret/get", headers=self.headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                logger.info(f"[{self.agent_id}] Получен секрет: {key}")
                return data
            else:
                err = await resp.text()
                logger.warning(f"[{self.agent_id}] Ошибка получения: {resp.status} {err}")
                return None

    async def verify_token(self, token: str) -> bool:
        payload = {"token": token}
        async with self.session.post(f"{self.api_url}/token/verify", headers=self.headers, json=payload) as resp:
            if resp.status == 200:
                logger.info(f"[{self.agent_id}] Эфемерный токен действителен.")
                return True
            else:
                logger.warning(f"[{self.agent_id}] Неверный токен: {resp.status}")
                return False

    async def close(self):
        await self.session.close()
