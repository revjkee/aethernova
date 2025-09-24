# keyvault/agent_sdk/auto_seal_client.py

import logging
import asyncio
import base64
from typing import Dict, Optional

from keyvault.utils.device_fingerprint import get_device_id
from keyvault.utils.context_utils import get_current_context_hash
from keyvault.config.vault_config_loader import get_seal_config
from keyvault.core.signing_engine import sign_payload_cli
from keyvault.agent_sdk.agent_keyvault_client import AgentKeyVaultClient

logger = logging.getLogger("auto_seal_client")
logger.setLevel(logging.INFO)


class AutoSealClient:
    def __init__(self, agent_id: str, jwt_token: str):
        self.agent_id = agent_id
        self.jwt_token = jwt_token
        self.config = get_seal_config()
        self.api_url = self.config["seal_url"]
        self.client = AgentKeyVaultClient(agent_id=agent_id, jwt_token=jwt_token)
        self.unsealed = False

    def _build_unseal_payload(self) -> Dict:
        context_hash = get_current_context_hash(self.agent_id)
        fingerprint = get_device_id()
        signature = base64.b64encode(sign_payload_cli(self.jwt_token.encode())).decode()

        return {
            "agent_id": self.agent_id,
            "context_hash": context_hash,
            "device_fingerprint": fingerprint,
            "signature": signature,
            "intent": "auto_unseal_request"
        }

    async def attempt_unseal(self) -> bool:
        """
        Попытка автоматической разблокировки хранилища.
        """
        if self.unsealed:
            logger.debug("Хранилище уже разблокировано.")
            return True

        try:
            payload = self._build_unseal_payload()
            logger.info(f"[{self.agent_id}] → Попытка автоматической разблокировки...")

            async with self.client.session.post(
                f"{self.api_url}/vault/unseal",
                json=payload,
                headers=self.client._build_headers()
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    if result.get("status") == "unsealed":
                        logger.info(f"[{self.agent_id}] Хранилище успешно разблокировано.")
                        self.unsealed = True
                        return True
                    else:
                        logger.warning(f"[{self.agent_id}] Ответ сервера: {result}")
                        return False
                else:
                    err = await resp.text()
                    logger.error(f"[{self.agent_id}] Ошибка unseal-запроса: {resp.status} {err}")
                    return False

        except Exception as e:
            logger.exception(f"[{self.agent_id}] Исключение при unseal: {str(e)}")
            return False

    async def close(self):
        await self.client.close()
