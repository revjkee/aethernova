import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any

class SentinelClient:
    """
    Асинхронный клиент для взаимодействия с Microsoft Sentinel API.
    Позволяет отправлять логи и события, а также управлять инцидентами в Sentinel.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str, resource_group: str, workspace_name: str):
        """
        :param tenant_id: Azure AD Tenant ID
        :param client_id: Azure AD Application (client) ID
        :param client_secret: Azure AD Application Secret
        :param subscription_id: Azure Subscription ID
        :param resource_group: Имя resource group
        :param workspace_name: Имя Log Analytics workspace (Sentinel workspace)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.token = None
        self.session = aiohttp.ClientSession()
        self._token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self._scope = "https://management.azure.com/.default"
        self._base_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"

    async def authenticate(self) -> bool:
        """
        Получение токена OAuth2 для работы с Azure API.
        """
        data = {
            "client_id": self.client_id,
            "scope": self._scope,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            async with self.session.post(self._token_url, data=data, headers=headers) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    self.token = result.get("access_token")
                    return True
                else:
                    logging.error(f"SentinelClient: Ошибка аутентификации, статус {resp.status}")
        except Exception as e:
            logging.error(f"SentinelClient: Исключение при аутентификации: {e}")
        return False

    async def send_custom_log(self, log_type: str, records: list) -> bool:
        """
        Отправка пользовательских логов в Sentinel через Data Collector API.
        :param log_type: Имя типа лога (CustomLogType)
        :param records: Список словарей с данными логов
        :return: True при успешной отправке, False при ошибке
        """
        if not self.token:
            authenticated = await self.authenticate()
            if not authenticated:
                return False

        url = f"https://{self.workspace_name}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        import hashlib
        import hmac
        import base64
        from datetime import datetime

        body = "\n".join([json.dumps(r) for r in records])
        body_bytes = body.encode('utf-8')
        content_length = len(body_bytes)
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        method = "POST"
        content_type = "application/json"
        resource = "/api/logs"
        signature_string = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{rfc1123date}\n{resource}"
        decoded_key = base64.b64decode(self.client_secret)
        hashed = hmac.new(decoded_key, signature_string.encode('utf-8'), hashlib.sha256)
        signature = base64.b64encode(hashed.digest()).decode()

        headers = {
            "Content-Type": content_type,
            "Log-Type": log_type,
            "x-ms-date": rfc1123date,
            "Authorization": f"SharedKey {self.workspace_name}:{signature}"
        }

        try:
            async with self.session.post(url, data=body_bytes, headers=headers) as resp:
                if resp.status in (200, 202):
                    return True
                else:
                    logging.error(f"SentinelClient: Ошибка отправки логов, статус {resp.status}")
        except Exception as e:
            logging.error(f"SentinelClient: Исключение при отправке логов: {e}")

        return False

    async def close(self):
        await self.session.close()
