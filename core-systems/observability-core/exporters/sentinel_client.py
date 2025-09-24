# observability/dashboards/exporters/sentinel_client.py

import json
import hashlib
import hmac
import base64
import datetime
import requests
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("sentinel_client")


class SentinelClient:
    """
    Клиент для отправки логов в Microsoft Sentinel (Azure Log Analytics Data Collector API).
    Поддержка подписей, сериализации, буферов и кастомных таблиц.
    """

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        log_type: str = "TeslaAILogs",
        api_version: str = "2016-04-01",
        flush_size: int = 50,
        buffer: Optional[List[Dict]] = None
    ):
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.api_version = api_version
        self.flush_size = flush_size
        self.buffer = buffer or []

        self.endpoint = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version={api_version}"

    def _build_signature(self, date: str, content_length: int) -> str:
        """
        Генерация подписи по формуле Microsoft для Log Analytics.
        """
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"POST\n{str(content_length)}\napplication/json\n{x_headers}\n/api/logs"
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        return base64.b64encode(encoded_hash).decode()

    def send(self, event: Dict):
        """
        Добавляет событие в буфер. Отправка происходит при достижении flush_size.
        """
        self.buffer.append(self._enrich(event))
        if len(self.buffer) >= self.flush_size:
            self.flush()

    def _enrich(self, event: Dict) -> Dict:
        """
        Добавляет timestamp, ECS-поля и AI-маркеры.
        """
        event["@timestamp"] = event.get("@timestamp", datetime.datetime.utcnow().isoformat() + "Z")
        event["event.module"] = event.get("event.module", "TeslaAI")
        event["event.dataset"] = event.get("event.dataset", "core")
        event["source.system"] = event.get("source.system", "genesis")
        return event

    def flush(self):
        """
        Отправка буфера в Microsoft Sentinel.
        """
        if not self.buffer:
            return

        body = json.dumps(self.buffer)
        content_length = len(body)
        rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        signature = self._build_signature(rfc1123date, content_length)
        headers = {
            "Content-Type": "application/json",
            "Log-Type": self.log_type,
            "x-ms-date": rfc1123date,
            "Authorization": f"SharedKey {self.workspace_id}:{signature}"
        }

        try:
            response = requests.post(self.endpoint, data=body, headers=headers, timeout=10)
            if response.status_code >= 400:
                logger.error("Sentinel push failed: %d - %s", response.status_code, response.text)
            else:
                logger.debug("Sent %d events to Sentinel", len(self.buffer))
        except Exception as e:
            logger.exception("Error sending data to Sentinel: %s", e)
        finally:
            self.buffer.clear()
