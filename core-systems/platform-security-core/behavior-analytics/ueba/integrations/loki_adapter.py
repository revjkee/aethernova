# ueba/integrations/loki_adapter.py
# Интеграция с Grafana Loki для вытягивания логов в систему UEBA

import httpx
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import urllib.parse

logger = logging.getLogger("ueba.loki")
logger.setLevel(logging.INFO)

class LokiAdapter:
    """
    Адаптер для извлечения логов из Grafana Loki через HTTP API.
    Используется UEBA-движком для анализа аномального поведения.
    """

    def __init__(self, base_url: str, auth_token: Optional[str] = None, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {auth_token}"
        } if auth_token else {}
        self.timeout = timeout

    def _build_range_query(self, label_selector: str, query: str, start: datetime, end: datetime) -> str:
        """Формирует URL для range-запроса в Loki."""
        params = {
            "query": f'{label_selector} |= "{query}"',
            "start": int(start.timestamp() * 1e9),  # наносекунды
            "end": int(end.timestamp() * 1e9),
            "limit": 1000,
            "direction": "forward"
        }
        return f"{self.base_url}/loki/api/v1/query_range?" + urllib.parse.urlencode(params)

    async def fetch_logs(
        self,
        label_selector: str,
        query: str,
        start: datetime,
        end: datetime
    ) -> List[Dict[str, str]]:
        """
        Возвращает список логов из Loki по заданным параметрам:
        - label_selector: '{job="syslog"}'
        - query: строка фильтра (например "login failed")
        - start/end: диапазон времени
        """
        url = self._build_range_query(label_selector, query, start, end)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                return self._parse_streams(data)
        except Exception as e:
            logger.error(f"Loki fetch_logs error: {e}", exc_info=True)
            return []

    def _parse_streams(self, data: Dict) -> List[Dict[str, str]]:
        """
        Преобразует ответ Loki в список логов.
        """
        entries = []
        try:
            streams = data.get("data", {}).get("result", [])
            for stream in streams:
                for value in stream.get("values", []):
                    ts, msg = value
                    entries.append({
                        "timestamp": datetime.fromtimestamp(int(ts) / 1e9).isoformat(),
                        "message": msg.strip(),
                        "labels": stream.get("stream", {})
                    })
            return entries
        except Exception as e:
            logger.warning(f"Ошибка парсинга потока Loki: {e}")
            return []
