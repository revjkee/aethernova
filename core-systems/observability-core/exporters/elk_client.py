# observability/dashboards/exporters/elk_client.py

import json
import logging
import threading
import time
from typing import Dict, Optional

import requests

logger = logging.getLogger("elk_client")

class ELKClient:
    """
    Клиент для отправки логов в ElasticSearch через REST API.
    Поддерживает ECS-совместимый формат, буферизацию и fault-tolerant отправку.
    """

    def __init__(
        self,
        elk_endpoint: str,
        index: str = "teslaai-logs",
        auth: Optional[tuple] = None,
        headers: Optional[Dict[str, str]] = None,
        flush_interval: int = 5,
        buffer_limit: int = 1000,
        verify_ssl: bool = True
    ):
        self.elk_endpoint = elk_endpoint.rstrip("/")
        self.index = index
        self.auth = auth
        self.headers = headers or {"Content-Type": "application/json"}
        self.flush_interval = flush_interval
        self.buffer_limit = buffer_limit
        self.verify_ssl = verify_ssl

        self._buffer = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._thread = threading.Thread(target=self._flusher, daemon=True)
        self._thread.start()
        logger.info("ELKClient initialized for index: %s", self.index)

    def send(self, log_entry: Dict):
        """
        Добавляет лог в буфер. Он будет отправлен в следующую итерацию flusher.
        """
        enriched = self._enrich(log_entry)
        with self._lock:
            self._buffer.append(enriched)
            if len(self._buffer) >= self.buffer_limit:
                self._flush()

    def _enrich(self, entry: Dict) -> Dict:
        """
        Добавляет ECS-поля и временные метки.
        """
        entry["@timestamp"] = entry.get("@timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        entry["event.dataset"] = entry.get("event.dataset", "teslaai.logs")
        entry["service.name"] = entry.get("service.name", "teslaai-core")
        entry["log.level"] = entry.get("log.level", "info")
        return entry

    def _flusher(self):
        """
        Периодически отправляет логи в ELK.
        """
        while not self._stop_event.is_set():
            time.sleep(self.flush_interval)
            with self._lock:
                if self._buffer:
                    self._flush()

    def _flush(self):
        """
        Отправка буфера в ElasticSearch.
        """
        if not self._buffer:
            return

        bulk_payload = ""
        for entry in self._buffer:
            meta = {"index": {"_index": self.index}}
            bulk_payload += json.dumps(meta) + "\n" + json.dumps(entry) + "\n"

        try:
            url = f"{self.elk_endpoint}/_bulk"
            response = requests.post(url, data=bulk_payload, headers=self.headers, auth=self.auth, verify=self.verify_ssl)
            if response.status_code >= 400:
                logger.error("ELK bulk upload failed [%d]: %s", response.status_code, response.text)
            else:
                logger.debug("ELK bulk upload success: %d entries", len(self._buffer))
        except Exception as e:
            logger.exception("Exception during ELK flush: %s", e)
        finally:
            self._buffer.clear()

    def shutdown(self):
        """
        Остановить flusher и сбросить буфер.
        """
        self._stop_event.set()
        self._thread.join()
        with self._lock:
            if self._buffer:
                self._flush()
        logger.info("ELKClient shutdown complete")
