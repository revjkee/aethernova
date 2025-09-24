# observability/dashboards/exporters/splunk_client.py

import json
import logging
import threading
import time
from typing import Dict, Optional, List

import requests

logger = logging.getLogger("splunk_client")


class SplunkHECClient:
    """
    Splunk HEC (HTTP Event Collector) клиент для отправки логов в Splunk.
    Поддерживает буфер, ECS-совместимые поля, асинхронную отправку.
    """

    def __init__(
        self,
        hec_url: str,
        token: str,
        source: str = "teslaai",
        sourcetype: str = "_json",
        index: str = "main",
        flush_interval: int = 5,
        buffer_limit: int = 100,
        verify_ssl: bool = True
    ):
        self.hec_url = hec_url.rstrip("/") + "/services/collector/event"
        self.token = token
        self.source = source
        self.sourcetype = sourcetype
        self.index = index
        self.verify_ssl = verify_ssl

        self.headers = {
            "Authorization": f"Splunk {self.token}"
        }

        self._buffer: List[Dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.flush_interval = flush_interval
        self.buffer_limit = buffer_limit

        self._thread = threading.Thread(target=self._flusher, daemon=True)
        self._thread.start()
        logger.info("SplunkHECClient initialized")

    def send(self, event: Dict):
        """
        Добавляет событие в буфер и инициирует отправку при необходимости.
        """
        enriched = self._enrich(event)
        with self._lock:
            self._buffer.append(enriched)
            if len(self._buffer) >= self.buffer_limit:
                self._flush()

    def _enrich(self, event: Dict) -> Dict:
        """
        Добавляет Splunk совместимый обёртку и ECS-поля.
        """
        return {
            "time": event.get("timestamp", time.time()),
            "host": event.get("host", "teslaai-node"),
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event
        }

    def _flusher(self):
        while not self._stop.is_set():
            time.sleep(self.flush_interval)
            with self._lock:
                if self._buffer:
                    self._flush()

    def _flush(self):
        if not self._buffer:
            return

        for entry in self._buffer:
            try:
                response = requests.post(
                    self.hec_url,
                    headers=self.headers,
                    json=entry,
                    timeout=5,
                    verify=self.verify_ssl
                )
                if response.status_code >= 400:
                    logger.error("Splunk HEC error [%d]: %s", response.status_code, response.text)
            except Exception as e:
                logger.exception("Error sending to Splunk: %s", e)

        logger.debug("Sent %d events to Splunk", len(self._buffer))
        self._buffer.clear()

    def shutdown(self):
        """
        Завершает фоновую задачу и отправляет оставшиеся события.
        """
        self._stop.set()
        self._thread.join()
        with self._lock:
            if self._buffer:
                self._flush()
        logger.info("SplunkHECClient shutdown complete")
