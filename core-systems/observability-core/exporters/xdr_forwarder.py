# observability/dashboards/exporters/xdr_forwarder.py

import logging
import socket
import json
import time
from typing import Dict, Optional, Literal
import requests
from threading import Thread, Lock

logger = logging.getLogger("xdr_forwarder")


class XDRForwarder:
    """
    XDR Forwarder для отправки событий в Cortex XDR / Falcon / Wazuh / Sentinel.
    Поддержка JSON, syslog (UDP/TCP), REST.
    """

    def __init__(
        self,
        mode: Literal["http", "udp", "tcp"] = "http",
        host: str = "localhost",
        port: int = 514,
        api_token: Optional[str] = None,
        api_url: Optional[str] = None,
        format: Literal["json", "cef"] = "json",
        verify_ssl: bool = True,
        flush_interval: int = 5
    ):
        self.mode = mode
        self.host = host
        self.port = port
        self.api_token = api_token
        self.api_url = api_url
        self.format = format
        self.verify_ssl = verify_ssl
        self.flush_interval = flush_interval

        self._buffer = []
        self._lock = Lock()
        self._stop = False
        self._thread = Thread(target=self._flusher, daemon=True)
        self._thread.start()

        if mode in {"udp", "tcp"}:
            sock_type = socket.SOCK_DGRAM if mode == "udp" else socket.SOCK_STREAM
            self.sock = socket.socket(socket.AF_INET, sock_type)
            if mode == "tcp":
                self.sock.connect((host, port))
        else:
            self.sock = None

        logger.info("XDRForwarder initialized in mode: %s", mode)

    def send(self, event: Dict):
        """
        Добавление события в буфер для последующей отправки.
        """
        with self._lock:
            self._buffer.append(event)

    def _flusher(self):
        while not self._stop:
            time.sleep(self.flush_interval)
            with self._lock:
                if self._buffer:
                    batch = self._buffer[:]
                    self._buffer.clear()
                    try:
                        self._flush(batch)
                    except Exception as e:
                        logger.exception("Failed to flush XDR batch: %s", e)

    def _flush(self, batch: list):
        if self.mode == "http":
            self._flush_http(batch)
        elif self.mode in {"udp", "tcp"}:
            self._flush_syslog(batch)
        else:
            logger.warning("Unsupported XDR forwarding mode: %s", self.mode)

    def _format_event(self, event: Dict) -> str:
        if self.format == "cef":
            # CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|Extension
            base = "CEF:0|TeslaAI|Core|1.0|100|XDR Event|5|"
            ext = " ".join([f"{k}={v}" for k, v in event.items()])
            return base + ext
        return json.dumps(event)

    def _flush_http(self, batch: list):
        if not self.api_url or not self.api_token:
            logger.error("Missing API config for HTTP mode")
            return

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "events": batch,
            "source": "TeslaAI",
            "timestamp": int(time.time())
        }

        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            verify=self.verify_ssl,
            timeout=5
        )
        if response.status_code >= 400:
            logger.error("XDR HTTP push failed: %d - %s", response.status_code, response.text)

    def _flush_syslog(self, batch: list):
        for event in batch:
            message = self._format_event(event).encode("utf-8")
            try:
                self.sock.sendto(message, (self.host, self.port)) if self.mode == "udp" else self.sock.send(message)
            except Exception as e:
                logger.exception("Syslog send error: %s", e)

    def shutdown(self):
        """
        Завершение работы forwarder, отправка оставшихся событий.
        """
        self._stop = True
        self._thread.join(timeout=3)
        with self._lock:
            if self._buffer:
                try:
                    self._flush(self._buffer)
                except Exception as e:
                    logger.error("Final flush failed: %s", e)
        if self.sock and self.mode == "tcp":
            self.sock.close()
        logger.info("XDRForwarder shutdown complete")
