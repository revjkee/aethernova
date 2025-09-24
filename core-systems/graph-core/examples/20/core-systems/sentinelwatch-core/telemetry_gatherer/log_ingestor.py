# File: log_ingestor.py
import os
import json
import socket
import logging
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime

import aiofiles
import aiohttp
import systemd.journal
import zmq
import zmq.asyncio

from elasticsearch import AsyncElasticsearch
from .ingest_filters import LogFilterEngine
from .ingest_auth import validate_source_identity

logger = logging.getLogger("telemetry.log_ingestor")
logger.setLevel(logging.INFO)


class LogIngestor:
    def __init__(self, elk_url: str, elk_index: str):
        self.elk_client = AsyncElasticsearch(hosts=[elk_url])
        self.elk_index = elk_index
        self.context = zmq.asyncio.Context()
        self.syslog_socket = None
        self.filter_engine = LogFilterEngine()

    async def start(self):
        logger.info("Starting log ingestor")
        await asyncio.gather(
            self.ingest_journald(),
            self.ingest_syslog(),
            self.ingest_from_zmq(),
        )

    async def ingest_journald(self):
        logger.info("Listening to journald")
        journal_reader = systemd.journal.Reader()
        journal_reader.log_level(systemd.journal.LOG_INFO)
        journal_reader.seek_tail()
        journal_reader.get_previous()
        journal_reader.wait()

        while True:
            journal_reader.wait(1000)
            for entry in journal_reader:
                await self.process_event(entry, source="journald")
            await asyncio.sleep(0.01)

    async def ingest_syslog(self):
        logger.info("Starting syslog listener on UDP 514")
        self.syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.syslog_socket.bind(("0.0.0.0", 514))
        self.syslog_socket.setblocking(False)

        loop = asyncio.get_running_loop()

        while True:
            data, _ = await loop.sock_recvfrom(self.syslog_socket, 4096)
            parsed = self.parse_syslog(data.decode("utf-8", errors="ignore"))
            await self.process_event(parsed, source="syslog")

    async def ingest_from_zmq(self):
        logger.info("Starting ZMQ ingest socket")
        socket = self.context.socket(zmq.SUB)
        socket.bind("tcp://0.0.0.0:6000")
        socket.setsockopt(zmq.SUBSCRIBE, b"")

        while True:
            raw = await socket.recv()
            event = json.loads(raw.decode())
            await self.process_event(event, source="zmq")

    async def process_event(self, event: Dict[str, Any], source: str):
        identity = event.get("identity", "unknown")

        if not validate_source_identity(identity):
            logger.warning(f"Rejected event from unknown identity: {identity}")
            return

        if not self.filter_engine.passes(event):
            logger.debug(f"Event dropped by filter engine: {event}")
            return

        enriched = self.enrich_event(event, source)
        await self.send_to_elasticsearch(enriched)

    async def send_to_elasticsearch(self, event: Dict[str, Any]):
        try:
            await self.elk_client.index(index=self.elk_index, document=event)
            logger.debug(f"Indexed event to {self.elk_index}")
        except Exception as e:
            logger.error(f"Failed to index event: {e}")

    def parse_syslog(self, raw: str) -> Dict[str, Any]:
        parts = raw.split(" ", 4)
        ts = datetime.utcnow().isoformat()
        return {
            "timestamp": ts,
            "identity": parts[2] if len(parts) > 2 else "unknown",
            "message": parts[-1] if len(parts) > 4 else raw,
            "source_type": "syslog"
        }

    def enrich_event(self, event: Dict[str, Any], source: str) -> Dict[str, Any]:
        event["received_at"] = datetime.utcnow().isoformat()
        event["source"] = source
        event["host"] = socket.gethostname()
        return event


async def main():
    elk_url = os.environ.get("ELK_URL", "http://localhost:9200")
    elk_index = os.environ.get("ELK_INDEX", "sentinel-logs")
    ingestor = LogIngestor(elk_url, elk_index)
    await ingestor.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Log ingestor terminated.")
