# phantommesh-core/tor_layer/snowflake_connector.py

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Optional, List

from pathlib import Path

logger = logging.getLogger("snowflake_connector")
logger.setLevel(logging.DEBUG)

DEFAULT_BROKER_URL = "https://snowflake-broker.torproject.net.global.prod.fastly.net/"
DEFAULT_FRONT_DOMAIN = "cdn.sstatic.net"
DEFAULT_SNOWFLAKE_BINARY = "/usr/bin/snowflake-client"

class SnowflakeConnector:
    def __init__(
        self,
        snowflake_binary: str = DEFAULT_SNOWFLAKE_BINARY,
        broker_url: str = DEFAULT_BROKER_URL,
        front_domain: str = DEFAULT_FRONT_DOMAIN,
        stun_servers: Optional[List[str]] = None,
        max_proxies: int = 5
    ):
        self.snowflake_binary = snowflake_binary
        self.broker_url = broker_url
        self.front_domain = front_domain
        self.stun_servers = stun_servers or [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302",
        ]
        self.max_proxies = max_proxies
        self.process: Optional[asyncio.subprocess.Process] = None
        self.running = False
        self.runtime_dir = tempfile.mkdtemp(prefix="snowflake_proxy_")

    def _build_args(self) -> List[str]:
        args = [
            self.snowflake_binary,
            "-broker", self.broker_url,
            "-front", self.front_domain,
            "-max", str(self.max_proxies)
        ]

        for stun in self.stun_servers:
            args.extend(["-stun", stun])

        args.extend(["-log", os.path.join(self.runtime_dir, "snowflake.log")])
        return args

    async def start(self) -> None:
        if self.running:
            logger.warning("Snowflake уже запущен.")
            return

        args = self._build_args()
        logger.info(f"Запуск snowflake с аргументами: {args}")

        self.process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self.running = True
        logger.info("Snowflake-прокси запущен.")

    async def monitor(self) -> None:
        if not self.process:
            logger.warning("Snowflake процесс не инициализирован.")
            return

        try:
            stdout, stderr = await self.process.communicate()
            logger.info(f"[snowflake stdout]:\n{stdout.decode()}")
            logger.error(f"[snowflake stderr]:\n{stderr.decode()}")
        finally:
            self.running = False
            logger.warning("Snowflake-прокси завершён.")

    async def stop(self) -> None:
        if self.process and self.running:
            logger.info("Остановка Snowflake-прокси...")
            self.process.terminate()
            await self.process.wait()
            self.running = False

    def cleanup(self) -> None:
        shutil.rmtree(self.runtime_dir, ignore_errors=True)
        logger.info(f"Удалена временная директория Snowflake: {self.runtime_dir}")

    async def restart(self) -> None:
        await self.stop()
        self.cleanup()
        self.runtime_dir = tempfile.mkdtemp(prefix="snowflake_proxy_")
        await self.start()

    def get_log_path(self) -> str:
        return os.path.join(self.runtime_dir, "snowflake.log")

# Пример использования
async def run_snowflake_example():
    connector = SnowflakeConnector()
    try:
        await connector.start()
        await asyncio.sleep(30)
        await connector.restart()
        await asyncio.sleep(30)
    finally:
        await connector.stop()
        connector.cleanup()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_snowflake_example())
