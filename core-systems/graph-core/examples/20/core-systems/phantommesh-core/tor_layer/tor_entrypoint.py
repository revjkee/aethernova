# phantommesh-core/tor_layer/tor_entrypoint.py

import asyncio
import os
import tempfile
import shutil
import logging
import socket
from pathlib import Path
from typing import Optional

from stem import Signal
from stem.control import Controller
from stem.process import launch_tor_with_config

logger = logging.getLogger("tor_entrypoint")
logger.setLevel(logging.DEBUG)

DEFAULT_TOR_PORT = 9050
DEFAULT_CONTROL_PORT = 9051
TOR_READY_MARKER = "Bootstrapped 100%"

class TorEntrypoint:
    def __init__(
        self,
        socks_port: int = DEFAULT_TOR_PORT,
        control_port: int = DEFAULT_CONTROL_PORT,
        tor_binary: str = "tor",
        use_obfs4: bool = False,
        bridges_file: Optional[str] = None,
    ):
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_binary = tor_binary
        self.use_obfs4 = use_obfs4
        self.bridges_file = bridges_file
        self.tor_process = None
        self.data_dir = tempfile.mkdtemp(prefix="tor_entry_")
        self.controller: Optional[Controller] = None

    def _get_base_config(self) -> dict:
        config = {
            "SocksPort": str(self.socks_port),
            "ControlPort": str(self.control_port),
            "DataDirectory": self.data_dir,
            "AvoidDiskWrites": "1",
            "CookieAuthentication": "1",
            "ClientOnly": "1",
            "Log": "NOTICE stdout",
        }

        if self.use_obfs4 and self.bridges_file and Path(self.bridges_file).exists():
            with open(self.bridges_file, "r") as f:
                bridges = f.read().splitlines()
            config.update({
                "UseBridges": "1",
                "ClientTransportPlugin": "obfs4 exec /usr/bin/obfs4proxy",
                "Bridge": bridges
            })

        return config

    async def _wait_for_bootstrap(self):
        logger.info("Ожидание завершения инициализации TOR...")
        while True:
            if self.controller and self.controller.is_alive():
                try:
                    status = self.controller.get_info("status/bootstrap-phase")
                    if "100" in status:
                        logger.info("TOR успешно загрузился.")
                        break
                except Exception as e:
                    logger.warning(f"Ошибка при проверке статуса TOR: {e}")
            await asyncio.sleep(1)

    def _is_port_open(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("127.0.0.1", port)) == 0

    def start_tor(self) -> None:
        config = self._get_base_config()
        logger.info(f"Запуск TOR с конфигурацией: {config}")
        self.tor_process = launch_tor_with_config(
            config=config,
            tor_cmd=self.tor_binary,
            init_msg_handler=lambda msg: logger.info(f"[tor] {msg}")
        )

    def connect_controller(self) -> None:
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            logger.info("Подключено к TOR контроллеру")
        except Exception as e:
            logger.error(f"Ошибка подключения к контроллеру TOR: {e}")
            raise

    def new_identity(self) -> None:
        if self.controller:
            logger.info("Запрос новой идентичности (NEWNYM)...")
            self.controller.signal(Signal.NEWNYM)

    def stop(self) -> None:
        if self.tor_process:
            self.tor_process.terminate()
            logger.info("TOR-процесс остановлен.")
        self.cleanup()

    def cleanup(self) -> None:
        shutil.rmtree(self.data_dir, ignore_errors=True)
        logger.info(f"Удалена временная директория TOR: {self.data_dir}")

    async def launch(self) -> None:
        self.start_tor()
        self.connect_controller()
        await self._wait_for_bootstrap()

    async def restart(self) -> None:
        logger.info("Перезапуск TOR-сессии...")
        self.stop()
        await asyncio.sleep(2)
        await self.launch()

    def get_socks_proxy_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.socks_port}"

# Пример запуска
async def run_entrypoint():
    entry = TorEntrypoint(use_obfs4=True, bridges_file="bridges.txt")
    try:
        await entry.launch()
        await asyncio.sleep(30)
        entry.new_identity()
        await asyncio.sleep(30)
    finally:
        entry.stop()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_entrypoint())
