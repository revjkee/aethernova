# phantommesh-core/firewall_layer/dynamic_port_scrambler.py

import asyncio
import random
import time
import logging
from typing import Dict, Optional, Tuple, Callable

logger = logging.getLogger("dynamic_port_scrambler")
logger.setLevel(logging.DEBUG)

SCRAMBLE_INTERVAL = 45
SCRAMBLED_PORT_RANGE = (20000, 60000)
MAX_ACTIVE_CHANNELS = 8
TTL_SECONDS = 120

class ScrambledPort:
    def __init__(self, port: int, assigned_at: float, ttl: int):
        self.port = port
        self.assigned_at = assigned_at
        self.ttl = ttl

    def is_expired(self) -> bool:
        return (time.time() - self.assigned_at) > self.ttl

class DynamicPortScrambler:
    def __init__(self):
        self.active_ports: Dict[int, ScrambledPort] = {}
        self.callbacks: Dict[int, Callable[[int], None]] = {}
        self.port_rotation_task: Optional[asyncio.Task] = None

    def _generate_random_port(self) -> int:
        while True:
            port = random.randint(*SCRAMBLED_PORT_RANGE)
            if port not in self.active_ports:
                return port

    def _purge_expired(self):
        expired_ports = [p for p, obj in self.active_ports.items() if obj.is_expired()]
        for port in expired_ports:
            del self.active_ports[port]
            if port in self.callbacks:
                del self.callbacks[port]
            logger.info(f"[SCRAMBLER] Порт {port} очищен по TTL")

    def _register_port(self, port: int, ttl: int = TTL_SECONDS, callback: Optional[Callable[[int], None]] = None):
        self.active_ports[port] = ScrambledPort(port, time.time(), ttl)
        if callback:
            self.callbacks[port] = callback
        logger.info(f"[SCRAMBLER] Зарегистрирован порт {port} на {ttl} сек")

    async def _rotate_ports_loop(self):
        while True:
            self._purge_expired()
            if len(self.active_ports) < MAX_ACTIVE_CHANNELS:
                port = self._generate_random_port()
                self._register_port(port)
                if port in self.callbacks:
                    self.callbacks[port](port)
            await asyncio.sleep(SCRAMBLE_INTERVAL)

    def get_active_ports(self) -> Dict[int, ScrambledPort]:
        self._purge_expired()
        return dict(self.active_ports)

    def start(self):
        if not self.port_rotation_task:
            self.port_rotation_task = asyncio.create_task(self._rotate_ports_loop())
            logger.info("[SCRAMBLER] Запущен цикл ротации портов")

    def stop(self):
        if self.port_rotation_task:
            self.port_rotation_task.cancel()
            self.port_rotation_task = None
            logger.info("[SCRAMBLER] Цикл ротации остановлен")

    def force_scramble(self, count: int = 3):
        self._purge_expired()
        for _ in range(count):
            port = self._generate_random_port()
            self._register_port(port)

    def bind_callback(self, callback: Callable[[int], None]):
        for port in self.active_ports:
            self.callbacks[port] = callback
        logger.info("[SCRAMBLER] Callback привязан к активным портам")

    def is_port_active(self, port: int) -> bool:
        self._purge_expired()
        return port in self.active_ports
