# autopwn-framework/core/health_check.py

import asyncio
import socket
import time
import logging
import psutil
import platform
import importlib.util
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger("autopwn.health_check")


class HealthCheck:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.start_time = time.time()

    def _uptime(self) -> float:
        return time.time() - self.start_time

    def _cpu_usage(self) -> float:
        return psutil.cpu_percent(interval=0.5)

    def _memory_usage(self) -> Dict[str, Any]:
        mem = psutil.virtual_memory()
        return {
            "total": mem.total,
            "available": mem.available,
            "used": mem.used,
            "percent": mem.percent,
        }

    def _disk_usage(self) -> Dict[str, Any]:
        disk = psutil.disk_usage("/")
        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        }

    def _network_io(self) -> Dict[str, Any]:
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        }

    def _python_packages(self) -> Dict[str, bool]:
        required = [
            "psutil",
            "aiohttp",
            "scapy",
            "pyzmq",
            "cryptography",
        ]
        return {pkg: importlib.util.find_spec(pkg) is not None for pkg in required}

    def _system_info(self) -> Dict[str, str]:
        return {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
        }

    async def _ping_service(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _check_services(self) -> Dict[str, bool]:
        services = {
            "redis": ("localhost", 6379),
            "rabbitmq": ("localhost", 5672),
            "mongodb": ("localhost", 27017),
        }
        results = {}
        for name, (host, port) in services.items():
            result = await self._ping_service(host, port)
            results[name] = result
        return results

    async def get_health_report(self) -> Dict[str, Any]:
        logger.debug("Collecting system health report...")
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
            "uptime_seconds": self._uptime(),
            "cpu_usage_percent": self._cpu_usage(),
            "memory": self._memory_usage(),
            "disk": self._disk_usage(),
            "network": self._network_io(),
            "python_packages_installed": self._python_packages(),
            "system_info": self._system_info(),
            "services": await self._check_services(),
        }
        logger.info("Health report collected successfully.")
        return report


# Пример асинхронного вызова (в проде вызывать из task loop)
# async def main():
#     hc = HealthCheck()
#     report = await hc.get_health_report()
#     print(report)

# if __name__ == "__main__":
#     asyncio.run(main())
