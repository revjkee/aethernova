import psutil
import logging
import time
from typing import Dict


class SystemMonitor:
    """
    Класс для мониторинга системных ресурсов: CPU, RAM, диск.
    """

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger("system_monitor")

    def get_cpu_usage(self) -> float:
        """
        Возвращает текущую загрузку CPU в процентах.
        """
        usage = psutil.cpu_percent(interval=1)
        self.logger.debug(f"CPU usage: {usage}%")
        return usage

    def get_memory_usage(self) -> Dict[str, float]:
        """
        Возвращает использование памяти: всего, доступно, использовано (в мегабайтах и процентах).
        """
        mem = psutil.virtual_memory()
        result = {
            "total_mb": mem.total / (1024 ** 2),
            "available_mb": mem.available / (1024 ** 2),
            "used_mb": mem.used / (1024 ** 2),
            "percent": mem.percent,
        }
        self.logger.debug(f"Memory usage: {result}")
        return result

    def get_disk_usage(self, path: str = "/") -> Dict[str, float]:
        """
        Возвращает использование диска по указанному пути.
        """
        disk = psutil.disk_usage(path)
        result = {
            "total_gb": disk.total / (1024 ** 3),
            "used_gb": disk.used / (1024 ** 3),
            "free_gb": disk.free / (1024 ** 3),
            "percent": disk.percent,
        }
        self.logger.debug(f"Disk usage for {path}: {result}")
        return result

    def log_system_status(self):
        """
        Логирует текущий статус системы.
        """
        cpu = self.get_cpu_usage()
        memory = self.get_memory_usage()
        disk = self.get_disk_usage()

        self.logger.info(f"CPU Usage: {cpu}% | Memory Usage: {memory['percent']}% | Disk Usage: {disk['percent']}%")

    def monitor_loop(self, interval_sec: int = 60):
        """
        Запускает мониторинг в бесконечном цикле с заданным интервалом.
        """
        self.logger.info("Starting system monitoring loop.")
        try:
            while True:
                self.log_system_status()
                time.sleep(interval_sec)
        except KeyboardInterrupt:
            self.logger.info("System monitoring stopped by user.")


monitor = SystemMonitor()
