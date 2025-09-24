
import logging
import psutil
import time
import json
from pathlib import Path

logger = logging.getLogger("metrics_collector")
logger.setLevel(logging.INFO)

class MetricsCollector:
    def __init__(self):
        self.initial_metrics = {}
        self.final_metrics = {}

    def collect_metrics(self) -> dict:
        metrics = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "used": psutil.virtual_memory().used,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "used": psutil.disk_usage("/").used,
                "free": psutil.disk_usage("/").free,
                "percent": psutil.disk_usage("/").percent
            },
            "network": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            }
        }
        return metrics

    def snapshot_before(self):
        self.initial_metrics = self.collect_metrics()
        logger.info("Снимок ДО инъекции сделан.")

    def snapshot_after(self):
        self.final_metrics = self.collect_metrics()
        logger.info("Снимок ПОСЛЕ инъекции сделан.")

    def compare_metrics(self) -> dict:
        def diff(before, after):
            if isinstance(before, dict):
                return {k: diff(before.get(k), after.get(k)) for k in before}
            return after - before if isinstance(before, (int, float)) else None

        return diff(self.initial_metrics, self.final_metrics)

    def export_to_file(self, path: str):
        report = {
            "before": self.initial_metrics,
            "after": self.final_metrics,
            "diff": self.compare_metrics()
        }
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(report, f, indent=4)
            logger.info(f"Метрики успешно экспортированы в {path}")
        except Exception as e:
            logger.error(f"Ошибка при экспорте метрик: {e}", exc_info=True)
