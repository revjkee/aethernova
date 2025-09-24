# autopwn-framework/core/metrics.py

import time
import psutil
import threading
import logging
from collections import defaultdict
from typing import Optional, Dict, Any
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, generate_latest

logger = logging.getLogger("autopwn.metrics")

class MetricsCollector:
    """
    Centralized metrics collector for the Autopwn framework.
    Tracks core metrics like execution time, memory usage, module success/failure, etc.
    """

    def __init__(self, enable_system_metrics: bool = True):
        self.registry = CollectorRegistry()
        self._init_counters()
        self._init_gauges()
        self._init_histograms()
        if enable_system_metrics:
            self._start_system_metrics_collector()

    def _init_counters(self):
        self.module_executions = Counter(
            'module_executions_total',
            'Total number of executed modules',
            ['module_name', 'status'],
            registry=self.registry
        )

        self.errors_total = Counter(
            'errors_total',
            'Total number of errors occurred in the framework',
            ['component'],
            registry=self.registry
        )

        self.custom_events = Counter(
            'custom_events_total',
            'Custom application-defined events',
            ['event_type'],
            registry=self.registry
        )

    def _init_gauges(self):
        self.cpu_usage = Gauge(
            'system_cpu_usage_percent',
            'Current CPU usage percentage',
            registry=self.registry
        )
        self.memory_usage = Gauge(
            'system_memory_usage_percent',
            'Current memory usage percentage',
            registry=self.registry
        )
        self.active_threads = Gauge(
            'active_threads_total',
            'Current number of active threads',
            registry=self.registry
        )

    def _init_histograms(self):
        self.execution_time = Histogram(
            'module_execution_seconds',
            'Execution time of modules',
            ['module_name'],
            buckets=(0.1, 0.5, 1, 2, 5, 10),
            registry=self.registry
        )

    def _start_system_metrics_collector(self):
        def collect():
            while True:
                try:
                    self.cpu_usage.set(psutil.cpu_percent(interval=1))
                    self.memory_usage.set(psutil.virtual_memory().percent)
                    self.active_threads.set(threading.active_count())
                except Exception as e:
                    logger.error(f"System metrics error: {e}")
                time.sleep(5)

        t = threading.Thread(target=collect, daemon=True)
        t.start()

    def track_execution(self, module_name: str, status: str, duration_seconds: float):
        """
        Call this after module execution to record metrics.
        """
        self.module_executions.labels(module_name=module_name, status=status).inc()
        self.execution_time.labels(module_name=module_name).observe(duration_seconds)

    def track_error(self, component: str):
        """
        Register a handled error for a specific component.
        """
        self.errors_total.labels(component=component).inc()

    def track_custom_event(self, event_type: str):
        """
        Register a custom event (e.g., "scan_started", "exploit_triggered").
        """
        self.custom_events.labels(event_type=event_type).inc()

    def export_metrics(self) -> bytes:
        """
        Export metrics in Prometheus text format.
        Useful for HTTP endpoint or pushing to Pushgateway.
        """
        return generate_latest(self.registry)

    def snapshot(self) -> Dict[str, Any]:
        """
        Export selected current metric values for internal use or logging.
        """
        return {
            "cpu": psutil.cpu_percent(interval=0.1),
            "memory": psutil.virtual_memory().percent,
            "threads": threading.active_count()
        }
