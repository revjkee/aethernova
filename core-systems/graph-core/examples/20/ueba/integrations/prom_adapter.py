# ueba/integrations/prom_adapter.py
# Промышленный адаптер UEBA метрик для Prometheus PushGateway

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from typing import Dict, Optional
from datetime import datetime
import threading
import logging

logger = logging.getLogger("ueba.prometheus")
logger.setLevel(logging.INFO)

class PrometheusUEBAAdapter:
    """
    UEBA интеграция с Prometheus PushGateway.
    Позволяет отправлять метрики по детектированным аномалиям и поведению.
    """

    def __init__(self, gateway_url: str, job_name: str = "ueba_metrics", instance_id: Optional[str] = None):
        self.gateway_url = gateway_url
        self.job_name = job_name
        self.instance_id = instance_id or "default"
        self.registry = CollectorRegistry()
        self._setup_metrics()

    def _setup_metrics(self):
        """Регистрируем метрики UEBA."""
        self.anomaly_score = Gauge(
            'ueba_anomaly_score',
            'Риск-скоринг аномалии от UEBA-модуля',
            ['entity_id', 'actor_type', 'tag'],
            registry=self.registry
        )
        self.alert_counter = Gauge(
            'ueba_alert_count',
            'Общее количество UEBA-алертов по категории',
            ['level', 'tag'],
            registry=self.registry
        )
        self.timestamp_metric = Gauge(
            'ueba_alert_timestamp',
            'Метка времени последнего алерта',
            ['entity_id'],
            registry=self.registry
        )

    def push_metrics(self, alert_data: Dict):
        """
        Асинхронная отправка метрик в Prometheus PushGateway.
        alert_data должен содержать: entity_id, actor_type, score, tag, level, timestamp
        """
        def _push():
            try:
                eid = alert_data["entity_id"]
                atype = alert_data["actor_type"]
                score = alert_data["score"]
                tag = alert_data["tag"]
                level = alert_data["level"]
                ts = alert_data["timestamp"]

                # Обновление значений метрик
                self.anomaly_score.labels(entity_id=eid, actor_type=atype, tag=tag).set(score)
                self.alert_counter.labels(level=level, tag=tag).inc()
                self.timestamp_metric.labels(entity_id=eid).set(self._ts_to_epoch(ts))

                # Push
                push_to_gateway(
                    self.gateway_url,
                    job=self.job_name,
                    registry=self.registry,
                    grouping_key={"instance": self.instance_id}
                )
                logger.info(f"Прометей-метрики успешно отправлены для entity_id={eid}")
            except Exception as e:
                logger.error(f"Ошибка Prometheus push: {e}", exc_info=True)

        threading.Thread(target=_push).start()

    def _ts_to_epoch(self, iso_ts: str) -> float:
        """Преобразует ISO 8601 timestamp в epoch секундный float."""
        try:
            return datetime.fromisoformat(iso_ts.replace("Z", "+00:00")).timestamp()
        except Exception as e:
            logger.warning(f"Ошибка парсинга timestamp {iso_ts}: {e}")
            return 0.0
