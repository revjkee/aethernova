# red-vs-blue-engine/agents/blue_team/monitoring_agent.py

import asyncio
import logging
from typing import List, Optional

from core.models.alert import DetectionAlert
from core.models.telemetry import TelemetrySnapshot
from core.ai.anomaly_detector import AnomalyDetector
from core.policy.rules_engine import RulesEngine
from core.telemetry.event_bus import EventBus
from core.security.zkp import attach_proof
from core.security.sandbox import MonitoringSandbox
from core.utils.tracing import trace_execution

logger = logging.getLogger("blue.monitoring_agent")


class MonitoringAgent:
    """
    Промышленный AI-агент Blue Team, предназначенный для постоянного наблюдения
    за активностью в системе, анализа аномалий, применения правил корреляции и
    передачи подтверждённых ZKP-инцидентов в систему оповещения.
    """

    def __init__(
        self,
        agent_id: str,
        detector: AnomalyDetector,
        rules_engine: RulesEngine,
        sandbox: MonitoringSandbox,
        event_bus: EventBus
    ):
        self.agent_id = agent_id
        self.detector = detector
        self.rules_engine = rules_engine
        self.sandbox = sandbox
        self.event_bus = event_bus

    @trace_execution
    async def monitor(self, stream: asyncio.Queue):
        logger.info(f"[{self.agent_id}] Запуск постоянного мониторинга")
        while True:
            snapshot: TelemetrySnapshot = await stream.get()

            async with self.sandbox.isolated(self.agent_id):
                alerts = await self._process_snapshot(snapshot)
                for alert in alerts:
                    await self._publish_alert(alert)

    async def _process_snapshot(self, snapshot: TelemetrySnapshot) -> List[DetectionAlert]:
        logger.debug(f"[{self.agent_id}] Обработка слепка: {snapshot.timestamp}")
        alerts = []

        anomalies = await self.detector.detect(snapshot)
        for anomaly in anomalies:
            if not self.rules_engine.evaluate(anomaly):
                continue

            alert = DetectionAlert(
                agent_id=self.agent_id,
                timestamp=snapshot.timestamp,
                anomaly=anomaly,
                risk_score=anomaly.risk_score,
                confirmed=True,
                zkp=attach_proof(self.agent_id, anomaly.id, anomaly)
            )
            alerts.append(alert)

        return alerts

    async def _publish_alert(self, alert: DetectionAlert):
        logger.info(f"[{self.agent_id}] Аномалия подтверждена: {alert.anomaly.id}")
        await self.event_bus.publish("blue.alert.detected", alert.dict())

