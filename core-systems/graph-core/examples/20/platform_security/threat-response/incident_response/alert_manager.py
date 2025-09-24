# platform-security/genius-core-security/defense/alert_manager.py

import logging
import time
from datetime import datetime
from typing import List, Dict, Any
from threading import Lock

from genius_core_security.defense.defense_layers import DefenseLevel
from genius_core_security.validators.utils.hash_context import hash_context
from genius_core_security.ztna.policy_enforcer import PolicyEnforcer
from genius_core_security.sase.edge_agent import EdgeAgent
from genius_core_security.ztna.behavior_graph import BehaviorGraph

logger = logging.getLogger("AlertManager")


class Alert:
    def __init__(self, source: str, level: DefenseLevel, message: str, metadata: Dict[str, Any]):
        self.timestamp = datetime.utcnow().isoformat()
        self.source = source
        self.level = level
        self.message = message
        self.metadata = metadata

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "level": self.level.name,
            "message": self.message,
            "metadata": self.metadata
        }


class AlertManager:
    def __init__(self):
        self.alert_queue: List[Alert] = []
        self.alert_log: List[Dict[str, Any]] = []
        self.lock = Lock()
        self.policy_enforcer = PolicyEnforcer()
        self.edge_agent = EdgeAgent()
        self.behavior_graph = BehaviorGraph()

    def receive_alert(self, alert: Alert):
        logger.debug(f"Received alert: {alert.to_dict()}")
        with self.lock:
            self.alert_queue.append(alert)
        self.process_alert(alert)

    def process_alert(self, alert: Alert):
        logger.info(f"Processing alert from {alert.source} at level {alert.level.name}")
        self.log_alert(alert)
        self.route_alert(alert)
        self.apply_defensive_measures(alert)

    def log_alert(self, alert: Alert):
        with self.lock:
            self.alert_log.append(alert.to_dict())
        logger.debug(f"Alert logged: {alert.to_dict()}")

    def route_alert(self, alert: Alert):
        # Placeholder for notification channels (Slack, Email, SIEM, etc.)
        logger.info(f"Routing alert to appropriate channels: {alert.message}")
        # This can be expanded with dynamic routing policies or ML-based prioritization.

    def apply_defensive_measures(self, alert: Alert):
        if alert.level == DefenseLevel.CRITICAL:
            self.policy_enforcer.harden_zone(alert.metadata.get("zone_id", "default"))
            self.edge_agent.trigger_isolation(alert.metadata.get("node_id", None))
            self.behavior_graph.flag_anomaly(alert.metadata.get("user_id", None))
            logger.warning("Critical defense triggered: Isolation and policy hardening applied.")
        elif alert.level == DefenseLevel.HIGH:
            self.policy_enforcer.enforce_temporary_rule(alert.metadata.get("rule", "temp-lockdown"))
            logger.info("High-level defense rule enforced.")
        else:
            logger.info("Alert level below threshold; monitoring only.")

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return self.alert_log[-limit:]

    def purge_old_alerts(self, retention_seconds: int = 86400):
        now = datetime.utcnow().timestamp()
        with self.lock:
            self.alert_log = [
                entry for entry in self.alert_log
                if now - datetime.fromisoformat(entry["timestamp"]).timestamp() <= retention_seconds
            ]
        logger.debug("Old alerts purged based on retention policy.")
