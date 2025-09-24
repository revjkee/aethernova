# platform-security/genius-core-security/defense/incident_response.py

import logging
from datetime import datetime
from typing import Dict, Optional

from genius_core_security.ztna.policy_enforcer import PolicyEnforcer
from genius_core_security.sase.edge_agent import EdgeAgent
from genius_core_security.defense.alert_manager import Alert
from genius_core_security.validators.utils.hash_context import hash_context

logger = logging.getLogger("IncidentResponse")


class IncidentResponseHandler:
    def __init__(self):
        self.policy_enforcer = PolicyEnforcer()
        self.edge_agent = EdgeAgent()

    def respond_to_incident(self, incident: Dict[str, str]) -> Dict[str, str]:
        """
        Главный метод для обработки инцидента.
        Ожидается словарь со следующими полями:
        - source_ip
        - user_id (опционально)
        - zone_id (опционально)
        - threat_type (например: "brute_force", "exfiltration")
        """
        logger.info(f"Инициирована реакция на инцидент: {incident}")

        response = {
            "incident_id": hash_context(incident.get("source_ip", "") + str(datetime.utcnow())),
            "status": "initiated",
            "actions": [],
            "timestamp": datetime.utcnow().isoformat()
        }

        ip = incident.get("source_ip")
        if ip:
            self.edge_agent.block_ip(ip)
            response["actions"].append(f"IP {ip} заблокирован")

        if zone := incident.get("zone_id"):
            self.policy_enforcer.harden_zone(zone)
            response["actions"].append(f"Зона {zone} усилена ZeroTrust-политиками")

        if user_id := incident.get("user_id"):
            self.policy_enforcer.revoke_user_access(user_id)
            response["actions"].append(f"Доступ пользователя {user_id} отозван")

        threat = incident.get("threat_type")
        if threat:
            logger.warning(f"Угроза типа '{threat}' зафиксирована и нейтрализуется.")

        logger.info(f"Ответные действия завершены: {response}")
        response["status"] = "completed"
        return response

    def generate_report(self, incident: Dict[str, str], actions: Dict[str, str]) -> Dict[str, str]:
        """
        Генерация отчёта для отправки в SIEM или в логгер инцидентов.
        """
        report = {
            "type": "incident_response",
            "incident": incident,
            "actions_taken": actions.get("actions", []),
            "incident_id": actions.get("incident_id"),
            "timestamp": actions.get("timestamp"),
        }

        logger.debug(f"Сформирован отчёт по инциденту: {report}")
        return report

    def escalate_to_alert(self, incident: Dict[str, str], level) -> Optional[Alert]:
        """
        При необходимости — эскалация инцидента в AlertManager.
        """
        if not incident.get("source_ip"):
            return None

        alert = Alert(
            source="IncidentResponseModule",
            level=level,
            message=f"Обнаружен инцидент: {incident.get('threat_type', 'unknown')}",
            metadata=incident
        )

        logger.info(f"Инцидент эскалирован в оповещение: {alert.to_dict()}")
        return alert
