# node_simulator.py — High-Fidelity Node Behavior Simulator
# TeslaAI Genesis Industrial Edition — Improved x20 by 20 agents & 3 metagenerals

import random
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional

from agents.shared.intelligence_core import ThreatModel
from agents.shared.base_agent import EventEmitter, NodeState

logger = logging.getLogger("NodeSimulator")


class Node:
    def __init__(self, node_id: str, config: Dict):
        self.id = node_id
        self.config = config
        self.type = config.get("type")
        self.os = config.get("os")
        self.services = config.get("services", [])
        self.vulnerabilities = config.get("vulnerabilities", [])
        self.sensors = config.get("sensors", [])
        self.tags = set(config.get("tags", []))
        self.state = NodeState()
        self.logs: List[Dict] = []
        self.last_action_ts = time.time()
        self.compromised = False
        self.honeypot = config.get("honeypot", False)
        self.deception_level = config.get("deception_level", 0.0)
        self.threat_model = ThreatModel(self.id, self.type, self.os)

    def receive_packet(self, packet: Dict):
        logger.debug(f"Node {self.id} received packet: {packet}")
        if self.state.quarantined:
            logger.info(f"Node {self.id} is quarantined; packet dropped.")
            return

        attacker_id = packet.get("source")
        action_type = packet.get("action")

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": attacker_id,
            "target": self.id,
            "type": action_type,
            "payload": packet.get("payload", {}),
        }

        self.logs.append(event)
        EventEmitter.emit("packet_received", event)

        # Process behavior
        if action_type == "scan":
            self._handle_scan(attacker_id)
        elif action_type == "exploit":
            self._handle_exploit(attacker_id, packet["payload"])
        elif action_type == "credential_access":
            self._handle_credential_access(attacker_id)
        elif action_type == "deception_probe":
            self._handle_deception(attacker_id)
        else:
            logger.warning(f"Node {self.id}: unknown action type {action_type}")

    def _handle_scan(self, attacker_id: str):
        logger.info(f"{self.id} scanned by {attacker_id}")
        if random.random() < 0.1:
            self.state.detected = True
            logger.info(f"Node {self.id} detected scanning activity")
            EventEmitter.emit("scan_detected", {"target": self.id, "attacker": attacker_id})

    def _handle_exploit(self, attacker_id: str, payload: Dict):
        exploit_id = payload.get("exploit_id")
        if exploit_id in self.vulnerabilities:
            self.compromised = True
            self.state.compromised_by = attacker_id
            logger.critical(f"{self.id} successfully exploited with {exploit_id}")
            EventEmitter.emit("node_compromised", {"target": self.id, "exploit": exploit_id})
        else:
            logger.debug(f"{self.id} exploit attempt failed ({exploit_id})")
            EventEmitter.emit("exploit_failed", {"target": self.id, "exploit": exploit_id})

    def _handle_credential_access(self, attacker_id: str):
        if "weak_passwords" in self.tags:
            self.state.compromised_by = attacker_id
            self.compromised = True
            EventEmitter.emit("credential_compromise", {"target": self.id})
            logger.critical(f"{self.id} compromised via weak credentials")

    def _handle_deception(self, attacker_id: str):
        if self.honeypot:
            trap_score = self.deception_level + random.random()
            EventEmitter.emit("honeypot_triggered", {
                "attacker": attacker_id,
                "target": self.id,
                "score": trap_score,
            })
            logger.warning(f"Honeypot {self.id} triggered by {attacker_id} (score={trap_score:.2f})")

    def generate_heartbeat(self) -> Dict:
        self.last_action_ts = time.time()
        status = {
            "id": self.id,
            "compromised": self.compromised,
            "services": self.services,
            "timestamp": datetime.utcnow().isoformat(),
        }
        EventEmitter.emit("heartbeat", status)
        return status

    def simulate_activity(self):
        if self.compromised and random.random() < 0.5:
            logger.info(f"Node {self.id} is beaconing to C2")
            EventEmitter.emit("beacon", {"node": self.id, "ts": datetime.utcnow().isoformat()})
        if not self.compromised and random.random() < 0.1:
            EventEmitter.emit("routine_activity", {"node": self.id, "ts": datetime.utcnow().isoformat()})
