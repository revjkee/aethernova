# chaos_injector.py — Industrial Chaos Resilience Injector (x20 Enhanced)
# TeslaAI Genesis | Improved by 20 agents + 3 metagenerals

import random
import time
import logging
from typing import List, Dict, Optional
from datetime import datetime

from agents.shared.base_agent import EventEmitter

logger = logging.getLogger("ChaosInjector")

class ChaosInjector:
    def __init__(self, topology: Dict[str, Dict], injection_policy: Optional[Dict] = None):
        self.topology = topology
        self.injection_policy = injection_policy or self.default_policy()
        self.injection_log: List[Dict] = []

    def default_policy(self) -> Dict:
        return {
            "frequency_seconds": 10,
            "failure_modes": ["shutdown", "packet_loss", "cpu_spike", "latency", "reboot", "drop_service"],
            "max_nodes": 3,
            "intensity": 0.3,
            "include_tags": [],
            "exclude_tags": ["critical"]
        }

    def should_inject(self) -> bool:
        return random.random() < self.injection_policy.get("intensity", 0.3)

    def select_targets(self) -> List[str]:
        nodes = list(self.topology.keys())
        include_tags = self.injection_policy.get("include_tags", [])
        exclude_tags = self.injection_policy.get("exclude_tags", [])

        def eligible(nid):
            node = self.topology[nid]
            tags = set(node.get("tags", []))
            if exclude_tags and tags.intersection(set(exclude_tags)):
                return False
            if include_tags and not tags.intersection(set(include_tags)):
                return False
            return True

        eligible_nodes = [nid for nid in nodes if eligible(nid)]
        random.shuffle(eligible_nodes)
        return eligible_nodes[:self.injection_policy.get("max_nodes", 3)]

    def inject_failure(self, node_id: str, failure_type: str):
        ts = datetime.utcnow().isoformat()
        event = {
            "timestamp": ts,
            "target": node_id,
            "type": failure_type,
            "origin": "chaos_injector"
        }
        self.injection_log.append(event)
        EventEmitter.emit("chaos_event", event)
        logger.warning(f"Injected failure [{failure_type}] into node [{node_id}] at {ts}")

    def run_cycle(self):
        if not self.should_inject():
            return

        targets = self.select_targets()
        failure_modes = self.injection_policy["failure_modes"]
        for node_id in targets:
            failure = random.choice(failure_modes)
            self.inject_failure(node_id, failure)

    def get_metrics(self) -> Dict:
        return {
            "total_injections": len(self.injection_log),
            "last_injection": self.injection_log[-1] if self.injection_log else None
        }

    def simulate_burst(self, burst_count: int = 10):
        for _ in range(burst_count):
            self.run_cycle()
            time.sleep(0.2)  # faster chaos for stress test
