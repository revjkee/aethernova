import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from core.alerts.alert_dispatcher import dispatch_critical_alert
from core.config.loader import load_heartbeat_config

logger = logging.getLogger("telemetry.heartbeat_watcher")
logger.setLevel(logging.INFO)


class AgentHeartbeatWatcher:
    def __init__(self):
        self.heartbeat_registry: Dict[str, Dict] = {}
        self.config = load_heartbeat_config()
        self.timeout_seconds = self.config.get("timeout_seconds", 30)
        self.alert_grace = self.config.get("alert_grace_seconds", 10)
        self.scan_interval = self.config.get("scan_interval_seconds", 5)
        self.alerted_agents = set()

    def register_heartbeat(self, agent_id: str):
        now = datetime.utcnow()
        self.heartbeat_registry[agent_id] = {
            "last_seen": now,
            "alerts": 0
        }
        logger.debug(f"Registered heartbeat: {agent_id} at {now.isoformat()}")

    def update_heartbeat(self, agent_id: str):
        now = datetime.utcnow()
        if agent_id not in self.heartbeat_registry:
            self.register_heartbeat(agent_id)
        else:
            self.heartbeat_registry[agent_id]["last_seen"] = now
            self.heartbeat_registry[agent_id]["alerts"] = 0
            if agent_id in self.alerted_agents:
                self.alerted_agents.remove(agent_id)
        logger.debug(f"Heartbeat updated: {agent_id} at {now.isoformat()}")

    async def start_monitoring(self):
        logger.info("HeartbeatWatcher activated.")
        while True:
            try:
                await self._scan_agents()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Heartbeat monitoring failed: {e}")

    async def _scan_agents(self):
        now = datetime.utcnow()
        for agent_id, record in list(self.heartbeat_registry.items()):
            last_seen = record["last_seen"]
            time_diff = (now - last_seen).total_seconds()

            if time_diff > self.timeout_seconds:
                if agent_id not in self.alerted_agents:
                    await self._trigger_alert(agent_id, time_diff)
                    self.alerted_agents.add(agent_id)
            elif time_diff > (self.timeout_seconds - self.alert_grace):
                logger.warning(f"Agent {agent_id} nearing timeout: {time_diff:.1f}s")
            else:
                logger.debug(f"Agent {agent_id} healthy: {time_diff:.1f}s since last heartbeat")

    async def _trigger_alert(self, agent_id: str, delay: float):
        alert_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": agent_id,
            "alert_type": "heartbeat_timeout",
            "delay_seconds": delay,
            "severity": "critical",
            "system": "heartbeat_watcher",
        }
        logger.warning(f"[ALERT] Agent {agent_id} unresponsive for {delay:.2f} seconds.")
        await dispatch_critical_alert(alert_payload)
        # Optional: trigger auto-recovery, redeploy, etc.


# External interface
heartbeat_watcher = AgentHeartbeatWatcher()


def heartbeat(agent_id: str):
    heartbeat_watcher.update_heartbeat(agent_id)


async def main():
    await heartbeat_watcher.start_monitoring()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("HeartbeatWatcher terminated.")
