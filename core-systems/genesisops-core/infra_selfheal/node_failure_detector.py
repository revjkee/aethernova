import time
import socket
import logging
from threading import Thread
from datetime import datetime
from typing import Dict, Optional

from genesisops_core.telemetry.pulse import heartbeat_register, get_cluster_status
from genesisops_core.security.zones import quarantine_node
from genesisops_core.ai.anomaly import detect_anomaly_score
from genesisops_core.control.audit import log_node_failure_event
from genesisops_core.core.errors import NodeHealthCheckError

logger = logging.getLogger("infra.node_failure_detector")
logging.basicConfig(level=logging.INFO)

CHECK_INTERVAL = 5
FAILURE_THRESHOLD = 3
ANOMALY_THRESHOLD = 0.82
CLUSTER_DOMAIN = "genesis-mesh.local"

class NodeFailureDetector:
    def __init__(self, local_node_id: str, peer_nodes: Dict[str, str]):
        self.local_node_id = local_node_id
        self.peer_nodes = peer_nodes
        self.failure_counters: Dict[str, int] = {node: 0 for node in peer_nodes}
        self.active = True

    def _ping_node(self, ip: str) -> bool:
        try:
            with socket.create_connection((ip, 443), timeout=2):
                return True
        except Exception:
            return False

    def _check_node_health(self, node_id: str, ip: str):
        success = self._ping_node(ip)
        if not success:
            self.failure_counters[node_id] += 1
            logger.warning(f"Node {node_id} failed ping ({self.failure_counters[node_id]})")
        else:
            self.failure_counters[node_id] = 0

        if self.failure_counters[node_id] >= FAILURE_THRESHOLD:
            self._handle_failure(node_id, ip)

    def _handle_failure(self, node_id: str, ip: str):
        try:
            anomaly_score = detect_anomaly_score(node_id)
            logger.warning(f"Node {node_id} marked failed with anomaly_score={anomaly_score}")

            if anomaly_score >= ANOMALY_THRESHOLD:
                quarantine_node(node_id)
                status_snapshot = get_cluster_status()

                log_node_failure_event({
                    "node_id": node_id,
                    "ip": ip,
                    "anomaly_score": anomaly_score,
                    "timestamp": datetime.utcnow().isoformat(),
                    "cluster_status": status_snapshot,
                    "quarantined": True
                })

        except Exception as e:
            logger.exception("Failure handling failed")
            raise NodeHealthCheckError("Failure event could not be processed") from e

    def _heartbeat_sync(self):
        while self.active:
            try:
                heartbeat_register(self.local_node_id)
            except Exception as e:
                logger.warning(f"Failed to send heartbeat: {e}")
            time.sleep(CHECK_INTERVAL)

    def _monitor_peers(self):
        while self.active:
            for node_id, ip in self.peer_nodes.items():
                if node_id == self.local_node_id:
                    continue
                try:
                    self._check_node_health(node_id, ip)
                except Exception as e:
                    logger.warning(f"Health check failed for {node_id}: {e}")
            time.sleep(CHECK_INTERVAL)

    def start(self):
        logger.info("Starting NodeFailureDetector service")
        Thread(target=self._heartbeat_sync, daemon=True).start()
        Thread(target=self._monitor_peers, daemon=True).start()

    def stop(self):
        logger.info("Stopping NodeFailureDetector service")
        self.active = False
