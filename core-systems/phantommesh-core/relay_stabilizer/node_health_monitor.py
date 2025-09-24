# phantommesh-core/relay_stabilizer/node_health_monitor.py

import asyncio
import logging
import time
from typing import Dict, Optional, List, Callable, Tuple

logger = logging.getLogger("node_health_monitor")
logger.setLevel(logging.DEBUG)

HEALTH_CHECK_INTERVAL = 30
FAILURE_THRESHOLD = 3
PING_TIMEOUT = 1.0
PORT_TIMEOUT = 1.5

class NodeStatus:
    def __init__(self, node_id: str, host: str, port: int):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.online = True
        self.last_latency_ms: Optional[float] = None
        self.fail_count = 0
        self.last_checked = 0.0
        self.last_error: Optional[str] = None

    def update_latency(self, latency: Optional[float]):
        if latency is not None:
            self.last_latency_ms = latency
            self.fail_count = 0
            self.online = True
            self.last_error = None
        else:
            self.fail_count += 1
            if self.fail_count >= FAILURE_THRESHOLD:
                self.online = False
                self.last_error = "UNREACHABLE"

        self.last_checked = time.time()

class NodeHealthMonitor:
    def __init__(self, nodes: List[Tuple[str, str, int]]):
        self.nodes: Dict[str, NodeStatus] = {
            nid: NodeStatus(nid, host, port) for nid, host, port in nodes
        }
        self.subscribers: List[Callable[[NodeStatus], None]] = []

    def subscribe(self, callback: Callable[[NodeStatus], None]) -> None:
        self.subscribers.append(callback)

    def _notify(self, status: NodeStatus) -> None:
        for subscriber in self.subscribers:
            subscriber(status)

    async def _ping(self, host: str, port: int) -> Optional[float]:
        try:
            start = asyncio.get_event_loop().time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=PORT_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            end = asyncio.get_event_loop().time()
            latency = (end - start) * 1000
            return latency
        except Exception as e:
            return None

    async def check_node(self, status: NodeStatus) -> None:
        latency = await self._ping(status.host, status.port)
        status.update_latency(latency)
        self._notify(status)

        if status.online:
            logger.info(f"[{status.node_id}] OK latency={status.last_latency_ms:.1f}ms")
        else:
            logger.warning(f"[{status.node_id}] OFFLINE fail_count={status.fail_count}")

    async def monitor_loop(self, interval: int = HEALTH_CHECK_INTERVAL):
        while True:
            tasks = [self.check_node(status) for status in self.nodes.values()]
            await asyncio.gather(*tasks)
            await asyncio.sleep(interval)

    def get_status(self, node_id: str) -> Optional[NodeStatus]:
        return self.nodes.get(node_id)

    def get_all_statuses(self) -> Dict[str, NodeStatus]:
        return self.nodes

    def get_online_nodes(self) -> List[NodeStatus]:
        return [n for n in self.nodes.values() if n.online]

    def remove_node(self, node_id: str) -> None:
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"Удалён узел: {node_id}")

    def add_node(self, node_id: str, host: str, port: int) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeStatus(node_id, host, port)
            logger.info(f"Добавлен узел: {node_id} @ {host}:{port}")

# === Пример использования ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    test_nodes = [
        ("relay-A", "192.168.1.10", 443),
        ("relay-B", "192.168.1.11", 443),
        ("relay-C", "192.168.1.12", 443)
    ]

    monitor = NodeHealthMonitor(test_nodes)

    def print_status(status: NodeStatus):
        logger.info(f"[{status.node_id}] online={status.online} latency={status.last_latency_ms}ms")

    monitor.subscribe(print_status)

    asyncio.run(monitor.monitor_loop(interval=20))
