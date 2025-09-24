# phantommesh-core/relay_stabilizer/latency_balancer.py

import asyncio
import statistics
import logging
import random
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("latency_balancer")
logger.setLevel(logging.DEBUG)

PING_TIMEOUT = 1.5
BALANCE_RECALC_INTERVAL = 30
STATS_WINDOW = 5
MAX_LATENCY_MS = 1000

# === Релеевый узел с метрикой ===
class RelayNode:
    def __init__(self, node_id: str, host: str, port: int):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.latency_samples: List[float] = []
        self.last_score: float = float("inf")

    def record_latency(self, value: float) -> None:
        if value < MAX_LATENCY_MS:
            self.latency_samples.append(value)
            if len(self.latency_samples) > STATS_WINDOW:
                self.latency_samples.pop(0)

    def average_latency(self) -> float:
        if not self.latency_samples:
            return float("inf")
        return statistics.mean(self.latency_samples)

    def jitter(self) -> float:
        if len(self.latency_samples) < 2:
            return 0.0
        return statistics.stdev(self.latency_samples)

    def score(self) -> float:
        avg = self.average_latency()
        jit = self.jitter()
        self.last_score = avg + (jit * 0.75)
        return self.last_score

# === Балансировщик с проверкой пинга ===
class LatencyBalancer:
    def __init__(self, relay_nodes: List[RelayNode]):
        self.nodes = {n.node_id: n for n in relay_nodes}
        self.best_node_id: Optional[str] = None

    async def _ping(self, host: str, port: int) -> Optional[float]:
        try:
            start = asyncio.get_event_loop().time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=PING_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            end = asyncio.get_event_loop().time()
            latency_ms = (end - start) * 1000
            return latency_ms
        except Exception:
            return None

    async def update_latencies(self) -> None:
        tasks = []
        for node in self.nodes.values():
            task = self._ping_and_record(node)
            tasks.append(task)
        await asyncio.gather(*tasks)

    async def _ping_and_record(self, node: RelayNode) -> None:
        latency = await self._ping(node.host, node.port)
        if latency is not None:
            node.record_latency(latency)
            logger.info(f"[{node.node_id}] latency={latency:.1f}ms")

    def get_best_node(self) -> Optional[RelayNode]:
        if not self.nodes:
            return None
        best = min(self.nodes.values(), key=lambda n: n.score())
        self.best_node_id = best.node_id
        return best

    async def balance_loop(self, interval: int = BALANCE_RECALC_INTERVAL) -> None:
        while True:
            await self.update_latencies()
            best = self.get_best_node()
            if best:
                logger.info(f"Выбран оптимальный узел: {best.node_id} @ {best.host}:{best.port} | score={best.last_score:.2f}")
            await asyncio.sleep(interval)

    def add_node(self, node: RelayNode) -> None:
        self.nodes[node.node_id] = node

    def remove_node(self, node_id: str) -> None:
        self.nodes.pop(node_id, None)

    def export_scores(self) -> Dict[str, float]:
        return {node.node_id: node.last_score for node in self.nodes.values()}

# === Пример использования ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    test_nodes = [
        RelayNode("relay-1", "192.168.1.10", 443),
        RelayNode("relay-2", "192.168.1.11", 443),
        RelayNode("relay-3", "192.168.1.12", 443),
    ]

    balancer = LatencyBalancer(test_nodes)

    async def run_balancer():
        await balancer.balance_loop(interval=20)

    asyncio.run(run_balancer())
