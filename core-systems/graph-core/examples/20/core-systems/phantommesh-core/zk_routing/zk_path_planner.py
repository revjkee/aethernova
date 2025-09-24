# phantommesh-core/zk_routing/zk_path_planner.py

import random
import hashlib
import logging
from typing import List, Dict, Optional, Tuple

from dataclasses import dataclass

logger = logging.getLogger("zk_path_planner")
logger.setLevel(logging.DEBUG)

# === Конфиденциальная нода маршрута ===
@dataclass
class ZKNode:
    node_id: str  # Хэшированный ID
    neighbors: List[str]  # Хэшированные ID соседей

# === ZK-Маршрут без раскрытия ===
@dataclass
class ZKRoute:
    path_hashes: List[str]  # Хэш-цепочка маршрута
    zk_proof: str           # Доказательство корректности (SNARK)

class ZKTopology:
    def __init__(self, private_graph: Dict[str, ZKNode]):
        self.graph = private_graph  # Топология в приватной ZK форме

    def get_neighbors(self, node_hash: str) -> List[str]:
        node = self.graph.get(node_hash)
        return node.neighbors if node else []

    def node_exists(self, node_hash: str) -> bool:
        return node_hash in self.graph

class ZKPathPlanner:
    def __init__(self, topology: ZKTopology):
        self.topology = topology

    def _hash(self, value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _generate_zksnark_proof(self, path: List[str]) -> str:
        # Моделируем zkSNARK-доказательство корректности маршрута
        digest = hashlib.blake2s("".join(path).encode()).hexdigest()
        proof = f"snark_{digest[:24]}"
        return proof

    def _validate_snark(self, path: List[str], proof: str) -> bool:
        expected = self._generate_zksnark_proof(path)
        return expected == proof

    def plan_path(self, src_hash: str, dst_hash: str, max_hops: int = 7) -> Optional[ZKRoute]:
        if not (self.topology.node_exists(src_hash) and self.topology.node_exists(dst_hash)):
            logger.warning("Один из хэшей отсутствует в ZK-топологии.")
            return None

        visited = set()
        queue: List[Tuple[str, List[str]]] = [(src_hash, [src_hash])]

        while queue:
            current, path = queue.pop(0)
            if current == dst_hash:
                zk_proof = self._generate_zksnark_proof(path)
                logger.info(f"Маршрут найден. Длина: {len(path)}. SNARK: {zk_proof}")
                return ZKRoute(path_hashes=path, zk_proof=zk_proof)

            if len(path) >= max_hops:
                continue

            for neighbor in self.topology.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        logger.warning("Путь не найден.")
        return None

    def verify_route(self, zk_route: ZKRoute) -> bool:
        valid = self._validate_snark(zk_route.path_hashes, zk_route.zk_proof)
        if valid:
            logger.info("SNARK-доказательство маршрута верифицировано.")
        else:
            logger.error("Неверное SNARK-доказательство.")
        return valid

    def replan_with_exclusion(self, src_hash: str, dst_hash: str, exclude: List[str]) -> Optional[ZKRoute]:
        if not self.topology.node_exists(src_hash) or not self.topology.node_exists(dst_hash):
            return None

        visited = set(exclude)
        queue: List[Tuple[str, List[str]]] = [(src_hash, [src_hash])]

        while queue:
            current, path = queue.pop(0)
            if current == dst_hash:
                zk_proof = self._generate_zksnark_proof(path)
                return ZKRoute(path_hashes=path, zk_proof=zk_proof)

            for neighbor in self.topology.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

# === Пример использования ===
def generate_mock_topology(num_nodes: int = 20) -> ZKTopology:
    nodes = {}
    for i in range(num_nodes):
        node_id = f"node_{i}"
        node_hash = hashlib.sha256(node_id.encode()).hexdigest()
        neighbors = random.sample(range(num_nodes), k=random.randint(2, 4))
        neighbor_hashes = [
            hashlib.sha256(f"node_{n}".encode()).hexdigest() for n in neighbors if n != i
        ]
        nodes[node_hash] = ZKNode(node_id=node_hash, neighbors=neighbor_hashes)
    return ZKTopology(nodes)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    zk_topology = generate_mock_topology()
    planner = ZKPathPlanner(zk_topology)

    nodes = list(zk_topology.graph.keys())
    src, dst = random.sample(nodes, 2)

    route = planner.plan_path(src, dst)
    if route and planner.verify_route(route):
        logger.info(f"ZK-маршрут успешно верифицирован: {route.path_hashes}")
    else:
        logger.error("Ошибка построения или верификации маршрута.")
