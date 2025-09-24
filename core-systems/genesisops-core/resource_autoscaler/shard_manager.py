import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from uuid import uuid4

from genesisops_core.telemetry.metrics import fetch_node_capacity, fetch_shard_loads
from genesisops_core.ai.optimizer import suggest_optimal_placement
from genesisops_core.control.audit import log_shard_allocation_event
from genesisops_core.security.isolation import isolate_faulty_shard
from genesisops_core.core.errors import ShardManagementError

logger = logging.getLogger("autoscaler.shard_manager")
logging.basicConfig(level=logging.INFO)

REALLOCATION_THRESHOLD = 0.15  # % нагрузки, при котором инициируется перебаланс
OVERLOAD_LIMIT = 0.90
MIN_SHARDS_PER_NODE = 1
MAX_SHARDS_PER_NODE = 12

class ShardState:
    def __init__(self, shard_id: str, node_id: str, load: float):
        self.shard_id = shard_id
        self.node_id = node_id
        self.load = load
        self.timestamp = datetime.utcnow()

class ShardManager:
    def __init__(self):
        self.shard_map: Dict[str, ShardState] = {}  # shard_id -> state
        self.node_shards: Dict[str, List[str]] = {}  # node_id -> list of shards

    def _register_shard(self, shard_id: str, node_id: str, load: float):
        self.shard_map[shard_id] = ShardState(shard_id, node_id, load)
        self.node_shards.setdefault(node_id, []).append(shard_id)
        logger.debug(f"Shard {shard_id} assigned to {node_id} with load {load}")

    def allocate_new_shard(self, shard_id: str) -> str:
        try:
            node_caps = fetch_node_capacity()
            node_loads = {nid: sum(self.shard_map[sh].load for sh in self.node_shards.get(nid, []))
                          for nid in node_caps.keys()}
            selected_node = suggest_optimal_placement(node_loads, node_caps)

            self._register_shard(shard_id, selected_node, load=0.0)

            log_shard_allocation_event({
                "shard_id": shard_id,
                "node_id": selected_node,
                "event": "allocate_new",
                "timestamp": datetime.utcnow().isoformat()
            })

            return selected_node

        except Exception as e:
            logger.exception("Shard allocation failed")
            raise ShardManagementError("Failed to allocate new shard") from e

    def rebalance(self):
        try:
            shard_loads = fetch_shard_loads()
            overloaded_shards = [
                (sid, data) for sid, data in shard_loads.items()
                if data["load"] > OVERLOAD_LIMIT
            ]

            if not overloaded_shards:
                logger.info("No overloaded shards found")
                return

            for shard_id, shard_info in overloaded_shards:
                node_id = shard_info["node"]
                load = shard_info["load"]
                logger.warning(f"Shard {shard_id} on {node_id} is overloaded ({load})")

                new_node = self._find_alternative_node(shard_id, node_id)
                if new_node and new_node != node_id:
                    self._migrate_shard(shard_id, from_node=node_id, to_node=new_node)

        except Exception as e:
            logger.error("Rebalance failed")
            raise ShardManagementError("Rebalancing error") from e

    def _find_alternative_node(self, shard_id: str, current_node: str) -> Optional[str]:
        node_caps = fetch_node_capacity()
        node_loads = {nid: sum(self.shard_map[sh].load for sh in self.node_shards.get(nid, []))
                      for nid in node_caps.keys() if nid != current_node}

        candidate_node = suggest_optimal_placement(node_loads, node_caps)
        return candidate_node

    def _migrate_shard(self, shard_id: str, from_node: str, to_node: str):
        try:
            self.node_shards[from_node].remove(shard_id)
            self.node_shards.setdefault(to_node, []).append(shard_id)
            self.shard_map[shard_id].node_id = to_node
            self.shard_map[shard_id].timestamp = datetime.utcnow()

            log_shard_allocation_event({
                "shard_id": shard_id,
                "from": from_node,
                "to": to_node,
                "event": "migrated",
                "timestamp": datetime.utcnow().isoformat()
            })

            logger.info(f"Shard {shard_id} migrated from {from_node} to {to_node}")

        except Exception as e:
            isolate_faulty_shard(shard_id)
            raise ShardManagementError(f"Failed to migrate shard {shard_id}") from e

    def get_shard_status(self) -> Dict[str, Dict]:
        return {
            shard_id: {
                "node": state.node_id,
                "load": state.load,
                "last_updated": state.timestamp.isoformat()
            } for shard_id, state in self.shard_map.items()
        }
