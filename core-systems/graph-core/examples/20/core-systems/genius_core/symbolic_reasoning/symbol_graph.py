# AI-platform-core/genius-core/symbolic-reasoning/symbol_graph.py

import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger("SymbolGraph")

class SymbolNode:
    def __init__(self, name: str, node_type: str, attributes: Optional[Dict[str, str]] = None):
        self.name = name
        self.node_type = node_type  # concept | action | property | agent | abstract
        self.attributes = attributes or {}
        self.relations: Dict[str, Set[str]] = {}  # relation_type -> set of target node names

    def add_relation(self, relation: str, target: str):
        if relation not in self.relations:
            self.relations[relation] = set()
        self.relations[relation].add(target)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.node_type,
            "attributes": self.attributes,
            "relations": {k: list(v) for k, v in self.relations.items()}
        }

class SymbolGraph:
    """
    Граф понятий и символов. Используется для построения логических цепочек, планирования, аналогий и дедуктивных выводов.
    """

    def __init__(self):
        self.nodes: Dict[str, SymbolNode] = {}

    def add_node(self, name: str, node_type: str, attributes: Optional[Dict[str, str]] = None):
        if name not in self.nodes:
            self.nodes[name] = SymbolNode(name, node_type, attributes)
            logger.info(f"[SymbolGraph] Добавлен узел: {name} ({node_type})")
        else:
            logger.warning(f"[SymbolGraph] Узел уже существует: {name}")

    def add_relation(self, source: str, relation: str, target: str):
        if source not in self.nodes or target not in self.nodes:
            logger.error(f"[SymbolGraph] Связь невозможна: один из узлов отсутствует ({source}, {target})")
            return
        self.nodes[source].add_relation(relation, target)
        logger.debug(f"[SymbolGraph] Добавлена связь: {source} -[{relation}]-> {target}")

    def get_node(self, name: str) -> Optional[SymbolNode]:
        return self.nodes.get(name)

    def query_related(self, name: str, relation: str) -> List[str]:
        node = self.nodes.get(name)
        if node and relation in node.relations:
            return list(node.relations[relation])
        return []

    def export_graph(self) -> Dict[str, Dict]:
        return {name: node.to_dict() for name, node in self.nodes.items()}

    def find_path(self, start: str, target: str, max_depth: int = 4) -> Optional[List[str]]:
        """
        Находит путь от start к target через символические связи
        """
        visited = set()
        path = []

        def dfs(current, depth):
            if current in visited or depth > max_depth:
                return False
            visited.add(current)
            path.append(current)
            if current == target:
                return True
            for rel in self.nodes.get(current, SymbolNode(current, "unknown")).relations.values():
                for neighbor in rel:
                    if dfs(neighbor, depth + 1):
                        return True
            path.pop()
            return False

        if dfs(start, 0):
            return path
        return None
