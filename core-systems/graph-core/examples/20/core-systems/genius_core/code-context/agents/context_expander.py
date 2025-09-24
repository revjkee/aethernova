# genius-core/code-context/agents/context_expander.py

from typing import Dict, List, Set, Optional
from pathlib import Path
import json

class ContextExpander:
    def __init__(
        self,
        graph_path: Path,
        max_depth: int = 2,
        exclude_types: Optional[Set[str]] = None
    ):
        self.graph: Dict[str, Dict] = self._load_graph(graph_path)
        self.max_depth = max_depth
        self.exclude_types = exclude_types or {"import", "comment"}

    def _load_graph(self, path: Path) -> Dict[str, Dict]:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def expand(self, symbol_name: str) -> Dict[str, Dict]:
        """
        Возвращает подграф, содержащий символ и его зависимости до заданной глубины
        """
        visited = set()
        queue = [(symbol_name, 0)]
        expanded = {}

        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > self.max_depth:
                continue
            node = self.graph.get(current)
            if not node:
                continue
            if node["type"] in self.exclude_types:
                continue

            expanded[current] = node
            visited.add(current)

            children = node.get("calls", []) + [c["name"] for c in node.get("children", [])]
            for child in children:
                queue.append((child, depth + 1))

        return expanded

    def extract_code_context(self, expanded_subgraph: Dict[str, Dict]) -> str:
        """
        Собирает фрагменты кода, соответствующие символам
        """
        context_blocks = []
        for name, node in expanded_subgraph.items():
            code = node.get("code_snippet", f"# [no code found for {name}]")
            context_blocks.append(f"# {name} ({node['type']})\n{code}")
        return "\n\n".join(context_blocks)
