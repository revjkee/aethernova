from typing import Dict, Set, List, Optional

class Graph:
    def __init__(self, directed: bool = False) -> None:
        self.directed = directed
        self.adj_list: Dict[str, Set[str]] = {}

    def add_node(self, node: str) -> None:
        if node not in self.adj_list:
            self.adj_list[node] = set()

    def add_edge(self, src: str, dst: str) -> None:
        self.add_node(src)
        self.add_node(dst)
        self.adj_list[src].add(dst)
        if not self.directed:
            self.adj_list[dst].add(src)

    def neighbors(self, node: str) -> Optional[Set[str]]:
        return self.adj_list.get(node)

    def nodes(self) -> List[str]:
        return list(self.adj_list.keys())

    def edges(self) -> List[tuple[str, str]]:
        edges = []
        for src, neighbors in self.adj_list.items():
            for dst in neighbors:
                edges.append((src, dst))
        return edges

    def __repr__(self) -> str:
        return f"Graph(directed={self.directed}, nodes={len(self.adj_list)})"
