from typing import Generator, Set, List, Dict, Optional

def dfs(graph: Dict[str, Set[str]], start: str, visited: Optional[Set[str]] = None) -> Generator[str, None, None]:
    if visited is None:
        visited = set()
    visited.add(start)
    yield start
    for neighbor in graph.get(start, []):
        if neighbor not in visited:
            yield from dfs(graph, neighbor, visited)

def bfs(graph: Dict[str, Set[str]], start: str) -> Generator[str, None, None]:
    visited: Set[str] = set()
    queue: List[str] = [start]
    visited.add(start)

    while queue:
        node = queue.pop(0)
        yield node
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
