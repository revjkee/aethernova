# genius-core/code-context/agents/dependency_tracer.py

import ast
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class DependencyTracer:
    def __init__(self, root_dir: Path, exclude_dirs: Optional[List[str]] = None):
        self.root_dir = root_dir
        self.exclude_dirs = set(exclude_dirs or ["__pycache__", "venv", "tests"])
        self.dependency_graph: Dict[str, List[str]] = defaultdict(list)

    def _is_excluded(self, path: Path) -> bool:
        return any(part in self.exclude_dirs for part in path.parts)

    def _extract_imports(self, node: ast.AST) -> List[str]:
        results = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                results.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                results.append(f"{module}.{alias.name}")
        return results

    def _analyze_file(self, filepath: Path) -> List[str]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content)
            imports = []
            for node in ast.walk(tree):
                imports += self._extract_imports(node)
            return imports
        except Exception as e:
            print(f"[warn] Failed to analyze {filepath}: {e}")
            return []

    def build_graph(self) -> Dict[str, List[str]]:
        for py_file in self.root_dir.rglob("*.py"):
            if self._is_excluded(py_file):
                continue
            rel_path = py_file.relative_to(self.root_dir).as_posix()
            imports = self._analyze_file(py_file)
            self.dependency_graph[rel_path] = imports
        return dict(self.dependency_graph)

    def export_as_json(self, output_path: Path):
        import json
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.dependency_graph, f, indent=2)


if __name__ == "__main__":
    tracer = DependencyTracer(root_dir=Path("genius-core/"))
    graph = tracer.build_graph()
    tracer.export_as_json(Path("genius-core/code-context/data/dependency_graph.json"))
    print(f"Dependency graph with {len(graph)} files traced.")
