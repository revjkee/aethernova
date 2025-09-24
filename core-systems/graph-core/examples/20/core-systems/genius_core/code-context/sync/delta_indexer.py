# genius-core/code-context/sync/delta_indexer.py

import difflib
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from .dag_tracker import MerkleDAG


class Delta:
    def __init__(self, file_path: str, old_code: str, new_code: str):
        self.file_path = file_path
        self.old_code = old_code
        self.new_code = new_code
        self.diff = self._generate_diff()
        self.changed_lines = self._extract_changed_lines()

    def _generate_diff(self) -> str:
        old_lines = self.old_code.splitlines(keepends=True)
        new_lines = self.new_code.splitlines(keepends=True)
        return ''.join(difflib.unified_diff(old_lines, new_lines, fromfile='old', tofile='new'))

    def _extract_changed_lines(self) -> List[int]:
        sm = difflib.SequenceMatcher(None, self.old_code.splitlines(), self.new_code.splitlines())
        changed = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in {"replace", "delete", "insert"}:
                changed.extend(range(j1, j2))
        return sorted(set(changed))

    def to_dict(self) -> Dict:
        return {
            "file": self.file_path,
            "lines_changed": self.changed_lines,
            "diff": self.diff
        }


class DeltaIndexer:
    def __init__(self, dag: MerkleDAG):
        self.dag = dag

    def compute_delta_by_cids(self, cid1: str, cid2: str) -> Optional[Delta]:
        node1 = self.dag.get_node(cid1)
        node2 = self.dag.get_node(cid2)

        if not node1 or not node2:
            return None

        if node1.file_path != node2.file_path:
            raise ValueError("Files do not match")

        return Delta(node1.file_path, node1.content_hash, node2.content_hash)

    def compute_delta_from_file(self, file_path: Path, new_code: str) -> Optional[Delta]:
        file_path_str = str(file_path)
        latest_cid = self.dag.latest_cid_by_file.get(file_path_str)
        if not latest_cid:
            return None

        latest_node = self.dag.get_node(latest_cid)
        if not latest_node:
            return None

        return Delta(file_path_str, latest_node.content_hash, new_code)

    def export_delta(self, delta: Delta, export_path: Path) -> None:
        with export_path.open("w", encoding="utf-8") as f:
            json.dump(delta.to_dict(), f, indent=2)

    def summarize_delta(self, delta: Delta) -> str:
        lines = delta.changed_lines
        return f"File `{delta.file_path}` changed in {len(lines)} lines: {lines}"


# Пример использования
if __name__ == "__main__":
    from pathlib import Path
    dag = MerkleDAG()

    path = Path("example/sample.py")
    dag.add_version(str(path), "def hello():\n    pass\n")
    dag.add_version(str(path), "def hello():\n    return 'world'\n")

    cid1 = dag.get_ancestors(dag.latest_cid_by_file[str(path)], depth=2)[-1]
    cid2 = dag.latest_cid_by_file[str(path)]

    indexer = DeltaIndexer(dag)
    delta = indexer.compute_delta_by_cids(cid1, cid2)
    if delta:
        print(delta.diff)
        print(delta.to_dict())
