# genius-core/code-context/sync/dag_tracker.py

import hashlib
import json
from typing import Dict, Optional, List, Tuple
from pathlib import Path
from collections import defaultdict


class DAGNode:
    def __init__(self, file_path: str, content_hash: str, parent_hashes: Optional[List[str]] = None):
        self.file_path = file_path
        self.content_hash = content_hash
        self.parent_hashes = parent_hashes or []
        self.node_hash = self.compute_cid()

    def compute_cid(self) -> str:
        node_data = f"{self.file_path}:{self.content_hash}:{','.join(sorted(self.parent_hashes))}"
        return hashlib.sha256(node_data.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "content_hash": self.content_hash,
            "parent_hashes": self.parent_hashes,
            "cid": self.node_hash,
        }


class MerkleDAG:
    def __init__(self):
        self.nodes: Dict[str, DAGNode] = {}            # key = cid
        self.latest_cid_by_file: Dict[str, str] = {}   # file_path -> latest cid
        self.children: Dict[str, List[str]] = defaultdict(list)  # cid -> [children]

    def add_version(self, file_path: str, content: str) -> str:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        parent_cid = self.latest_cid_by_file.get(file_path)
        parents = [parent_cid] if parent_cid else []

        node = DAGNode(file_path, content_hash, parents)
        self.nodes[node.node_hash] = node
        self.latest_cid_by_file[file_path] = node.node_hash

        for parent in parents:
            self.children[parent].append(node.node_hash)

        return node.node_hash

    def get_ancestors(self, cid: str, depth: int = 5) -> List[str]:
        result = []
        queue = [cid]
        while queue and len(result) < depth:
            current = queue.pop(0)
            result.append(current)
            node = self.nodes.get(current)
            if node:
                queue.extend(node.parent_hashes)
        return result

    def get_node(self, cid: str) -> Optional[DAGNode]:
        return self.nodes.get(cid)

    def export_json(self, output_path: Path) -> None:
        graph_data = {
            cid: node.to_dict()
            for cid, node in self.nodes.items()
        }
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)

    def diff(self, cid1: str, cid2: str) -> Dict[str, str]:
        """Compare two nodes and return difference metadata."""
        node1 = self.get_node(cid1)
        node2 = self.get_node(cid2)
        if not node1 or not node2:
            return {"error": "Invalid CIDs"}
        return {
            "file": node1.file_path,
            "same_file": node1.file_path == node2.file_path,
            "same_content": node1.content_hash == node2.content_hash,
            "cid1": cid1,
            "cid2": cid2
        }

    def has_changed(self, file_path: str, content: str) -> bool:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        latest_cid = self.latest_cid_by_file.get(file_path)
        if not latest_cid:
            return True
        latest_node = self.nodes.get(latest_cid)
        return latest_node.content_hash != content_hash


# Example usage
if __name__ == "__main__":
    dag = MerkleDAG()
    path = "sample/code.py"

    cid1 = dag.add_version(path, "def a(): pass")
    cid2 = dag.add_version(path, "def a(): return 42")

    print("CID1:", cid1)
    print("CID2:", cid2)
    print("DIFF:", dag.diff(cid1, cid2))
    dag.export_json(Path("dag_output.json"))
