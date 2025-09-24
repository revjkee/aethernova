import os
import json
import threading
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from graph_core.security.access_control import check_graph_permission
from graph_core.security.integrity import verify_checksum, compute_checksum
from graph_core.utils.locking import transactional_lock
from graph_core.audit.logger import graph_audit_log
from graph_core.cache.graph_cache import GraphCache
from graph_core.versioning.revision_store import GraphVersionManager
from graph_core.validation.schema_validator import validate_graph_schema

GRAPH_STORAGE_PATH = Path(os.getenv("GRAPH_STORAGE_PATH", "./graph_data"))
GRAPH_STORAGE_PATH.mkdir(parents=True, exist_ok=True)

class GraphStorage:
    def __init__(self):
        self.cache = GraphCache()
        self.lock = threading.RLock()
        self.version_manager = GraphVersionManager()
        graph_audit_log("storage_initialized", {"path": str(GRAPH_STORAGE_PATH)})

    def _get_path(self, graph_id: str) -> Path:
        return GRAPH_STORAGE_PATH / f"{graph_id}.json"

    @transactional_lock
    def save_graph(self, graph_id: str, graph_data: Dict[str, Any], user: Optional[str] = None) -> None:
        check_graph_permission(graph_id, user, action="write")
        validate_graph_schema(graph_data)

        path = self._get_path(graph_id)
        json_data = json.dumps(graph_data, sort_keys=True, indent=2)
        checksum = compute_checksum(json_data)

        with open(path, "w", encoding="utf-8") as f:
            f.write(json_data)

        self.version_manager.commit(graph_id, json_data, checksum, user)
        self.cache.update(graph_id, graph_data)
        graph_audit_log("graph_saved", {
            "graph_id": graph_id,
            "checksum": checksum,
            "timestamp": datetime.utcnow().isoformat(),
            "user": user
        })

    @transactional_lock
    def load_graph(self, graph_id: str, user: Optional[str] = None) -> Dict[str, Any]:
        check_graph_permission(graph_id, user, action="read")

        cached = self.cache.get(graph_id)
        if cached:
            return cached

        path = self._get_path(graph_id)
        if not path.exists():
            raise FileNotFoundError(f"Graph {graph_id} not found.")

        with open(path, "r", encoding="utf-8") as f:
            json_data = f.read()

        if not verify_checksum(json_data):
            graph_audit_log("graph_checksum_failed", {"graph_id": graph_id})
            raise ValueError("Graph integrity check failed.")

        graph_data = json.loads(json_data)
        self.cache.update(graph_id, graph_data)
        return graph_data

    @transactional_lock
    def delete_graph(self, graph_id: str, user: Optional[str] = None) -> None:
        check_graph_permission(graph_id, user, action="delete")

        path = self._get_path(graph_id)
        if path.exists():
            os.remove(path)
            self.cache.invalidate(graph_id)
            self.version_manager.archive(graph_id, user)
            graph_audit_log("graph_deleted", {
                "graph_id": graph_id,
                "timestamp": datetime.utcnow().isoformat(),
                "user": user
            })

    def get_versions(self, graph_id: str, user: Optional[str] = None) -> list:
        check_graph_permission(graph_id, user, action="read")
        return self.version_manager.list_versions(graph_id)
