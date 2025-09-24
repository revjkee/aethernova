import json
import threading
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime


class RegistryStorage:
    """
    Регистратор состояний агентов с поддержкой thread-safe операций, резервного копирования,
    версионирования и сохранения в JSON-формате.
    """

    def __init__(self, storage_path: Optional[str] = None, autosave: bool = True):
        self._lock = threading.Lock()
        self._storage: Dict[str, dict] = {}
        self._storage_path = Path(storage_path) if storage_path else None
        self._autosave = autosave

        if self._storage_path:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def _load(self):
        if self._storage_path and self._storage_path.exists():
            try:
                with self._storage_path.open('r', encoding='utf-8') as f:
                    self._storage = json.load(f)
            except Exception as e:
                print(f"[RegistryStorage] Error loading storage: {e}")

    def _save(self):
        if not self._autosave or not self._storage_path:
            return
        try:
            with self._storage_path.open('w', encoding='utf-8') as f:
                json.dump(self._storage, f, indent=2, ensure_ascii=False, sort_keys=True)
        except Exception as e:
            print(f"[RegistryStorage] Error saving storage: {e}")

    def set(self, agent_id: str, data: dict):
        with self._lock:
            self._storage[agent_id] = data
            self._save()

    def get(self, agent_id: str) -> Optional[dict]:
        with self._lock:
            return self._storage.get(agent_id)

    def delete(self, agent_id: str):
        with self._lock:
            if agent_id in self._storage:
                del self._storage[agent_id]
                self._save()

    def exists(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._storage

    def all(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._storage)

    def clear(self):
        with self._lock:
            self._storage.clear()
            self._save()

    def backup(self, suffix: Optional[str] = None):
        if not self._storage_path:
            return
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        suffix = suffix or "backup"
        backup_path = self._storage_path.parent / f"{self._storage_path.stem}_{suffix}_{timestamp}.json"
        try:
            with backup_path.open('w', encoding='utf-8') as f:
                json.dump(self._storage, f, indent=2, ensure_ascii=False, sort_keys=True)
        except Exception as e:
            print(f"[RegistryStorage] Error creating backup: {e}")
