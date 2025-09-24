import json
import threading
from datetime import datetime
from typing import Dict, Optional

class ReputationManager:
    def __init__(self, storage_file: str):
        self.storage_file = storage_file
        self._lock = threading.Lock()
        self._reputations = self._load_reputations()

    def _load_reputations(self) -> Dict[str, int]:
        try:
            with open(self.storage_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_reputations(self) -> None:
        with open(self.storage_file, 'w', encoding='utf-8') as f:
            json.dump(self._reputations, f, indent=2, ensure_ascii=False)

    def get_reputation(self, user_id: str) -> int:
        return self._reputations.get(user_id, 0)

    def increase_reputation(self, user_id: str, amount: int = 1) -> None:
        with self._lock:
            self._reputations[user_id] = self.get_reputation(user_id) + amount
            self._save_reputations()

    def decrease_reputation(self, user_id: str, amount: int = 1) -> None:
        with self._lock:
            current = self.get_reputation(user_id)
            self._reputations[user_id] = max(current - amount, 0)
            self._save_reputations()

    def set_reputation(self, user_id: str, amount: int) -> None:
        if amount < 0:
            raise ValueError("Reputation cannot be negative")
        with self._lock:
            self._reputations[user_id] = amount
            self._save_reputations()

    def get_all_reputations(self) -> Dict[str, int]:
        return dict(self._reputations)

    def export_reputations(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({
                "exported_at": datetime.utcnow().isoformat() + 'Z',
                "data": self._reputations
            }, f, indent=2, ensure_ascii=False)
