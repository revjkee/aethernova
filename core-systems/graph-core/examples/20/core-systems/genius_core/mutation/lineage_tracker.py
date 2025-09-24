# lineage_tracker.py

import json
import uuid
import logging
import os
from typing import Dict, List, Optional, Tuple

BANK_PATH = "core-systems/ai_platform_core/genius_core/mutation/mutation_bank.json"

logger = logging.getLogger("lineage_tracker")
logger.setLevel(logging.INFO)


class LineageTracker:
    def __init__(self, bank_path: str = BANK_PATH):
        self.bank_path = bank_path
        self._load_bank()

    def _load_bank(self):
        if not os.path.exists(self.bank_path):
            self.bank = {"mutations": [], "metadata": {}}
            logger.warning("[LineageTracker] Банк мутаций не найден. Создан временный.")
        else:
            with open(self.bank_path, "r") as f:
                self.bank = json.load(f)
            logger.info("[LineageTracker] Банк успешно загружен.")

    def _save_bank(self):
        with open(self.bank_path, "w") as f:
            json.dump(self.bank, f, indent=2)
        logger.info("[LineageTracker] Банк мутаций обновлён.")

    def record(
        self,
        config: Dict[str, any],
        fitness: float,
        strategy: str = "unknown",
        parent_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        source: str = "unknown"
    ) -> str:
        new_id = f"mut_{str(uuid.uuid4())[:8]}"
        entry = {
            "id": new_id,
            "timestamp": self._current_timestamp(),
            "strategy": strategy,
            "source": source,
            "generation": self._infer_generation(parent_ids),
            "config": config,
            "fitness_score": round(fitness, 6),
            "used_in": [],
            "lineage": parent_ids or [],
            "tags": tags or []
        }
        self.bank["mutations"].append(entry)
        self._save_bank()
        logger.info(f"[LineageTracker] Мутация записана: {new_id}")
        return new_id

    def get_lineage(self, mutation_id: str) -> List[str]:
        lineage = []
        current = self._find_by_id(mutation_id)
        while current and current.get("lineage"):
            parent_id = current["lineage"][0]
            lineage.append(parent_id)
            current = self._find_by_id(parent_id)
        return lineage

    def _find_by_id(self, mutation_id: str) -> Optional[Dict]:
        for entry in self.bank["mutations"]:
            if entry["id"] == mutation_id:
                return entry
        return None

    def _infer_generation(self, parent_ids: Optional[List[str]]) -> int:
        if not parent_ids:
            return 0
        generations = [
            self._find_by_id(pid).get("generation", 0) for pid in parent_ids if self._find_by_id(pid)
        ]
        return max(generations, default=0) + 1

    def get_mutation_summary(self) -> Dict[str, int]:
        return {
            "total_mutations": len(self.bank["mutations"]),
            "strategies": self._count_by_field("strategy"),
            "generations": self._count_by_field("generation")
        }

    def _count_by_field(self, field: str) -> Dict[str, int]:
        counter = {}
        for m in self.bank["mutations"]:
            key = str(m.get(field, "unknown"))
            counter[key] = counter.get(key, 0) + 1
        return counter

    def _current_timestamp(self) -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
