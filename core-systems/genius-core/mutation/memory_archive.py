# memory_archive.py

import os
import json
import logging
from typing import Dict, Any, List, Optional

ARCHIVE_PATH = "core-systems/ai_platform_core/genius_core/mutation/archive/memory_archive.json"

logger = logging.getLogger("memory_archive")
logger.setLevel(logging.INFO)


class MemoryArchive:
    def __init__(self, archive_path: str = ARCHIVE_PATH):
        self.archive_path = archive_path
        self._load()

    def _load(self):
        if os.path.exists(self.archive_path):
            with open(self.archive_path, "r") as f:
                self.archive = json.load(f)
            logger.info(f"[MemoryArchive] Архив загружен. Записей: {len(self.archive.get('strategies', []))}")
        else:
            self.archive = {"strategies": []}
            logger.warning("[MemoryArchive] Архив не найден. Создан новый.")

    def _save(self):
        os.makedirs(os.path.dirname(self.archive_path), exist_ok=True)
        with open(self.archive_path, "w") as f:
            json.dump(self.archive, f, indent=2)
        logger.info(f"[MemoryArchive] Архив обновлён. Записей: {len(self.archive['strategies'])}")

    def store(self, config: Dict[str, Any], fitness: float, metadata: Optional[Dict[str, Any]] = None):
        entry = {
            "config": config,
            "fitness": round(fitness, 6),
            "metadata": metadata or {},
            "id": f"arch_{len(self.archive['strategies']):05d}"
        }
        self.archive["strategies"].append(entry)
        self._save()
        logger.info(f"[MemoryArchive] Сохранена стратегия ID={entry['id']} с fitness={fitness:.4f}")

    def get_top_k(self, k: int = 5) -> List[Dict[str, Any]]:
        return sorted(self.archive["strategies"], key=lambda x: x["fitness"], reverse=True)[:k]

    def find_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        return [s for s in self.archive["strategies"] if tag in s.get("metadata", {}).get("tags", [])]

    def restore_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        for s in self.archive["strategies"]:
            if s["id"] == id:
                return s
        logger.warning(f"[MemoryArchive] Стратегия с ID={id} не найдена.")
        return None

    def summary(self) -> Dict[str, Any]:
        count = len(self.archive["strategies"])
        avg_fitness = round(sum(s["fitness"] for s in self.archive["strategies"]) / count, 6) if count else 0.0
        return {
            "total_strategies": count,
            "average_fitness": avg_fitness,
            "max_fitness": max((s["fitness"] for s in self.archive["strategies"]), default=0.0)
        }
