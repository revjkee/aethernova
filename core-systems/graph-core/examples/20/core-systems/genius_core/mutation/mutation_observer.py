# mutation_observer.py

import logging
import json
import os
from typing import Dict, Any, List
from datetime import datetime
from statistics import mean, stdev

from genius_core.utils.paths import ensure_dir

LOG_DIR = "core-systems/ai_platform_core/genius_core/mutation/logs"
OBSERVED_FILE = os.path.join(LOG_DIR, "mutation_metrics.json")

logger = logging.getLogger("mutation_observer")
logger.setLevel(logging.INFO)


class MutationObserver:
    def __init__(self):
        ensure_dir(LOG_DIR)
        self.observed_mutations: List[Dict[str, Any]] = []

    def log_mutation(self, config: Dict[str, Any], fitness: float, strategy: str = "unknown"):
        timestamp = datetime.utcnow().isoformat() + "Z"
        entry = {
            "timestamp": timestamp,
            "fitness": round(fitness, 6),
            "strategy": strategy,
            "params": config.copy()
        }
        self.observed_mutations.append(entry)
        self._persist(entry)
        logger.info(f"[MutationObserver] Мутация зафиксирована. Fitness={fitness:.4f}")

    def _persist(self, entry: Dict[str, Any]):
        if not os.path.exists(OBSERVED_FILE):
            with open(OBSERVED_FILE, "w") as f:
                json.dump({"mutations": [entry]}, f, indent=2)
        else:
            with open(OBSERVED_FILE, "r") as f:
                data = json.load(f)
            data["mutations"].append(entry)
            with open(OBSERVED_FILE, "w") as f:
                json.dump(data, f, indent=2)

    def summary(self) -> Dict[str, Any]:
        if not self.observed_mutations:
            return {}

        fitness_scores = [m["fitness"] for m in self.observed_mutations]
        strategies = [m["strategy"] for m in self.observed_mutations]
        params = self._collect_param_stats()

        return {
            "total_mutations": len(self.observed_mutations),
            "avg_fitness": round(mean(fitness_scores), 4),
            "std_fitness": round(stdev(fitness_scores), 4) if len(fitness_scores) > 1 else 0.0,
            "strategies_used": {s: strategies.count(s) for s in set(strategies)},
            "param_coverage": params
        }

    def _collect_param_stats(self) -> Dict[str, int]:
        param_count: Dict[str, int] = {}
        for m in self.observed_mutations:
            for k in m["params"].keys():
                param_count[k] = param_count.get(k, 0) + 1
        return param_count

    def export_csv(self, path: str = os.path.join(LOG_DIR, "mutation_export.csv")):
        import csv
        if not self.observed_mutations:
            logger.warning("[MutationObserver] Нет данных для экспорта.")
            return

        keys = ["timestamp", "fitness", "strategy"] + list(self.observed_mutations[0]["params"].keys())
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for entry in self.observed_mutations:
                row = {
                    "timestamp": entry["timestamp"],
                    "fitness": entry["fitness"],
                    "strategy": entry["strategy"],
                    **entry["params"]
                }
                writer.writerow(row)
        logger.info(f"[MutationObserver] Данные экспортированы в {path}")
