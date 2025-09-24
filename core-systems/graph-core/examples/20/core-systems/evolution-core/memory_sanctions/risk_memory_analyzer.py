# AI-platform-core/genius-core/memory_sanctions/risk_memory_analyzer.py

import logging
from typing import List, Dict
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("RiskMemoryAnalyzer")

class RiskMemoryAnalyzer:
    """
    Анализирует накопленные риски, санкции и ошибки в памяти агента.
    Выявляет закономерности, повторения, потенциальные угрозы и зоны высокой уязвимости.
    """

    def __init__(self):
        self.risk_history: List[Dict] = []
        self.agent_profiles: Dict[str, Dict] = defaultdict(lambda: {
            "total_events": 0,
            "critical_count": 0,
            "repeat_violations": 0,
            "last_violation": None
        })

    def load_violations(self, violations: List[Dict]):
        """
        Загружает логи нарушений (обычно из ethical_violations_log.json)
        """
        logger.info(f"[RiskMemoryAnalyzer] Загружено {len(violations)} записей нарушений")
        for v in violations:
            agent_id = v.get("agent_id")
            self.risk_history.append(v)

            profile = self.agent_profiles[agent_id]
            profile["total_events"] += 1
            if v.get("risk_level") == "CRITICAL":
                profile["critical_count"] += 1

            if profile["last_violation"] and profile["last_violation"]["intention"] == v.get("intention"):
                profile["repeat_violations"] += 1

            profile["last_violation"] = v

    def summarize_agent(self, agent_id: str) -> Dict:
        """
        Возвращает сводку по конкретному агенту.
        """
        return self.agent_profiles.get(agent_id, {
            "total_events": 0,
            "critical_count": 0,
            "repeat_violations": 0,
            "last_violation": None
        })

    def detect_hotspots(self) -> List[str]:
        """
        Выявляет агентов с аномально высокой долей критических событий.
        """
        flagged = []
        for agent_id, profile in self.agent_profiles.items():
            total = profile["total_events"]
            critical = profile["critical_count"]
            if total >= 3 and critical / total >= 0.5:
                flagged.append(agent_id)
        return flagged

    def export_summary(self) -> Dict[str, Dict]:
        """
        Возвращает полную сводку по всем агентам.
        """
        return self.agent_profiles

    def reset(self):
        self.risk_history.clear()
        self.agent_profiles.clear()
        logger.info("[RiskMemoryAnalyzer] Память рисков сброшена")
