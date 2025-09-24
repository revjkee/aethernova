# agent-mesh/registry/runtime_stats.py

import time
from typing import Dict, Optional
import logging

logger = logging.getLogger("RuntimeStats")


class RuntimeStats:
    """
    Сбор и обновление runtime-метрик агентов:
    - загрузка (load)
    - средняя задержка (latency)
    - uptime
    - успешность (success rate)
    - количество задач
    """

    def __init__(self):
        self._stats: Dict[str, Dict[str, float]] = {}  # agent_id -> metric map
        self._timestamps: Dict[str, float] = {}        # agent_id -> last heartbeat

    def heartbeat(self, agent_id: str):
        """
        Обновляет время последнего сигнала от агента
        """
        self._timestamps[agent_id] = time.time()
        logger.debug(f"Heartbeat from {agent_id}")

    def update_latency(self, agent_id: str, latency_ms: float):
        """
        Обновляет среднюю задержку по формуле скользящего среднего
        """
        s = self._ensure(agent_id)
        prev = s.get("latency_avg", 0.0)
        count = s.get("task_count", 0)
        s["latency_avg"] = (prev * count + latency_ms) / (count + 1)
        logger.debug(f"Updated latency for {agent_id}: {s['latency_avg']:.2f}ms")

    def increment_tasks(self, agent_id: str, success: bool = True):
        """
        Увеличивает счётчики задач и успешных ответов
        """
        s = self._ensure(agent_id)
        s["task_count"] += 1
        if success:
            s["success_count"] += 1

    def get_stats(self, agent_id: str) -> Optional[Dict[str, float]]:
        """
        Возвращает текущие метрики агента
        """
        if agent_id not in self._stats:
            return None
        s = self._stats[agent_id].copy()
        s["uptime"] = time.time() - self._timestamps.get(agent_id, time.time())
        if s["task_count"] > 0:
            s["success_rate"] = s["success_count"] / s["task_count"]
        else:
            s["success_rate"] = 1.0
        return s

    def list_all(self) -> Dict[str, Dict[str, float]]:
        """
        Возвращает метрики всех агентов
        """
        return {
            aid: self.get_stats(aid)
            for aid in self._stats
        }

    def _ensure(self, agent_id: str) -> Dict[str, float]:
        if agent_id not in self._stats:
            self._stats[agent_id] = {
                "task_count": 0,
                "success_count": 0,
                "latency_avg": 0.0
            }
            self._timestamps[agent_id] = time.time()
        return self._stats[agent_id]
