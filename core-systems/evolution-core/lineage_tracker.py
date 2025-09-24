import threading
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any

class AgentLineageTracker:
    """
    Класс для отслеживания происхождения и версий агентов.
    Позволяет сохранять родственные связи, версии и метаданные агентов.
    """

    def __init__(self):
        # Хранение данных в формате: agent_id -> список предков (agent_id, версия, timestamp)
        self._lineage_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._lock = threading.Lock()

    def add_lineage(self, agent_id: str, parent_id: Optional[str], parent_version: Optional[int], metadata: Optional[Dict[str, Any]] = None):
        """
        Добавляет запись происхождения агента.

        :param agent_id: ID текущего агента.
        :param parent_id: ID родителя агента, если есть.
        :param parent_version: Версия родительского агента.
        :param metadata: Дополнительные метаданные (например, тип мутации, условия эволюции).
        """
        with self._lock:
            record = {
                "parent_id": parent_id,
                "parent_version": parent_version,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": metadata or {}
            }
            self._lineage_map[agent_id].append(record)

    def get_lineage(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Возвращает список предков с информацией о версии и времени.

        :param agent_id: ID агента.
        :return: Список записей происхождения.
        """
        with self._lock:
            return list(self._lineage_map.get(agent_id, []))

    def get_full_lineage_tree(self, agent_id: str) -> Dict[str, Any]:
        """
        Рекурсивно строит дерево происхождения агента.

        :param agent_id: ID агента.
        :return: Дерево в формате словаря.
        """
        with self._lock:
            lineage = self._lineage_map.get(agent_id, [])
        
        tree = {"agent_id": agent_id, "ancestors": []}
        for record in lineage:
            parent_id = record.get("parent_id")
            if parent_id:
                parent_tree = self.get_full_lineage_tree(parent_id)
                tree["ancestors"].append({
                    "record": record,
                    "parent_tree": parent_tree
                })
        return tree

    def clear_lineage(self):
        """
        Очищает все данные о происхождении.
        """
        with self._lock:
            self._lineage_map.clear()
