# ai-core/attack-generator/attack_planner_v2.py

import random
from typing import List, Dict, Any, Optional
import datetime

class AttackPlannerV2:
    """
    Новый генератор цепочек атак с использованием AI.
    Модуль создает оптимизированные сценарии атак, учитывая контекст цели, возможности атакующих,
    уязвимости, время и ресурсные ограничения.
    """

    def __init__(self, attack_vectors: Optional[List[Dict[str, Any]]] = None):
        """
        :param attack_vectors: Исходный список векторов атак с параметрами (тип, вероятность успеха, требования)
        """
        self.attack_vectors = attack_vectors if attack_vectors else self._default_attack_vectors()
        self.planned_chains: List[List[Dict[str, Any]]] = []

    def _default_attack_vectors(self) -> List[Dict[str, Any]]:
        """
        Базовые векторы атак для генерации.
        """
        return [
            {"name": "phishing", "success_rate": 0.4, "resources": ["email"], "time": 2},
            {"name": "bruteforce", "success_rate": 0.2, "resources": ["computing_power"], "time": 5},
            {"name": "exploit_cve", "success_rate": 0.7, "resources": ["exploit_kit"], "time": 1},
            {"name": "privilege_escalation", "success_rate": 0.5, "resources": ["local_access"], "time": 3},
            {"name": "lateral_movement", "success_rate": 0.6, "resources": ["network_access"], "time": 4},
            {"name": "data_exfiltration", "success_rate": 0.9, "resources": ["network_access"], "time": 2},
        ]

    def generate_attack_chain(
        self,
        target_profile: Dict[str, Any],
        max_steps: int = 5,
        time_budget: int = 10,
        resource_constraints: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Генерирует цепочку атак, оптимизированную по успешности и ресурсам.

        :param target_profile: Профиль цели (уровень защиты, ОС, активы и т.д.)
        :param max_steps: Максимальное число шагов в цепочке
        :param time_budget: Максимальное время на выполнение цепочки (в условных единицах)
        :param resource_constraints: Доступные ресурсы для атакующего
        :return: Список шагов цепочки атак
        """
        if resource_constraints is None:
            resource_constraints = []

        chain = []
        time_spent = 0

        available_vectors = [
            v for v in self.attack_vectors
            if all(r in resource_constraints for r in v["resources"]) or not v["resources"]
        ]

        for step in range(max_steps):
            candidates = [v for v in available_vectors if (time_spent + v["time"]) <= time_budget]
            if not candidates:
                break

            # AI-эмуляция выбора лучшего варианта
            candidates.sort(key=lambda x: x["success_rate"], reverse=True)

            chosen = self._select_best_vector(candidates, target_profile)
            if not chosen:
                break

            chain.append({
                "step": step + 1,
                "attack": chosen["name"],
                "success_rate": chosen["success_rate"],
                "time_required": chosen["time"],
                "resources": chosen["resources"],
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            })

            time_spent += chosen["time"]

        self.planned_chains.append(chain)
        return chain

    def _select_best_vector(self, candidates: List[Dict[str, Any]], target_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        AI-логика выбора наиболее подходящего вектора атаки с учетом профиля цели.
        """

        # Пример: снижаем успешность, если цель имеет повышенную защиту
        defense_level = target_profile.get("defense_level", 0)
        weighted_candidates = []

        for v in candidates:
            adjusted_success = v["success_rate"] * max(0.1, 1 - 0.1 * defense_level)
            weighted_candidates.append((adjusted_success, v))

        if not weighted_candidates:
            return None

        weighted_candidates.sort(key=lambda x: x[0], reverse=True)

        # Вероятностный выбор с уклоном на более успешные атаки
        top_candidates = weighted_candidates[:3]  # Топ 3
        weights = [w[0] for w in top_candidates]
        total = sum(weights)
        probabilities = [w / total for w in weights]

        chosen_vector = random.choices([w[1] for w in top_candidates], probabilities)[0]
        return chosen_vector

    def evaluate_chain_success(self, chain: List[Dict[str, Any]]) -> float:
        """
        Оценивает общую вероятность успешного выполнения всей цепочки.

        :param chain: Цепочка атак
        :return: Общая вероятность успеха (от 0 до 1)
        """
        prob_fail = 1.0
        for step in chain:
            prob_fail *= (1 - step["success_rate"])
        return 1 - prob_fail

    def reset(self):
        """
        Сбросить все запланированные цепочки.
        """
        self.planned_chains.clear()

