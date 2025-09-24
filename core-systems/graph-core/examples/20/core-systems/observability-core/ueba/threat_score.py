# observability/dashboards/ueba/threat_score.py

from typing import Dict, Any
import logging
import time

logger = logging.getLogger(__name__)


class ThreatScorer:
    """
    Расчёт итогового балла угрозы для UEBA-модуля.
    Система использует вес событий, decay-функцию и возможность контекстной коррекции.
    """

    def __init__(self, decay_factor: float = 0.95):
        self.user_scores: Dict[str, float] = {}
        self.last_seen: Dict[str, float] = {}
        self.decay_factor = decay_factor

    def score_event(self, user_id: str, event: Dict[str, Any]) -> float:
        """
        Присваивает балл событию и обновляет общий score пользователя.

        :param user_id: идентификатор пользователя/сущности
        :param event: событие, содержащее weight и context
        :return: обновлённый threat score
        """
        now = time.time()
        last_time = self.last_seen.get(user_id, now)
        time_delta = now - last_time

        prev_score = self.user_scores.get(user_id, 0.0)
        decayed_score = prev_score * (self.decay_factor ** time_delta)

        base_weight = float(event.get("weight", 1.0))
        context_risk = self._calculate_context_modifier(event.get("context", {}))

        new_score = decayed_score + (base_weight * context_risk)
        self.user_scores[user_id] = new_score
        self.last_seen[user_id] = now

        logger.debug(
            f"Threat score updated for {user_id}: "
            f"base={base_weight}, context={context_risk}, "
            f"prev={prev_score:.2f}, new={new_score:.2f}"
        )
        return new_score

    def _calculate_context_modifier(self, context: Dict[str, Any]) -> float:
        """
        Модифицирует вес события с учётом контекста (например, время, гео, устройство).
        """
        risk = 1.0

        if context.get("off_hours"):
            risk += 0.5
        if context.get("unusual_location"):
            risk += 1.0
        if context.get("new_device"):
            risk += 0.7
        if context.get("blacklisted_ip"):
            risk += 2.0
        if context.get("privileged_account"):
            risk += 1.5

        return risk

    def get_user_score(self, user_id: str) -> float:
        """
        Возвращает текущий threat score пользователя с учётом decay.
        """
        now = time.time()
        last_time = self.last_seen.get(user_id, now)
        prev_score = self.user_scores.get(user_id, 0.0)
        time_delta = now - last_time

        return prev_score * (self.decay_factor ** time_delta)

    def reset_user(self, user_id: str):
        """
        Сбрасывает threat score конкретного пользователя.
        """
        self.user_scores.pop(user_id, None)
        self.last_seen.pop(user_id, None)
