import logging
from typing import List, Dict, Optional, Tuple
from genius_core.code_context.agents.context_expander import expand_context
from genius_core.code_context.agents.code_summary_agent import summarize_code
from genius_core.code_context.search.semantic_search import search_code_semantically
from genius_core.governor.intention_policy import IntentionPolicy
from genius_core.utils.context_score import score_intent_relevance
from genius_core.utils.trust_filter import filter_by_trust_score
from genius_core.utils.priority_graph import resolve_priority_conflict

logger = logging.getLogger(__name__)


class IntentResolver:
    """
    Выбор доминирующего намерения на основе приоритетов, доверия, контекста и динамики среды.
    """

    def __init__(self, policy: Optional[IntentionPolicy] = None):
        self.policy = policy or IntentionPolicy()

    def resolve(self, intentions: List[Dict], context: Dict, agent_name: str) -> Optional[Dict]:
        """
        Основная точка входа: принимает список намерений, контекст исполнения и имя агента.
        Возвращает наиболее подходящее намерение.

        :param intentions: Список кандидатов {intent, confidence, metadata}
        :param context: Текущий контекст выполнения
        :param agent_name: Имя агента, инициировавшего выбор
        :return: Одно доминирующее намерение или None
        """
        logger.debug(f"[{agent_name}] Получено {len(intentions)} намерений. Начинаем фильтрацию...")

        if not intentions:
            logger.warning("Список намерений пуст.")
            return None

        expanded_context = expand_context(context)
        logger.debug(f"Контекст расширен: {list(expanded_context.keys())}")

        trusted_intents = filter_by_trust_score(intentions)
        if not trusted_intents:
            logger.warning("Ни одно намерение не прошло фильтра доверия.")
            return None

        scored_intents = []
        for intent in trusted_intents:
            summary = summarize_code(intent["metadata"].get("code", ""))
            semantic_match = search_code_semantically(summary, expanded_context)
            score = score_intent_relevance(intent, expanded_context, semantic_match)
            scored_intents.append((intent, score))
            logger.debug(f"Оценка намерения {intent.get('intent')} = {score:.4f}")

        best_intent, _ = self._select_best(scored_intents)
        if best_intent:
            logger.info(f"Выбрано намерение: {best_intent.get('intent')}")
        else:
            logger.warning("Не удалось выбрать подходящее намерение.")

        return best_intent

    def _select_best(self, scored_intents: List[Tuple[Dict, float]]) -> Tuple[Optional[Dict], float]:
        """
        Логика выбора лучшего намерения на основе приоритетов, политик и пользовательского контекста.

        :param scored_intents: Список кортежей (намерение, оценка)
        :return: Лучшее намерение и его оценка
        """
        if not scored_intents:
            return None, 0.0

        sorted_by_score = sorted(scored_intents, key=lambda x: x[1], reverse=True)
        top_score = sorted_by_score[0][1]
        top_intents = [i for i in sorted_by_score if abs(i[1] - top_score) < 0.05]

        if len(top_intents) == 1:
            return top_intents[0]

        # Конфликт намерений: подключаем политику и граф приоритетов
        resolved = resolve_priority_conflict([i[0] for i in top_intents], self.policy)
        return resolved, top_score


# Пример использования:
if __name__ == "__main__":
    resolver = IntentResolver()
    sample_intents = [
        {"intent": "analyze_threat", "confidence": 0.91, "metadata": {"priority": 2}},
        {"intent": "refactor_code", "confidence": 0.89, "metadata": {"priority": 1}},
        {"intent": "generate_test", "confidence": 0.93, "metadata": {"priority": 1}},
    ]
    context = {
        "current_task": "security audit",
        "user_profile": {"role": "lead_engineer"},
        "environment": {"secure_mode": True}
    }
    result = resolver.resolve(sample_intents, context, "GovernorAgent")
    print(f"Выбранное намерение: {result}")
