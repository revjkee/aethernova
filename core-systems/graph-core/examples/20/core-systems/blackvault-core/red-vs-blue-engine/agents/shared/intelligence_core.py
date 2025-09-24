# red-vs-blue-engine/agents/shared/intelligence_core.py

from typing import Dict, Any, Optional, List
from core.ai.memory import MemoryManager
from core.ai.planner import StrategicPlanner
from core.ai.knowledge_base import KnowledgeBase
from core.ai.rationale import HypothesisEngine
from core.logging.tracer import Tracer


class IntelligenceCore:
    """
    Промышленное интеллектуальное ядро агента.
    Поддерживает:
    - динамическую генерацию гипотез
    - адаптивную стратегию
    - подключение к памяти и базе знаний
    - трассировку reasoning-процесса
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.memory = MemoryManager(agent_id=agent_id)
        self.planner = StrategicPlanner(agent_id=agent_id)
        self.kb = KnowledgeBase(agent_id=agent_id)
        self.hypothesis_engine = HypothesisEngine(agent_id=agent_id)

    async def process_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Обрабатывает входные данные, строит гипотезы, выбирает стратегию, обновляет память.
        """
        with Tracer(f"intelligence_core::{self.agent_id}"):
            # Этап 1: Сохранение наблюдений
            await self.memory.store_observation(input_data)

            # Этап 2: Извлечение релевантного опыта
            context = await self.memory.retrieve_context(input_data)

            # Этап 3: Генерация гипотез
            hypotheses = self.hypothesis_engine.generate(input_data, context)

            # Этап 4: Обогащение знаний
            self.kb.update(input_data, hypotheses)

            # Этап 5: Построение стратегии
            strategy = self.planner.plan(hypotheses, context)

            # Этап 6: Возврат решения
            return {
                "strategy": strategy,
                "hypotheses": hypotheses,
                "context": context,
            }

    def diagnostics(self) -> Dict[str, Any]:
        """
        Возвращает состояние всех компонентов ядра.
        """
        return {
            "agent_id": self.agent_id,
            "memory": self.memory.status(),
            "planner": self.planner.status(),
            "knowledge_base": self.kb.status(),
            "hypothesis_engine": self.hypothesis_engine.status(),
        }

