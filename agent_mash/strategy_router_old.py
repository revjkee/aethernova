# agent-mesh/strategy_router.py

from typing import Dict, Optional, List, Tuple
import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from agent_mash.core.agent_message import AgentMessage
from agent_mash.registry.agent_registry import AgentRegistry
from agent_mash.agent_bus import AgentBus
import logging
import heapq

logger = logging.getLogger("StrategyRouter")

@dataclass
class AgentLoadInfo:
    """Информация о загруженности агента"""
    agent_id: str
    current_load: int  # количество активных задач
    max_capacity: int
    avg_response_time: float  # в миллисекундах
    success_rate: float  # от 0 до 1
    last_activity: float  # timestamp
    priority_bonus: float = 0.0  # бонус за приоритет агента

    @property
    def load_ratio(self) -> float:
        """Коэффициент загруженности (0-1)"""
        return self.current_load / max(1, self.max_capacity)
    
    @property
    def efficiency_score(self) -> float:
        """Общий показатель эффективности агента"""
        # Учитывает загруженность, скорость ответа и успешность
        load_penalty = self.load_ratio * 0.5
        speed_bonus = max(0, (2000 - self.avg_response_time) / 2000) * 0.3
        success_bonus = self.success_rate * 0.2
        
        return (success_bonus + speed_bonus - load_penalty + self.priority_bonus)

class LoadBalancer:
    """Балансировщик нагрузки для распределения задач между агентами"""
    
    def __init__(self):
        self.agent_loads: Dict[str, AgentLoadInfo] = {}
        self.task_history: deque = deque(maxlen=1000)  # история последних задач
        self.priority_queue: List[Tuple[int, float, str]] = []  # приоритетная очередь

    def update_agent_load(self, agent_id: str, load_info: AgentLoadInfo):
        """Обновить информацию о загруженности агента"""
        self.agent_loads[agent_id] = load_info

    def select_best_agent(self, agent_candidates: List[str], task_priority: int = 1) -> Optional[str]:
        """Выбрать лучшего агента для задачи на основе загруженности и эффективности"""
        if not agent_candidates:
            return None
        
        available_agents = [
            (agent_id, self.agent_loads.get(agent_id))
            for agent_id in agent_candidates
            if agent_id in self.agent_loads and self.agent_loads[agent_id].load_ratio < 1.0
        ]
        
        if not available_agents:
            # Если нет доступных агентов, выбираем наименее загруженного
            available_agents = [
                (agent_id, self.agent_loads.get(agent_id, AgentLoadInfo(agent_id, 0, 1, 1000, 0.5, time.time())))
                for agent_id in agent_candidates
            ]
        
        # Сортировка по эффективности с учетом приоритета задачи
        def score_function(item):
            agent_id, load_info = item
            if load_info is None:
                return -1  # неизвестные агенты имеют низкий приоритет
            
            # Для высокоприоритетных задач больше внимания к скорости
            if task_priority <= 2:
                return load_info.efficiency_score + (1 - load_info.load_ratio) * 0.3
            else:
                return load_info.efficiency_score
        
        best_agent = max(available_agents, key=score_function)
        return best_agent[0]

    def record_task_completion(self, agent_id: str, success: bool, response_time: float):
        """Зарегистрировать завершение задачи для обновления метрик"""
        self.task_history.append({
            "agent_id": agent_id,
            "success": success,
            "response_time": response_time,
            "timestamp": time.time()
        })
        
        # Обновить метрики агента
        if agent_id in self.agent_loads:
            load_info = self.agent_loads[agent_id]
            # Экспоненциальное сглаживание для метрик
            alpha = 0.1
            load_info.avg_response_time = (1 - alpha) * load_info.avg_response_time + alpha * response_time
            
            # Обновление success_rate на основе последних задач
            recent_tasks = [task for task in self.task_history if task["agent_id"] == agent_id][-10:]
            if recent_tasks:
                load_info.success_rate = sum(1 for task in recent_tasks if task["success"]) / len(recent_tasks)

class PriorityQueue:
    """Приоритетная очередь сообщений"""
    
    def __init__(self):
        self._queue = []
        self._index = 0
        self._lock = asyncio.Lock()
    
    async def put(self, message: AgentMessage):
        """Добавить сообщение в очередь"""
        async with self._lock:
            # Использует отрицательный приоритет для сортировки (меньшее число = выше приоритет)
            heapq.heappush(self._queue, (-message.priority, self._index, message))
            self._index += 1
    
    async def get(self) -> Optional[AgentMessage]:
        """Получить сообщение с наивысшим приоритетом"""
        async with self._lock:
            if self._queue:
                _, _, message = heapq.heappop(self._queue)
                return message
            return None
    
    def empty(self) -> bool:
        return len(self._queue) == 0
    
    def size(self) -> int:
        return len(self._queue)

@dataclass
class AgentLoadInfo:
    """Информация о загруженности агента"""
    agent_id: str
    current_load: int  # количество активных задач
    max_capacity: int
    avg_response_time: float  # в миллисекундах
    success_rate: float  # от 0 до 1
    last_activity: float  # timestamp
    priority_bonus: float = 0.0  # бонус за приоритет агента

    @property
    def load_ratio(self) -> float:
        """Коэффициент загруженности (0-1)"""
        return self.current_load / max(1, self.max_capacity)
    
    @property
    def efficiency_score(self) -> float:
        """Общий показатель эффективности агента"""
        # Учитывает загруженность, скорость ответа и успешность
        load_penalty = self.load_ratio * 0.5
        speed_bonus = max(0, (2000 - self.avg_response_time) / 2000) * 0.3
        success_bonus = self.success_rate * 0.2
        
        return (success_bonus + speed_bonus - load_penalty + self.priority_bonus)

class LoadBalancer:
    """Балансировщик нагрузки для распределения задач между агентами"""
    
    def __init__(self):
        self.agent_loads: Dict[str, AgentLoadInfo] = {}
        self.task_history: deque = deque(maxlen=1000)  # история последних задач

    def update_agent_load(self, agent_id: str, load_info: AgentLoadInfo):
        """Обновить информацию о загруженности агента"""
        self.agent_loads[agent_id] = load_info

    def select_best_agent(self, agent_candidates: List[str], task_priority: int = 1) -> Optional[str]:
        """Выбрать лучшего агента для задачи на основе загруженности и эффективности"""
        if not agent_candidates:
            return None
        
        available_agents = [
            (agent_id, self.agent_loads.get(agent_id))
            for agent_id in agent_candidates
            if agent_id in self.agent_loads and self.agent_loads[agent_id].load_ratio < 1.0
        ]
        
        if not available_agents:
            # Если нет доступных агентов, выбираем наименее загруженного
            available_agents = [
                (agent_id, self.agent_loads.get(agent_id, AgentLoadInfo(agent_id, 0, 1, 1000, 0.5, time.time())))
                for agent_id in agent_candidates
            ]
        
        # Сортировка по эффективности с учетом приоритета задачи
        def score_function(item):
            agent_id, load_info = item
            if load_info is None:
                return -1  # неизвестные агенты имеют низкий приоритет
            
            # Для высокоприоритетных задач больше внимания к скорости
            if task_priority <= 2:
                return load_info.efficiency_score + (1 - load_info.load_ratio) * 0.3
            else:
                return load_info.efficiency_score
        
        best_agent = max(available_agents, key=score_function)
        return best_agent[0]

class StrategyRouter:
    """
    Интеллектуальный роутер задач с балансировкой нагрузки:
    - LLM-агенты (генерация текста, анализ, reasoning)
    - RL-агенты (планирование, оптимизация, обучение)
    - Rule-based агенты (модерация, фильтрация, валидация)
    - Hybrid агенты (комбинированные задачи)

    Включает:
    - Балансировку нагрузки между агентами
    - Приоритезацию задач
    - Мониторинг производительности
    - Адаптивный выбор агентов
    """

    def __init__(self, agent_bus: AgentBus, registry: Optional[AgentRegistry] = None):
        self.bus = agent_bus
        self.registry = registry or AgentRegistry()
        self.load_balancer = LoadBalancer()
        
        # Расширенная карта стратегий с поддержкой множественных типов
        self.strategy_map = {
            # LLM задачи
            "text-generation": self._route_to_llm,
            "code_generation": self._route_to_llm,
            "code_review": self._route_to_llm,
            "documentation": self._route_to_llm,
            "translation": self._route_to_llm,
            "summarization": self._route_to_llm,
            "question-answering": self._route_to_llm,
            "reasoning": self._route_to_llm,
            
            # RL задачи
            "planning": self._route_to_rl,
            "optimization": self._route_to_rl,
            "control-policy": self._route_to_rl,
            "learning": self._route_to_rl,
            "adaptation": self._route_to_rl,
            
            # Rule-based задачи
            "moderation": self._route_to_rule,
            "filtering": self._route_to_rule,
            "validation": self._route_to_rule,
            "classification": self._route_to_rule,
            "parsing": self._route_to_rule,
            
            # Гибридные задачи
            "analysis": self._route_hybrid,
            "testing": self._route_hybrid,
            "refactoring": self._route_hybrid,
            
            "default": self._route_smart
        }
        
        # Метрики и статистика
        self.routing_stats = defaultdict(int)
        self.agent_performance = defaultdict(dict)

    async def route(self, message: AgentMessage):
        """
        Главная точка входа: маршрутизирует message на нужного исполнителя.
        Поддерживает приоритизацию и балансировку нагрузки.
        """
        try:
            # Проверка на истечение времени жизни
            if message.is_expired():
                logger.warning(f"Message {message.message_id} expired, dropping")
                return
            
            start_time = time.time()
            
            # Выбор стратегии маршрутизации
            strategy_fn = self.strategy_map.get(message.task_type, self.strategy_map["default"])
            agent_id = await strategy_fn(message)

            if not agent_id:
                logger.error(f"No suitable agent found for task type: {message.task_type}")
                # Попытка fallback маршрутизации
                agent_id = await self._fallback_routing(message)
                if not agent_id:
                    return

            # Обновление метрик загруженности
            if agent_id in self.load_balancer.agent_loads:
                self.load_balancer.agent_loads[agent_id].current_load += 1
            
            # Отправка сообщения
            await self.bus.async_send(message, target_agent_id=agent_id)
            
            routing_time = (time.time() - start_time) * 1000
            self.routing_stats[message.task_type] += 1
            
            logger.info(f"Message routed to {agent_id} for task: {message.task_type} (routing time: {routing_time:.2f}ms)")
            
        except Exception as e:
            logger.error(f"Error routing message {message.message_id}: {e}")

    async def _route_to_llm(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор LLM-агента с балансировкой нагрузки
        """
        candidates = [
            agent_id for agent_id in self.registry.list_agents_by_type("llm")
            if self.registry.supports(agent_id, message.task_type)
        ]
        return self.load_balancer.select_best_agent(candidates, message.priority)

    async def _route_to_rl(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор RL-агента с учетом специализации и загруженности
        """
        candidates = [
            agent_id for agent_id in self.registry.list_agents_by_type("rl")
            if self.registry.supports(agent_id, message.task_type)
        ]
        return self.load_balancer.select_best_agent(candidates, message.priority)

    async def _route_to_rule(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор rule-based агента (обычно быстрые, детерминированные задачи)
        """
        candidates = [
            agent_id for agent_id in self.registry.list_agents_by_type("rule")
            if self.registry.supports(agent_id, message.task_type)
        ]
        return self.load_balancer.select_best_agent(candidates, message.priority)
    
    async def _route_hybrid(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор гибридного агента или лучшего из доступных типов
        """
        # Сначала ищем специализированные гибридные агенты
        candidates = [
            agent_id for agent_id in self.registry.list_agents_by_type("hybrid")
            if self.registry.supports(agent_id, message.task_type)
        ]
        
        if candidates:
            return self.load_balancer.select_best_agent(candidates, message.priority)
        
        # Если нет гибридных, пробуем LLM агентов
        return await self._route_to_llm(message)
    
    async def _route_smart(self, message: AgentMessage) -> Optional[str]:
        """
        Интеллектуальная маршрутизация на основе анализа задачи
        """
        task_type = message.task_type
        payload = message.payload
        
        # Выбор подходящих агентов на основе всех доступных типов
        all_candidates = []
        
        for agent_type in ["llm", "rl", "rule", "hybrid"]:
            type_agents = [
                agent_id for agent_id in self.registry.list_agents_by_type(agent_type)
                if self.registry.supports(agent_id, task_type)
            ]
            all_candidates.extend(type_agents)
        
        if not all_candidates:
            # Если нет точного соответствия, берем всех доступных агентов
            all_candidates = self.registry.list_agents()
        
        return self.load_balancer.select_best_agent(all_candidates, message.priority)
    
    async def _fallback_routing(self, message: AgentMessage) -> Optional[str]:
        """Резервная маршрутизация когда основные стратегии не сработали"""
        # Получаем всех доступных агентов
        all_agents = self.registry.list_agents()
        if all_agents:
            return self.load_balancer.select_best_agent(all_agents, message.priority)
        return None

    def register_custom_strategy(self, task_type: str, handler_fn):
        """
        Позволяет расширять стратегию маршрутизации кастомной функцией
        """
        self.strategy_map[task_type] = handler_fn
