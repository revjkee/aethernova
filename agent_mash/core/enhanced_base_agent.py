# agent_mash/core/enhanced_base_agent.py

from typing import Dict, Any, List, Optional, Union, Callable, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import logging
from datetime import datetime, timedelta
import json
import uuid
from contextlib import asynccontextmanager

# Импорты наших новых модулей
from .advanced_data_processor import (
    AdvancedDataProcessor, DataSchema, ProcessingPipeline, 
    create_text_schema, create_numerical_schema
)
from .decision_engine import (
    AdvancedDecisionEngine, DecisionContext, DecisionResult,
    RuleBasedDecisionMaker, MLBasedDecisionMaker, ConsensusDecisionMaker,
    create_simple_rule, create_threshold_rule
)
from .external_api_integration import (
    ExternalAPIManager, APIEndpoint, AuthConfig, APIRequest,
    create_rest_endpoint, create_api_key_auth
)

# Импорты из существующих модулей
from .base_agent import BaseAgent, AgentStatus, AgentType, AgentMetrics, AgentCapability
from .agent_message import AgentMessage

logger = logging.getLogger(__name__)

class LearningMode(Enum):
    SUPERVISED = "supervised"
    UNSUPERVISED = "unsupervised"
    REINFORCEMENT = "reinforcement"
    TRANSFER = "transfer"
    FEDERATED = "federated"

class AdaptationStrategy(Enum):
    REACTIVE = "reactive"           # Реагирует на изменения
    PROACTIVE = "proactive"        # Предвосхищает изменения
    HYBRID = "hybrid"              # Комбинация обоих подходов

@dataclass
class AgentPersonality:
    """Личность агента влияющая на принятие решений"""
    risk_tolerance: float = 0.5      # 0.0 - консервативный, 1.0 - рисковый
    curiosity_level: float = 0.5     # Склонность к исследованию
    cooperation_tendency: float = 0.7 # Склонность к сотрудничеству
    learning_rate: float = 0.1       # Скорость обучения
    confidence_threshold: float = 0.7 # Порог уверенности для действий

@dataclass
class AgentMemory:
    """Система памяти агента"""
    short_term: Dict[str, Any] = field(default_factory=dict)  # Текущий контекст
    long_term: Dict[str, Any] = field(default_factory=dict)   # Постоянные знания
    episodic: List[Dict[str, Any]] = field(default_factory=list)  # События
    semantic: Dict[str, Any] = field(default_factory=dict)    # Семантические знания
    
class AgentKnowledgeBase:
    """База знаний агента с возможностями обучения"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.facts: Dict[str, Any] = {}
        self.rules: List[Dict[str, Any]] = []
        self.patterns: Dict[str, Any] = {}
        self.confidence_scores: Dict[str, float] = {}
        
    async def add_fact(self, key: str, value: Any, confidence: float = 1.0):
        """Добавление факта в базу знаний"""
        self.facts[key] = value
        self.confidence_scores[key] = confidence
        logger.debug(f"Added fact: {key} = {value} (confidence: {confidence})")
        
    async def get_fact(self, key: str) -> Optional[Any]:
        """Получение факта из базы знаний"""
        return self.facts.get(key)
        
    async def add_rule(self, name: str, condition: str, action: str, 
                      confidence: float = 1.0):
        """Добавление правила"""
        rule = {
            "name": name,
            "condition": condition,
            "action": action,
            "confidence": confidence,
            "usage_count": 0,
            "success_rate": 1.0
        }
        self.rules.append(rule)
        
    async def learn_pattern(self, pattern_name: str, data: List[Dict[str, Any]]):
        """Обучение на паттернах данных"""
        # Простой анализ частоты
        frequency_map = {}
        
        for item in data:
            for key, value in item.items():
                if key not in frequency_map:
                    frequency_map[key] = {}
                if value not in frequency_map[key]:
                    frequency_map[key][value] = 0
                frequency_map[key][value] += 1
                
        # Нормализация частот
        for key in frequency_map:
            total = sum(frequency_map[key].values())
            for value in frequency_map[key]:
                frequency_map[key][value] /= total
                
        self.patterns[pattern_name] = frequency_map
        logger.info(f"Learned pattern '{pattern_name}' from {len(data)} samples")
        
    async def update_rule_performance(self, rule_name: str, success: bool):
        """Обновление производительности правила"""
        for rule in self.rules:
            if rule["name"] == rule_name:
                rule["usage_count"] += 1
                old_rate = rule["success_rate"]
                old_count = rule["usage_count"] - 1
                
                if old_count == 0:
                    rule["success_rate"] = 1.0 if success else 0.0
                else:
                    rule["success_rate"] = (
                        (old_rate * old_count + (1.0 if success else 0.0)) / 
                        rule["usage_count"]
                    )
                break

class EnhancedBaseAgent(BaseAgent):
    """
    Расширенный базовый агент с продвинутыми возможностями:
    - Обработка данных с валидацией и кэшированием
    - Умное принятие решений с множественными стратегиями
    - Интеграция с внешними API
    - Система обучения и адаптации
    - Улучшенное логирование и мониторинг
    """
    
    def __init__(self, agent_id: str, agent_type: AgentType, 
                 capabilities: List[AgentCapability],
                 personality: Optional[AgentPersonality] = None):
        
        super().__init__(agent_id, agent_type, capabilities)
        
        # Новые компоненты
        self.data_processor = AdvancedDataProcessor()
        self.decision_engine = AdvancedDecisionEngine()
        self.api_manager = ExternalAPIManager()
        self.knowledge_base = AgentKnowledgeBase(agent_id)
        
        # Конфигурация агента
        self.personality = personality or AgentPersonality()
        self.memory = AgentMemory()
        
        # Система обучения
        self.learning_mode = LearningMode.SUPERVISED
        self.adaptation_strategy = AdaptationStrategy.REACTIVE
        self.learning_history: List[Dict[str, Any]] = []
        
        # Мониторинг и статистика
        self.performance_metrics = {
            "decisions_made": 0,
            "successful_decisions": 0,
            "failed_decisions": 0,
            "data_processed": 0,
            "api_calls_made": 0,
            "learning_episodes": 0,
            "avg_decision_confidence": 0.0,
            "avg_processing_time": 0.0
        }
        
        # Задачи агента
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.task_results: Dict[str, Any] = {}
        
        # Системы уведомлений
        self.event_handlers: Dict[str, List[Callable]] = {}
        
    async def initialize(self):
        """Инициализация агента"""
        try:
            await super().initialize()
            
            # Настройка обработки данных
            await self._setup_data_processing()
            
            # Настройка системы принятия решений
            await self._setup_decision_making()
            
            # Инициализация базы знаний
            await self._initialize_knowledge_base()
            
            # Запуск мониторинга
            await self._start_monitoring()
            
            logger.info(f"Enhanced agent '{self.agent_id}' initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize enhanced agent '{self.agent_id}': {e}")
            raise
            
    async def _setup_data_processing(self):
        """Настройка обработки данных"""
        # Регистрация базовых схем данных
        await self.data_processor.register_schema(
            create_text_schema("message", min_length=1, max_length=10000)
        )
        
        await self.data_processor.register_schema(
            create_numerical_schema("score", min_value=0.0, max_value=1.0)
        )
        
        # Создание конвейеров обработки
        basic_pipeline = ProcessingPipeline(
            name="basic_text_processing",
            steps=[
                lambda x: x.strip() if isinstance(x, str) else x,
                lambda x: x.lower() if isinstance(x, str) else x
            ],
            parallel=False,
            cache_enabled=True
        )
        
        await self.data_processor.create_pipeline(basic_pipeline)
        
    async def _setup_decision_making(self):
        """Настройка системы принятия решений"""
        # Rule-based decision maker
        rule_maker = RuleBasedDecisionMaker(
            confidence_threshold=self.personality.confidence_threshold
        )
        
        # Добавление базовых правил
        confidence_rule = create_threshold_rule(
            name="high_confidence",
            field="confidence",
            threshold=0.8,
            action_value="proceed",
            operator=">="
        )
        rule_maker.add_rule(confidence_rule)
        
        # ML-based decision maker
        ml_maker = MLBasedDecisionMaker(
            confidence_threshold=self.personality.confidence_threshold
        )
        
        # Consensus decision maker
        consensus_maker = ConsensusDecisionMaker(
            decision_makers=[rule_maker, ml_maker],
            confidence_threshold=self.personality.confidence_threshold
        )
        
        # Регистрация в движке решений
        self.decision_engine.register_decision_maker("rules", rule_maker)
        self.decision_engine.register_decision_maker("ml", ml_maker)
        self.decision_engine.register_decision_maker("consensus", consensus_maker)
        
    async def _initialize_knowledge_base(self):
        """Инициализация базы знаний"""
        # Добавление базовых фактов о себе
        await self.knowledge_base.add_fact("agent_id", self.agent_id)
        await self.knowledge_base.add_fact("agent_type", self.agent_type.value)
        await self.knowledge_base.add_fact("initialization_time", datetime.utcnow())
        
        # Добавление базовых правил
        await self.knowledge_base.add_rule(
            name="respond_to_greetings",
            condition="message_type == 'greeting'",
            action="send_greeting_response",
            confidence=0.9
        )
        
    async def _start_monitoring(self):
        """Запуск системы мониторинга"""
        # Создание задачи периодического мониторинга
        monitor_task = asyncio.create_task(self._monitor_performance())
        self.running_tasks["performance_monitor"] = monitor_task
        
    async def _monitor_performance(self):
        """Мониторинг производительности агента"""
        while self.status != AgentStatus.STOPPED:
            try:
                # Обновление метрик
                await self._update_performance_metrics()
                
                # Проверка здоровья систем
                await self._health_check()
                
                # Анализ производительности
                await self._analyze_performance()
                
                # Ожидание перед следующей проверкой
                await asyncio.sleep(60)  # Проверка каждую минуту
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring: {e}")
                await asyncio.sleep(60)
                
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка сообщения с использованием новых возможностей"""
        start_time = datetime.utcnow()
        
        try:
            # Валидация и предобработка данных
            processed_data = await self._preprocess_message_data(message.content)
            
            # Создание контекста для принятия решения
            decision_context = DecisionContext(
                agent_id=self.agent_id,
                task_type="message_processing",
                input_data={
                    "message": processed_data,
                    "sender": message.sender_id,
                    "timestamp": message.timestamp
                },
                historical_context=self._get_conversation_history(message.sender_id)
            )
            
            # Принятие решения о том, как обработать сообщение
            decision = await self.decision_engine.make_decision(decision_context)
            
            # Обновление памяти
            await self._update_memory(message, decision)
            
            # Выполнение действия на основе решения
            response = await self._execute_decision(message, decision)
            
            # Обновление статистики
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            await self._record_processing_stats(decision, processing_time, True)
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            await self._record_processing_stats(None, processing_time, False)
            return None
            
    async def _preprocess_message_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Предобработка данных сообщения"""
        result = await self.data_processor.process_data(
            data=data,
            pipeline_name="basic_text_processing",
            schema_name="message"
        )
        
        if result["success"]:
            self.performance_metrics["data_processed"] += 1
            return result["result"]
        else:
            logger.warning(f"Data preprocessing failed: {result.get('errors', [])}")
            return data
            
    async def _update_memory(self, message: AgentMessage, decision: DecisionResult):
        """Обновление системы памяти агента"""
        # Краткосрочная память - текущий контекст
        self.memory.short_term["last_message"] = message
        self.memory.short_term["last_decision"] = decision
        self.memory.short_term["conversation_partner"] = message.sender_id
        
        # Эпизодическая память - события
        episode = {
            "timestamp": datetime.utcnow(),
            "event_type": "message_processed",
            "message_id": message.message_id,
            "sender": message.sender_id,
            "decision_confidence": decision.confidence,
            "chosen_action": decision.chosen_option.value
        }
        
        self.memory.episodic.append(episode)
        
        # Ограничение размера эпизодической памяти
        if len(self.memory.episodic) > 1000:
            self.memory.episodic = self.memory.episodic[-1000:]
            
    async def _execute_decision(self, message: AgentMessage, 
                              decision: DecisionResult) -> Optional[AgentMessage]:
        """Выполнение действия на основе решения"""
        action = decision.chosen_option.value
        
        if action == "respond":
            return await self._generate_response(message, decision)
        elif action == "forward":
            return await self._forward_message(message, decision)
        elif action == "ignore":
            return None
        elif action == "escalate":
            return await self._escalate_message(message, decision)
        else:
            # Попытка выполнить пользовательское действие
            return await self._execute_custom_action(message, decision, action)
            
    async def _generate_response(self, message: AgentMessage, 
                               decision: DecisionResult) -> AgentMessage:
        """Генерация ответа на сообщение"""
        # Базовая логика генерации ответа
        response_content = {
            "text": f"Processed your message with confidence {decision.confidence:.2f}",
            "decision_reasoning": decision.reasoning,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            content=response_content,
            message_type="response",
            timestamp=datetime.utcnow()
        )
        
        return response
        
    async def learn_from_feedback(self, message_id: str, feedback: Dict[str, Any]):
        """Обучение на основе обратной связи"""
        try:
            # Поиск соответствующего эпизода в памяти
            episode = None
            for ep in reversed(self.memory.episodic):
                if ep.get("message_id") == message_id:
                    episode = ep
                    break
                    
            if not episode:
                logger.warning(f"Episode for message {message_id} not found")
                return
                
            # Создание записи обучения
            learning_record = {
                "timestamp": datetime.utcnow(),
                "episode": episode,
                "feedback": feedback,
                "learning_mode": self.learning_mode.value
            }
            
            self.learning_history.append(learning_record)
            
            # Обновление базы знаний на основе обратной связи
            await self._update_knowledge_from_feedback(episode, feedback)
            
            # Адаптация личности агента
            await self._adapt_personality(feedback)
            
            self.performance_metrics["learning_episodes"] += 1
            logger.info(f"Learned from feedback for message {message_id}")
            
        except Exception as e:
            logger.error(f"Error in learning from feedback: {e}")
            
    async def _update_knowledge_from_feedback(self, episode: Dict[str, Any], 
                                            feedback: Dict[str, Any]):
        """Обновление базы знаний на основе обратной связи"""
        success = feedback.get("success", False)
        quality_score = feedback.get("quality", 0.5)
        
        # Обновление производительности правил
        # Это упрощенная версия - в реальности нужна более сложная логика
        action = episode.get("chosen_action")
        if action and "rule_" in str(action):
            rule_name = str(action).replace("rule_", "")
            await self.knowledge_base.update_rule_performance(rule_name, success)
            
        # Обновление паттернов успешных действий
        if success and quality_score > 0.7:
            pattern_key = f"successful_actions_{episode.get('event_type', 'unknown')}"
            
            if pattern_key not in self.knowledge_base.patterns:
                self.knowledge_base.patterns[pattern_key] = []
                
            self.knowledge_base.patterns[pattern_key].append({
                "action": action,
                "context": episode,
                "quality": quality_score
            })
            
    async def _adapt_personality(self, feedback: Dict[str, Any]):
        """Адаптация личности агента на основе обратной связи"""
        if self.adaptation_strategy == AdaptationStrategy.REACTIVE:
            # Простая адаптация на основе успеха/неудачи
            success = feedback.get("success", False)
            adaptation_rate = 0.01  # Медленная адаптация
            
            if success:
                # Увеличиваем уверенность при успехе
                self.personality.confidence_threshold = min(
                    0.9,
                    self.personality.confidence_threshold + adaptation_rate
                )
            else:
                # Уменьшаем уверенность при неудаче
                self.personality.confidence_threshold = max(
                    0.3,
                    self.personality.confidence_threshold - adaptation_rate
                )
                
    async def register_api(self, name: str, endpoint_config: Dict[str, Any]) -> bool:
        """Регистрация внешнего API"""
        try:
            endpoint = APIEndpoint(**endpoint_config["endpoint"])
            auth = None
            
            if "auth" in endpoint_config:
                auth = AuthConfig(**endpoint_config["auth"])
                
            success = await self.api_manager.register_api(name, endpoint, auth)
            
            if success:
                self.performance_metrics["api_calls_made"] = 0
                logger.info(f"API '{name}' registered successfully")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to register API '{name}': {e}")
            return False
            
    async def call_external_api(self, api_name: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Вызов внешнего API"""
        try:
            request = APIRequest(**request_data)
            response = await self.api_manager.call_api(api_name, request)
            
            self.performance_metrics["api_calls_made"] += 1
            
            return {
                "success": 200 <= response.status_code < 300,
                "status_code": response.status_code,
                "data": response.data,
                "response_time": response.response_time
            }
            
        except Exception as e:
            logger.error(f"API call to '{api_name}' failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time": 0.0
            }
            
    def add_event_handler(self, event_type: str, handler: Callable):
        """Добавление обработчика событий"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
        
    async def emit_event(self, event_type: str, event_data: Dict[str, Any]):
        """Генерация события"""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event_data)
                    else:
                        handler(event_data)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")
                    
    async def get_enhanced_status(self) -> Dict[str, Any]:
        """Получение расширенного статуса агента"""
        base_status = await self.get_status()
        
        # Статистика обработки данных
        data_stats = await self.data_processor.get_processing_stats()
        
        # Статистика принятия решений
        decision_stats = await self.decision_engine.get_performance_report()
        
        # Статистика API
        api_stats = await self.api_manager.get_global_stats()
        
        # Статус памяти
        memory_status = {
            "short_term_items": len(self.memory.short_term),
            "episodic_memories": len(self.memory.episodic),
            "long_term_facts": len(self.memory.long_term),
            "semantic_knowledge": len(self.memory.semantic)
        }
        
        # Статус базы знаний
        knowledge_status = {
            "facts_count": len(self.knowledge_base.facts),
            "rules_count": len(self.knowledge_base.rules),
            "patterns_count": len(self.knowledge_base.patterns)
        }
        
        return {
            "base_status": base_status,
            "personality": {
                "risk_tolerance": self.personality.risk_tolerance,
                "confidence_threshold": self.personality.confidence_threshold,
                "learning_rate": self.personality.learning_rate
            },
            "performance_metrics": dict(self.performance_metrics),
            "data_processing": data_stats,
            "decision_making": decision_stats,
            "api_integration": api_stats,
            "memory": memory_status,
            "knowledge_base": knowledge_status,
            "running_tasks": list(self.running_tasks.keys()),
            "learning_history_size": len(self.learning_history)
        }
        
    async def shutdown(self):
        """Корректное завершение работы агента"""
        try:
            logger.info(f"Shutting down enhanced agent '{self.agent_id}'")
            
            # Отмена всех задач
            for task_name, task in self.running_tasks.items():
                logger.debug(f"Cancelling task: {task_name}")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
            # Закрытие API соединений
            await self.api_manager.shutdown()
            
            # Очистка кэшей
            await self.data_processor.clear_cache()
            
            # Вызов родительского shutdown
            await super().shutdown()
            
            logger.info(f"Enhanced agent '{self.agent_id}' shut down successfully")
            
        except Exception as e:
            logger.error(f"Error during shutdown of agent '{self.agent_id}': {e}")
            
    # Абстрактные методы, которые должны быть реализованы в наследниках
    
    @abstractmethod
    async def _execute_custom_action(self, message: AgentMessage, 
                                   decision: DecisionResult, 
                                   action: str) -> Optional[AgentMessage]:
        """Выполнение пользовательского действия"""
        pass
        
    @abstractmethod  
    async def _forward_message(self, message: AgentMessage, 
                             decision: DecisionResult) -> Optional[AgentMessage]:
        """Пересылка сообщения"""
        pass
        
    @abstractmethod
    async def _escalate_message(self, message: AgentMessage,
                              decision: DecisionResult) -> Optional[AgentMessage]:
        """Эскалация сообщения"""
        pass
        
    # Вспомогательные методы
    
    def _get_conversation_history(self, partner_id: str) -> List[Dict[str, Any]]:
        """Получение истории разговора с конкретным партнером"""
        history = []
        for episode in self.memory.episodic:
            if episode.get("sender") == partner_id or episode.get("receiver") == partner_id:
                history.append(episode)
        return history[-10:]  # Последние 10 сообщений
        
    async def _record_processing_stats(self, decision: Optional[DecisionResult], 
                                     processing_time: float, success: bool):
        """Запись статистики обработки"""
        self.performance_metrics["avg_processing_time"] = (
            (self.performance_metrics["avg_processing_time"] * 
             self.performance_metrics["decisions_made"] + processing_time) /
            (self.performance_metrics["decisions_made"] + 1)
        )
        
        self.performance_metrics["decisions_made"] += 1
        
        if success:
            self.performance_metrics["successful_decisions"] += 1
            if decision:
                old_avg = self.performance_metrics["avg_decision_confidence"]
                old_count = self.performance_metrics["successful_decisions"] - 1
                
                if old_count == 0:
                    self.performance_metrics["avg_decision_confidence"] = decision.confidence
                else:
                    self.performance_metrics["avg_decision_confidence"] = (
                        (old_avg * old_count + decision.confidence) / 
                        self.performance_metrics["successful_decisions"]
                    )
        else:
            self.performance_metrics["failed_decisions"] += 1
            
    async def _update_performance_metrics(self):
        """Обновление метрик производительности"""
        # Здесь можно добавить дополнительную логику для расчета метрик
        pass
        
    async def _health_check(self):
        """Проверка здоровья всех систем агента"""
        try:
            # Проверка API
            api_health = await self.api_manager.health_check_all()
            
            # Проверка обработки данных
            test_data = {"test": "health_check"}
            data_result = await self.data_processor.process_data(
                test_data, "basic_text_processing"
            )
            
            # Генерация события о состоянии здоровья
            await self.emit_event("health_check", {
                "agent_id": self.agent_id,
                "timestamp": datetime.utcnow(),
                "api_health": api_health,
                "data_processing_ok": data_result["success"],
                "status": self.status.value
            })
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            
    async def _analyze_performance(self):
        """Анализ производительности и генерация рекомендаций"""
        try:
            metrics = self.performance_metrics
            
            # Анализ успешности решений
            if metrics["decisions_made"] > 0:
                success_rate = metrics["successful_decisions"] / metrics["decisions_made"]
                
                if success_rate < 0.7:  # Низкая успешность
                    await self.emit_event("low_performance", {
                        "agent_id": self.agent_id,
                        "success_rate": success_rate,
                        "recommendation": "Consider adjusting decision parameters"
                    })
                    
            # Анализ времени обработки
            if metrics["avg_processing_time"] > 5.0:  # Медленная обработка
                await self.emit_event("slow_processing", {
                    "agent_id": self.agent_id,
                    "avg_time": metrics["avg_processing_time"],
                    "recommendation": "Consider optimizing data processing pipeline"
                })
                
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")

# Фабричные функции для создания специализированных агентов

def create_chatbot_agent(agent_id: str, api_configs: Optional[Dict[str, Any]] = None) -> EnhancedBaseAgent:
    """Создание агента-чатбота"""
    
    class ChatbotAgent(EnhancedBaseAgent):
        async def _execute_custom_action(self, message: AgentMessage, 
                                       decision: DecisionResult, 
                                       action: str) -> Optional[AgentMessage]:
            # Пользовательская логика для чатбота
            return await self._generate_response(message, decision)
            
        async def _forward_message(self, message: AgentMessage, 
                                 decision: DecisionResult) -> Optional[AgentMessage]:
            # Логика пересылки для чатбота
            return None
            
        async def _escalate_message(self, message: AgentMessage,
                                  decision: DecisionResult) -> Optional[AgentMessage]:
            # Логика эскалации для чатбота
            return await self._generate_response(message, decision)
    
    capabilities = [
        AgentCapability(
            name="text_processing",
            version="1.0",
            description="Natural language processing and response generation"
        )
    ]
    
    personality = AgentPersonality(
        risk_tolerance=0.3,
        curiosity_level=0.7,
        cooperation_tendency=0.9,
        confidence_threshold=0.6
    )
    
    agent = ChatbotAgent(agent_id, AgentType.LLM, capabilities, personality)
    
    return agent

def create_data_analyst_agent(agent_id: str) -> EnhancedBaseAgent:
    """Создание агента-аналитика данных"""
    
    class DataAnalystAgent(EnhancedBaseAgent):
        async def _execute_custom_action(self, message: AgentMessage, 
                                       decision: DecisionResult, 
                                       action: str) -> Optional[AgentMessage]:
            if action == "analyze_data":
                return await self._perform_data_analysis(message)
            return await self._generate_response(message, decision)
            
        async def _perform_data_analysis(self, message: AgentMessage) -> AgentMessage:
            # Логика анализа данных
            analysis_result = {
                "analysis_type": "basic_statistics",
                "timestamp": datetime.utcnow().isoformat(),
                "summary": "Data analysis completed"
            }
            
            response = AgentMessage(
                message_id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                content=analysis_result,
                message_type="analysis_result",
                timestamp=datetime.utcnow()
            )
            
            return response
            
        async def _forward_message(self, message: AgentMessage, 
                                 decision: DecisionResult) -> Optional[AgentMessage]:
            return None
            
        async def _escalate_message(self, message: AgentMessage,
                                  decision: DecisionResult) -> Optional[AgentMessage]:
            return await self._generate_response(message, decision)
    
    capabilities = [
        AgentCapability(
            name="data_analysis",
            version="1.0", 
            description="Statistical analysis and data processing"
        ),
        AgentCapability(
            name="pattern_recognition",
            version="1.0",
            description="Pattern detection in datasets"
        )
    ]
    
    personality = AgentPersonality(
        risk_tolerance=0.2,
        curiosity_level=0.9,
        cooperation_tendency=0.6,
        confidence_threshold=0.8
    )
    
    agent = DataAnalystAgent(agent_id, AgentType.HYBRID, capabilities, personality)
    
    return agent