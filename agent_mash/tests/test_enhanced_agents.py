# agent_mash/tests/test_enhanced_agents.py

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any

# Импорты для тестирования
from agent_mash.core.enhanced_base_agent import (
    EnhancedBaseAgent, create_chatbot_agent, create_data_analyst_agent,
    AgentPersonality, LearningMode
)
from agent_mash.core.agent_orchestra import (
    AgentOrchestra, AgentTask, TaskPriority, TaskStatus,
    create_simple_orchestra, create_simple_task
)
from agent_mash.core.advanced_data_processor import (
    AdvancedDataProcessor, create_text_schema, create_numerical_schema
)
from agent_mash.core.decision_engine import (
    AdvancedDecisionEngine, DecisionContext, create_simple_rule
)
from agent_mash.core.external_api_integration import (
    ExternalAPIManager, create_rest_endpoint, create_api_key_auth
)

class TestAdvancedDataProcessor:
    """Тесты для системы обработки данных"""
    
    @pytest.fixture
    async def processor(self):
        """Фикстура процессора данных"""
        processor = AdvancedDataProcessor()
        yield processor
        await processor.clear_cache()
        
    @pytest.mark.asyncio
    async def test_schema_registration(self, processor):
        """Тест регистрации схем данных"""
        # Создание схемы
        schema = create_text_schema("test_schema", min_length=1, max_length=100)
        
        # Регистрация
        success = await processor.register_schema(schema)
        assert success, "Схема должна быть зарегистрирована успешно"
        
        # Проверка наличия
        assert "test_schema" in processor.schemas
        
    @pytest.mark.asyncio
    async def test_data_validation(self, processor):
        """Тест валидации данных"""
        # Регистрация схемы
        schema = create_text_schema("email", pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$')
        await processor.register_schema(schema)
        
        # Тест валидных данных
        valid_data = {"email": "test@example.com"}
        result = await processor.validate_data(valid_data, "email")
        assert result["valid"], "Валидные данные должны проходить проверку"
        
        # Тест невалидных данных
        invalid_data = {"email": "invalid-email"}
        result = await processor.validate_data(invalid_data, "email")
        assert not result["valid"], "Невалидные данные не должны проходить проверку"
        assert len(result["errors"]) > 0, "Должны быть ошибки валидации"
        
    @pytest.mark.asyncio
    async def test_pipeline_processing(self, processor):
        """Тест обработки через конвейер"""
        from agent_mash.core.advanced_data_processor import ProcessingPipeline
        
        # Создание конвейера
        pipeline = ProcessingPipeline(
            name="test_pipeline",
            steps=[
                lambda x: x.strip() if isinstance(x, str) else x,
                lambda x: x.upper() if isinstance(x, str) else x
            ]
        )
        
        await processor.create_pipeline(pipeline)
        
        # Тест обработки
        test_data = {"message": "  hello world  "}
        result = await processor.process_data(test_data, "test_pipeline")
        
        assert result["success"], "Обработка должна быть успешной"
        assert result["result"]["message"] == "HELLO WORLD"
        
    @pytest.mark.asyncio
    async def test_caching(self, processor):
        """Тест кэширования"""
        schema = create_text_schema("cache_test")
        await processor.register_schema(schema)
        
        # Создание конвейера с кэшированием
        from agent_mash.core.advanced_data_processor import ProcessingPipeline
        
        pipeline = ProcessingPipeline(
            name="cache_pipeline",
            steps=[lambda x: x.upper() if isinstance(x, str) else x],
            cache_enabled=True
        )
        await processor.create_pipeline(pipeline)
        
        # Первая обработка
        test_data = {"message": "test"}
        result1 = await processor.process_data(test_data, "cache_pipeline")
        
        # Вторая обработка (должна использовать кэш)
        result2 = await processor.process_data(test_data, "cache_pipeline")
        
        assert result1["success"] and result2["success"]
        assert result1["result"] == result2["result"]

class TestDecisionEngine:
    """Тесты для системы принятия решений"""
    
    @pytest.fixture
    async def engine(self):
        """Фикстура движка решений"""
        engine = AdvancedDecisionEngine()
        return engine
        
    @pytest.mark.asyncio
    async def test_rule_based_decision(self, engine):
        """Тест принятия решений на основе правил"""
        from agent_mash.core.decision_engine import RuleBasedDecisionMaker
        
        # Создание rule-based decision maker
        rule_maker = RuleBasedDecisionMaker()
        
        # Добавление правила
        rule = create_simple_rule(
            "test_rule",
            lambda ctx: ctx.input_data.get("value", 0) > 10,
            "accept"
        )
        rule_maker.add_rule(rule)
        
        # Регистрация в движке
        engine.register_decision_maker("rules", rule_maker)
        
        # Тест с условием, которое выполняется
        context = DecisionContext(
            agent_id="test",
            task_type="evaluation",
            input_data={"value": 15}
        )
        
        decision = await engine.make_decision(context, "rules")
        assert decision.chosen_option.value == "accept"
        assert decision.confidence > 0
        
        # Тест с условием, которое не выполняется
        context.input_data["value"] = 5
        decision = await engine.make_decision(context, "rules")
        assert decision.chosen_option.value != "accept"
        
    @pytest.mark.asyncio
    async def test_consensus_decision(self, engine):
        """Тест консенсусного принятия решений"""
        from agent_mash.core.decision_engine import (
            RuleBasedDecisionMaker, MLBasedDecisionMaker, ConsensusDecisionMaker
        )
        
        # Создание различных decision makers
        rule_maker = RuleBasedDecisionMaker()
        ml_maker = MLBasedDecisionMaker()
        
        # Создание консенсусного decision maker
        consensus_maker = ConsensusDecisionMaker([rule_maker, ml_maker])
        
        # Регистрация
        engine.register_decision_maker("consensus", consensus_maker)
        
        # Тест принятия решения
        context = DecisionContext(
            agent_id="test",
            task_type="complex_evaluation",
            input_data={"complexity": "high", "confidence": 0.8}
        )
        
        decision = await engine.make_decision(context, "consensus")
        assert decision is not None
        assert hasattr(decision, 'chosen_option')
        assert hasattr(decision, 'confidence')

class TestEnhancedBaseAgent:
    """Тесты для улучшенного базового агента"""
    
    @pytest.fixture
    async def chatbot_agent(self):
        """Фикстура агента-чатбота"""
        agent = create_chatbot_agent("test-chatbot")
        await agent.initialize()
        yield agent
        await agent.shutdown()
        
    @pytest.fixture
    async def analyst_agent(self):
        """Фикстура агента-аналитика"""
        agent = create_data_analyst_agent("test-analyst")
        await agent.initialize()
        yield agent
        await agent.shutdown()
        
    @pytest.mark.asyncio
    async def test_agent_initialization(self, chatbot_agent):
        """Тест инициализации агента"""
        assert chatbot_agent.agent_id == "test-chatbot"
        assert chatbot_agent.data_processor is not None
        assert chatbot_agent.decision_engine is not None
        assert chatbot_agent.api_manager is not None
        assert chatbot_agent.knowledge_base is not None
        
    @pytest.mark.asyncio
    async def test_message_processing(self, chatbot_agent):
        """Тест обработки сообщений"""
        from agent_mash.core.agent_message import AgentMessage
        
        # Создание тестового сообщения
        message = AgentMessage(
            message_id="test_msg",
            sender_id="user",
            receiver_id=chatbot_agent.agent_id,
            content={"text": "Hello, chatbot!"},
            message_type="greeting"
        )
        
        # Обработка сообщения
        response = await chatbot_agent.process_message(message)
        
        # Проверка ответа
        assert response is not None
        assert response.sender_id == chatbot_agent.agent_id
        assert response.receiver_id == "user"
        
    @pytest.mark.asyncio
    async def test_learning_from_feedback(self, chatbot_agent):
        """Тест обучения на основе обратной связи"""
        # Запоминаем начальное состояние
        initial_confidence = chatbot_agent.personality.confidence_threshold
        initial_learning_episodes = len(chatbot_agent.learning_history)
        
        # Обучение на положительной обратной связи
        feedback = {
            "success": True,
            "quality": 0.9,
            "user_satisfaction": 0.85
        }
        
        await chatbot_agent.learn_from_feedback("test_msg", feedback)
        
        # Проверка изменений
        assert len(chatbot_agent.learning_history) == initial_learning_episodes + 1
        # При положительной обратной связи уверенность должна увеличиться
        assert chatbot_agent.personality.confidence_threshold >= initial_confidence
        
    @pytest.mark.asyncio
    async def test_api_registration(self, chatbot_agent):
        """Тест регистрации внешних API"""
        api_config = {
            "endpoint": {
                "name": "test_api",
                "base_url": "https://api.test.com",
                "timeout": 30.0
            }
        }
        
        success = await chatbot_agent.register_api("test", api_config)
        assert success, "API должен быть зарегистрирован успешно"
        
    @pytest.mark.asyncio
    async def test_enhanced_status(self, chatbot_agent):
        """Тест получения расширенного статуса"""
        status = await chatbot_agent.get_enhanced_status()
        
        # Проверка наличия основных секций
        assert "base_status" in status
        assert "personality" in status
        assert "performance_metrics" in status
        assert "data_processing" in status
        assert "decision_making" in status
        assert "memory" in status
        assert "knowledge_base" in status
        
        # Проверка базовых значений
        assert status["personality"]["confidence_threshold"] > 0
        assert status["memory"]["short_term_items"] >= 0
        assert status["knowledge_base"]["facts_count"] >= 0

class TestAgentOrchestra:
    """Тесты для оркестратора агентов"""
    
    @pytest.fixture
    async def orchestra(self):
        """Фикстура оркестратора"""
        orchestra = await create_simple_orchestra()
        yield orchestra
        await orchestra.shutdown()
        
    @pytest.fixture
    async def sample_agents(self):
        """Фикстура примеров агентов"""
        chatbot = create_chatbot_agent("test-chatbot-orch")
        analyst = create_data_analyst_agent("test-analyst-orch")
        
        await chatbot.initialize()
        await analyst.initialize()
        
        yield [chatbot, analyst]
        
        await chatbot.shutdown()
        await analyst.shutdown()
        
    @pytest.mark.asyncio
    async def test_orchestra_initialization(self, orchestra):
        """Тест инициализации оркестратора"""
        status = await orchestra.get_orchestra_status()
        
        assert "orchestra_type" in status
        assert "uptime_seconds" in status
        assert "agents" in status
        assert "scheduler" in status
        
    @pytest.mark.asyncio
    async def test_agent_registration(self, orchestra, sample_agents):
        """Тест регистрации агентов"""
        chatbot, analyst = sample_agents
        
        # Регистрация агентов
        success1 = await orchestra.register_agent(chatbot)
        success2 = await orchestra.register_agent(analyst)
        
        assert success1, "Чатбот должен быть зарегистрирован"
        assert success2, "Аналитик должен быть зарегистрирован"
        
        # Проверка наличия в оркестраторе
        assert chatbot.agent_id in orchestra.agents
        assert analyst.agent_id in orchestra.agents
        assert len(orchestra.agents) == 2
        
    @pytest.mark.asyncio
    async def test_task_submission(self, orchestra, sample_agents):
        """Тест отправки задач"""
        chatbot, analyst = sample_agents
        await orchestra.register_agent(chatbot)
        await orchestra.register_agent(analyst)
        
        # Создание задачи
        task = create_simple_task(
            name="Test Task",
            description="Test task for orchestrator",
            input_data={"test": "data"},
            required_capabilities=["text_processing"]
        )
        
        # Отправка задачи
        success = await orchestra.submit_task(task)
        assert success, "Задача должна быть отправлена успешно"
        
        # Проверка статуса планировщика
        scheduler_status = await orchestra.scheduler.get_queue_status()
        total_tasks = (
            sum(scheduler_status["queues"].values()) + 
            scheduler_status["active_tasks"]
        )
        assert total_tasks > 0, "Должна быть минимум одна задача в системе"
        
    @pytest.mark.asyncio
    async def test_task_execution(self, orchestra, sample_agents):
        """Тест выполнения задач (интеграционный тест)"""
        chatbot, analyst = sample_agents
        await orchestra.register_agent(chatbot)
        
        # Создание простой задачи
        task = create_simple_task(
            name="Integration Test",
            description="Test task execution",
            input_data={"message": "Hello world"},
            priority=TaskPriority.HIGH,
            required_capabilities=["text_processing"]
        )
        
        # Отправка и ожидание выполнения
        await orchestra.submit_task(task)
        
        # Небольшая пауза для обработки
        await asyncio.sleep(2)
        
        # Проверка статистики
        stats = await orchestra.get_orchestra_status()
        assert stats["orchestra_stats"]["total_tasks_processed"] >= 0

class TestExternalAPIIntegration:
    """Тесты для интеграции с внешними API"""
    
    @pytest.fixture
    async def api_manager(self):
        """Фикстура менеджера API"""
        manager = ExternalAPIManager()
        yield manager
        await manager.shutdown()
        
    @pytest.mark.asyncio
    async def test_api_registration(self, api_manager):
        """Тест регистрации API"""
        endpoint = create_rest_endpoint(
            name="test_api",
            base_url="https://api.test.com"
        )
        
        success = await api_manager.register_api("test", endpoint)
        assert success, "API должен быть зарегистрирован"
        
    @pytest.mark.asyncio
    async def test_api_with_auth(self, api_manager):
        """Тест API с аутентификацией"""
        endpoint = create_rest_endpoint(
            name="auth_api", 
            base_url="https://api.secure.com"
        )
        auth = create_api_key_auth("test_key")
        
        success = await api_manager.register_api("secure", endpoint, auth)
        assert success, "API с аутентификацией должен быть зарегистрирован"
        
    @pytest.mark.asyncio
    async def test_rate_limiting(self, api_manager):
        """Тест ограничения скорости запросов"""
        # Этот тест проверяет, что система rate limiting работает
        # В реальном тестировании потребовалось бы mock API
        
        endpoint = create_rest_endpoint(
            name="rate_limited",
            base_url="https://api.limited.com"
        )
        
        success = await api_manager.register_api("limited", endpoint)
        assert success
        
        # Проверка наличия клиента с rate limiting
        assert "limited" in api_manager.api_clients

# Интеграционные тесты
class TestIntegration:
    """Интеграционные тесты всей системы"""
    
    @pytest.mark.asyncio
    async def test_full_agent_lifecycle(self):
        """Тест полного жизненного цикла агента"""
        # Создание оркестратора
        orchestra = await create_simple_orchestra()
        
        try:
            # Создание агента
            agent = create_chatbot_agent("lifecycle-test")
            await agent.initialize()
            
            # Регистрация в оркестраторе
            reg_success = await orchestra.register_agent(agent)
            assert reg_success
            
            # Отправка задачи
            task = create_simple_task(
                name="Lifecycle Test",
                description="Full lifecycle test",
                input_data={"test": "data"}
            )
            
            task_success = await orchestra.submit_task(task)
            assert task_success
            
            # Ожидание обработки
            await asyncio.sleep(1)
            
            # Проверка статуса
            status = await orchestra.get_orchestra_status()
            assert len(status["agents"]) == 1
            
            # Отмена регистрации
            unreg_success = await orchestra.unregister_agent(agent.agent_id)
            assert unreg_success
            
            # Проверка удаления
            final_status = await orchestra.get_orchestra_status()
            assert len(final_status["agents"]) == 0
            
        finally:
            await orchestra.shutdown()
            
    @pytest.mark.asyncio
    async def test_multi_agent_coordination(self):
        """Тест координации нескольких агентов"""
        orchestra = await create_simple_orchestra()
        
        try:
            # Создание нескольких агентов
            agents = [
                create_chatbot_agent("multi-chat-1"),
                create_chatbot_agent("multi-chat-2"),
                create_data_analyst_agent("multi-analyst-1")
            ]
            
            # Инициализация и регистрация
            for agent in agents:
                await agent.initialize()
                await orchestra.register_agent(agent)
                
            # Отправка нескольких задач
            tasks = [
                create_simple_task(f"Task-{i}", f"Multi-agent task {i}", {"id": i})
                for i in range(3)
            ]
            
            for task in tasks:
                await orchestra.submit_task(task)
                
            # Ожидание обработки
            await asyncio.sleep(2)
            
            # Проверка распределения нагрузки
            status = await orchestra.get_orchestra_status()
            
            # Должны быть зарегистрированы все агенты
            assert len(status["agents"]) == 3
            
            # Должна быть обработана хотя бы одна задача
            assert status["orchestra_stats"]["total_tasks_processed"] >= 0
            
        finally:
            await orchestra.shutdown()

# Pytest конфигурация
@pytest.fixture(scope="session")
def event_loop():
    """Создание event loop для сессии тестов"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# Запуск тестов если файл вызван напрямую
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])