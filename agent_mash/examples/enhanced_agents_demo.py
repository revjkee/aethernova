# agent_mash/examples/enhanced_agents_demo.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json

# Импорты из нашего проекта
from agent_mash.core.enhanced_base_agent import (
    create_chatbot_agent, create_data_analyst_agent,
    EnhancedBaseAgent, AgentPersonality, LearningMode
)
from agent_mash.core.agent_orchestra import (
    AgentOrchestra, AgentTask, TaskPriority,
    create_simple_orchestra, create_simple_task, create_urgent_task
)
from agent_mash.core.advanced_data_processor import create_text_schema, create_numerical_schema
from agent_mash.core.decision_engine import create_simple_rule, create_threshold_rule
from agent_mash.core.external_api_integration import create_rest_endpoint, create_api_key_auth

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedAgentsDemo:
    """Демонстрация возможностей улучшенных AI агентов"""
    
    def __init__(self):
        self.orchestra = None
        self.agents: Dict[str, EnhancedBaseAgent] = {}
        self.tasks: List[AgentTask] = []
        self.results: Dict[str, Any] = {}
        
    async def run_complete_demo(self):
        """Запуск полной демонстрации"""
        try:
            logger.info("=" * 60)
            logger.info("ДЕМОНСТРАЦИЯ УЛУЧШЕННЫХ AI АГЕНТОВ")
            logger.info("=" * 60)
            
            # 1. Инициализация оркестратора
            await self.demo_orchestra_setup()
            
            # 2. Создание и регистрация агентов
            await self.demo_agent_creation()
            
            # 3. Настройка обработки данных
            await self.demo_data_processing()
            
            # 4. Демонстрация принятия решений
            await self.demo_decision_making()
            
            # 5. Интеграция с внешними API
            await self.demo_api_integration()
            
            # 6. Выполнение задач через оркестратор
            await self.demo_task_execution()
            
            # 7. Обучение агентов
            await self.demo_agent_learning()
            
            # 8. Мониторинг и статистика
            await self.demo_monitoring()
            
            # 9. Завершение
            await self.demo_cleanup()
            
            logger.info("=" * 60)
            logger.info("ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА УСПЕШНО")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Ошибка в демонстрации: {e}")
            raise
            
    async def demo_orchestra_setup(self):
        """Демонстрация настройки оркестратора"""
        logger.info("\n🎼 НАСТРОЙКА ОРКЕСТРАТОРА АГЕНТОВ")
        logger.info("-" * 40)
        
        # Создание оркестратора
        self.orchestra = await create_simple_orchestra()
        
        # Получение начального статуса
        status = await self.orchestra.get_orchestra_status()
        logger.info(f"Оркестратор создан: {status['orchestra_type']}")
        logger.info(f"Время запуска: {status['orchestra_stats']['system_uptime']}")
        
        # Настройка обработчиков событий
        self.orchestra.event_handlers["agent_registered"].append(
            self._on_agent_registered
        )
        self.orchestra.event_handlers["task_completed"].append(
            self._on_task_completed
        )
        
        logger.info("✅ Оркестратор настроен и готов к работе")
        
    async def demo_agent_creation(self):
        """Демонстрация создания различных типов агентов"""
        logger.info("\n🤖 СОЗДАНИЕ И РЕГИСТРАЦИЯ АГЕНТОВ")
        logger.info("-" * 40)
        
        # 1. Создание агента-чатбота
        chatbot = create_chatbot_agent("chatbot-001")
        
        # Настройка личности чатбота
        chatbot.personality.curiosity_level = 0.8
        chatbot.personality.cooperation_tendency = 0.9
        chatbot.learning_mode = LearningMode.SUPERVISED
        
        logger.info("Создан агент-чатбот:")
        logger.info(f"  - ID: {chatbot.agent_id}")
        logger.info(f"  - Тип: {chatbot.agent_type.value}")
        logger.info(f"  - Любопытство: {chatbot.personality.curiosity_level}")
        logger.info(f"  - Кооперативность: {chatbot.personality.cooperation_tendency}")
        
        # 2. Создание агента-аналитика данных
        analyst = create_data_analyst_agent("analyst-001")
        
        # Настройка личности аналитика
        analyst.personality.risk_tolerance = 0.2
        analyst.personality.confidence_threshold = 0.8
        analyst.learning_mode = LearningMode.UNSUPERVISED
        
        logger.info("Создан агент-аналитик:")
        logger.info(f"  - ID: {analyst.agent_id}")
        logger.info(f"  - Тип: {analyst.agent_type.value}")
        logger.info(f"  - Толерантность к риску: {analyst.personality.risk_tolerance}")
        logger.info(f"  - Порог уверенности: {analyst.personality.confidence_threshold}")
        
        # Регистрация агентов в оркестраторе
        success1 = await self.orchestra.register_agent(chatbot)
        success2 = await self.orchestra.register_agent(analyst)
        
        if success1 and success2:
            self.agents["chatbot"] = chatbot
            self.agents["analyst"] = analyst
            logger.info("✅ Все агенты успешно зарегистрированы в оркестраторе")
        else:
            logger.error("❌ Ошибка регистрации агентов")
            
    async def demo_data_processing(self):
        """Демонстрация обработки данных"""
        logger.info("\n📊 ОБРАБОТКА И ВАЛИДАЦИЯ ДАННЫХ")
        logger.info("-" * 40)
        
        chatbot = self.agents["chatbot"]
        
        # Регистрация дополнительных схем данных
        email_schema = create_text_schema(
            "email", 
            pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        await chatbot.data_processor.register_schema(email_schema)
        
        confidence_schema = create_numerical_schema(
            "confidence", 
            min_value=0.0, 
            max_value=1.0
        )
        await chatbot.data_processor.register_schema(confidence_schema)
        
        logger.info("Зарегистрированы схемы данных: email, confidence")
        
        # Тестирование валидации
        test_data = [
            {"email": "user@example.com", "confidence": 0.95},
            {"email": "invalid-email", "confidence": 1.2},
            {"email": "valid@test.org", "confidence": 0.7}
        ]
        
        for i, data in enumerate(test_data):
            result = await chatbot.data_processor.validate_data(data, "email")
            logger.info(f"Валидация данных #{i+1}: {'✅' if result['valid'] else '❌'}")
            if not result['valid']:
                logger.info(f"  Ошибки: {result['errors']}")
                
        # Демонстрация обработки через конвейер
        text_data = {"message": "  HELLO WORLD!  "}
        processed = await chatbot.data_processor.process_data(
            text_data, "basic_text_processing"
        )
        
        logger.info(f"Исходный текст: '{text_data['message']}'")
        logger.info(f"Обработанный: '{processed['result']['message']}'")
        
        # Статистика обработки
        stats = await chatbot.data_processor.get_processing_stats()
        logger.info(f"Статистика обработки: {stats}")
        
        logger.info("✅ Демонстрация обработки данных завершена")
        
    async def demo_decision_making(self):
        """Демонстрация принятия решений"""
        logger.info("\n🧠 СИСТЕМА ПРИНЯТИЯ РЕШЕНИЙ")
        logger.info("-" * 40)
        
        from agent_mash.core.decision_engine import DecisionContext
        
        analyst = self.agents["analyst"]
        
        # Добавление пользовательского правила
        priority_rule = create_simple_rule(
            name="high_priority_rule",
            condition=lambda ctx: ctx.input_data.get("priority") == "high",
            action_value="immediate_action"
        )
        
        rule_maker = analyst.decision_engine.decision_makers["rules"]
        rule_maker.add_rule(priority_rule)
        
        logger.info("Добавлено правило для высокого приоритета")
        
        # Тестирование различных сценариев принятия решений
        test_scenarios = [
            {
                "name": "Высокий приоритет",
                "context": DecisionContext(
                    agent_id="analyst-001",
                    task_type="data_analysis",
                    input_data={"priority": "high", "data_size": 1000}
                )
            },
            {
                "name": "Низкая уверенность",
                "context": DecisionContext(
                    agent_id="analyst-001", 
                    task_type="prediction",
                    input_data={"confidence": 0.3, "risk_level": "medium"}
                )
            },
            {
                "name": "Стандартная задача",
                "context": DecisionContext(
                    agent_id="analyst-001",
                    task_type="processing",
                    input_data={"priority": "normal", "confidence": 0.85}
                )
            }
        ]
        
        for scenario in test_scenarios:
            logger.info(f"\nСценарий: {scenario['name']}")
            
            # Принятие решения разными способами
            for strategy in ["rules", "ml", "consensus"]:
                decision = await analyst.decision_engine.make_decision(
                    scenario["context"], strategy
                )
                
                logger.info(f"  {strategy.upper()}: {decision.chosen_option.value} "
                          f"(уверенность: {decision.confidence:.2f})")
                if decision.reasoning:
                    logger.info(f"    Обоснование: {decision.reasoning[:50]}...")
                    
        # Статистика принятия решений
        report = await analyst.decision_engine.get_performance_report()
        logger.info(f"\nСтатистика принятия решений:")
        for maker_name, stats in report.items():
            logger.info(f"  {maker_name}: {stats['decisions_made']} решений, "
                       f"средняя уверенность: {stats['avg_confidence']:.2f}")
            
        logger.info("✅ Демонстрация принятия решений завершена")
        
    async def demo_api_integration(self):
        """Демонстрация интеграции с внешними API"""
        logger.info("\n🌐 ИНТЕГРАЦИЯ С ВНЕШНИМИ API")
        logger.info("-" * 40)
        
        chatbot = self.agents["chatbot"]
        
        # Настройка тестового API (JSON Placeholder)
        test_api_config = {
            "endpoint": {
                "name": "jsonplaceholder",
                "base_url": "https://jsonplaceholder.typicode.com",
                "timeout": 10.0,
                "max_retries": 3
            }
        }
        
        success = await chatbot.register_api("test_api", test_api_config)
        logger.info(f"Регистрация API: {'✅' if success else '❌'}")
        
        if success:
            # Тест вызова API
            request_data = {
                "method": "GET",
                "endpoint": "/posts/1",
                "headers": {"Content-Type": "application/json"}
            }
            
            response = await chatbot.call_external_api("test_api", request_data)
            logger.info(f"API вызов: {'✅' if response['success'] else '❌'}")
            logger.info(f"Время отклика: {response.get('response_time', 0):.2f}s")
            
            if response["success"]:
                data = response["data"]
                logger.info(f"Получен пост: '{data.get('title', 'N/A')[:50]}...'")
                
        # Демонстрация статистики API
        api_stats = await chatbot.api_manager.get_global_stats()
        logger.info(f"Статистика API: {api_stats}")
        
        logger.info("✅ Демонстрация API интеграции завершена")
        
    async def demo_task_execution(self):
        """Демонстрация выполнения задач через оркестратор"""
        logger.info("\n📋 ВЫПОЛНЕНИЕ ЗАДАЧ ЧЕРЕЗ ОРКЕСТРАТОР")
        logger.info("-" * 40)
        
        # Создание различных типов задач
        tasks = [
            create_simple_task(
                name="Анализ настроений",
                description="Анализ настроений в тексте отзывов",
                input_data={
                    "text": "Отличный продукт! Очень доволен покупкой.",
                    "language": "ru"
                },
                priority=TaskPriority.HIGH,
                required_capabilities=["text_processing"]
            ),
            
            create_simple_task(
                name="Обработка данных",
                description="Статистический анализ набора данных",
                input_data={
                    "dataset": [1, 2, 3, 4, 5, 10, 15, 20],
                    "analysis_type": "descriptive"
                },
                priority=TaskPriority.MEDIUM,
                required_capabilities=["data_analysis"]
            ),
            
            create_urgent_task(
                name="Срочный отчет",
                description="Создание срочного отчета по продажам",
                input_data={
                    "period": "last_week",
                    "format": "summary"
                },
                deadline=datetime.utcnow() + timedelta(minutes=30),
                required_capabilities=["pattern_recognition"]
            )
        ]
        
        # Отправка задач в оркестратор
        logger.info(f"Отправка {len(tasks)} задач в оркестратор...")
        
        for task in tasks:
            success = await self.orchestra.submit_task(task)
            status = "✅" if success else "❌"
            logger.info(f"  {status} Задача '{task.name}' ({task.priority.value})")
            
            if success:
                self.tasks.append(task)
                
        # Ожидание выполнения задач
        logger.info("Ожидание выполнения задач...")
        await asyncio.sleep(5)  # Дать время на выполнение
        
        # Проверка статуса задач
        scheduler_status = await self.orchestra.scheduler.get_queue_status()
        logger.info(f"Статус очередей: {scheduler_status['queues']}")
        logger.info(f"Активные задачи: {scheduler_status['active_tasks']}")
        logger.info(f"Завершенные задачи: {scheduler_status['completed_tasks']}")
        
        logger.info("✅ Демонстрация выполнения задач завершена")
        
    async def demo_agent_learning(self):
        """Демонстрация обучения агентов"""
        logger.info("\n🎓 ОБУЧЕНИЕ И АДАПТАЦИЯ АГЕНТОВ")
        logger.info("-" * 40)
        
        chatbot = self.agents["chatbot"]
        
        # Имитация получения обратной связи
        feedback_scenarios = [
            {
                "message_id": "msg_001",
                "feedback": {
                    "success": True,
                    "quality": 0.9,
                    "user_satisfaction": 0.85,
                    "response_appropriateness": "very_good"
                }
            },
            {
                "message_id": "msg_002", 
                "feedback": {
                    "success": False,
                    "quality": 0.3,
                    "user_satisfaction": 0.2,
                    "error_type": "misunderstanding"
                }
            },
            {
                "message_id": "msg_003",
                "feedback": {
                    "success": True,
                    "quality": 0.75,
                    "user_satisfaction": 0.8,
                    "response_speed": "fast"
                }
            }
        ]
        
        logger.info("Обработка обратной связи...")
        
        initial_confidence = chatbot.personality.confidence_threshold
        logger.info(f"Начальный порог уверенности: {initial_confidence:.3f}")
        
        for i, scenario in enumerate(feedback_scenarios):
            logger.info(f"\nОбратная связь #{i+1}:")
            logger.info(f"  Успех: {'✅' if scenario['feedback']['success'] else '❌'}")
            logger.info(f"  Качество: {scenario['feedback'].get('quality', 'N/A')}")
            
            # Обучение на основе обратной связи
            await chatbot.learn_from_feedback(
                scenario["message_id"], 
                scenario["feedback"]
            )
            
            # Проверка изменений в личности
            new_confidence = chatbot.personality.confidence_threshold
            change = new_confidence - initial_confidence
            logger.info(f"  Новый порог уверенности: {new_confidence:.3f} "
                       f"({'+'if change > 0 else ''}{change:.3f})")
                       
        # Статистика обучения
        logger.info(f"\nВсего эпизодов обучения: {len(chatbot.learning_history)}")
        logger.info(f"Режим обучения: {chatbot.learning_mode.value}")
        
        # Демонстрация базы знаний
        knowledge_stats = {
            "facts": len(chatbot.knowledge_base.facts),
            "rules": len(chatbot.knowledge_base.rules),
            "patterns": len(chatbot.knowledge_base.patterns)
        }
        logger.info(f"База знаний: {knowledge_stats}")
        
        logger.info("✅ Демонстрация обучения агентов завершена")
        
    async def demo_monitoring(self):
        """Демонстрация мониторинга и статистики"""
        logger.info("\n📈 МОНИТОРИНГ И СТАТИСТИКА")
        logger.info("-" * 40)
        
        # Получение полного статуса оркестратора
        orchestra_status = await self.orchestra.get_orchestra_status()
        
        logger.info("Статус оркестратора:")
        logger.info(f"  - Время работы: {orchestra_status['uptime_seconds']:.1f}s")
        logger.info(f"  - Активных агентов: {orchestra_status['orchestra_stats']['agents_active']}")
        logger.info(f"  - Обработано задач: {orchestra_status['orchestra_stats']['total_tasks_processed']}")
        
        # Статус каждого агента
        logger.info("\nСтатус агентов:")
        for agent_id, agent_status in orchestra_status['agents'].items():
            logger.info(f"  {agent_id}:")
            logger.info(f"    - Статус: {agent_status['status']}")
            logger.info(f"    - Тип: {agent_status['type']}")
            logger.info(f"    - Возможности: {len(agent_status['capabilities'])}")
            
            metrics = agent_status.get('metrics', {})
            if metrics:
                logger.info(f"    - Задач выполнено: {metrics.get('tasks_completed', 0)}")
                logger.info(f"    - Успешность: {metrics.get('success_rate', 0):.1%}")
                logger.info(f"    - Эффективность: {metrics.get('efficiency_score', 0):.2f}")
                
        # Детальный статус одного из агентов
        chatbot = self.agents["chatbot"]
        detailed_status = await chatbot.get_enhanced_status()
        
        logger.info(f"\nДетальный статус агента '{chatbot.agent_id}':")
        logger.info(f"  - Память (краткосрочная): {detailed_status['memory']['short_term_items']} элементов")
        logger.info(f"  - Память (эпизодическая): {detailed_status['memory']['episodic_memories']} воспоминаний")
        logger.info(f"  - База знаний (факты): {detailed_status['knowledge_base']['facts_count']}")
        logger.info(f"  - База знаний (правила): {detailed_status['knowledge_base']['rules_count']}")
        
        perf_metrics = detailed_status['performance_metrics']
        logger.info(f"  - Принято решений: {perf_metrics['decisions_made']}")
        logger.info(f"  - Среднее время обработки: {perf_metrics['avg_processing_time']:.2f}s")
        logger.info(f"  - API вызовов: {perf_metrics['api_calls_made']}")
        
        logger.info("✅ Демонстрация мониторинга завершена")
        
    async def demo_cleanup(self):
        """Завершение демонстрации и очистка ресурсов"""
        logger.info("\n🧹 ЗАВЕРШЕНИЕ И ОЧИСТКА")
        logger.info("-" * 40)
        
        try:
            # Корректное завершение работы оркестратора
            if self.orchestra:
                logger.info("Завершение работы оркестратора...")
                await self.orchestra.shutdown()
                logger.info("✅ Оркестратор завершен")
                
            # Сохранение результатов демонстрации
            self.results = {
                "demo_completed_at": datetime.utcnow().isoformat(),
                "agents_created": len(self.agents),
                "tasks_submitted": len(self.tasks),
                "demo_duration": "completed_successfully"
            }
            
            logger.info("Результаты демонстрации сохранены")
            
        except Exception as e:
            logger.error(f"Ошибка при очистке: {e}")
            
    # Обработчики событий
    
    async def _on_agent_registered(self, data: Dict[str, Any]):
        """Обработчик регистрации агента"""
        logger.info(f"🔔 Событие: Агент {data['agent_id']} зарегистрирован")
        
    async def _on_task_completed(self, data: Dict[str, Any]):
        """Обработчик завершения задачи"""
        logger.info(f"🔔 Событие: Задача {data['task_id']} выполнена за {data.get('execution_time', 0):.2f}s")

# Функция для запуска демонстрации
async def run_demo():
    """Запуск полной демонстрации"""
    demo = EnhancedAgentsDemo()
    await demo.run_complete_demo()
    return demo.results

# Быстрая демонстрация отдельных возможностей
async def quick_data_processing_demo():
    """Быстрая демонстрация обработки данных"""
    logger.info("🚀 Быстрая демонстрация обработки данных")
    
    from agent_mash.core.advanced_data_processor import AdvancedDataProcessor
    
    processor = AdvancedDataProcessor()
    
    # Регистрация схемы
    schema = create_text_schema("test", min_length=1, max_length=100)
    await processor.register_schema(schema)
    
    # Тест данных
    test_data = {"message": "  Hello, World!  "}
    
    # Обработка
    result = await processor.process_data(test_data, schema_name="test")
    
    logger.info(f"Результат: {result}")
    logger.info("✅ Демонстрация обработки данных завершена")
    
    return result

async def quick_decision_demo():
    """Быстрая демонстрация принятия решений"""
    logger.info("🚀 Быстрая демонстрация принятия решений")
    
    from agent_mash.core.decision_engine import (
        AdvancedDecisionEngine, DecisionContext, RuleBasedDecisionMaker
    )
    
    engine = AdvancedDecisionEngine()
    rule_maker = RuleBasedDecisionMaker()
    
    # Добавление правила
    rule = create_simple_rule(
        "test_rule",
        lambda ctx: ctx.input_data.get("value", 0) > 5,
        "accept"
    )
    rule_maker.add_rule(rule)
    
    # Регистрация в движке
    engine.register_decision_maker("rules", rule_maker)
    
    # Тест решения
    context = DecisionContext(
        agent_id="test",
        task_type="evaluation",
        input_data={"value": 7}
    )
    
    decision = await engine.make_decision(context)
    
    logger.info(f"Решение: {decision.chosen_option.value} (уверенность: {decision.confidence})")
    logger.info("✅ Демонстрация принятия решений завершена")
    
    return decision

# Если запускается как скрипт
if __name__ == "__main__":
    
    async def main():
        """Главная функция"""
        try:
            # Выбор типа демонстрации
            print("Выберите тип демонстрации:")
            print("1. Полная демонстрация (рекомендуется)")
            print("2. Быстрая демонстрация обработки данных")
            print("3. Быстрая демонстрация принятия решений")
            
            choice = input("Ваш выбор (1-3): ").strip()
            
            if choice == "1":
                result = await run_demo()
                print(f"\nРезультаты демонстрации: {json.dumps(result, indent=2, ensure_ascii=False)}")
            elif choice == "2":
                await quick_data_processing_demo()
            elif choice == "3":
                await quick_decision_demo()
            else:
                print("Запуск полной демонстрации по умолчанию...")
                await run_demo()
                
        except KeyboardInterrupt:
            print("\nДемонстрация прервана пользователем")
        except Exception as e:
            logger.error(f"Ошибка в демонстрации: {e}")
            
    # Запуск
    asyncio.run(main())