#!/usr/bin/env python3
"""
Тест межагентного взаимодействия для системы AetherNova
Демонстрирует работу различных типов агентов и их коммуникацию через AgentBus
"""

import sys
import os
import asyncio
import time
sys.path.append('/workspaces/aethernova')

from agent_mash.core.agent_message import AgentMessage
from agents.development_01.agent import DevelopmentAgent01
from agents.planning_01.src.agent import PlanningAgent01
from agents.security_01.agent import SecurityAgent01
from agents.research_01.agent import ResearchAgent01

async def test_individual_agents():
    """Тестирование каждого агента по отдельности"""
    print("=== Тестирование индивидуальных агентов ===\n")
    
    # Инициализация агентов
    agents = {
        'development': DevelopmentAgent01(),
        'planning': PlanningAgent01(),
        'security': SecurityAgent01(),
        'research': ResearchAgent01()
    }
    
    # Инициализация всех агентов
    for name, agent in agents.items():
        success = await agent.initialize()
        print(f"{'✅' if success else '❌'} {name.title()}Agent инициализирован: {success}")
    
    print()
    
    # Тестирование различных типов задач
    test_cases = [
        {
            'agent': 'development',
            'message': AgentMessage(
                sender="test_system",
                task_type="generate_code",
                payload={
                    "language": "python",
                    "description": "Создать функцию для сортировки списка",
                    "requirements": ["использовать quicksort", "добавить тесты"]
                }
            )
        },
        {
            'agent': 'planning',
            'message': AgentMessage(
                sender="test_system",
                task_type="create_project_plan",
                payload={
                    "project_name": "AI Assistant Development",
                    "requirements": ["NLP processing", "API integration", "User interface"],
                    "deadline": "2024-12-31"
                }
            )
        },
        {
            'agent': 'security',
            'message': AgentMessage(
                sender="test_system",
                task_type="scan_vulnerabilities",
                payload={
                    "target": "web_application",
                    "scan_type": "comprehensive"
                }
            )
        },
        {
            'agent': 'research',
            'message': AgentMessage(
                sender="test_system",
                task_type="analyze_data",
                payload={
                    "dataset": "user_behavior_data",
                    "analysis_type": "statistical",
                    "data": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 25]
                }
            )
        }
    ]
    
    # Выполнение тестовых задач
    for i, test_case in enumerate(test_cases, 1):
        agent_name = test_case['agent']
        message = test_case['message']
        agent = agents[agent_name]
        
        print(f"{i}. Тестирование {agent_name}Agent:")
        print(f"   Задача: {message.task_type}")
        
        try:
            start_time = time.time()
            response = await agent.process_message(message)
            end_time = time.time()
            
            if response and response.payload.get('success', False):
                print(f"   ✅ Успешно выполнено за {end_time - start_time:.2f}с")
                if 'message' in response.payload:
                    print(f"   📝 {response.payload['message']}")
            else:
                print(f"   ❌ Ошибка: {response.payload.get('error', 'Unknown error') if response else 'No response'}")
                
        except Exception as e:
            print(f"   ❌ Исключение: {e}")
        
        print()
    
    # Завершение работы агентов
    print("=== Завершение работы агентов ===")
    for name, agent in agents.items():
        success = await agent.shutdown()
        print(f"{'✅' if success else '❌'} {name.title()}Agent завершен: {success}")

async def test_agent_collaboration():
    """Тестирование совместной работы агентов"""
    print("\n=== Тестирование совместной работы агентов ===\n")
    
    # Создание агентов
    planning_agent = PlanningAgent01()
    security_agent = SecurityAgent01()
    research_agent = ResearchAgent01()
    
    # Инициализация
    await planning_agent.initialize()
    await security_agent.initialize()
    await research_agent.initialize()
    
    print("Сценарий: Создание нового проекта с проверкой безопасности и анализом данных\n")
    
    # Шаг 1: Планирование проекта
    print("1. Создание плана проекта...")
    plan_message = AgentMessage(
        sender="coordinator",
        task_type="create_project_plan",
        payload={
            "project_name": "Secure Data Analytics Platform",
            "requirements": ["Data processing", "Security compliance", "User dashboard"],
            "deadline": "2024-06-01"
        }
    )
    
    plan_response = await planning_agent.process_message(plan_message)
    if plan_response and plan_response.payload.get('success'):
        project_id = plan_response.payload.get('project_id')
        print(f"   ✅ План создан: {project_id}")
        
        # Шаг 2: Анализ безопасности проекта
        print("2. Проведение анализа безопасности...")
        security_message = AgentMessage(
            sender="coordinator",
            task_type="check_compliance",
            payload={
                "standard": "ISO27001",
                "project_id": project_id
            }
        )
        
        security_response = await security_agent.process_message(security_message)
        if security_response and security_response.payload.get('success'):
            compliance_score = security_response.payload['compliance_result']['overall_score']
            print(f"   ✅ Анализ безопасности завершен. Соответствие: {compliance_score}%")
            
            # Шаг 3: Исследование требований
            print("3. Исследовательский анализ...")
            research_message = AgentMessage(
                sender="coordinator",
                task_type="literature_review",
                payload={
                    "topic": "secure data analytics platforms",
                    "keywords": ["data security", "analytics", "compliance"],
                    "time_range": "last_3_years"
                }
            )
            
            research_response = await research_agent.process_message(research_message)
            if research_response and research_response.payload.get('success'):
                papers_count = research_response.payload['literature_review']['results']['papers_included']
                print(f"   ✅ Исследование завершено. Проанализировано {papers_count} статей")
                
                print("\n🎉 Совместная работа агентов успешно завершена!")
                print("   - План проекта создан")
                print(f"   - Соответствие требованиям безопасности: {compliance_score}%")
                print(f"   - Исследовательская база: {papers_count} источников")
            else:
                print("   ❌ Ошибка в исследовательском анализе")
        else:
            print("   ❌ Ошибка в анализе безопасности")
    else:
        print("   ❌ Ошибка при создании плана")
    
    # Завершение работы
    await planning_agent.shutdown()
    await security_agent.shutdown() 
    await research_agent.shutdown()

def test_message_system():
    """Тестирование системы сообщений"""
    print("\n=== Тестирование системы сообщений ===\n")
    
    # Создание тестового сообщения
    test_message = AgentMessage(
        sender="test_sender",
        task_type="test_task",
        payload={"data": "test_data", "number": 42},
        priority=1
    )
    
    print(f"Создано сообщение:")
    print(f"  ID: {test_message.message_id}")
    print(f"  Отправитель: {test_message.sender}")
    print(f"  Тип задачи: {test_message.task_type}")
    print(f"  Данные: {test_message.payload}")
    print(f"  Приоритет: {test_message.priority}")
    print(f"  Время: {test_message.timestamp}")
    
    # Сериализация
    message_dict = test_message.to_dict()
    print(f"\nСериализация успешна: {len(message_dict)} полей")
    
    # Проверка обязательных полей
    required_fields = ['message_id', 'sender', 'task_type', 'payload', 'timestamp']
    missing_fields = [field for field in required_fields if field not in message_dict]
    
    if not missing_fields:
        print("✅ Все обязательные поля присутствуют")
    else:
        print(f"❌ Отсутствуют поля: {missing_fields}")

async def main():
    """Главная функция тестирования"""
    print("🤖 Тестирование агентной системы AetherNova\n")
    
    # Тест системы сообщений
    test_message_system()
    
    # Тест индивидуальных агентов
    await test_individual_agents()
    
    # Тест совместной работы
    await test_agent_collaboration()
    
    print("\n🏁 Тестирование завершено!")

if __name__ == "__main__":
    asyncio.run(main())