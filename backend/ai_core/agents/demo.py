#!/usr/bin/env python3
"""
Демонстрация использования AI Core Agent System

Этот файл показывает основные возможности системы агентов:
- Инициализация системы
- Отправка задач различным агентам
- Мониторинг статуса
- Управление жизненным циклом
"""

import asyncio
import logging
from typing import Dict, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from backend.ai_core.agents import (
    agent_system, 
    Priority,
    config_manager,
    agent_monitor,
    notification_manager
)

async def demo_system_initialization():
    """Демонстрация инициализации системы"""
    print("=== Инициализация AI Core Agent System ===")
    
    # Проверка конфигурации
    system_config = config_manager.get_system_config()
    print(f"Система: {system_config.name} v{system_config.version}")
    print(f"Окружение: {system_config.environment}")
    
    # Инициализация
    await agent_system.initialize()
    
    # Проверка статуса
    status = await agent_system.get_system_status()
    print(f"Статус системы: {status}")
    
    return True

async def demo_architecture_design():
    """Демонстрация проектирования архитектуры"""
    print("\n=== Демонстрация проектирования архитектуры ===")
    
    # Задача для архитектора
    architecture_task = {
        "name": "E-commerce Platform",
        "functional_requirements": [
            "User authentication and authorization",
            "Product catalog management", 
            "Shopping cart functionality",
            "Payment processing",
            "Order management",
            "Inventory tracking"
        ],
        "non_functional_requirements": {
            "scalability": "Support 10,000 concurrent users",
            "performance": "Response time < 200ms",
            "availability": "99.9% uptime",
            "security": "PCI DSS compliance"
        },
        "constraints": {
            "budget": "medium",
            "timeline": "6 months",
            "team_size": "8 developers"
        }
    }
    
    try:
        result = await agent_system.submit_task(
            task_type="design_system",
            data=architecture_task,
            priority=Priority.HIGH
        )
        
        print("Результат проектирования архитектуры:")
        print(f"- ID дизайна: {result.get('design_id')}")
        print(f"- Архитектурный паттерн: {result.get('architecture_pattern')}")
        print(f"- Количество компонентов: {result.get('components_count')}")
        print(f"- Оценка сложности: {result.get('estimated_complexity')}")
        print(f"- Рекомендации: {result.get('recommendations')}")
        
        return result
        
    except Exception as e:
        print(f"Ошибка при проектировании: {e}")
        return None

async def demo_code_generation():
    """Демонстрация генерации кода"""
    print("\n=== Демонстрация генерации кода ===")
    
    # Задача для разработчика
    code_task = {
        "language": "python",
        "module_name": "user_authentication",
        "requirements": [
            "Create User model with email, password, and profile fields",
            "Implement password hashing using bcrypt",
            "Add JWT token generation and validation",
            "Include login and logout functionality",
            "Add password reset mechanism"
        ],
        "pattern": "mvc"
    }
    
    try:
        result = await agent_system.submit_task(
            task_type="generate_code",
            data=code_task,
            priority=Priority.MEDIUM
        )
        
        print("Результат генерации кода:")
        print(f"- ID модуля: {result.get('module_id')}")
        print(f"- Строк кода: {result.get('code_metrics', {}).get('lines_of_code')}")
        print(f"- Оценка сложности: {result.get('code_metrics', {}).get('complexity_score')}")
        print(f"- Количество зависимостей: {result.get('code_metrics', {}).get('dependencies_count')}")
        print(f"- Рекомендации: {result.get('recommendations')}")
        
        return result
        
    except Exception as e:
        print(f"Ошибка при генерации кода: {e}")
        return None

async def demo_code_review():
    """Демонстрация ревью кода"""
    print("\n=== Демонстрация ревью кода ===")
    
    # Пример кода для ревью
    sample_code = '''
def authenticate_user(email, password):
    user = User.objects.get(email=email)
    if user and check_password(password, user.password_hash):
        token = generate_jwt_token(user.id)
        return {"success": True, "token": token}
    return {"success": False, "error": "Invalid credentials"}

class UserManager:
    def create_user(self, email, password, profile_data=None):
        if not self.validate_email(email):
            raise ValueError("Invalid email format")
        
        password_hash = hash_password(password)
        user = User(email=email, password_hash=password_hash)
        
        if profile_data:
            user.profile = UserProfile(**profile_data)
            
        user.save()
        return user
'''
    
    review_task = {
        "file_path": "src/auth/user_manager.py",
        "code": sample_code,
        "language": "python",
        "type": "comprehensive"
    }
    
    try:
        result = await agent_system.submit_task(
            task_type="review_code",
            data=review_task,
            priority=Priority.MEDIUM
        )
        
        print("Результат ревью кода:")
        print(f"- ID ревью: {result.get('review_id')}")
        print(f"- Общая оценка: {result.get('overall_score')}/10")
        print(f"- Одобрено: {'Да' if result.get('approved') else 'Нет'}")
        print(f"- Всего комментариев: {result.get('total_comments')}")
        
        comments_by_severity = result.get('comments_by_severity', {})
        print("Комментарии по важности:")
        for severity, count in comments_by_severity.items():
            print(f"  - {severity}: {count}")
            
        print(f"- Краткое описание: {result.get('summary')}")
        print(f"- Рекомендации: {result.get('recommendations')}")
        
        return result
        
    except Exception as e:
        print(f"Ошибка при ревью кода: {e}")
        return None

async def demo_test_creation():
    """Демонстрация создания тестов"""
    print("\n=== Демонстрация создания тестов ===")
    
    test_task = {
        "module_name": "user_authentication",
        "test_types": ["unit", "integration"],
        "code": '''
class UserAuth:
    def authenticate(self, email, password):
        # Authentication logic
        pass
    
    def generate_token(self, user_id):
        # Token generation logic  
        pass
''',
        "requirements": [
            "Test successful authentication",
            "Test failed authentication with wrong password",
            "Test failed authentication with non-existent user",
            "Test token generation and validation",
            "Test token expiration"
        ]
    }
    
    try:
        result = await agent_system.submit_task(
            task_type="create_tests",
            data=test_task,
            priority=Priority.MEDIUM
        )
        
        print("Результат создания тестов:")
        print(f"- ID тест-сьюта: {result.get('suite_id')}")
        print(f"- Создано тестов: {result.get('tests_created')}")
        print(f"- Типы тестов: {', '.join(result.get('test_types', []))}")
        print(f"- Ожидаемое время выполнения: {result.get('estimated_execution_time')} сек")
        
        test_cases = result.get('test_cases', [])
        print("Созданные тест-кейсы:")
        for test_case in test_cases[:3]:  # Показываем первые 3
            print(f"  - {test_case.get('name')}: {test_case.get('description')}")
            
        print(f"- Рекомендации: {result.get('recommendations')}")
        
        return result
        
    except Exception as e:
        print(f"Ошибка при создании тестов: {e}")
        return None

async def demo_system_monitoring():
    """Демонстрация мониторинга системы"""
    print("\n=== Мониторинг системы ===")
    
    # Получение статуса системы
    status = await agent_system.get_system_status()
    print("Текущий статус системы:")
    for key, value in status.items():
        if key == "monitoring":
            print(f"- {key}:")
            for sub_key, sub_value in value.items():
                print(f"  - {sub_key}: {sub_value}")
        else:
            print(f"- {key}: {value}")
    
    # Получение детального обзора мониторинга
    print(f"\n=== Детальный мониторинг ===")
    overview = await agent_monitor.get_system_overview()
    print(f"📊 Обзор системы:")
    print(f"- Всего агентов: {overview['total_agents']}")
    print(f"- Здоровых агентов: {overview['healthy_agents']}")
    print(f"- Проблемных агентов: {overview['unhealthy_agents']}")
    print(f"- Активных алертов: {overview['active_alerts']}")
    print(f"- Критических алертов: {overview['critical_alerts']}")
    print(f"- Предупреждений: {overview['warning_alerts']}")
    print(f"- Состояние системы: {overview['system_status']}")
    
    # Получение здоровья всех агентов
    print(f"\n🏥 Здоровье агентов:")
    all_health = await agent_monitor.get_all_agents_health()
    for agent_id, health in all_health.items():
        status_icon = "✅" if health.is_healthy else "❌" if health.status == "critical" else "⚠️"
        print(f"{status_icon} {agent_id}: {health.status}")
        if health.issues:
            for issue in health.issues:
                print(f"    - Проблема: {issue}")
        if health.recommendations:
            for rec in health.recommendations:
                print(f"    - Рекомендация: {rec}")
    
    # Получение активных алертов
    print(f"\n🚨 Активные алерты:")
    alerts = await agent_monitor.get_active_alerts()
    if not alerts:
        print("✅ Нет активных алертов")
    else:
        for alert in alerts:
            severity_icon = "🔴" if alert.severity == "critical" else "🟡" if alert.severity == "warning" else "ℹ️"
            print(f"{severity_icon} [{alert.severity.upper()}] {alert.agent_id}: {alert.message}")
            print(f"    Время: {alert.triggered_at.strftime('%H:%M:%S')}")
    
    # Статистика уведомлений
    print(f"\n📢 Система уведомлений:")
    channels = await notification_manager.get_channels()
    enabled_channels = [c for c in channels if c.enabled]
    print(f"- Всего каналов: {len(channels)}")
    print(f"- Активных каналов: {len(enabled_channels)}")
    for channel in enabled_channels:
        print(f"  - {channel.name} ({channel.type}): {', '.join(channel.severity_filter)}")
    
    # Получение статуса через API (симуляция)
    try:
        from backend.ai_core.agents.api.router import get_system_status
        api_status = await get_system_status()
        
        print(f"\n🔌 Статус через API:")
        print(f"- Всего агентов: {api_status.total_agents}")
        print(f"- Активных агентов: {api_status.active_agents}")
        print(f"- Обработано задач: {api_status.total_tasks_processed}")
        print(f"- Размер очереди: {api_status.current_queue_size}")
        print(f"- Здоровье системы: {api_status.system_health}")
        
    except Exception as e:
        print(f"Ошибка получения статуса API: {e}")

async def main():
    """Главная функция демонстрации"""
    print("🤖 Добро пожаловать в демонстрацию AI Core Agent System!")
    
    try:
        # 1. Инициализация системы
        await demo_system_initialization()
        
        # 2. Демонстрация различных возможностей
        await demo_architecture_design()
        await demo_code_generation()
        await demo_code_review()
        await demo_test_creation()
        
        # 3. Мониторинг системы
        await demo_system_monitoring()
        
        print("\n✅ Демонстрация завершена успешно!")
        
    except KeyboardInterrupt:
        print("\n⏹️ Демонстрация прервана пользователем")
        
    except Exception as e:
        print(f"\n❌ Ошибка во время демонстрации: {e}")
        
    finally:
        # Завершение работы системы
        print("\n🔄 Завершение работы системы агентов...")
        await agent_system.shutdown()
        print("👋 До свидания!")

if __name__ == "__main__":
    # Запуск демонстрации
    asyncio.run(main())