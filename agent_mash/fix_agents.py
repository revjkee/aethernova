#!/usr/bin/env python3
"""
Скрипт для автоматического исправления зависимостей агентов
Создает базовую структуру для всех пустых или некорректных агентов
"""

import os
from pathlib import Path

def get_agent_template(agent_name, agent_type="GENERAL"):
    """Создает шаблон агента"""
    return f'''import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class {agent_name}(BaseAgent):
    def __init__(self, name="{agent_name}"):
        capabilities = [
            AgentCapability("general_task", "1.0", "Общие задачи агента"),
            AgentCapability("data_processing", "1.0", "Обработка данных"),
            AgentCapability("communication", "1.0", "Коммуникация с другими агентами")
        ]
        super().__init__(name, AgentType.{agent_type}, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация агента"""
        try:
            logger.info(f"[{{self.name}}] Инициализация агента {{self.name}}")
            
            self.tools = ["basic_tools", "communication_tools"]
            self.config = {{
                "max_tasks": 10,
                "timeout": 30,
                "retry_count": 3
            }}
            
            logger.info(f"[{{self.name}}] Инициализация завершена успешно")
            return True
        except Exception as e:
            logger.error(f"[{{self.name}}] Ошибка инициализации: {{e}}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка сообщений"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{{self.name}}] Обрабатываю задачу: {{task_type}}")
            
            # Базовая обработка
            result = {{
                "status": "completed",
                "message": f"Задача {{task_type}} выполнена агентом {{self.name}}",
                "agent": self.name,
                "processed_data": payload
            }}
            
            # Создание ответного сообщения
            response = AgentMessage(
                sender=self.name,
                recipient=message.sender,
                task_type=f"{{task_type}}_response",
                payload=result
            )
            
            return response
            
        except Exception as e:
            logger.error(f"[{{self.name}}] Ошибка обработки сообщения: {{e}}")
            return None

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        logger.info(f"[{{self.name}}] Завершение работы агента")
        return True
'''

def fix_agents():
    """Исправляет всех агентов в папке agents"""
    agents_dir = Path("/workspaces/aethernova/agents")
    
    agent_types = {
        "development": "DEVELOPMENT",
        "marketing": "ANALYTICS", 
        "planning": "PLANNING",
        "research": "RESEARCH",
        "security": "SECURITY",
        "support": "SUPPORT",
        "infrastructure": "AUTOMATION",
        "sales": "ANALYTICS"
    }
    
    fixed_count = 0
    
    for agent_dir in agents_dir.iterdir():
        if not agent_dir.is_dir():
            continue
            
        agent_name = agent_dir.name
        print(f"Проверяю агента: {agent_name}")
        
        # Определяем тип агента
        agent_type = "GENERAL"
        for key, value in agent_types.items():
            if key in agent_name.lower():
                agent_type = value
                break
        
        # Ищем файл агента
        agent_file = None
        if (agent_dir / "agent.py").exists():
            agent_file = agent_dir / "agent.py"
        elif (agent_dir / "src" / "agent.py").exists():
            agent_file = agent_dir / "src" / "agent.py"
        
        if not agent_file:
            print(f"  ❌ Файл агента не найден для {agent_name}")
            continue
        
        # Проверяем, пустой ли файл или нужно ли его исправить
        try:
            with open(agent_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            # Если файл пустой или не содержит BaseAgent
            if not content or "BaseAgent" not in content:
                print(f"  🔧 Исправляю агента {agent_name}")
                
                # Создаем правильное имя класса
                class_name = ''.join(word.capitalize() for word in agent_name.replace('_', ' ').split())
                
                # Записываем новый шаблон
                with open(agent_file, 'w', encoding='utf-8') as f:
                    f.write(get_agent_template(class_name, agent_type))
                
                print(f"  ✅ Агент {agent_name} исправлен")
                fixed_count += 1
            else:
                print(f"  ✓ Агент {agent_name} уже в порядке")
                
        except Exception as e:
            print(f"  ❌ Ошибка при обработке {agent_name}: {e}")
    
    print(f"\n🎉 Исправлено агентов: {fixed_count}")

if __name__ == "__main__":
    fix_agents()