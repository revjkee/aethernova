import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class DevelopmentAgent01(BaseAgent):
    def __init__(self, name="DevelopmentAgent01"):
        capabilities = [
            AgentCapability("code_generation", "1.0", "Генерация кода на Python, JavaScript, TypeScript"),
            AgentCapability("code_review", "1.0", "Проверка кода на качество и соответствие стандартам"),
            AgentCapability("testing", "1.0", "Создание и выполнение тестов"),
            AgentCapability("refactoring", "1.0", "Рефакторинг и оптимизация кода"),
            AgentCapability("documentation", "1.0", "Создание и обновление документации")
        ]
        super().__init__(name, AgentType.LLM, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация среды разработки и инструментов"""
        try:
            logger.info(f"[{self.name}] Инициализация среды разработки и инструментов.")
            
            # Инициализация инструментов разработки
            self.tools = [
                "git", "pytest", "flake8", "black", "mypy", 
                "docker", "npm", "yarn", "eslint", "prettier"
            ]
            
            # Проверка доступности инструментов (симуляция)
            self.config = {
                "max_concurrent_tasks": 5,
                "supported_languages": ["python", "javascript", "typescript", "bash"],
                "code_quality_threshold": 0.8,
                "test_coverage_threshold": 80
            }
            
            logger.info(f"[{self.name}] Инициализация завершена успешно. Доступные инструменты: {', '.join(self.tools)}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка задач разработки"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{self.name}] Обрабатываю задачу: {task_type}")
            
            result = None
            
            if task_type == "code_generation":
                result = await self._generate_code(payload)
            elif task_type == "code_review":
                result = await self._review_code(payload)
            elif task_type == "testing":
                result = await self._run_tests(payload)
            elif task_type == "refactoring":
                result = await self._refactor_code(payload)
            elif task_type == "documentation":
                result = await self._generate_docs(payload)
            else:
                result = {
                    "status": "error",
                    "message": f"Неподдерживаемый тип задачи: {task_type}"
                }
            
            # Создание ответного сообщения
            if result:
                return message.create_reply(result, self.agent_id)
            
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения: {e}")
            return message.create_reply({
                "status": "error", 
                "message": str(e)
            }, self.agent_id)
        
        return None

    async def _generate_code(self, payload):
        """Генерация кода"""
        language = payload.get("language", "python")
        requirements = payload.get("requirements", "")
        
        # Симуляция генерации кода
        code = f"""
# Генерированный код на {language}
# Требования: {requirements}

def generated_function():
    \"\"\"Автоматически сгенерированная функция\"\"\"
    return "Hello from {self.name}!"

if __name__ == "__main__":
    print(generated_function())
"""
        
        return {
            "status": "success",
            "code": code.strip(),
            "language": language,
            "quality_score": 0.85
        }

    async def _review_code(self, payload):
        """Проверка кода"""
        code = payload.get("code", "")
        
        # Симуляция анализа кода
        issues = [
            {"line": 5, "type": "style", "message": "Используйте snake_case для имен функций"},
            {"line": 12, "type": "performance", "message": "Рассмотрите использование list comprehension"}
        ]
        
        return {
            "status": "success",
            "issues": issues,
            "quality_score": 0.75,
            "recommendations": ["Добавить документацию", "Покрыть тестами"]
        }

    async def _run_tests(self, payload):
        """Выполнение тестов"""
        test_type = payload.get("test_type", "unit")
        
        return {
            "status": "success",
            "test_type": test_type,
            "passed": 42,
            "failed": 3,
            "coverage": 87.5,
            "duration": 15.3
        }

    async def _refactor_code(self, payload):
        """Рефакторинг кода"""
        code = payload.get("code", "")
        
        return {
            "status": "success",
            "refactored_code": f"# Рефакторенный код\n{code}",
            "improvements": [
                "Улучшена читаемость",
                "Сокращена сложность",
                "Добавлена типизация"
            ],
            "quality_improvement": 0.15
        }

    async def _generate_docs(self, payload):
        """Генерация документации"""
        code = payload.get("code", "")
        doc_type = payload.get("doc_type", "api")
        
        return {
            "status": "success",
            "documentation": f"# Документация ({doc_type})\n\nАвто-сгенерированная документация для кода.",
            "format": "markdown",
            "sections": ["Описание", "API", "Примеры", "Установка"]
        }

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        try:
            logger.info(f"[{self.name}] Завершение работы, сохранение прогресса.")
            
            # Сохранение состояния и очистка ресурсов
            self.tools.clear()
            self.config.clear()
            
            logger.info(f"[{self.name}] Корректно завершен.")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка при завершении: {e}")
            return False
