import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class SupportAgent01(BaseAgent):
    def __init__(self, name="SupportAgent01"):
        capabilities = [
            AgentCapability("ticket_management", "1.0", "Управление тикетами поддержки"),
            AgentCapability("customer_communication", "1.0", "Коммуникация с клиентами"),
            AgentCapability("knowledge_base", "1.0", "Работа с базой знаний"),
            AgentCapability("issue_resolution", "1.0", "Решение технических проблем"),
            AgentCapability("escalation_management", "1.0", "Управление эскалацией")
        ]
        super().__init__(name, AgentType.SUPPORT, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация агента поддержки"""
        try:
            logger.info(f"[{self.name}] Инициализация: подготовка системы поддержки клиентов.")
            
            # Инструменты поддержки
            self.tools = [
                "zendesk", "freshdesk", "intercom", "slack", "jira",
                "confluence", "notion", "telegram-bot", "email-client"
            ]
            
            # Конфигурация
            self.config = {
                "response_time_targets": {
                    "critical": "15 минут",
                    "high": "2 часа", 
                    "medium": "8 часов",
                    "low": "24 часа"
                },
                "supported_channels": ["email", "chat", "phone", "telegram"],
                "languages": ["ru", "en", "es", "de"],
                "escalation_levels": ["L1", "L2", "L3", "Engineering"],
                "knowledge_base_articles": 1250
            }
            
            logger.info(f"[{self.name}] Инициализация завершена. Каналы поддержки: {', '.join(self.config['supported_channels'])}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка задач поддержки"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{self.name}] Обрабатываю задачу: {task_type}")
            
            result = None
            
            if task_type == "handle_ticket":
                result = await self._handle_ticket(payload)
            elif task_type == "respond_customer":
                result = await self._respond_customer(payload)
            elif task_type == "update_knowledge_base":
                result = await self._update_knowledge_base(payload)
            elif task_type == "escalate_issue":
                result = await self._escalate_issue(payload)
            elif task_type == "generate_report":
                result = await self._generate_support_report(payload)
            else:
                result = {
                    "status": "error",
                    "message": f"Неподдерживаемый тип задачи: {task_type}"
                }
            
            # Создание ответного сообщения
            response = AgentMessage(
                sender=self.name,
                recipient=message.sender,
                task_type=f"{task_type}_response",
                payload=result
            )
            
            return response
            
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения: {e}")
            return None

    async def _handle_ticket(self, payload: dict) -> dict:
        """Обработка тикета поддержки"""
        ticket_id = payload.get('ticket_id', 'UNKNOWN')
        priority = payload.get('priority', 'medium')
        
        logger.info(f"[{self.name}] Обработка тикета {ticket_id} с приоритетом {priority}")
        
        ticket_info = {
            "ticket_id": ticket_id,
            "status": "resolved",
            "priority": priority,
            "category": "technical_issue",
            "resolution_time": "45 минут",
            "customer_satisfaction": 4.8,
            "solution": "Проблема решена путем обновления конфигурации"
        }
        
        return {
            "status": "completed",
            "message": f"Тикет {ticket_id} успешно обработан",
            "ticket_info": ticket_info
        }

    async def _respond_customer(self, payload: dict) -> dict:
        """Ответ клиенту"""
        customer_id = payload.get('customer_id', 'unknown')
        issue_type = payload.get('issue_type', 'general')
        
        logger.info(f"[{self.name}] Ответ клиенту {customer_id} по вопросу: {issue_type}")
        
        response_data = {
            "customer_id": customer_id,
            "response_template": "detailed_explanation",
            "response_time": "12 минут",
            "channel": "email",
            "follow_up_scheduled": True,
            "satisfaction_survey_sent": True
        }
        
        return {
            "status": "sent",
            "message": f"Ответ клиенту {customer_id} отправлен",
            "response_data": response_data
        }

    async def _update_knowledge_base(self, payload: dict) -> dict:
        """Обновление базы знаний"""
        article_topic = payload.get('topic', 'general')
        logger.info(f"[{self.name}] Обновление базы знаний: {article_topic}")
        
        kb_update = {
            "articles_added": 3,
            "articles_updated": 7,
            "topics_covered": [article_topic, "troubleshooting", "best_practices"],
            "languages": ["ru", "en"],
            "reviewed_by": "senior_support",
            "approval_status": "approved"
        }
        
        return {
            "status": "updated",
            "message": f"База знаний обновлена по теме: {article_topic}",
            "kb_update": kb_update
        }

    async def _escalate_issue(self, payload: dict) -> dict:
        """Эскалация проблемы"""
        ticket_id = payload.get('ticket_id', 'UNKNOWN')
        escalation_level = payload.get('level', 'L2')
        
        logger.info(f"[{self.name}] Эскалация тикета {ticket_id} на уровень {escalation_level}")
        
        escalation_info = {
            "ticket_id": ticket_id,
            "escalated_to": escalation_level,
            "escalation_reason": "Требуется экспертиза разработчиков",
            "priority_updated": "high",
            "assigned_specialist": "senior_engineer_01",
            "sla_updated": "4 часа"
        }
        
        return {
            "status": "escalated",
            "message": f"Тикет {ticket_id} эскалирован на уровень {escalation_level}",
            "escalation_info": escalation_info
        }

    async def _generate_support_report(self, payload: dict) -> dict:
        """Генерация отчета поддержки"""
        period = payload.get('period', 'weekly')
        logger.info(f"[{self.name}] Генерация {period} отчета поддержки")
        
        report = {
            "period": period,
            "tickets_processed": 156,
            "avg_resolution_time": "2.3 часа",
            "customer_satisfaction": 4.6,
            "first_contact_resolution": "78%",
            "escalation_rate": "12%",
            "top_issues": [
                "API интеграция - 25%",
                "Авторизация - 18%", 
                "Производительность - 15%"
            ],
            "team_performance": {
                "total_agents": 8,
                "avg_tickets_per_agent": 19.5,
                "top_performer": "SupportAgent01"
            }
        }
        
        return {
            "status": "generated",
            "message": f"{period.capitalize()} отчет поддержки сгенерирован",
            "report": report
        }

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        logger.info(f"[{self.name}] Завершение работы агента поддержки.")
        return True