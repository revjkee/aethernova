import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List, Dict, Any
import logging
import json

logger = logging.getLogger(__name__)

class SecurityAgent01(BaseAgent):
    """
    Агент безопасности для мониторинга системы и обнаружения угроз.
    Специализируется на анализе безопасности, мониторинге аномалий и защите системы.
    """
    
    def __init__(self, name="SecurityAgent01"):
        capabilities = [
            AgentCapability("threat_detection", "1.0", "Обнаружение угроз и аномалий в системе"),
            AgentCapability("vulnerability_scan", "1.0", "Сканирование уязвимостей системы"),
            AgentCapability("access_monitoring", "1.0", "Мониторинг доступа и авторизации"),
            AgentCapability("incident_response", "1.0", "Реагирование на инциденты безопасности"),
            AgentCapability("compliance_check", "1.0", "Проверка соответствия стандартам безопасности")
        ]
        super().__init__(name, AgentType.RULE, capabilities)
        self.name = name
        self.security_rules = {}
        self.active_threats = {}
        self.security_logs = []

    async def initialize(self) -> bool:
        """Инициализация системы безопасности"""
        try:
            logger.info(f"[{self.name}] Инициализация системы безопасности.")
            
            # Инициализация правил безопасности
            self.security_rules = {
                "max_failed_logins": 5,
                "session_timeout_minutes": 30,
                "password_min_length": 12,
                "suspicious_activity_threshold": 10,
                "admin_action_monitoring": True,
                "data_encryption_required": True
            }
            
            # Инициализация базовых настроек мониторинга
            self.config = {
                "real_time_monitoring": True,
                "alert_threshold": "medium",
                "log_retention_days": 90,
                "automated_response": True,
                "notification_channels": ["email", "slack", "sms"]
            }
            
            logger.info(f"[{self.name}] Система безопасности инициализирована. Активные правила: {len(self.security_rules)}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации системы безопасности: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка входящих сообщений безопасности"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            if task_type == "scan_vulnerabilities":
                return await self._scan_vulnerabilities(message)
            elif task_type == "detect_threats":
                return await self._detect_threats(message)
            elif task_type == "monitor_access":
                return await self._monitor_access(message)
            elif task_type == "respond_incident":
                return await self._respond_incident(message)
            elif task_type == "check_compliance":
                return await self._check_compliance(message)
            elif task_type == "security_audit":
                return await self._security_audit(message)
            else:
                logger.warning(f"[{self.name}] Неизвестный тип задачи безопасности: {task_type}")
                return self._create_error_response(message, f"Неподдерживаемый тип задачи: {task_type}")
                
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения безопасности: {e}")
            return self._create_error_response(message, str(e))

    async def _scan_vulnerabilities(self, message: AgentMessage) -> AgentMessage:
        """Сканирование уязвимостей системы"""
        payload = message.payload
        target_system = payload.get("target", "entire_system")
        scan_type = payload.get("scan_type", "comprehensive")
        
        # Симуляция сканирования уязвимостей
        vulnerabilities = [
            {
                "id": "CVE-2024-001",
                "severity": "medium",
                "component": "web_server",
                "description": "Потенциальная уязвимость в обработке HTTP заголовков",
                "recommendation": "Обновить до версии 2.4.1"
            },
            {
                "id": "SEC-2024-002",
                "severity": "low",
                "component": "database",
                "description": "Слабая конфигурация шифрования",
                "recommendation": "Увеличить длину ключа шифрования"
            },
            {
                "id": "SEC-2024-003",
                "severity": "high",
                "component": "authentication",
                "description": "Отсутствие двухфакторной аутентификации",
                "recommendation": "Внедрить 2FA для всех административных аккаунтов"
            }
        ]
        
        scan_result = {
            "scan_id": f"scan_{int(message.timestamp)}",
            "target": target_system,
            "scan_type": scan_type,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "risk_score": self._calculate_risk_score(vulnerabilities),
            "scan_completed_at": message.timestamp
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="vulnerability_scan_completed",
            payload={
                "scan_result": scan_result,
                "success": True,
                "immediate_action_required": any(v["severity"] == "high" for v in vulnerabilities)
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _detect_threats(self, message: AgentMessage) -> AgentMessage:
        """Обнаружение угроз в системе"""
        payload = message.payload
        log_data = payload.get("logs", [])
        time_window = payload.get("time_window", "1h")
        
        # Анализ логов на предмет угроз
        detected_threats = []
        
        # Симуляция обнаружения различных типов угроз
        threat_patterns = [
            {
                "threat_id": "THR-001",
                "type": "brute_force",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "description": "Обнаружена попытка брутфорса пароля",
                "attempts": 15,
                "target_account": "admin"
            },
            {
                "threat_id": "THR-002",
                "type": "suspicious_activity",
                "severity": "medium",
                "source_ip": "10.0.0.50",
                "description": "Необычная активность доступа к данным",
                "anomaly_score": 0.85
            }
        ]
        
        for threat in threat_patterns:
            if threat["severity"] == "high":
                # Автоматическое реагирование на критические угрозы
                await self._auto_respond_threat(threat)
        
        return AgentMessage(
            sender=self.name,
            task_type="threats_detected",
            payload={
                "threats": threat_patterns,
                "threat_count": len(threat_patterns),
                "analysis_window": time_window,
                "success": True,
                "auto_response_triggered": any(t["severity"] == "high" for t in threat_patterns)
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _monitor_access(self, message: AgentMessage) -> AgentMessage:
        """Мониторинг доступа к системе"""
        payload = message.payload
        user_id = payload.get("user_id")
        action = payload.get("action")
        resource = payload.get("resource")
        
        # Проверка правил доступа
        access_analysis = {
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "timestamp": message.timestamp,
            "access_granted": True,  # Базовая проверка
            "risk_level": "low",
            "additional_verification_required": False
        }
        
        # Логика проверки доступа
        if action == "admin_action" and self.security_rules["admin_action_monitoring"]:
            access_analysis["additional_verification_required"] = True
            access_analysis["risk_level"] = "medium"
        
        # Сохранение в логи безопасности
        security_event = {
            "event_type": "access_monitoring",
            "timestamp": message.timestamp,
            "details": access_analysis
        }
        self.security_logs.append(security_event)
        
        return AgentMessage(
            sender=self.name,
            task_type="access_monitored",
            payload={
                "access_analysis": access_analysis,
                "success": True
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _respond_incident(self, message: AgentMessage) -> AgentMessage:
        """Реагирование на инцидент безопасности"""
        payload = message.payload
        incident_id = payload.get("incident_id")
        incident_type = payload.get("type")
        severity = payload.get("severity", "medium")
        
        # План реагирования в зависимости от типа инцидента
        response_plan = {
            "incident_id": incident_id,
            "response_actions": [],
            "estimated_resolution_time": "2h",
            "notifications_sent": [],
            "containment_measures": []
        }
        
        if incident_type == "data_breach":
            response_plan["response_actions"] = [
                "Изоляция скомпрометированной системы",
                "Уведомление администрации",
                "Анализ масштаба утечки",
                "Активация плана восстановления"
            ]
            response_plan["containment_measures"] = ["firewall_rules", "access_revocation"]
        elif incident_type == "malware":
            response_plan["response_actions"] = [
                "Карантин зараженных систем",
                "Запуск антивирусного сканирования",
                "Восстановление из резервных копий",
                "Обновление защитных систем"
            ]
        
        return AgentMessage(
            sender=self.name,
            task_type="incident_response_initiated",
            payload={
                "incident_id": incident_id,
                "response_plan": response_plan,
                "success": True,
                "status": "in_progress"
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _check_compliance(self, message: AgentMessage) -> AgentMessage:
        """Проверка соответствия стандартам безопасности"""
        payload = message.payload
        standard = payload.get("standard", "ISO27001")
        
        compliance_check = {
            "standard": standard,
            "overall_score": 85,  # Процент соответствия
            "compliant_controls": 34,
            "total_controls": 40,
            "non_compliant_areas": [
                {
                    "control_id": "A.9.2.1",
                    "description": "Регистрация пользователей",
                    "status": "partial",
                    "required_actions": ["Автоматизация процесса регистрации"]
                },
                {
                    "control_id": "A.12.6.1",
                    "description": "Управление техническими уязвимостями",
                    "status": "non_compliant",
                    "required_actions": ["Внедрение регулярного сканирования"]
                }
            ],
            "recommendations": [
                "Усилить процедуры управления доступом",
                "Автоматизировать мониторинг безопасности",
                "Обновить политики резервного копирования"
            ]
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="compliance_checked",
            payload={
                "compliance_result": compliance_check,
                "success": True,
                "certification_ready": compliance_check["overall_score"] >= 90
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _security_audit(self, message: AgentMessage) -> AgentMessage:
        """Полный аудит безопасности системы"""
        audit_result = {
            "audit_id": f"audit_{int(message.timestamp)}",
            "audit_type": "comprehensive",
            "security_posture": {
                "overall_score": 82,
                "threat_detection": 90,
                "access_control": 85,
                "data_protection": 78,
                "incident_response": 80,
                "compliance": 85
            },
            "critical_findings": [
                "Отсутствие шифрования для некоторых баз данных",
                "Недостаточное логирование административных действий"
            ],
            "recommendations": [
                "Внедрить end-to-end шифрование",
                "Усилить мониторинг привилегированных аккаунтов",
                "Автоматизировать реагирование на инциденты"
            ],
            "next_audit_recommended": "3 months"
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="security_audit_completed",
            payload={
                "audit_result": audit_result,
                "success": True
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _auto_respond_threat(self, threat: Dict[str, Any]) -> None:
        """Автоматическое реагирование на угрозу"""
        threat_id = threat.get("threat_id")
        threat_type = threat.get("type")
        
        if threat_type == "brute_force":
            # Блокировка IP-адреса
            source_ip = threat.get("source_ip")
            logger.warning(f"[{self.name}] Автоблокировка IP {source_ip} из-за брутфорса")
            
        # Добавление в список активных угроз
        self.active_threats[threat_id] = {
            **threat,
            "response_time": 30,  # секунды
            "status": "contained"
        }

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Расчет общего балла риска"""
        severity_weights = {"low": 1, "medium": 5, "high": 10, "critical": 20}
        total_score = sum(severity_weights.get(v["severity"], 0) for v in vulnerabilities)
        return min(total_score, 100)  # Максимум 100 баллов

    async def shutdown(self) -> bool:
        """Корректное завершение работы агента безопасности"""
        try:
            logger.info(f"[{self.name}] Завершение работы агента безопасности.")
            
            # Сохранение логов безопасности
            if self.security_logs:
                logger.info(f"[{self.name}] Сохранение {len(self.security_logs)} записей логов безопасности")
            
            # Закрытие активных мониторингов угроз
            if self.active_threats:
                logger.info(f"[{self.name}] Закрытие мониторинга {len(self.active_threats)} активных угроз")
            
            # Очистка данных
            self.security_logs.clear()
            self.active_threats.clear()
            
            logger.info(f"[{self.name}] Агент безопасности успешно завершил работу")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка при завершении работы агента безопасности: {e}")
            return False

    def _create_error_response(self, original_message: AgentMessage, error_msg: str) -> AgentMessage:
        """Создание сообщения об ошибке"""
        return AgentMessage(
            sender=self.name,
            task_type="security_error",
            payload={
                "success": False,
                "error": error_msg,
                "original_task": original_message.task_type
            },
            correlation_id=original_message.correlation_id,
            reply_to=original_message.sender
        )