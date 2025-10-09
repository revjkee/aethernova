import yaml
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class SystemConfig:
    name: str
    version: str
    environment: str

@dataclass
class MessageBusConfig:
    type: str
    connection_url: str
    heartbeat: int
    connection_attempts: int
    retry_delay: int
    default_queue: str
    priority_queue: str
    monitoring_queue: str

@dataclass
class RegistryConfig:
    max_agents: int
    health_check_interval: int
    task_timeout: int
    max_retries: int
    load_balancing_strategy: str
    enable_sticky_sessions: bool

@dataclass
class AgentRoleConfig:
    enabled: bool
    instances: int
    auto_start: bool
    capabilities: list
    config: Dict[str, Any]

class ConfigManager:
    """Менеджер конфигурации для системы агентов"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), "agents.yaml")
            
        self.config_path = Path(config_path)
        self.config_data = {}
        self.load_config()
        
    def load_config(self) -> None:
        """Загрузка конфигурации из YAML файла"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as file:
                    self.config_data = yaml.safe_load(file)
            else:
                raise FileNotFoundError(f"Config file not found: {self.config_path}")
                
        except Exception as e:
            raise RuntimeError(f"Failed to load config: {e}")
            
    def save_config(self) -> None:
        """Сохранение конфигурации в YAML файл"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config_data, file, default_flow_style=False, allow_unicode=True)
                
        except Exception as e:
            raise RuntimeError(f"Failed to save config: {e}")
            
    def get_system_config(self) -> SystemConfig:
        """Получение конфигурации системы"""
        system = self.config_data.get("system", {})
        return SystemConfig(
            name=system.get("name", "AI Core Agent System"),
            version=system.get("version", "1.0.0"),
            environment=system.get("environment", "development")
        )
        
    def get_message_bus_config(self) -> MessageBusConfig:
        """Получение конфигурации системы сообщений"""
        mb_config = self.config_data.get("message_bus", {})
        connection = mb_config.get("connection", {})
        queues = mb_config.get("queues", {})
        
        return MessageBusConfig(
            type=mb_config.get("type", "in_memory"),
            connection_url=connection.get("url", "amqp://guest:guest@localhost:5672/"),
            heartbeat=connection.get("heartbeat", 600),
            connection_attempts=connection.get("connection_attempts", 3),
            retry_delay=connection.get("retry_delay", 5),
            default_queue=queues.get("default_queue", "agent_tasks"),
            priority_queue=queues.get("priority_queue", "priority_tasks"),
            monitoring_queue=queues.get("monitoring_queue", "monitoring_events")
        )
        
    def get_registry_config(self) -> RegistryConfig:
        """Получение конфигурации реестра агентов"""
        registry = self.config_data.get("registry", {})
        lb_config = registry.get("load_balancing", {})
        
        return RegistryConfig(
            max_agents=registry.get("max_agents", 100),
            health_check_interval=registry.get("health_check_interval", 30),
            task_timeout=registry.get("task_timeout", 300),
            max_retries=registry.get("max_retries", 3),
            load_balancing_strategy=lb_config.get("strategy", "round_robin"),
            enable_sticky_sessions=lb_config.get("enable_sticky_sessions", False)
        )
        
    def get_metageneral_config(self, metageneral_name: str) -> Optional[Dict[str, Any]]:
        """Получение конфигурации мета-генерала"""
        metagenerals = self.config_data.get("metagenerals", {})
        return metagenerals.get(metageneral_name)
        
    def get_role_config(self, role_name: str) -> Optional[AgentRoleConfig]:
        """Получение конфигурации роли агента"""
        roles = self.config_data.get("roles", {})
        role_data = roles.get(role_name)
        
        if not role_data:
            return None
            
        return AgentRoleConfig(
            enabled=role_data.get("enabled", False),
            instances=role_data.get("instances", 1),
            auto_start=role_data.get("auto_start", False),
            capabilities=role_data.get("capabilities", []),
            config=role_data.get("config", {})
        )
        
    def get_all_enabled_roles(self) -> Dict[str, AgentRoleConfig]:
        """Получение всех включенных ролей"""
        roles = self.config_data.get("roles", {})
        enabled_roles = {}
        
        for role_name, role_data in roles.items():
            if role_data.get("enabled", False):
                enabled_roles[role_name] = AgentRoleConfig(
                    enabled=True,
                    instances=role_data.get("instances", 1),
                    auto_start=role_data.get("auto_start", False),
                    capabilities=role_data.get("capabilities", []),
                    config=role_data.get("config", {})
                )
                
        return enabled_roles
        
    def get_all_enabled_metagenerals(self) -> Dict[str, Dict[str, Any]]:
        """Получение всех включенных мета-генералов"""
        metagenerals = self.config_data.get("metagenerals", {})
        enabled_metagenerals = {}
        
        for mg_name, mg_data in metagenerals.items():
            if mg_data.get("enabled", False):
                enabled_metagenerals[mg_name] = mg_data
                
        return enabled_metagenerals
        
    def get_policies_config(self) -> Dict[str, Any]:
        """Получение конфигурации политик"""
        return self.config_data.get("policies", {})
        
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Получение конфигурации мониторинга"""
        return self.config_data.get("monitoring", {})
        
    def get_logging_config(self) -> Dict[str, Any]:
        """Получение конфигурации логирования"""
        return self.config_data.get("logging", {})
        
    def get_api_config(self) -> Dict[str, Any]:
        """Получение конфигурации API"""
        return self.config_data.get("api", {})
        
    def get_database_config(self) -> Dict[str, Any]:
        """Получение конфигурации базы данных"""
        return self.config_data.get("database", {})
        
    def get_cache_config(self) -> Dict[str, Any]:
        """Получение конфигурации кэша"""
        return self.config_data.get("cache", {})
        
    def is_development_mode(self) -> bool:
        """Проверка режима разработки"""
        dev_config = self.config_data.get("development", {})
        return dev_config.get("debug_mode", False)
        
    def get_environment(self) -> str:
        """Получение текущего окружения"""
        system = self.config_data.get("system", {})
        return system.get("environment", "development")
        
    def update_config(self, path: str, value: Any) -> None:
        """Обновление значения в конфигурации"""
        keys = path.split('.')
        current = self.config_data
        
        # Навигация до последнего ключа
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
            
        # Установка значения
        current[keys[-1]] = value
        
    def get_config_value(self, path: str, default: Any = None) -> Any:
        """Получение значения из конфигурации по пути"""
        keys = path.split('.')
        current = self.config_data
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default

# Глобальный экземпляр менеджера конфигурации
config_manager = ConfigManager()