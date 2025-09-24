# keyvault/providers/base_provider.py
"""
TeslaAI Genesis BaseSecretProvider v4.9
Абстрактный интерфейс для всех провайдеров хранилищ:
локальные, облачные, распределённые, ZK-совместимые.
"""

import abc
from typing import Optional, Literal, Dict, Union

ProviderMode = Literal["read", "write", "delete", "rotate", "exists"]

class SecretMetadata:
    def __init__(self, key_id: str, created_at: int, version: int, tags: Optional[Dict[str, str]] = None):
        self.key_id = key_id
        self.created_at = created_at
        self.version = version
        self.tags = tags or {}

    def to_dict(self) -> Dict:
        return {
            "key_id": self.key_id,
            "created_at": self.created_at,
            "version": self.version,
            "tags": self.tags,
        }


class BaseSecretProvider(abc.ABC):
    """
    Интерфейс, который должны реализовать все секретные провайдеры.
    """

    def __init__(self, provider_id: str, config: Dict):
        self.provider_id = provider_id
        self.config = config

    @abc.abstractmethod
    def store_secret(self, key_id: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        """
        Сохранить секрет в хранилище.
        """
        pass

    @abc.abstractmethod
    def retrieve_secret(self, key_id: str, version: Optional[int] = None) -> bytes:
        """
        Получить секрет по идентификатору.
        """
        pass

    @abc.abstractmethod
    def delete_secret(self, key_id: str) -> None:
        """
        Удалить секрет полностью.
        """
        pass

    @abc.abstractmethod
    def rotate_secret(self, key_id: str, new_value: bytes, metadata: Optional[Dict] = None) -> None:
        """
        Ротация секрета.
        """
        pass

    @abc.abstractmethod
    def secret_exists(self, key_id: str) -> bool:
        """
        Проверка существования секрета.
        """
        pass

    @abc.abstractmethod
    def get_metadata(self, key_id: str) -> SecretMetadata:
        """
        Получить метаинформацию о секрете.
        """
        pass

    def validate_access(self, key_id: str, mode: ProviderMode, context: Dict) -> bool:
        """
        Общая Zero Trust проверка контекста, которая может быть переопределена.
        """
        # Примерная реализация, может быть переопределена в наследниках
        if context.get("threat_score", 0.0) > 0.6:
            return False
        return True

    def log_action(self, action: str, key_id: str, context: Optional[Dict] = None) -> None:
        """
        Унифицированный логгер для действий с провайдером.
        """
        from logging import getLogger
        logger = getLogger(f"teslaai.providers.{self.provider_id}")
        logger.info(f"[{action.upper()}] key_id={key_id}, context={context}")
