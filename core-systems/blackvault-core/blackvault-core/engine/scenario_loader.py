# blackvault-core/engine/scenario_loader.py

import json
import yaml
import os
import logging
from typing import Dict, Optional, Any, List

from core.schemas.scenario import ScenarioSchema
from core.exceptions.scenario import InvalidScenarioError, ScenarioNotFoundError
from core.utils.validation import validate_schema
from core.telemetry.event_bus import EventBus
from core.security.hashing import verify_integrity_hash
from core.policy.rbac import enforce_scenario_permissions
from core.ai.embedding_loader import ScenarioVectorizer
from core.utils.tracing import trace_execution

logger = logging.getLogger("scenario_loader")

SCENARIO_EXTENSIONS = [".yaml", ".yml", ".json"]


class ScenarioLoader:
    """
    Промышленный загрузчик сценариев, обеспечивающий безопасную, верифицированную,
    масштабируемую загрузку боевых симуляций с поддержкой AI-индексации и RBAC.
    """

    def __init__(self, base_path: str, event_bus: Optional[EventBus] = None):
        self.base_path = base_path
        self.event_bus = event_bus or EventBus()
        self.vectorizer = ScenarioVectorizer()

    @trace_execution
    def load(self, name: str, user_id: str) -> Dict[str, Any]:
        """
        Загрузить и проверить сценарий симуляции.
        """
        path = self._resolve_path(name)

        if not os.path.exists(path):
            raise ScenarioNotFoundError(f"Сценарий не найден: {name}")

        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        data = self._parse_file(path, raw)
        self._validate(name, data)
        enforce_scenario_permissions(user_id=user_id, scenario=data)

        # AI-привязка (векторизация сценария)
        vector = self.vectorizer.vectorize(data)

        # Верификация целостности сценария (например, через подпись)
        if not verify_integrity_hash(path, expected_hash=data.get("integrity_hash")):
            raise InvalidScenarioError("Хэш целостности не совпадает")

        logger.info(f"Сценарий загружен: {name}")
        self.event_bus.publish("scenario.loaded", {"name": name, "user": user_id})

        return {
            "name": name,
            "data": data,
            "vector": vector
        }

    def list_available(self) -> List[str]:
        """
        Возвращает список всех доступных сценариев в директории.
        """
        files = [
            f for f in os.listdir(self.base_path)
            if os.path.splitext(f)[1] in SCENARIO_EXTENSIONS
        ]
        return sorted([os.path.splitext(f)[0] for f in files])

    def _resolve_path(self, name: str) -> str:
        for ext in SCENARIO_EXTENSIONS:
            candidate = os.path.join(self.base_path, name + ext)
            if os.path.exists(candidate):
                return candidate
        raise ScenarioNotFoundError(f"Файл сценария не найден: {name}")

    def _parse_file(self, path: str, raw: str) -> Dict[str, Any]:
        ext = os.path.splitext(path)[1]
        if ext in [".yaml", ".yml"]:
            return yaml.safe_load(raw)
        elif ext == ".json":
            return json.loads(raw)
        raise InvalidScenarioError(f"Неподдерживаемый формат: {ext}")

    def _validate(self, name: str, data: Dict[str, Any]) -> None:
        if not validate_schema(data, ScenarioSchema):
            raise InvalidScenarioError(f"Сценарий {name} не соответствует схеме")
