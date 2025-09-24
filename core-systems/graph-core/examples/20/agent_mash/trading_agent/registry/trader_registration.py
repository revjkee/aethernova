# trader_registration.py

import uuid
import json
import logging
from typing import Dict, Optional, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("trader_registration")
logger.setLevel(logging.INFO)


class TraderRegistry:
    """
    Промышленный реестр торговых агентов. Обеспечивает уникальность,
    валидацию, хранение метаданных, безопасность ID и логи регистрации.
    """

    def __init__(self, registry_path: str = "./registry/traders.json"):
        self.registry_path = Path(registry_path)
        self.traders: Dict[str, Dict] = {}
        self._load_registry()

    def _load_registry(self):
        if self.registry_path.exists():
            try:
                with open(self.registry_path, "r", encoding="utf-8") as f:
                    self.traders = json.load(f)
                logger.info(f"[Registry] Загрузка реестра агентов из {self.registry_path}")
            except Exception as e:
                logger.error(f"[Registry] Ошибка загрузки: {e}")
                self.traders = {}
        else:
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            self._save_registry()

    def _save_registry(self):
        try:
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(self.traders, f, indent=4)
            logger.debug(f"[Registry] Сохранено в {self.registry_path}")
        except Exception as e:
            logger.error(f"[Registry] Ошибка при сохранении: {e}")

    def register_trader(
        self,
        name: str,
        strategy_class: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Регистрирует нового агента и возвращает его уникальный ID.
        """
        trader_id = str(uuid.uuid4())

        self.traders[trader_id] = {
            "name": name,
            "strategy_class": strategy_class,
            "metadata": metadata or {},
            "registered_at": datetime.utcnow().isoformat(),
            "active": True
        }

        logger.info(f"[Registry] Агент зарегистрирован: {name} ({strategy_class}) -> ID: {trader_id}")
        self._save_registry()
        return trader_id

    def deregister_trader(self, trader_id: str) -> bool:
        """
        Деактивирует агента по ID.
        """
        if trader_id in self.traders:
            self.traders[trader_id]["active"] = False
            self.traders[trader_id]["deregistered_at"] = datetime.utcnow().isoformat()
            logger.warning(f"[Registry] Агент отключен: {trader_id}")
            self._save_registry()
            return True
        else:
            logger.warning(f"[Registry] Агент не найден: {trader_id}")
            return False

    def list_active(self) -> List[Dict[str, str]]:
        """
        Возвращает список всех активных агентов.
        """
        return [
            {"id": k, "name": v["name"], "strategy_class": v["strategy_class"]}
            for k, v in self.traders.items() if v.get("active")
        ]

    def get_trader_info(self, trader_id: str) -> Optional[Dict[str, str]]:
        return self.traders.get(trader_id)
