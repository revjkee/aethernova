import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

class InventoryPlugin:
    """
    Плагин управления товарами в маркетплейсе.
    Обеспечивает CRUD операции с товарами, управление запасами, 
    категорий и интеграцию с внешними системами.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._inventory = {}  # Внутреннее хранилище товаров: {product_id: product_data}

    def add_product(self, product_id: str, name: str, category: str, price: float, quantity: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Добавить новый товар в инвентарь.
        """
        if product_id in self._inventory:
            self.logger.error(f"Товар с product_id={product_id} уже существует")
            return False
        if price < 0 or quantity < 0:
            self.logger.error("Цена и количество должны быть неотрицательными")
            return False

        self._inventory[product_id] = {
            "name": name,
            "category": category,
            "price": price,
            "quantity": quantity,
            "metadata": metadata or {},
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        self.logger.info(f"Товар {product_id} добавлен успешно")
        return True

    def update_product(self, product_id: str, **updates) -> bool:
        """
        Обновить параметры товара.
        """
        product = self._inventory.get(product_id)
        if not product:
            self.logger.error(f"Товар с product_id={product_id} не найден")
            return False

        allowed_fields = {"name", "category", "price", "quantity", "metadata"}
        for key, value in updates.items():
            if key not in allowed_fields:
                self.logger.warning(f"Игнорируем недопустимое поле {key}")
                continue
            if key in {"price", "quantity"} and value < 0:
                self.logger.error(f"Недопустимое значение для {key}: {value}")
                return False
            if key == "metadata" and not isinstance(value, dict):
                self.logger.error("metadata должно быть словарём")
                return False
            product[key] = value
        product["updated_at"] = datetime.utcnow()
        self.logger.info(f"Товар {product_id} обновлён успешно")
        return True

    def remove_product(self, product_id: str) -> bool:
        """
        Удалить товар из инвентаря.
        """
        if product_id not in self._inventory:
            self.logger.error(f"Товар с product_id={product_id} не найден")
            return False
        del self._inventory[product_id]
        self.logger.info(f"Товар {product_id} удалён")
        return True

    def get_product(self, product_id: str) -> Optional[Dict[str, Any]]:
        """
        Получить информацию о товаре.
        """
        return self._inventory.get(product_id)

    def list_products(self, category: Optional[str] = None, available_only: bool = False) -> List[Dict[str, Any]]:
        """
        Получить список товаров, с возможностью фильтрации по категории и наличию.
        """
        result = []
        for product in self._inventory.values():
            if category and product["category"] != category:
                continue
            if available_only and product["quantity"] <= 0:
                continue
            result.append(product)
        return result

    def adjust_stock(self, product_id: str, delta: int) -> bool:
        """
        Изменить количество товара на складе (пополнение или списание).
        """
        product = self._inventory.get(product_id)
        if not product:
            self.logger.error(f"Товар с product_id={product_id} не найден")
            return False
        new_quantity = product["quantity"] + delta
        if new_quantity < 0:
            self.logger.error(f"Недостаточно товара для списания: current={product['quantity']}, delta={delta}")
            return False
        product["quantity"] = new_quantity
        product["updated_at"] = datetime.utcnow()
        self.logger.info(f"Количество товара {product_id} изменено на {delta}, новое количество {new_quantity}")
        return True
