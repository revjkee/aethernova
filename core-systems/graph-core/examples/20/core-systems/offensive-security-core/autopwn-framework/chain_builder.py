import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ChainBuilder:
    """
    Класс для построения цепочек атак (эксплойт-пайплайнов) в автоматизированном пентесте.
    """

    def __init__(self):
        self.chains: List[List[Dict[str, Any]]] = []

    def add_chain(self, chain: List[Dict[str, Any]]):
        """
        Добавить новую цепочку атак.

        :param chain: список этапов цепочки, каждый этап — словарь с параметрами.
        """
        if not chain or not all(isinstance(step, dict) for step in chain):
            logger.error("Неверный формат цепочки: должна быть непустым списком словарей.")
            raise ValueError("Chain must be a non-empty list of dicts.")
        self.chains.append(chain)
        logger.debug(f"Добавлена новая цепочка: {chain}")

    def build(self) -> List[List[Dict[str, Any]]]:
        """
        Вернуть все построенные цепочки.

        :return: список цепочек.
        """
        logger.debug(f"Возвращается список цепочек, количество: {len(self.chains)}")
        return self.chains

    def clear(self):
        """
        Очистить все сохранённые цепочки.
        """
        self.chains.clear()
        logger.debug("Все цепочки очищены.")

    def validate_chain(self, chain: List[Dict[str, Any]]) -> bool:
        """
        Проверка валидности цепочки: каждый шаг должен иметь ключ 'exploit' и 'target'.

        :param chain: цепочка для проверки.
        :return: True если валидна, иначе False.
        """
        valid = all(
            isinstance(step, dict) and
            'exploit' in step and
            'target' in step
            for step in chain
        )
        logger.debug(f"Проверка валидности цепочки: {valid}")
        return valid

    def add_chain_checked(self, chain: List[Dict[str, Any]]):
        """
        Добавить цепочку с предварительной проверкой.

        :param chain: цепочка.
        :raises ValueError: если цепочка невалидна.
        """
        if not self.validate_chain(chain):
            logger.error("Цепочка невалидна, пропуск добавления.")
            raise ValueError("Invalid chain format: each step must contain 'exploit' and 'target'.")
        self.add_chain(chain)
