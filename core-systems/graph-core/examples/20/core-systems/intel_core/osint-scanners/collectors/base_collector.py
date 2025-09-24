import abc
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class BaseCollector(abc.ABC):
    """
    Абстрактный базовый класс для всех сборщиков данных в OSINT-системе.
    Обеспечивает стандартный интерфейс и базовую логику для планирования и запуска задач сбора.
    """

    def __init__(self, source_name: str, config: Optional[Dict] = None):
        """
        Инициализация сборщика.

        :param source_name: Название источника данных (например, сайт, форум, соцсеть)
        :param config: Конфигурационные параметры (таймауты, лимиты и пр.)
        """
        self.source_name = source_name
        self.config = config or {}
        self.is_running = False

    @abc.abstractmethod
    async def collect(self) -> List[Dict]:
        """
        Основной метод для запуска сбора данных.
        Должен быть переопределён в наследниках.

        :return: Список собранных элементов (обычно словарей)
        """
        raise NotImplementedError("Метод collect должен быть реализован в дочернем классе")

    async def start(self):
        """
        Запуск процесса сбора.
        """
        if self.is_running:
            logger.warning(f"Collector {self.source_name} уже запущен.")
            return
        self.is_running = True
        logger.info(f"Запуск коллектора {self.source_name}")
        try:
            results = await self.collect()
            logger.info(f"Коллектор {self.source_name} собрал {len(results)} элементов")
            return results
        except Exception as e:
            logger.error(f"Ошибка при сборе данных в {self.source_name}: {e}")
            return []
        finally:
            self.is_running = False

    async def stop(self):
        """
        Метод остановки сбора, при необходимости переопределяется в наследниках.
        """
        if self.is_running:
            logger.info(f"Остановка коллектора {self.source_name}")
            self.is_running = False
