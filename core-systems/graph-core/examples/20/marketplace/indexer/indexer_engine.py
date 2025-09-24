import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class IndexerEngine:
    """
    Основной движок индексации данных маркетплейса TeslaAI.
    Отвечает за сбор, обработку и обновление индексов товаров и заказов.
    Поддерживает асинхронную обработку и расширяемость.
    """

    def __init__(self, fetcher: Callable[[], Any], indexer: Callable[[List[Dict[str, Any]]], None], batch_size: int = 100, interval_sec: int = 60):
        """
        :param fetcher: Асинхронная функция получения сырых данных для индексации.
        :param indexer: Функция обработки и записи данных в индекс.
        :param batch_size: Размер пакета для обработки.
        :param interval_sec: Интервал периодической индексации в секундах.
        """
        self.fetcher = fetcher
        self.indexer = indexer
        self.batch_size = batch_size
        self.interval_sec = interval_sec
        self._running = False

    async def _process_batch(self, data_batch: List[Dict[str, Any]]) -> None:
        try:
            logger.debug(f"Обработка пакета из {len(data_batch)} элементов.")
            await asyncio.to_thread(self.indexer, data_batch)
            logger.info(f"Пакет успешно проиндексирован ({len(data_batch)} элементов).")
        except Exception as e:
            logger.error(f"Ошибка при индексации пакета: {e}", exc_info=True)

    async def _index_loop(self) -> None:
        while self._running:
            try:
                logger.info(f"Запуск очередного цикла индексации в {datetime.now(timezone.utc).isoformat()}")
                raw_data = await self.fetcher()
                if not raw_data:
                    logger.info("Нет данных для индексации.")
                else:
                    # Разбиваем на батчи
                    for i in range(0, len(raw_data), self.batch_size):
                        batch = raw_data[i:i + self.batch_size]
                        await self._process_batch(batch)
                await asyncio.sleep(self.interval_sec)
            except Exception as e:
                logger.error(f"Ошибка в цикле индексации: {e}", exc_info=True)
                await asyncio.sleep(self.interval_sec)

    def start(self) -> None:
        """
        Запустить асинхронный цикл индексации.
        """
        if self._running:
            logger.warning("IndexerEngine уже запущен.")
            return
        self._running = True
        asyncio.create_task(self._index_loop())
        logger.info("IndexerEngine запущен.")

    def stop(self) -> None:
        """
        Остановить цикл индексации.
        """
        if not self._running:
            logger.warning("IndexerEngine уже остановлен.")
            return
        self._running = False
        logger.info("IndexerEngine остановлен.")
