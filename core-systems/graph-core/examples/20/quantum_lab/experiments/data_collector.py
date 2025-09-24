# quantum-lab/experiments/data_collector.py

import threading
import time
from typing import Callable, List, Dict, Any

class DataCollector:
    """
    Класс для сбора данных в ходе проведения квантовых экспериментов.
    Позволяет запускать сбор данных в отдельном потоке с периодическим опросом источников.
    """

    def __init__(self, poll_interval: float = 1.0):
        """
        :param poll_interval: Интервал опроса данных в секундах.
        """
        self.poll_interval = poll_interval
        self._data_sources: List[Callable[[], Any]] = []
        self._collected_data: List[Dict[str, Any]] = []
        self._running = False
        self._thread = None

    def add_data_source(self, source_func: Callable[[], Any]) -> None:
        """
        Добавляет источник данных — функцию, которая возвращает данные при вызове.
        """
        self._data_sources.append(source_func)

    def _collect_loop(self):
        """
        Внутренний метод: запускается в отдельном потоке, собирает данные периодически.
        """
        while self._running:
            snapshot = {}
            for idx, source in enumerate(self._data_sources):
                try:
                    snapshot[f"source_{idx}"] = source()
                except Exception as e:
                    snapshot[f"source_{idx}"] = f"Error: {e}"
            self._collected_data.append(snapshot)
            time.sleep(self.poll_interval)

    def start(self) -> None:
        """
        Запускает сбор данных в отдельном потоке.
        """
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """
        Останавливает сбор данных.
        """
        self._running = False
        if self._thread is not None:
            self._thread.join()

    def get_data(self) -> List[Dict[str, Any]]:
        """
        Возвращает собранные данные.
        """
        return self._collected_data

