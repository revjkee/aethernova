# quantum-lab/hardware/calibration/t1_t2_measurer.py

"""
Модуль для измерения времени когерентности кубитов T₁ и T₂.

Функционал:
- Запуск экспериментов на измерение T1 (время релаксации)
- Запуск экспериментов на измерение T2 (время декогеренции)
- Асинхронное взаимодействие с оборудованием
- Сбор и первичная обработка данных
"""

import asyncio
from typing import Dict, Optional

class T1T2Measurer:
    def __init__(self, device_interface):
        """
        device_interface — объект, отвечающий за коммуникацию с квантовым устройством
        """
        self.device = device_interface
        self.last_results: Dict[str, Optional[float]] = {
            "T1": None,
            "T2": None
        }

    async def measure_t1(self) -> float:
        """
        Запускает измерение T1 - времени релаксации кубита.
        Возвращает время в микросекундах.
        """
        await self.device.prepare_experiment("T1")
        raw_data = await self.device.run_experiment()
        t1 = self._process_t1_data(raw_data)
        self.last_results["T1"] = t1
        return t1

    async def measure_t2(self) -> float:
        """
        Запускает измерение T2 - времени декогеренции кубита.
        Возвращает время в микросекундах.
        """
        await self.device.prepare_experiment("T2")
        raw_data = await self.device.run_experiment()
        t2 = self._process_t2_data(raw_data)
        self.last_results["T2"] = t2
        return t2

    def _process_t1_data(self, raw_data) -> float:
        """
        Обработка сырых данных эксперимента T1.
        Здесь реализуется конкретный алгоритм оценки времени релаксации.
        """
        # Пример: аппроксимация экспонентой, placeholder
        processed_value = float(raw_data.get("decay_time_us", 0))
        return processed_value

    def _process_t2_data(self, raw_data) -> float:
        """
        Обработка сырых данных эксперимента T2.
        Здесь реализуется алгоритм оценки времени декогеренции.
        """
        # Пример: аппроксимация экспонентой, placeholder
        processed_value = float(raw_data.get("decay_time_us", 0))
        return processed_value

    async def get_last_results(self) -> Dict[str, Optional[float]]:
        """
        Возвращает последние измеренные значения T1 и T2.
        """
        return self.last_results

# Конец файла
