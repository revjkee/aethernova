# quantum-lab/hardware/calibration/gate_fidelity.py

"""
Модуль для оценки точности квантовых вентилей (gate fidelity).

Функционал:
- Проведение экспериментов для оценки fidelity одиночных и двухкубитных вентилей
- Обработка результатов и вычисление метрик точности
- Асинхронное взаимодействие с оборудованием и контроллерами
"""

import asyncio
from typing import Dict, Optional

class GateFidelityEstimator:
    def __init__(self, device_interface):
        """
        device_interface — интерфейс для коммуникации с квантовым устройством
        """
        self.device = device_interface
        self.last_fidelity: Optional[float] = None

    async def measure_single_qubit_fidelity(self, gate_name: str) -> float:
        """
        Измеряет fidelity одиночного кубитного вентиля.
        gate_name — имя вентиля, например "X", "Y", "Hadamard"
        Возвращает fidelity как число от 0 до 1.
        """
        await self.device.prepare_experiment("single_qubit_fidelity", gate=gate_name)
        raw_data = await self.device.run_experiment()
        fidelity = self._process_fidelity_data(raw_data)
        self.last_fidelity = fidelity
        return fidelity

    async def measure_two_qubit_fidelity(self, gate_name: str) -> float:
        """
        Измеряет fidelity двухкубитного вентиля.
        gate_name — имя вентиля, например "CNOT", "CZ"
        Возвращает fidelity как число от 0 до 1.
        """
        await self.device.prepare_experiment("two_qubit_fidelity", gate=gate_name)
        raw_data = await self.device.run_experiment()
        fidelity = self._process_fidelity_data(raw_data)
        self.last_fidelity = fidelity
        return fidelity

    def _process_fidelity_data(self, raw_data) -> float:
        """
        Обработка сырых данных экспериментов.
        В этом методе реализуется алгоритм вычисления fidelity из измеренных данных.
        """
        # Пример обработки, placeholder
        fidelity_value = float(raw_data.get("fidelity", 0.0))
        return fidelity_value

    async def get_last_fidelity(self) -> Optional[float]:
        """
        Возвращает последнее измеренное значение fidelity.
        """
        return self.last_fidelity

# Конец файла
