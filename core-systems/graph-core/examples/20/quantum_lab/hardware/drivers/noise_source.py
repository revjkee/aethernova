# quantum-lab/hardware/drivers/noise_source.py

"""
Модуль управления источником шума для quantum-lab.

Основные функции:
- Включение и выключение источника шума
- Настройка уровня шума и частотного диапазона
- Мониторинг состояния и параметров источника
- Асинхронное управление для точной синхронизации с экспериментом
"""

import asyncio
from typing import Optional, Dict

class NoiseSource:
    def __init__(self, device_address: str):
        self.device_address = device_address
        self.connected = False
        self.status: Dict[str, Optional[float]] = {
            "noise_level_dbm": None,
            "frequency_start_ghz": None,
            "frequency_stop_ghz": None,
            "is_on": False,
            "error": None,
        }

    async def connect(self) -> bool:
        """
        Асинхронное подключение к источнику шума.
        """
        await asyncio.sleep(0.2)  # эмуляция подключения
        self.connected = True
        return True

    async def disconnect(self) -> None:
        """
        Отключение от источника шума.
        """
        await asyncio.sleep(0.1)
        self.connected = False

    async def set_noise_level(self, noise_level_dbm: float) -> bool:
        """
        Установка уровня шума в dBm.
        """
        if not self.connected:
            raise RuntimeError("Noise source not connected")
        if not (-150.0 <= noise_level_dbm <= 0.0):
            raise ValueError("Noise level out of range (-150 to 0 dBm)")
        await asyncio.sleep(0.1)
        self.status["noise_level_dbm"] = noise_level_dbm
        return True

    async def set_frequency_range(self, start_ghz: float, stop_ghz: float) -> bool:
        """
        Настройка частотного диапазона источника шума в ГГц.
        """
        if not self.connected:
            raise RuntimeError("Noise source not connected")
        if not (0.1 <= start_ghz < stop_ghz <= 20.0):
            raise ValueError("Invalid frequency range: start must be < stop and within 0.1-20 GHz")
        await asyncio.sleep(0.1)
        self.status["frequency_start_ghz"] = start_ghz
        self.status["frequency_stop_ghz"] = stop_ghz
        return True

    async def turn_on(self) -> bool:
        """
        Включение источника шума.
        """
        if not self.connected:
            raise RuntimeError("Noise source not connected")
        self.status["is_on"] = True
        await asyncio.sleep(0.05)
        return True

    async def turn_off(self) -> bool:
        """
        Выключение источника шума.
        """
        if not self.connected:
            raise RuntimeError("Noise source not connected")
        self.status["is_on"] = False
        await asyncio.sleep(0.05)
        return True

    async def get_status(self) -> Dict[str, Optional[float]]:
        """
        Получение текущего статуса источника шума.
        """
        if not self.connected:
            raise RuntimeError("Noise source not connected")
        await asyncio.sleep(0.05)
        return self.status

# Конец файла
