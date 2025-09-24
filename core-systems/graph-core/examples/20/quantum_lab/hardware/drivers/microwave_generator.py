# quantum-lab/hardware/drivers/microwave_generator.py

"""
Модуль управления микроволновым генератором для quantum-lab.

Основные функции:
- Управление частотой и мощностью микроволновых импульсов
- Запуск и остановка импульсов с точным таймингом
- Конфигурирование параметров импульсов для квантовых экспериментов
- Мониторинг состояния генератора

Реализован с использованием асинхронных вызовов для точного и гибкого управления.
"""

import asyncio
from typing import Optional, Dict

class MicrowaveGenerator:
    def __init__(self, device_address: str):
        self.device_address = device_address
        self.connected = False
        self.status: Dict[str, Optional[float]] = {
            "frequency_ghz": None,
            "power_dbm": None,
            "is_emitting": False,
            "error": None,
        }

    async def connect(self) -> bool:
        """
        Асинхронное подключение к микроволновому генератору.
        """
        await asyncio.sleep(0.2)  # имитация подключения
        self.connected = True
        return True

    async def disconnect(self) -> None:
        """
        Отключение от генератора.
        """
        await asyncio.sleep(0.1)
        self.connected = False

    async def set_frequency(self, frequency_ghz: float) -> bool:
        """
        Установка частоты генератора в ГГц.
        """
        if not self.connected:
            raise RuntimeError("Microwave generator not connected")
        if not (1.0 <= frequency_ghz <= 20.0):
            raise ValueError("Frequency out of range (1.0 - 20.0 GHz)")
        await asyncio.sleep(0.1)
        self.status["frequency_ghz"] = frequency_ghz
        return True

    async def set_power(self, power_dbm: float) -> bool:
        """
        Установка мощности сигнала в dBm.
        """
        if not self.connected:
            raise RuntimeError("Microwave generator not connected")
        if not (-120.0 <= power_dbm <= 20.0):
            raise ValueError("Power out of range (-120 to 20 dBm)")
        await asyncio.sleep(0.1)
        self.status["power_dbm"] = power_dbm
        return True

    async def emit_pulse(self, duration_ns: int) -> bool:
        """
        Запуск микроволнового импульса с заданной длительностью в наносекундах.
        """
        if not self.connected:
            raise RuntimeError("Microwave generator not connected")
        if self.status["frequency_ghz"] is None or self.status["power_dbm"] is None:
            raise RuntimeError("Frequency and power must be set before emission")
        self.status["is_emitting"] = True
        await asyncio.sleep(duration_ns / 1_000_000_000)  # эмуляция длительности импульса
        self.status["is_emitting"] = False
        return True

    async def stop_emission(self) -> None:
        """
        Принудительная остановка излучения.
        """
        if not self.connected:
            return
        self.status["is_emitting"] = False
        await asyncio.sleep(0.05)

    async def get_status(self) -> Dict[str, Optional[float]]:
        """
        Получение текущего статуса генератора.
        """
        if not self.connected:
            raise RuntimeError("Microwave generator not connected")
        await asyncio.sleep(0.05)
        return self.status

# Конец файла
