# autopwn-framework/tests/test_scanners.py

import unittest
import asyncio
from autopwn_framework.scanners import Scanner, ScannerError

class TestScanner(unittest.IsolatedAsyncioTestCase):
    """
    Тесты для модулей сканеров — проверка запуска, остановки, корректности обработки данных и ошибок.
    """

    async def asyncSetUp(self):
        # Создаем тестовый экземпляр сканера с базовой конфигурацией
        self.scanner = Scanner(name="TestScanner", config={"timeout": 5})

    async def test_scan_start_stop(self):
        # Проверяем успешный запуск и остановку сканера
        await self.scanner.start(target="127.0.0.1")
        self.assertTrue(self.scanner.is_running)
        await self.scanner.stop()
        self.assertFalse(self.scanner.is_running)

    async def test_scan_results_type(self):
        # Проверяем тип возвращаемых результатов
        await self.scanner.start(target="127.0.0.1")
        results = await self.scanner.get_results()
        self.assertIsInstance(results, list)
        await self.scanner.stop()

    async def test_scan_invalid_target(self):
        # Проверяем, что сканер бросает ошибку на некорректный таргет
        with self.assertRaises(ScannerError):
            await self.scanner.start(target="")

    async def test_scan_timeout(self):
        # Тестируем таймаут сканирования
        self.scanner.config["timeout"] = 0.01
        with self.assertRaises(ScannerError):
            await self.scanner.start(target="192.168.1.1")

if __name__ == "__main__":
    unittest.main()
