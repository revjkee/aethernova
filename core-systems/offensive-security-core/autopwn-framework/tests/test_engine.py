# autopwn-framework/tests/test_engine.py

import asyncio
import unittest
from autopwn_framework.engine import ScanEngine, ScanResult

class TestScanEngine(unittest.IsolatedAsyncioTestCase):
    """
    Тесты для модуля ScanEngine, отвечающего за выполнение сканирования и управление задачами.
    Проверяем корректность запуска, остановки, обработки результатов и обработки ошибок.
    """

    async def asyncSetUp(self):
        # Создание экземпляра движка для тестирования
        self.engine = ScanEngine()

    async def test_start_and_stop_scan(self):
        # Проверяем запуск и остановку сканирования
        await self.engine.start_scan(targets=["127.0.0.1"])
        self.assertTrue(self.engine.is_running)
        await self.engine.stop_scan()
        self.assertFalse(self.engine.is_running)

    async def test_scan_result_collection(self):
        # Проверяем, что результаты сканирования собираются корректно
        await self.engine.start_scan(targets=["127.0.0.1"])
        await asyncio.sleep(1)  # Имитация времени сканирования
        results = self.engine.get_results()
        self.assertIsInstance(results, list)
        for result in results:
            self.assertIsInstance(result, ScanResult)
        await self.engine.stop_scan()

    async def test_handle_scan_errors(self):
        # Проверяем обработку ошибок при сканировании
        with self.assertRaises(ValueError):
            await self.engine.start_scan(targets=[])  # Пустой список целей недопустим

    async def test_scan_concurrency_limits(self):
        # Проверка ограничения одновременных сканирований
        self.engine.max_concurrent_scans = 2
        await self.engine.start_scan(targets=["127.0.0.1", "192.168.1.1", "10.0.0.1"])
        running_tasks = self.engine.get_running_tasks_count()
        self.assertLessEqual(running_tasks, 2)
        await self.engine.stop_scan()

if __name__ == "__main__":
    unittest.main()

