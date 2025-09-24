# autopwn-framework/tests/test_c2.py

import unittest
import asyncio
from autopwn_framework.c2 import C2Controller, C2ConnectionError

class TestC2Controller(unittest.IsolatedAsyncioTestCase):
    """
    Тесты для модуля управления C2 (Command and Control):
    проверка подключения, отправки команд, обработки ошибок и корректного завершения сессий.
    """

    async def asyncSetUp(self):
        # Инициализация контроллера C2 с тестовыми параметрами
        self.c2 = C2Controller(address="127.0.0.1", port=9999)

    async def test_c2_connect_success(self):
        # Проверка успешного подключения к C2 серверу
        result = await self.c2.connect()
        self.assertTrue(result)

    async def test_c2_connect_failure(self):
        # Проверка обработки ошибки подключения при неверных параметрах
        bad_c2 = C2Controller(address="256.256.256.256", port=9999)
        with self.assertRaises(C2ConnectionError):
            await bad_c2.connect()

    async def test_c2_send_command(self):
        # Проверка успешной отправки команды и получения результата
        await self.c2.connect()
        response = await self.c2.send_command("status")
        self.assertIn("status", response)
        self.assertIsInstance(response, dict)

    async def test_c2_disconnect(self):
        # Проверка корректного отключения от C2
        await self.c2.connect()
        result = await self.c2.disconnect()
        self.assertTrue(result)

if __name__ == "__main__":
    unittest.main()
