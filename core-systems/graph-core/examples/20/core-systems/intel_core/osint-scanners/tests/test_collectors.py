"""
test_collectors.py
Юнит-тесты для модулей collectors OSINT-сканеров.

Проверяют корректность работы базового класса и производных сборщиков,
обработку ошибок и стабильность выполнения.
"""

import unittest
from unittest.mock import AsyncMock, patch
from intel_core.osint_scanners.collectors.base_collector import BaseCollector
from intel_core.osint_scanners.collectors.website_collector import WebsiteCollector
from intel_core.osint_scanners.collectors.forum_collector import ForumCollector

class TestBaseCollector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.collector = BaseCollector()

    async def test_collect_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            await self.collector.collect()

class TestWebsiteCollector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.collector = WebsiteCollector()

    @patch('intel_core.osint_scanners.collectors.website_collector.aiohttp.ClientSession.get')
    async def test_collect_success(self, mock_get):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<html>Test</html>")
        mock_get.return_value.__aenter__.return_value = mock_response

        result = await self.collector.collect()
        self.assertIsInstance(result, str)
        self.assertIn("Test", result)

    @patch('intel_core.osint_scanners.collectors.website_collector.aiohttp.ClientSession.get')
    async def test_collect_http_error(self, mock_get):
        mock_response = AsyncMock()
        mock_response.status = 404
        mock_get.return_value.__aenter__.return_value = mock_response

        with self.assertRaises(Exception):
            await self.collector.collect()

class TestForumCollector(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.collector = ForumCollector()

    @patch('intel_core.osint_scanners.collectors.forum_collector.asyncio.sleep', new=AsyncMock())
    async def test_collect_stub(self):
        # Тест-заглушка для ForumCollector, который должен быть реализован в проекте
        result = await self.collector.collect()
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
