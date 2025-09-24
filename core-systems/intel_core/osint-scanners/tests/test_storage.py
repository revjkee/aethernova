"""
test_storage.py
Юнит-тесты для модуля storage OSINT-сканера.

Проверяют правильность работы кеша данных и моделей,
а также базовые операции CRUD.
"""

import unittest
from intel_core.osint_scanners.storage.cache import Cache
from intel_core.osint_scanners.storage.models import DataModel

class TestCache(unittest.TestCase):
    def setUp(self):
        self.cache = Cache()

    def test_set_and_get(self):
        self.cache.set('key1', 'value1')
        result = self.cache.get('key1')
        self.assertEqual(result, 'value1')

    def test_get_nonexistent_key(self):
        result = self.cache.get('missing_key')
        self.assertIsNone(result)

    def test_delete(self):
        self.cache.set('key2', 'value2')
        self.cache.delete('key2')
        self.assertIsNone(self.cache.get('key2'))

class TestDataModel(unittest.TestCase):
    def test_model_creation(self):
        data = {'id': 1, 'content': 'test data'}
        model = DataModel(**data)
        self.assertEqual(model.id, 1)
        self.assertEqual(model.content, 'test data')

    def test_model_str(self):
        data = {'id': 2, 'content': 'another test'}
        model = DataModel(**data)
        self.assertIn('another test', str(model))

if __name__ == "__main__":
    unittest.main()
