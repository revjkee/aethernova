"""
test_processors.py
Юнит-тесты для модулей processors OSINT-сканеров.

Проверяют корректность работы базового процессора и дочерних классов,
а также фильтрации, нормализации и удаления дубликатов данных.
"""

import unittest
from intel_core.osint_scanners.processors.base_processor import BaseProcessor
from intel_core.osint_scanners.processors.filter import FilterProcessor
from intel_core.osint_scanners.processors.normalizer import NormalizerProcessor
from intel_core.osint_scanners.processors.deduplicator import DeduplicatorProcessor

class TestBaseProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = BaseProcessor()

    def test_process_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.processor.process(None)

class TestFilterProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = FilterProcessor()

    def test_process_filters_data(self):
        data = ["valid", "invalid", "", None, "valid2"]
        filtered = self.processor.process(data)
        self.assertNotIn("", filtered)
        self.assertNotIn(None, filtered)
        self.assertIn("valid", filtered)

class TestNormalizerProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = NormalizerProcessor()

    def test_process_normalizes_data(self):
        data = [" TeST ", "DATA", "nOrMalize"]
        normalized = self.processor.process(data)
        self.assertTrue(all(isinstance(item, str) for item in normalized))
        self.assertIn("test", normalized)
        self.assertIn("data", normalized)
        self.assertIn("normalize", normalized)

class TestDeduplicatorProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = DeduplicatorProcessor()

    def test_process_removes_duplicates(self):
        data = ["dup", "unique", "dup", "another", "unique"]
        deduped = self.processor.process(data)
        self.assertEqual(len(deduped), 3)
        self.assertIn("dup", deduped)
        self.assertIn("unique", deduped)
        self.assertIn("another", deduped)

if __name__ == "__main__":
    unittest.main()
