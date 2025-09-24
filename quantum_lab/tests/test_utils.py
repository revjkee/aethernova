# quantum-lab/tests/test_utils.py

import unittest
from quantum_lab.utils import math_helpers, yaml_utils, file_manager, logger

class TestUtils(unittest.TestCase):
    """
    Тесты для вспомогательных утилит: математика, YAML, файловый менеджер, логирование.
    Цель — проверить корректность и устойчивость функций к разным входным данным.
    """

    def test_math_helpers_functions(self):
        self.assertAlmostEqual(math_helpers.square(3), 9)
        self.assertAlmostEqual(math_helpers.factorial(5), 120)
        self.assertRaises(ValueError, math_helpers.factorial, -1)

    def test_yaml_utils_load_dump(self):
        data = {"key": "value", "num": 42}
        dumped = yaml_utils.dump_yaml(data)
        loaded = yaml_utils.load_yaml(dumped)
        self.assertEqual(data, loaded)

    def test_file_manager_versioning(self):
        filename = "testfile.txt"
        content_v1 = "Version 1"
        content_v2 = "Version 2"
        file_manager.save_version(filename, content_v1)
        file_manager.save_version(filename, content_v2)
        versions = file_manager.list_versions(filename)
        self.assertGreaterEqual(len(versions), 2)
        latest_content = file_manager.load_version(filename, versions[-1])
        self.assertEqual(latest_content, content_v2)

    def test_logger_logging(self):
        logger.log_info("Test info message")
        logger.log_error("Test error message")
        # Проверка через ручную инспекцию или подключение mock-фреймворка при необходимости

if __name__ == "__main__":
    unittest.main()
