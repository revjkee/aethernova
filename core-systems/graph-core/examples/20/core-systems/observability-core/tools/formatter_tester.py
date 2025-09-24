# observability/dashboards/tools/formatter_tester.py

import importlib
import json
import logging
import os
import traceback
from typing import Any, Dict, List


class FormatterTester:
    """
    Утилита для тестирования и валидации кастомных лог-форматтеров:
    - Проверяет, что форматтер не выбрасывает исключений;
    - Гарантирует наличие ключевых полей в структуре;
    - Поддерживает динамическую подгрузку по имени класса.
    """

    def __init__(self, formatter_paths: List[str], test_record: logging.LogRecord = None):
        self.formatter_paths = formatter_paths
        self.test_record = test_record or self._create_default_record()
        self.results: Dict[str, Dict[str, Any]] = {}

    def _create_default_record(self) -> logging.LogRecord:
        return logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Test log message",
            args=(),
            exc_info=None
        )

    def _load_formatter(self, path: str):
        try:
            module_path, class_name = path.rsplit(".", 1)
            module = importlib.import_module(module_path)
            return getattr(module, class_name)
        except Exception:
            return None

    def _validate_output(self, formatter: logging.Formatter, formatted: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(formatted)
            essential_fields = ["message", "level", "timestamp"]
            missing_fields = [field for field in essential_fields if field not in parsed]
            return {
                "valid_json": True,
                "missing_fields": missing_fields,
                "parsed_output": parsed
            }
        except json.JSONDecodeError:
            return {
                "valid_json": False,
                "missing_fields": [],
                "parsed_output": None
            }

    def run_tests(self) -> Dict[str, Dict[str, Any]]:
        for path in self.formatter_paths:
            try:
                formatter_cls = self._load_formatter(path)
                if not formatter_cls:
                    self.results[path] = {"error": "Formatter class not found"}
                    continue

                formatter_instance = formatter_cls()
                output = formatter_instance.format(self.test_record)
                result = self._validate_output(formatter_instance, output)
                self.results[path] = {"success": True, "output": result}
            except Exception as e:
                self.results[path] = {
                    "success": False,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
        return self.results

    def print_results(self):
        for path, result in self.results.items():
            print(f"Formatter: {path}")
            print(json.dumps(result, indent=2))
            print("-" * 40)
