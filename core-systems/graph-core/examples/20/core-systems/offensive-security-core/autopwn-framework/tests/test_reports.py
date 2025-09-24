# autopwn-framework/tests/test_reports.py

import unittest
from autopwn_framework.cli.commands import report
from autopwn_framework.reports import ReportGenerator, ReportError

class TestReportGenerator(unittest.TestCase):
    """
    Тесты для модуля генерации отчетов:
    проверка создания отчетов в разных форматах,
    обработка ошибок при некорректных данных,
    валидация структуры итогового отчета.
    """

    def setUp(self):
        self.generator = ReportGenerator()

    def test_generate_report_success(self):
        data = {
            "scan_results": [
                {"ip": "192.168.1.1", "vulnerabilities": ["CVE-2021-1234"]},
                {"ip": "192.168.1.2", "vulnerabilities": []},
            ],
            "summary": "2 hosts scanned, 1 vulnerability found"
        }
        report = self.generator.generate(data, format="json")
        self.assertIsInstance(report, str)
        self.assertIn('"scan_results"', report)

    def test_generate_report_invalid_format(self):
        data = {"key": "value"}
        with self.assertRaises(ReportError):
            self.generator.generate(data, format="unsupported_format")

    def test_generate_report_empty_data(self):
        with self.assertRaises(ReportError):
            self.generator.generate({}, format="json")

    def test_cli_report_command(self):
        # Тестирование CLI команды report - базовый вызов
        result = report.run_report_command("--format json --output test_report.json")
        self.assertEqual(result, 0)

if __name__ == "__main__":
    unittest.main()
