import unittest
import os
from scanners.wapiti.reports.formats import report_html

class TestReportHTML(unittest.TestCase):
    def setUp(self):
        # Тестовые данные для отчёта
        self.test_data = {
            'scan_info': {
                'target': 'http://example.com',
                'date': '2025-07-14T17:00:00'
            },
            'vulnerabilities': [
                {
                    'name': 'XSS',
                    'severity': 'High',
                    'description': 'Cross-site scripting vulnerability',
                    'url': 'http://example.com/vuln',
                    'parameter': 'q',
                    'method': 'GET'
                },
                {
                    'name': 'SQL Injection',
                    'severity': 'Critical',
                    'description': 'SQL Injection vulnerability',
                    'url': 'http://example.com/login',
                    'parameter': 'username',
                    'method': 'POST'
                }
            ]
        }
        self.output_file = 'test_report.html'

    def test_generate_report_creates_file(self):
        # Генерация отчёта
        report_html.generate_report(self.test_data, self.output_file)
        self.assertTrue(os.path.exists(self.output_file), "Файл отчёта не создан")

    def test_report_contains_vulnerabilities(self):
        report_html.generate_report(self.test_data, self.output_file)
        with open(self.output_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('XSS', content, "Отчёт не содержит XSS")
            self.assertIn('SQL Injection', content, "Отчёт не содержит SQL Injection")
            self.assertIn('http://example.com/vuln', content, "Отчёт не содержит URL уязвимости")

    def test_report_includes_scan_info(self):
        report_html.generate_report(self.test_data, self.output_file)
        with open(self.output_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('http://example.com', content, "Отчёт не содержит информацию о цели сканирования")
            self.assertIn('2025-07-14T17:00:00', content, "Отчёт не содержит дату сканирования")

    def tearDown(self):
        # Очистка после теста
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

if __name__ == '__main__':
    unittest.main()
