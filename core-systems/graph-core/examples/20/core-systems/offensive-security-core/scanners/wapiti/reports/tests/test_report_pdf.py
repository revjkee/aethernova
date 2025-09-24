import unittest
import os
from scanners.wapiti.reports.formats import report_pdf

class TestReportPDF(unittest.TestCase):
    def setUp(self):
        self.test_data = {
            'scan_info': {
                'target': 'http://example.com',
                'date': '2025-07-14T17:00:00'
            },
            'vulnerabilities': [
                {
                    'name': 'SQL Injection',
                    'severity': 'Critical',
                    'description': 'SQL Injection vulnerability detected',
                    'url': 'http://example.com/login',
                    'parameter': 'username',
                    'method': 'POST'
                },
                {
                    'name': 'XSS',
                    'severity': 'High',
                    'description': 'Cross-site scripting vulnerability',
                    'url': 'http://example.com/search',
                    'parameter': 'q',
                    'method': 'GET'
                }
            ]
        }
        self.output_file = 'test_report.pdf'

    def test_generate_pdf_creates_file(self):
        report_pdf.generate_report(self.test_data, self.output_file)
        self.assertTrue(os.path.exists(self.output_file), "PDF файл отчёта не создан")

    def test_pdf_file_is_not_empty(self):
        report_pdf.generate_report(self.test_data, self.output_file)
        size = os.path.getsize(self.output_file)
        self.assertGreater(size, 0, "PDF файл отчёта пустой")

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

if __name__ == '__main__':
    unittest.main()
