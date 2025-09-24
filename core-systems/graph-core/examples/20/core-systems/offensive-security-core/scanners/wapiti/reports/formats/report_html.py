# -*- coding: utf-8 -*-
"""
report_html.py
Модуль генерации HTML-отчётов для Wapiti Scanner
"""

import os
import datetime
import html
from jinja2 import Environment, FileSystemLoader, select_autoescape

class ReportHTML:
    def __init__(self, output_dir, scan_info, vulnerabilities):
        """
        :param output_dir: Путь к директории для сохранения отчета
        :param scan_info: Словарь с информацией о сканировании (цель, дата, версия и т.д.)
        :param vulnerabilities: Список словарей с описанием уязвимостей
        """
        self.output_dir = output_dir
        self.scan_info = scan_info
        self.vulnerabilities = vulnerabilities

        # Инициализация Jinja2
        templates_path = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(templates_path),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def generate_report(self):
        """
        Генерирует и сохраняет HTML отчет
        """
        template = self.env.get_template('report.html')

        # Обработка данных
        scan_info = {
            'target': html.escape(self.scan_info.get('target', 'Неизвестно')),
            'start_time': self.scan_info.get('start_time', 'Неизвестно'),
            'end_time': self.scan_info.get('end_time', 'Неизвестно'),
            'version': html.escape(self.scan_info.get('version', 'N/A')),
        }

        vulns = []
        for vuln in self.vulnerabilities:
            vulns.append({
                'name': html.escape(vuln.get('name', '')),
                'severity': html.escape(vuln.get('severity', '')),
                'url': html.escape(vuln.get('url', '')),
                'description': html.escape(vuln.get('description', '')),
                'param': html.escape(vuln.get('param', '')),
                'method': html.escape(vuln.get('method', '')),
                'evidence': html.escape(vuln.get('evidence', '')),
            })

        output_html = template.render(scan_info=scan_info, vulnerabilities=vulns, generated_at=datetime.datetime.now())

        # Запись файла
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        output_file = os.path.join(self.output_dir, 'wapiti_report.html')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_html)

        return output_file
