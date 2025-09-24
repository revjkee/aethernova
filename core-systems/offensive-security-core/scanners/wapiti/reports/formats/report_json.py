# -*- coding: utf-8 -*-
"""
report_json.py
Модуль экспорта результатов сканирования Wapiti в JSON-формат
"""

import os
import json
import datetime

class ReportJSON:
    def __init__(self, output_dir, scan_info, vulnerabilities):
        """
        :param output_dir: Путь к директории для сохранения отчета
        :param scan_info: Словарь с информацией о сканировании (цель, дата, версия и т.д.)
        :param vulnerabilities: Список словарей с описанием уязвимостей
        """
        self.output_dir = output_dir
        self.scan_info = scan_info
        self.vulnerabilities = vulnerabilities

    def generate_report(self):
        """
        Создаёт и сохраняет JSON-отчёт с результатами сканирования
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        report_data = {
            "scan_info": {
                "target": self.scan_info.get("target", ""),
                "start_time": str(self.scan_info.get("start_time", "")),
                "end_time": str(self.scan_info.get("end_time", "")),
                "version": self.scan_info.get("version", ""),
                "report_generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "vulnerabilities": self.vulnerabilities
        }

        filename = os.path.join(self.output_dir, "wapiti_report.json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

        return filename
