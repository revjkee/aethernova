import json
import csv
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_json_report(self, data, report_name=None):
        if not report_name:
            report_name = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        path = os.path.join(self.output_dir, report_name)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return path

    def generate_csv_report(self, data, report_name=None):
        if not report_name:
            report_name = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        path = os.path.join(self.output_dir, report_name)

        if not data or not isinstance(data, list) or not isinstance(data[0], dict):
            raise ValueError("Данные для CSV должны быть списком словарей")

        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return path

    def generate_text_report(self, data, report_name=None):
        if not report_name:
            report_name = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        path = os.path.join(self.output_dir, report_name)

        with open(path, 'w', encoding='utf-8') as f:
            if isinstance(data, dict):
                for key, value in data.items():
                    f.write(f'{key}: {value}\n')
            elif isinstance(data, list):
                for item in data:
                    f.write(f'{item}\n')
            else:
                f.write(str(data))
        return path

    # Расширяемость: добавление форматов, шаблонов, интеграций с email, базами и др.

