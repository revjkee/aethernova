# llmops/security/audit_log_exporter.py

"""
Модуль для экспорта и обработки журналов аудита безопасности LLM-системы.
Отвечает за сбор, фильтрацию и передачу логов о событиях безопасности,
включая попытки jailbreak, подозрительные запросы и действия агентов.

Основные функции:
- Сбор логов из разных компонентов системы.
- Форматирование и фильтрация аудита.
- Экспорт в удобные форматы (JSON, CSV).
- Интеграция с внешними SIEM-системами и мониторингом.
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional

class AuditLogExporter:
    def __init__(self, log_source_path: str, export_path: str):
        """
        Инициализация экспортера аудита.

        :param log_source_path: Путь к файлу/директории с исходными логами
        :param export_path: Путь для сохранения экспортированных файлов
        """
        self.log_source_path = log_source_path
        self.export_path = export_path
        os.makedirs(export_path, exist_ok=True)

    def load_logs(self) -> List[Dict]:
        """
        Загрузка и парсинг логов из исходного файла/директории.
        Поддерживается JSON формат.

        :return: Список словарей с логами
        """
        logs = []
        if os.path.isdir(self.log_source_path):
            for filename in os.listdir(self.log_source_path):
                if filename.endswith(".json"):
                    with open(os.path.join(self.log_source_path, filename), "r", encoding="utf-8") as f:
                        try:
                            logs.extend(json.load(f))
                        except Exception:
                            continue
        else:
            with open(self.log_source_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        return logs

    def filter_logs(self, logs: List[Dict], severity: Optional[str] = None) -> List[Dict]:
        """
        Фильтрация логов по уровню важности (severity).

        :param logs: Список логов
        :param severity: Уровень важности (например, "WARNING", "ERROR")
        :return: Отфильтрованный список логов
        """
        if severity is None:
            return logs
        return [log for log in logs if log.get("level", "").upper() == severity.upper()]

    def export_to_json(self, logs: List[Dict], filename: str) -> None:
        """
        Экспорт логов в JSON файл.

        :param logs: Логи для экспорта
        :param filename: Имя файла
        """
        path = os.path.join(self.export_path, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

    def export_to_csv(self, logs: List[Dict], filename: str) -> None:
        """
        Экспорт логов в CSV файл.

        :param logs: Логи для экспорта
        :param filename: Имя файла
        """
        path = os.path.join(self.export_path, filename)
        if not logs:
            return
        keys = logs[0].keys()
        with open(path, "w", newline='', encoding="utf-8") as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(logs)

    def export(self, severity: Optional[str] = None) -> None:
        """
        Основной метод экспорта логов с опциональной фильтрацией.

        :param severity: Уровень важности для фильтрации
        """
        logs = self.load_logs()
        filtered_logs = self.filter_logs(logs, severity=severity)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"audit_logs_{severity or 'all'}_{timestamp}.json"
        csv_filename = f"audit_logs_{severity or 'all'}_{timestamp}.csv"
        self.export_to_json(filtered_logs, json_filename)
        self.export_to_csv(filtered_logs, csv_filename)


if __name__ == "__main__":
    # Пример использования
    exporter = AuditLogExporter(
        log_source_path="logs/security/",
        export_path="exports/audit/"
    )
    exporter.export(severity="WARNING")
