import json
import csv
import io
from typing import List, Dict, Any


class ReportFormatter:
    """
    Класс для конвертации данных в различные форматы:
    HTML, JSON, CSV.
    """

    @staticmethod
    def to_json(data: Any, indent: int = 4) -> str:
        """
        Конвертация данных в JSON строку.
        """
        return json.dumps(data, indent=indent, ensure_ascii=False)

    @staticmethod
    def to_csv(data: List[Dict[str, Any]]) -> str:
        """
        Конвертация списка словарей в CSV строку.
        Требует однородной структуры данных.
        """
        if not data:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    @staticmethod
    def to_html_table(data: List[Dict[str, Any]], title: str = "Report") -> str:
        """
        Конвертация списка словарей в HTML таблицу.
        Генерирует простой и валидный HTML код.
        """
        if not data:
            return f"<html><head><title>{title}</title></head><body><p>Нет данных для отображения</p></body></html>"

        headers = data[0].keys()
        rows = ""

        for row in data:
            row_html = "".join(f"<td>{row.get(col, '')}</td>" for col in headers)
            rows += f"<tr>{row_html}</tr>"

        html = f"""
        <html>
        <head>
            <title>{title}</title>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
            </style>
        </head>
        <body>
            <h2>{title}</h2>
            <table>
                <thead>
                    <tr>{"".join(f"<th>{col}</th>" for col in headers)}</tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </body>
        </html>
        """
        return html.strip()
