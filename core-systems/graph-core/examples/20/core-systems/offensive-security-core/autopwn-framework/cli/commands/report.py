# autopwn-framework/cli/commands/report.py

import asyncio
from autopwn_framework.reporting import ReportGenerator
from autopwn_framework.utils.file import save_report_to_file

async def report_command(scan_id: str, output_path: str = None, report_format: str = "pdf"):
    """
    Команда для генерации отчёта по заданному сканированию.
    
    :param scan_id: Идентификатор завершенного сканирования
    :param output_path: Путь для сохранения отчёта (если None - сохраняется в дефолтную папку)
    :param report_format: Формат отчёта (pdf, html, txt и т.п.)
    """

    generator = ReportGenerator(scan_id)

    report_content = await generator.generate(report_format)
    if not output_path:
        output_path = f"./reports/report_{scan_id}.{report_format}"

    save_report_to_file(report_content, output_path)

    print(f"Отчёт по сканированию {scan_id} успешно сохранён в {output_path}")
