# -*- coding: utf-8 -*-
"""
report_pdf.py
Модуль генерации PDF-отчётов для Wapiti Scanner
"""

import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import mm

class ReportPDF:
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
        Генерирует и сохраняет PDF отчет
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        filename = os.path.join(self.output_dir, "wapiti_report.pdf")
        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Heading1Center', parent=styles['Heading1'], alignment=1))
        styles.add(ParagraphStyle(name='Small', fontSize=8, leading=10))

        elements = []

        # Заголовок
        elements.append(Paragraph("Wapiti Scanner Report", styles['Heading1Center']))
        elements.append(Spacer(1, 12))

        # Информация о сканировании
        scan_info_table_data = [
            ['Target:', self.scan_info.get('target', 'Неизвестно')],
            ['Start Time:', str(self.scan_info.get('start_time', 'Неизвестно'))],
            ['End Time:', str(self.scan_info.get('end_time', 'Неизвестно'))],
            ['Scanner Version:', self.scan_info.get('version', 'N/A')],
            ['Report Generated:', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        table = Table(scan_info_table_data, hAlign='LEFT', colWidths=[100*mm, 80*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Секция уязвимостей
        elements.append(Paragraph("Vulnerabilities Found:", styles['Heading2']))
        elements.append(Spacer(1, 12))

        if not self.vulnerabilities:
            elements.append(Paragraph("No vulnerabilities found during the scan.", styles['Normal']))
        else:
            for i, vuln in enumerate(self.vulnerabilities, start=1):
                elements.append(Paragraph(f"{i}. {vuln.get('name', 'Unnamed vulnerability')} (Severity: {vuln.get('severity', 'N/A')})", styles['Heading3']))
                elements.append(Spacer(1, 4))
                details = (
                    f"<b>URL:</b> {vuln.get('url', '')}<br/>"
                    f"<b>Method:</b> {vuln.get('method', '')}<br/>"
                    f"<b>Parameter:</b> {vuln.get('param', '')}<br/>"
                    f"<b>Description:</b> {vuln.get('description', '')}<br/>"
                    f"<b>Evidence:</b> {vuln.get('evidence', '')}"
                )
                elements.append(Paragraph(details, styles['Normal']))
                elements.append(Spacer(1, 12))

        doc.build(elements)
        return filename
