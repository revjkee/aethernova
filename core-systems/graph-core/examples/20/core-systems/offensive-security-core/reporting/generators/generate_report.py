import os
import json
import yaml
import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from reportlab.pdfgen import canvas
from rich.console import Console
from rich.table import Table
from rich import box

from ..mitre_mapping.mappings import load_mitre_rules
from ..mitre_mapping.ai_reasoning import generate_ai_diagnostics
from ..utils.logger import get_logger
from ..utils.security_hash import verify_integrity

logger = get_logger("ReportGenerator")

class ReportGenerator:
    def __init__(self, input_data_path, output_dir, template_dir="templates"):
        self.input_path = Path(input_data_path)
        self.output_dir = Path(output_dir)
        self.template_env = Environment(loader=FileSystemLoader(template_dir))
        self.console = Console()

    def load_threat_data(self):
        with open(self.input_path, 'r') as f:
            if self.input_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(f)
            return json.load(f)

    def validate_data(self, data):
        # Проверка хешей целостности
        if not verify_integrity(data):
            raise ValueError("Data failed integrity verification")
        logger.info("Data passed integrity check")
        return True

    def enrich_with_mitre_mapping(self, data):
        mitre_rules = load_mitre_rules()
        for entry in data.get("events", []):
            for rule in mitre_rules:
                if rule.matches(entry):
                    entry["mitre_techniques"] = rule.get_techniques()
        return data

    def add_ai_diagnostics(self, data):
        for entry in data.get("events", []):
            entry["ai_analysis"] = generate_ai_diagnostics(entry)
        return data

    def render_html(self, data):
        template = self.template_env.get_template("report.html.j2")
        return template.render(data=data)

    def export_html(self, rendered_html):
        output_file = self.output_dir / f"threat_report_{self.timestamp()}.html"
        output_file.write_text(rendered_html, encoding="utf-8")
        logger.info(f"HTML report saved to {output_file}")
        return output_file

    def export_pdf(self, data):
        pdf_file = self.output_dir / f"threat_report_{self.timestamp()}.pdf"
        c = canvas.Canvas(str(pdf_file))
        c.setFont("Helvetica", 12)
        y = 800
        for event in data.get("events", []):
            c.drawString(50, y, f"Event: {event.get('id', 'N/A')}")
            y -= 20
            for k, v in event.items():
                if k != "id":
                    c.drawString(70, y, f"{k}: {v}")
                    y -= 15
            y -= 10
        c.save()
        logger.info(f"PDF report saved to {pdf_file}")
        return pdf_file

    def export_json(self, data):
        json_file = self.output_dir / f"threat_report_{self.timestamp()}.json"
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"JSON report saved to {json_file}")
        return json_file

    def display_console_summary(self, data):
        table = Table(title="Threat Events Summary", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Event ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="magenta")
        table.add_column("AI Flag", style="green")
        for event in data.get("events", []):
            table.add_row(
                str(event.get("id", "N/A")),
                str(event.get("severity", "N/A")),
                str(event.get("ai_analysis", {}).get("flag", "N/A"))
            )
        self.console.print(table)

    def generate(self):
        logger.info("Starting report generation")
        data = self.load_threat_data()
        self.validate_data(data)
        data = self.enrich_with_mitre_mapping(data)
        data = self.add_ai_diagnostics(data)
        self.display_console_summary(data)
        rendered_html = self.render_html(data)
        self.export_html(rendered_html)
        self.export_pdf(data)
        self.export_json(data)

    def timestamp(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# CLI entry point
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate AI-enhanced MITRE Threat Report")
    parser.add_argument("--input", required=True, help="Path to input threat data file (.json/.yaml)")
    parser.add_argument("--output", required=True, help="Directory to store generated reports")
    args = parser.parse_args()

    generator = ReportGenerator(input_data_path=args.input, output_dir=args.output)
    generator.generate()
