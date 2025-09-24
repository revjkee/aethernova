import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.security_hash import compute_sha256_hash

logger = get_logger("HTMLExporter")

class HTMLExporter:
    def __init__(self, template_dir="templates", output_dir="reports/html"):
        self.template_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def render_report(self, context_data, template_name="report.html.j2"):
        try:
            template = self.template_env.get_template(template_name)
            rendered = template.render(context_data)
            logger.debug(f"Rendered HTML from template: {template_name}")
            return rendered
        except Exception as e:
            logger.error(f"Error rendering HTML template: {e}")
            raise

    def export(self, context_data, report_name=None):
        report_name = report_name or f"ai_threat_report_{self._timestamp()}.html"
        rendered_html = self.render_report(context_data)
        output_path = self.output_dir / report_name

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rendered_html)

        integrity_hash = compute_sha256_hash(output_path)
        logger.info(f"HTML report exported to {output_path}")
        logger.info(f"SHA-256 Integrity: {integrity_hash}")

        return {
            "path": str(output_path),
            "integrity_sha256": integrity_hash,
            "timestamp": self._timestamp()
        }

    def _timestamp(self):
        return datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
