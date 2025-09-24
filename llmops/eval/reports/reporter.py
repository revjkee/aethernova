import json
import os
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from jinja2 import Environment, FileSystemLoader

from ..utils import save_json, save_markdown, logger
from .metrics_aggregator import aggregate_metrics
from ..constants import EVAL_REPORTS_DIR, DEFAULT_OUTPUT_FORMATS


class EvaluationReporter:
    def __init__(
        self,
        report_dir: Optional[Union[str, Path]] = None,
        formats: Optional[List[str]] = None,
    ):
        self.report_dir = Path(report_dir or EVAL_REPORTS_DIR)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.formats = formats or DEFAULT_OUTPUT_FORMATS
        self.env = Environment(
            loader=FileSystemLoader(searchpath=str(Path(__file__).parent / "templates")),
            autoescape=True
        )

    def build_report_filename(self, model_name: str, extension: str) -> Path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{model_name}_report_{timestamp}.{extension}"
        return self.report_dir / filename

    def generate(
        self,
        model_name: str,
        raw_results: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Path]:
        logger.info(f"Starting report generation for: {model_name}")
        aggregated = aggregate_metrics(raw_results)

        report_payload = {
            "model": model_name,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "summary": aggregated,
            "raw_results": raw_results,
            "metadata": metadata or {}
        }

        output_paths: Dict[str, Path] = {}

        if "json" in self.formats:
            json_path = self.build_report_filename(model_name, "json")
            save_json(report_payload, json_path)
            output_paths["json"] = json_path
            logger.debug(f"Saved JSON report to {json_path}")

        if "md" in self.formats:
            md_path = self.build_report_filename(model_name, "md")
            markdown = self._render_markdown(report_payload)
            save_markdown(markdown, md_path)
            output_paths["md"] = md_path
            logger.debug(f"Saved Markdown report to {md_path}")

        if "html" in self.formats:
            html_path = self.build_report_filename(model_name, "html")
            html = self._render_html(report_payload)
            html.write_text(html_path, encoding="utf-8")
            output_paths["html"] = html_path
            logger.debug(f"Saved HTML report to {html_path}")

        logger.info(f"Report generation complete. Outputs: {output_paths}")
        return output_paths

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        template = self.env.get_template("report.md.j2")
        return template.render(data=data)

    def _render_html(self, data: Dict[str, Any]) -> str:
        template = self.env.get_template("report.html.j2")
        return template.render(data=data)
