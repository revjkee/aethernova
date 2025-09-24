import os
import json
import datetime
from typing import List, Dict, Optional

from autopwn_core.shared.attack_context import AttackContext
from autopwn_core.shared.tactics_mapping import get_mitre_tactics
from autopwn_core.shared.markdown_utils import markdown_to_pdf, markdown_to_html
from autopwn_core.shared.audit_logger import get_events_by_session

class ReportFormatter:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx
        self.session_id = ctx.session_id
        self.report_dir = f"/tmp/autopwn/reports/{self.session_id}"
        os.makedirs(self.report_dir, exist_ok=True)
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def _build_timeline(self, events: List[Dict]) -> str:
        timeline = "| Time | Event | Details |\n|------|-------|---------|\n"
        for evt in sorted(events, key=lambda e: e["timestamp"]):
            t = evt["timestamp"]
            action = evt["action"]
            meta = json.dumps(evt.get("metadata", {}))[:100]
            timeline += f"| {t} | {action} | {meta} |\n"
        return timeline

    def _build_iocs(self, events: List[Dict]) -> str:
        iocs = set()
        for evt in events:
            meta = evt.get("metadata", {})
            for key in ["ip", "hash", "url", "domain", "filepath"]:
                if key in meta:
                    iocs.add(f"{key}: {meta[key]}")
        return "\n".join(f"- {ioc}" for ioc in sorted(iocs))

    def _generate_markdown(self, events: List[Dict]) -> str:
        tactics = get_mitre_tactics(events)
        md = f"# Autopwn Simulation Report\n\n"
        md += f"**Session ID:** `{self.session_id}`\n"
        md += f"**Target:** `{self.ctx.target_host}`\n"
        md += f"**Generated:** `{self.timestamp}`\n\n"
        md += f"## MITRE ATT&CK Coverage\n\n"
        for tactic, techniques in tactics.items():
            md += f"### {tactic}\n"
            for tech in techniques:
                md += f"- `{tech['id']}` {tech['name']}\n"
        md += "\n## Timeline of Events\n\n"
        md += self._build_timeline(events)
        md += "\n\n## Indicators of Compromise (IOCs)\n\n"
        md += self._build_iocs(events)
        return md

    def generate(self, format: str = "pdf") -> str:
        events = get_events_by_session(self.session_id)
        markdown_content = self._generate_markdown(events)
        base_path = os.path.join(self.report_dir, f"report_{self.timestamp}")
        if format == "pdf":
            output_path = f"{base_path}.pdf"
            markdown_to_pdf(markdown_content, output_path)
        elif format == "html":
            output_path = f"{base_path}.html"
            markdown_to_html(markdown_content, output_path)
        elif format == "md":
            output_path = f"{base_path}.md"
            with open(output_path, "w") as f:
                f.write(markdown_content)
        elif format == "json":
            output_path = f"{base_path}.json"
            with open(output_path, "w") as f:
                json.dump(events, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
        return output_path
