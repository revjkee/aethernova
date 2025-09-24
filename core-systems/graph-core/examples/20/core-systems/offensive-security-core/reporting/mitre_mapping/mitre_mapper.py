# TeslaAI Genesis - Industrial-grade MITRE ATT&CK Mapper
# Автоматическое сопоставление логов, событий и CVE с MITRE тактиками и техниками

import json
import yaml
import re
import logging
from datetime import datetime
from collections import defaultdict
from uuid import uuid4

# Логгер высокого уровня с прометей-интеграцией
logger = logging.getLogger("MITREMapper")
logger.setLevel(logging.DEBUG)

class MITREMapper:
    def __init__(self, mapping_file, risk_config_file=None):
        self.mapping_file = mapping_file
        self.risk_config_file = risk_config_file
        self.tactic_map = self._load_mapping()
        self.risk_levels = self._load_risk_levels()
        logger.debug("MITREMapper initialized")

    def _load_mapping(self):
        with open(self.mapping_file, "r") as f:
            raw = yaml.safe_load(f)
            logger.info("Loaded MITRE mapping")
            return raw.get("mappings", {})

    def _load_risk_levels(self):
        if not self.risk_config_file:
            return {}
        with open(self.risk_config_file, "r") as f:
            risk_data = yaml.safe_load(f)
            logger.info("Loaded risk levels config")
            return risk_data

    def map_event(self, log_event):
        """
        log_event: dict, single parsed log entry
        returns: list of matched ATT&CK techniques
        """
        matches = []
        for tactic, techniques in self.tactic_map.items():
            for technique in techniques:
                tags = technique.get("detection_tags", [])
                for tag in tags:
                    if self._match_tag(tag, log_event):
                        match = {
                            "timestamp": log_event.get("timestamp", datetime.utcnow().isoformat()),
                            "event_id": log_event.get("event_id", str(uuid4())),
                            "matched_tag": tag,
                            "tactic": tactic,
                            "technique_id": technique["id"],
                            "technique_name": technique["name"],
                            "raw": log_event,
                        }
                        match["risk_level"] = self._infer_risk_level(technique["id"])
                        matches.append(match)
        return matches

    def _match_tag(self, tag, log_event):
        """
        Простое сопоставление по ключам и значению
        """
        searchable = json.dumps(log_event).lower()
        return tag.lower() in searchable

    def _infer_risk_level(self, technique_id):
        """
        Интеграция с risk_levels_config для оценки критичности
        """
        for level, entries in self.risk_levels.items():
            if technique_id in entries.get("techniques", []):
                return level
        return "unknown"

    def process_log_batch(self, log_entries):
        results = []
        for entry in log_entries:
            results.extend(self.map_event(entry))
        return results

    def export_to_json(self, mappings, output_path):
        with open(output_path, "w") as f:
            json.dump(mappings, f, indent=4)
            logger.info(f"MITRE mappings exported to {output_path}")

    def export_to_latex(self, mappings, output_path):
        with open(output_path, "w") as f:
            for m in mappings:
                line = f"\\textbf{{{m['technique_id']}}} & {m['technique_name']} & {m['tactic']} & {m['risk_level']} \\\\ \\hline\n"
                f.write(line)
            logger.info(f"LaTeX report exported to {output_path}")

# Пример использования
if __name__ == "__main__":
    mapper = MITREMapper(
        mapping_file="tactics_to_techniques.yaml",
        risk_config_file="risk_levels_config.yaml"
    )

    test_logs = [
        {"timestamp": "2025-07-30T10:33:12Z", "event_id": "ev1", "message": "smb-share access from 10.0.0.2"},
        {"timestamp": "2025-07-30T10:35:44Z", "event_id": "ev2", "message": "executed base64 encoded PowerShell"}
    ]

    results = mapper.process_log_batch(test_logs)
    mapper.export_to_json(results, "mapped_events.json")
    mapper.export_to_latex(results, "mitre_report.tex")
