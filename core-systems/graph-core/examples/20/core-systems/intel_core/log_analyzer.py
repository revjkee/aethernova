import re
import hashlib
import json
from typing import List, Dict, Any
from datetime import datetime
from intel_core.security.signature_verifier import verify_log_signature
from intel_core.detection.patterns import load_threat_signatures
from intel_core.analytics.behavioral_model import analyze_behavior
from intel_core.analytics.anomaly_scoring import score_log_entry
from intel_core.utils.timezone import utc_now
from intel_core.audit.logger import intel_audit_log
from intel_core.streaming.log_buffer import LogBuffer
from intel_core.validation.schema_validator import validate_log_schema
from intel_core.metadata.parser import extract_metadata
from intel_core.intel_tags.detector import tag_log_entry

THREAT_SIGNATURES = load_threat_signatures()
log_buffer = LogBuffer(size=10000)

class LogAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mode = config.get("mode", "full")  # full, fast, forensic
        self.verify_signature = config.get("verify_signature", True)
        self.enable_behavioral = config.get("enable_behavioral", True)
        self.anomaly_threshold = config.get("anomaly_threshold", 0.75)

    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []

        for raw_entry in logs:
            try:
                validate_log_schema(raw_entry)
                if self.verify_signature and not verify_log_signature(raw_entry):
                    intel_audit_log("log_signature_failed", {"entry": raw_entry})
                    continue

                enriched = self._enrich_log(raw_entry)
                threat_matches = self._match_threat_signatures(enriched)
                anomaly_score = score_log_entry(enriched)

                if self.enable_behavioral:
                    behavior_flags = analyze_behavior(enriched)
                    enriched["behavioral_flags"] = behavior_flags

                enriched["anomaly_score"] = anomaly_score
                enriched["threat_matches"] = threat_matches
                enriched["timestamp_analyzed"] = utc_now().isoformat()

                if anomaly_score > self.anomaly_threshold or threat_matches or behavior_flags:
                    intel_audit_log("log_flagged", {"entry": enriched})

                tag_log_entry(enriched)
                log_buffer.add(enriched)
                results.append(enriched)

            except Exception as e:
                intel_audit_log("log_analysis_failed", {
                    "error": str(e),
                    "raw_entry": raw_entry
                })

        return results

    def _enrich_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        log["checksum"] = hashlib.sha512(json.dumps(log, sort_keys=True).encode()).hexdigest()
        log["metadata"] = extract_metadata(log)
        return log

    def _match_threat_signatures(self, log: Dict[str, Any]) -> List[str]:
        matches = []
        for pattern_id, regex in THREAT_SIGNATURES.items():
            if any(re.search(regex, str(value)) for value in log.values()):
                matches.append(pattern_id)
        return matches
