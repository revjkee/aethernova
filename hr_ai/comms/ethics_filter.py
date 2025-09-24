import logging
from typing import List, Dict, Any
from hr_ai.security.input_validator import sanitize_text
from hr_ai.compliance.ethical_rules import ETHICAL_BLOCKLIST, SENSITIVE_TOPICS
from hr_ai.compliance.bias_detector import detect_bias, BiasSeverity
from hr_ai.compliance.intent_validator import is_malicious_intent

logger = logging.getLogger("EthicsFilter")
logger.setLevel(logging.INFO)

class EthicsFilter:
    def __init__(self, language: str = "en"):
        self.language = language

    def analyze(self, text: str) -> Dict[str, Any]:
        clean_text = sanitize_text(text)
        result = {
            "approved": True,
            "violations": [],
            "severity": "none"
        }

        for keyword in ETHICAL_BLOCKLIST.get(self.language, []):
            if keyword.lower() in clean_text.lower():
                result["violations"].append(f"prohibited: '{keyword}'")
                result["approved"] = False

        for topic in SENSITIVE_TOPICS.get(self.language, []):
            if topic.lower() in clean_text.lower():
                result["violations"].append(f"sensitive: '{topic}'")

        if is_malicious_intent(clean_text):
            result["violations"].append("malicious intent detected")
            result["approved"] = False
            result["severity"] = "critical"

        bias_score, bias_details = detect_bias(clean_text)
        if bias_score >= BiasSeverity.MEDIUM:
            result["violations"].append(f"bias risk: {bias_details}")
            result["approved"] = False
            result["severity"] = "high"

        return result

    def filter_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        return [self.analyze(text) for text in texts]
