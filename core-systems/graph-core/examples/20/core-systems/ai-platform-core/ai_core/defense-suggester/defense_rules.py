import json
import logging
import uuid
from typing import List, Dict, Optional
from datetime import datetime

from genius-core/genius-core-security/defense/policy_enforcer import apply_defense_policy
from genius-core/meta-awareness/system_consistency_checker import check_defense_consistency
from platform-security/enforcement/signature_base import get_attack_signatures
from logging/ueba/anomaly_detector import analyze_behavior_pattern

# === TeslaAI Defense Engine v3.4 ===
# Agents: RuleSynthesizer, PatternMatcher, CoverageAnalyzer, ThreatBinder,
# PolicyComposer, SignatureIntegrator, ImpactScorer, EnforcementPlanner,
# RuleOptimizer, MutationResistantizer, FeedbackInjector, RelevanceSorter,
# SandboxTester, ScenarioAligner, ConflictResolver, SimulationObserver,
# MITRECrosslinker, LogAdapter, RedTeamTracer, AutoExporter
# MetaGenerals: Guardian, Architectus, Evolver

logger = logging.getLogger("defense_rules")
logger.setLevel(logging.INFO)


class DefenseRule:
    def __init__(self, rule_id: Optional[str] = None):
        self.rule_id = rule_id or str(uuid.uuid4())
        self.created_at = datetime.utcnow().isoformat()
        self.trigger: str = ""
        self.response: str = ""
        self.conditions: Dict[str, str] = {}
        self.severity: str = "low"
        self.source: str = "ai-core/defense-suggester"
        self.tags: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "created_at": self.created_at,
            "trigger": self.trigger,
            "response": self.response,
            "conditions": self.conditions,
            "severity": self.severity,
            "source": self.source,
            "tags": self.tags,
        }


class DefenseRuleGenerator:
    def __init__(self):
        self.known_signatures = get_attack_signatures()

    def generate_rules_from_logs(self, event_logs: List[Dict]) -> List[DefenseRule]:
        logger.info("Generating rules from event logs...")
        rules = []

        for event in event_logs:
            action = event.get("action", "")
            mitre_id = event.get("mitre_id", "")
            ioc = event.get("meta", {}).get("ioc", {})

            if action in self.known_signatures:
                rule = self._generate_signature_based_rule(action, mitre_id, ioc)
                rules.append(rule)
            else:
                rule = self._generate_behavioral_rule(event)
                rules.append(rule)

        logger.info(f"Generated {len(rules)} rules")
        return rules

    def _generate_signature_based_rule(self, action: str, mitre_id: str, ioc: Dict) -> DefenseRule:
        rule = DefenseRule()
        rule.trigger = f"signature:{action}"
        rule.response = "block_and_alert"
        rule.conditions = ioc
        rule.severity = self._map_severity(mitre_id)
        rule.tags = [mitre_id, "signature"]
        logger.debug(f"Generated signature-based rule for action: {action}")
        return rule

    def _generate_behavioral_rule(self, event: Dict) -> DefenseRule:
        rule = DefenseRule()
        pattern = analyze_behavior_pattern(event)
        rule.trigger = f"behavior:{pattern.get('behavior_type', 'unknown')}"
        rule.response = "alert_and_monitor"
        rule.conditions = pattern.get("conditions", {})
        rule.severity = pattern.get("risk", "medium")
        rule.tags = [event.get("mitre_id", "T0000"), "behavior"]
        logger.debug(f"Generated behavioral rule from event: {event.get('action')}")
        return rule

    def _map_severity(self, mitre_id: str) -> str:
        high = {"T1078", "T1041", "T1068", "T1486"}
        medium = {"T1046", "T1021", "T1059", "T1105"}
        if mitre_id in high:
            return "high"
        elif mitre_id in medium:
            return "medium"
        return "low"

    def optimize_ruleset(self, rules: List[DefenseRule]) -> List[DefenseRule]:
        logger.info("Optimizing ruleset for redundancy and coverage...")
        unique = {}
        for rule in rules:
            key = (rule.trigger, json.dumps(rule.conditions, sort_keys=True))
            if key not in unique:
                unique[key] = rule
        return list(unique.values())

    def apply_rules(self, rules: List[DefenseRule]):
        logger.info("Applying rules via policy enforcer...")
        for rule in rules:
            apply_defense_policy(rule.to_dict())

    def export_rules(self, rules: List[DefenseRule], path: str):
        logger.info(f"Exporting rules to {path}")
        with open(path, "w") as f:
            json.dump([r.to_dict() for r in rules], f, indent=2)

    def validate_rules(self, rules: List[DefenseRule]) -> Dict[str, Any]:
        logger.info("Validating rules for architectural consistency...")
        serialized = [r.to_dict() for r in rules]
        return check_defense_consistency(serialized)
