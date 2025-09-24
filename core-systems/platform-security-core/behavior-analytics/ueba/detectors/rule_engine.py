# ueba/detectors/rule_engine.py

import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Callable, Optional, Any

from ueba.alerts.ueba_alerts import generate_alert
from ueba.config.thresholds import RULE_THRESHOLDS
from ueba.detectors.zt_baselines import ZeroTrustProfile
from ueba.features.session_features import extract_session_metadata

logger = logging.getLogger("ueba.rule_engine")

class RuleContext:
    def __init__(self, session_data: Dict[str, Any], timestamp: datetime):
        self.session_data = session_data
        self.timestamp = timestamp
        self.risk_score = 0
        self.violated_rules = []
        self.trusted_baseline = ZeroTrustProfile(session_data)

    def add_violation(self, rule_name: str, weight: int):
        logger.debug(f"Rule violated: {rule_name} (+{weight})")
        self.risk_score += weight
        self.violated_rules.append(rule_name)

class UEBA_Rule:
    def __init__(
        self,
        name: str,
        condition: Callable[[RuleContext], bool],
        weight: int,
        tags: Optional[List[str]] = None,
    ):
        self.name = name
        self.condition = condition
        self.weight = weight
        self.tags = tags or []

    def evaluate(self, context: RuleContext) -> bool:
        try:
            if self.condition(context):
                context.add_violation(self.name, self.weight)
                return True
        except Exception as e:
            logger.warning(f"Rule {self.name} evaluation error: {e}")
        return False

class RuleEngine:
    def __init__(self):
        self.rules: List[UEBA_Rule] = []

    def register_rule(self, rule: UEBA_Rule):
        logger.info(f"Registering rule: {rule.name}")
        self.rules.append(rule)

    def evaluate_session(self, session_data: Dict[str, Any], timestamp: datetime = None):
        context = RuleContext(session_data, timestamp or datetime.utcnow())
        for rule in self.rules:
            rule.evaluate(context)

        if context.risk_score >= RULE_THRESHOLDS.get("risk_alert_level", 50):
            logger.info(f"ALERT TRIGGERED: score={context.risk_score}, rules={context.violated_rules}")
            generate_alert(
                actor=context.session_data.get("user_id", "unknown"),
                risk_score=context.risk_score,
                rules=context.violated_rules,
                timestamp=context.timestamp,
            )
        return context

# ========================
# Built-in Rule Examples
# ========================

def excessive_token_use(ctx: RuleContext) -> bool:
    return ctx.session_data.get("token_use", 0) > 3000

def access_outside_baseline(ctx: RuleContext) -> bool:
    return not ctx.trusted_baseline.is_within_trust(ctx.session_data)

def suspicious_country(ctx: RuleContext) -> bool:
    return ctx.session_data.get("country") in {"KP", "IR", "RU"}

def repeated_failed_attempts(ctx: RuleContext) -> bool:
    return ctx.session_data.get("failed_logins", 0) > 10

# ========================
# Rule Registration
# ========================

rule_engine = RuleEngine()

rule_engine.register_rule(
    UEBA_Rule("ExcessiveTokenUse", excessive_token_use, weight=20, tags=["tokens", "llm"])
)

rule_engine.register_rule(
    UEBA_Rule("OutsideZeroTrustBaseline", access_outside_baseline, weight=25, tags=["zt", "location"])
)

rule_engine.register_rule(
    UEBA_Rule("BlockedCountryAccess", suspicious_country, weight=40, tags=["geoip", "access"])
)

rule_engine.register_rule(
    UEBA_Rule("RepeatedLoginFailures", repeated_failed_attempts, weight=15, tags=["auth"])
)
