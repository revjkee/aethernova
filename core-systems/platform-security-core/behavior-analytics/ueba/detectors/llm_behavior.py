# ueba/detectors/llm_behavior.py

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from ueba.features.session_features import extract_session_metadata
from ueba.alerts.ueba_alerts import generate_alert
from ueba.config.thresholds import RULE_THRESHOLDS
from ueba.detectors.zt_baselines import ZeroTrustProfile

logger = logging.getLogger("ueba.llm_behavior")

SUSPICIOUS_KEYWORDS = [
    "os.system", "subprocess", "eval", "exec", "rm -rf", "curl", "wget", "base64",
    "fork", "socket", "import pty", "shadow", "passwd", "api_key", "token"
]

MAX_PROMPT_LENGTH = 2048
FREQUENT_CALL_WINDOW_SEC = 30
MAX_CALLS_PER_WINDOW = 10

class LLMBehaviorContext:
    def __init__(self, agent_id: str, input_text: str, session: Dict[str, Any], timestamp: Optional[datetime] = None):
        self.agent_id = agent_id
        self.input_text = input_text
        self.session = session
        self.timestamp = timestamp or datetime.utcnow()
        self.risk_score = 0
        self.violations: List[str] = []
        self.zt_profile = ZeroTrustProfile(session)

    def add_violation(self, tag: str, score: int):
        self.risk_score += score
        self.violations.append(tag)
        logger.debug(f"[LLM] Violation '{tag}' (+{score}) — risk={self.risk_score}")

    def is_high_risk(self) -> bool:
        return self.risk_score >= RULE_THRESHOLDS.get("llm_risk_alert_level", 50)

def detect_suspicious_keywords(ctx: LLMBehaviorContext):
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in ctx.input_text.lower():
            ctx.add_violation(f"Keyword:{keyword}", 15)

def detect_prompt_length(ctx: LLMBehaviorContext):
    if len(ctx.input_text) > MAX_PROMPT_LENGTH:
        ctx.add_violation("ExcessivePromptLength", 10)

def detect_anomalous_behavior(ctx: LLMBehaviorContext):
    if not ctx.zt_profile.is_within_trust(ctx.session):
        ctx.add_violation("OutsideZT", 25)

def detect_rapid_fire(ctx: LLMBehaviorContext, call_history: List[datetime]):
    now = ctx.timestamp
    recent_calls = [t for t in call_history if (now - t).total_seconds() <= FREQUENT_CALL_WINDOW_SEC]
    if len(recent_calls) >= MAX_CALLS_PER_WINDOW:
        ctx.add_violation("RapidFireLLM", 20)

def evaluate_llm_behavior(agent_id: str, input_text: str, session: Dict[str, Any], call_history: List[datetime]) -> LLMBehaviorContext:
    ctx = LLMBehaviorContext(agent_id, input_text, session)

    detect_suspicious_keywords(ctx)
    detect_prompt_length(ctx)
    detect_anomalous_behavior(ctx)
    detect_rapid_fire(ctx, call_history)

    if ctx.is_high_risk():
        generate_alert(
            actor=agent_id,
            risk_score=ctx.risk_score,
            rules=ctx.violations,
            timestamp=ctx.timestamp,
            source="llm"
        )
    return ctx
