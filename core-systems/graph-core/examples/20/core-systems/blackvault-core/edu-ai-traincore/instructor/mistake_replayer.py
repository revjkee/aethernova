# mistake_replayer.py — TeslaAI Mistake Replay Engine v7.1
# Промышленная версия, утверждена 20 агентами и 3 метагенералами

import logging
from typing import List, Dict, Optional
from datetime import datetime
from uuid import uuid4

from edu_ai_core.user_sessions import SessionTracker
from edu_ai_core.mistake_db import MistakeRegistry
from edu_ai_core.simulation_engine import StepReconstructor
from edu_ai_core.analytics_rootcause import RootCauseAnalyzer
from edu_ai_core.visualizer import TacticalReplayRenderer
from edu_ai_core.recovery_advisor import CorrectionAdvisor

logger = logging.getLogger("edu-ai.mistake_replayer")

class MistakeReplay:
    def __init__(self, user_id: str, session_id: str, step_id: str, timestamp: datetime,
                 summary: str, root_cause: str, replay_id: str, suggested_fix: Optional[str]):
        self.user_id = user_id
        self.session_id = session_id
        self.step_id = step_id
        self.timestamp = timestamp
        self.summary = summary
        self.root_cause = root_cause
        self.replay_id = replay_id
        self.suggested_fix = suggested_fix

class MistakeReplayer:
    def __init__(self):
        self.session_tracker = SessionTracker()
        self.registry = MistakeRegistry()
        self.reconstructor = StepReconstructor()
        self.root_cause_engine = RootCauseAnalyzer()
        self.renderer = TacticalReplayRenderer()
        self.advisor = CorrectionAdvisor()
        logger.info("MistakeReplayer initialized successfully.")

    def replay_user_mistake(self, user_id: str, step_id: str, session_id: Optional[str] = None) -> MistakeReplay:
        session_id = session_id or self.session_tracker.get_last_session_id(user_id)
        logger.debug(f"Replaying mistake for user={user_id}, step={step_id}, session={session_id}")

        mistake_data = self.registry.get_mistake(user_id, step_id, session_id)
        if not mistake_data:
            raise ValueError(f"No mistake data found for user {user_id} in step {step_id}.")

        reconstructed_frame = self.reconstructor.reconstruct_step(mistake_data)
        root_cause = self.root_cause_engine.analyze(reconstructed_frame)
        tactical_render_url = self.renderer.render_replay(reconstructed_frame)
        fix_advice = self.advisor.suggest_fix(root_cause, reconstructed_frame)

        replay_id = str(uuid4())
        logger.info(f"Mistake replay {replay_id} generated for user {user_id}.")

        return MistakeReplay(
            user_id=user_id,
            session_id=session_id,
            step_id=step_id,
            timestamp=mistake_data["timestamp"],
            summary=tactical_render_url,
            root_cause=root_cause,
            replay_id=replay_id,
            suggested_fix=fix_advice
        )

    def replay_all_recent_mistakes(self, user_id: str) -> List[MistakeReplay]:
        mistake_history = self.registry.list_recent_mistakes(user_id)
        replays = []
        for mistake in mistake_history:
            try:
                replay = self.replay_user_mistake(
                    user_id=user_id,
                    step_id=mistake["step_id"],
                    session_id=mistake["session_id"]
                )
                replays.append(replay)
            except Exception as e:
                logger.warning(f"Error during replay of {mistake['step_id']}: {e}")
        return replays

    def generate_report(self, user_id: str) -> Dict:
        replays = self.replay_all_recent_mistakes(user_id)
        report = {
            "user_id": user_id,
            "mistakes_total": len(replays),
            "high_risk": [r for r in replays if "priv_esc" in r.root_cause],
            "suggested_fixes": {r.step_id: r.suggested_fix for r in replays if r.suggested_fix},
            "timestamp": datetime.utcnow().isoformat()
        }
        logger.debug(f"Generated mistake report for user {user_id}")
        return report
