# battle_controller.py

from typing import Dict, Any, Optional
from enum import Enum, auto
from datetime import datetime
from .scenario_orchestrator import ScenarioOrchestrator
from .red_team_emulator import RedTeamEmulator
from .blue_team_defender import BlueTeamDefender
from ..battle_metrics.event_timeline_tracker import EventTimelineTracker
from ..battle_metrics.kill_chain_visualizer import KillChainVisualizer

class BattlePhase(Enum):
    INITIALIZATION = auto()
    RECONNAISSANCE = auto()
    EXPLOITATION = auto()
    PERSISTENCE = auto()
    DETECTION = auto()
    RESPONSE = auto()
    FINALIZED = auto()

class BattleController:
    def __init__(self, session_id: str, scenario_config: Dict[str, Any]):
        self.session_id = session_id
        self.start_time = datetime.utcnow()
        self.scenario = ScenarioOrchestrator(scenario_config)
        self.red_team = RedTeamEmulator()
        self.blue_team = BlueTeamDefender()
        self.timeline = EventTimelineTracker(session_id=session_id)
        self.kill_chain = KillChainVisualizer(session_id=session_id)
        self.phase = BattlePhase.INITIALIZATION
        self.session_state: Dict[str, Any] = {}
        self.finished = False

    def initialize_battle(self):
        self.timeline.log_event("INIT", "Battle initialization started.")
        self.scenario.prepare_environment()
        self.red_team.configure(self.scenario.red_config)
        self.blue_team.configure(self.scenario.blue_config)
        self.phase = BattlePhase.RECONNAISSANCE
        self.timeline.log_event("READY", "Red and Blue teams are ready.")

    def advance_phase(self):
        if self.phase == BattlePhase.RECONNAISSANCE:
            self._execute_reconnaissance()
            self.phase = BattlePhase.EXPLOITATION

        elif self.phase == BattlePhase.EXPLOITATION:
            self._execute_exploitation()
            self.phase = BattlePhase.PERSISTENCE

        elif self.phase == BattlePhase.PERSISTENCE:
            self._execute_persistence()
            self.phase = BattlePhase.DETECTION

        elif self.phase == BattlePhase.DETECTION:
            self._execute_detection()
            self.phase = BattlePhase.RESPONSE

        elif self.phase == BattlePhase.RESPONSE:
            self._execute_response()
            self.phase = BattlePhase.FINALIZED
            self.finalize_battle()

    def _execute_reconnaissance(self):
        red_actions = self.red_team.perform_recon()
        self.timeline.log_event("RECON", f"Red team actions: {red_actions}")
        self.kill_chain.capture_phase("Recon", red_actions)

    def _execute_exploitation(self):
        exploits = self.red_team.launch_exploits()
        self.timeline.log_event("EXPLOIT", f"Exploits launched: {exploits}")
        self.kill_chain.capture_phase("Exploit", exploits)

    def _execute_persistence(self):
        persistence_methods = self.red_team.maintain_access()
        self.timeline.log_event("PERSIST", f"Persistence achieved: {persistence_methods}")
        self.kill_chain.capture_phase("Persistence", persistence_methods)

    def _execute_detection(self):
        detections = self.blue_team.detect_intrusions()
        self.timeline.log_event("DETECT", f"Detections: {detections}")
        self.kill_chain.capture_phase("Detection", detections)

    def _execute_response(self):
        responses = self.blue_team.respond_to_threats()
        self.timeline.log_event("RESPOND", f"Response actions: {responses}")
        self.kill_chain.capture_phase("Response", responses)

    def finalize_battle(self):
        self.timeline.log_event("FINISH", "Battle session finalized.")
        self.finished = True
        self.kill_chain.finalize_visualization()
        self._store_final_state()

    def _store_final_state(self):
        self.session_state["end_time"] = datetime.utcnow().isoformat()
        self.session_state["kill_chain"] = self.kill_chain.export_data()
        self.session_state["events"] = self.timeline.export_events()
        self.timeline.log_event("STORED", "Session state stored.")
