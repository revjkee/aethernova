# red_battle_controller.py

from enum import Enum, auto
from typing import List, Dict, Any
from datetime import datetime

from ..intel.feed_loader import CVEFeedParser
from ..strategy.attack_graph_engine import AttackGraphExecutor
from ..payloads.exploit_deployer import ExploitDeployer
from ..telemetry.simulation_logger import SimulationLogger

class RedPhase(Enum):
    PREPARATION = auto()
    SCANNING = auto()
    EXPLOIT_DEPLOYMENT = auto()
    POST_EXPLOIT_ACTION = auto()
    ESCALATION = auto()
    PERSISTENCE = auto()
    COVER_TRACKS = auto()
    COMPLETED = auto()

class RedBattleController:
    def __init__(self, session_id: str, target_profile: Dict[str, Any]):
        self.session_id = session_id
        self.phase = RedPhase.PREPARATION
        self.cve_parser = CVEFeedParser()
        self.attack_engine = AttackGraphExecutor()
        self.exploit_toolkit = ExploitDeployer()
        self.logger = SimulationLogger(session_id)
        self.target_profile = target_profile
        self.history: List[Dict[str, Any]] = []

    def advance(self):
        if self.phase == RedPhase.PREPARATION:
            self._prepare_campaign()
            self.phase = RedPhase.SCANNING

        elif self.phase == RedPhase.SCANNING:
            self._scan_targets()
            self.phase = RedPhase.EXPLOIT_DEPLOYMENT

        elif self.phase == RedPhase.EXPLOIT_DEPLOYMENT:
            self._deploy_exploits()
            self.phase = RedPhase.POST_EXPLOIT_ACTION

        elif self.phase == RedPhase.POST_EXPLOIT_ACTION:
            self._post_exploitation()
            self.phase = RedPhase.ESCALATION

        elif self.phase == RedPhase.ESCALATION:
            self._privilege_escalation()
            self.phase = RedPhase.PERSISTENCE

        elif self.phase == RedPhase.PERSISTENCE:
            self._install_backdoors()
            self.phase = RedPhase.COVER_TRACKS

        elif self.phase == RedPhase.COVER_TRACKS:
            self._cover_tracks()
            self.phase = RedPhase.COMPLETED

        self.logger.log_phase(self.phase.name, datetime.utcnow().isoformat())

    def _prepare_campaign(self):
        cve_list = self.cve_parser.fetch_relevant_cves(self.target_profile["os"], self.target_profile["services"])
        self.history.append({"phase": "PREPARATION", "cves": cve_list})
        self.logger.log_event("PREPARATION", f"Loaded {len(cve_list)} CVEs")

    def _scan_targets(self):
        open_ports = self.attack_engine.perform_scan(self.target_profile["ip"])
        self.history.append({"phase": "SCANNING", "ports": open_ports})
        self.logger.log_event("SCANNING", f"Open ports detected: {open_ports}")

    def _deploy_exploits(self):
        results = self.exploit_toolkit.deploy(self.target_profile["ip"], self.history[-2]["ports"])
        self.history.append({"phase": "EXPLOIT_DEPLOYMENT", "results": results})
        self.logger.log_event("EXPLOIT", f"Exploits deployed: {results}")

    def _post_exploitation(self):
        data_exfil = self.attack_engine.perform_data_exfil(self.target_profile["ip"])
        self.history.append({"phase": "POST_EXPLOIT_ACTION", "exfiltrated_data": data_exfil})
        self.logger.log_event("EXFIL", f"Data exfiltrated: {data_exfil}")

    def _privilege_escalation(self):
        escalation_result = self.attack_engine.perform_privilege_escalation(self.target_profile["ip"])
        self.history.append({"phase": "ESCALATION", "result": escalation_result})
        self.logger.log_event("ESCALATE", f"Privilege escalation result: {escalation_result}")

    def _install_backdoors(self):
        backdoor_status = self.exploit_toolkit.install_persistence_tools(self.target_profile["ip"])
        self.history.append({"phase": "PERSISTENCE", "status": backdoor_status})
        self.logger.log_event("PERSISTENCE", f"Persistence mechanisms installed: {backdoor_status}")

    def _cover_tracks(self):
        cleanup = self.attack_engine.clean_logs(self.target_profile["ip"])
        self.history.append({"phase": "COVER_TRACKS", "actions": cleanup})
        self.logger.log_event("COVER", f"Tracks covered: {cleanup}")
