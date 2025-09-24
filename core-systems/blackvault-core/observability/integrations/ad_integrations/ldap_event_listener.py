import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional

from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.signature_engine import SignatureEngine
from blackvault_core.utils.auth_identity_map import resolve_sid_to_user
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("LDAPEventListener")

AD_DOMAIN = "corp.local"
AD_DC = "ad1.corp.local"
AD_USER = "audit_bot"
AD_PASS = "REDACTED"
BASE_DN = "DC=corp,DC=local"

EVENT_FILTER = "(objectClass=user)"

class LDAPEventListener:
    def __init__(self, emitter: TelemetryEmitter, engine: SignatureEngine):
        self.emitter = emitter
        self.engine = engine
        self.stop_event = threading.Event()
        self.worker = threading.Thread(target=self._watch_events, daemon=True)
        self.worker.start()
        LOG.info("LDAPEventListener started")

    def _watch_events(self):
        server = Server(AD_DC, get_info=ALL, use_ssl=True)
        conn = Connection(server, user=f"{AD_DOMAIN}\\{AD_USER}", password=AD_PASS, auto_bind=True)
        conn.search(BASE_DN, EVENT_FILTER, SUBTREE, attributes=["whenChanged", "sAMAccountName", "memberOf", "pwdLastSet", "lastLogonTimestamp", "userAccountControl", "objectGUID"])

        for entry in conn.entries:
            try:
                parsed_event = self._parse_entry(entry)
                if parsed_event:
                    trace_event("ldap_directory_event", parsed_event)
                    self.emitter.emit(parsed_event)
            except Exception as e:
                LOG.error(f"LDAP event parsing failed: {e}")

    def _parse_entry(self, entry) -> Optional[Dict[str, Any]]:
        username = entry.sAMAccountName.value
        timestamp = datetime.utcnow().isoformat()
        risk_score = 0
        event_tags = []

        # Example anomaly: frequent password resets
        if hasattr(entry, "pwdLastSet") and str(entry.pwdLastSet.value) == "0":
            event_tags.append("password_reset_detected")
            risk_score += 15

        if hasattr(entry, "userAccountControl"):
            uac = int(entry.userAccountControl.value)
            if uac & 0x0002:
                event_tags.append("account_disabled")
                risk_score += 10
            if uac & 0x10000:
                event_tags.append("password_never_expires")
                risk_score += 5

        if hasattr(entry, "memberOf"):
            groups = [str(g) for g in entry.memberOf]
            if any("Domain Admins" in g for g in groups):
                event_tags.append("privileged_account")
                risk_score += 20

        guid = str(entry.objectGUID)
        sid_resolved = resolve_sid_to_user(guid) if guid else None

        message = f"LDAP event: {username} modified. Tags: {event_tags}"

        # Signature-based detection
        if self.engine.detect_from_ldap_entry(entry):
            event_tags.append("sig:ldap_anomaly")
            risk_score += 30

        return {
            "timestamp": timestamp,
            "actor": username,
            "resolved_sid": sid_resolved,
            "event_tags": event_tags,
            "risk_score": risk_score,
            "source": "ldap_audit",
            "message": message,
            "classification": self._classify(risk_score)
        }

    def _classify(self, score: int) -> str:
        if score >= 40:
            return "critical"
        elif score >= 20:
            return "suspicious"
        return "normal"

    def shutdown(self):
        self.stop_event.set()
        LOG.info("LDAPEventListener shutting down")
