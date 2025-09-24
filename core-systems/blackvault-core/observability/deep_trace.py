import uuid
import json
import hashlib
import time
from typing import Dict, List, Optional
from threading import Lock

from blackvault_core.storage.trace_db import persist_trace_event, retrieve_trace_chain
from blackvault_core.security.identity import resolve_user_identity
from blackvault_core.forensic.case_manager import link_event_to_case
from blackvault_core.utils.hashing import fingerprint_event
from blackvault_core.alerting.notifier import send_alert

lock = Lock()


class DeepTrace:
    def __init__(self):
        self.chain_id: Optional[str] = None
        self.current_chain: List[Dict] = []

    def start_chain(self, label: str, metadata: Optional[Dict] = None) -> str:
        self.chain_id = str(uuid.uuid4())
        self.current_chain = []
        self._log_trace({
            "action": "START_CHAIN",
            "label": label,
            "metadata": metadata or {},
        })
        return self.chain_id

    def _log_trace(self, data: Dict, severity: str = "info"):
        identity = resolve_user_identity()
        event = {
            "timestamp": time.time(),
            "chain_id": self.chain_id,
            "user": identity.username,
            "uid": identity.uid,
            "data": data,
            "severity": severity,
            "event_fingerprint": fingerprint_event(data)
        }

        with lock:
            self.current_chain.append(event)

        persist_trace_event(event)

        if severity == "critical":
            send_alert({
                "type": "deep_trace_critical",
                "identity": identity.username,
                "event": data,
                "chain_id": self.chain_id,
                "severity": severity
            })

    def trace_event(self, event_name: str, payload: Dict, critical: bool = False):
        trace_payload = {
            "action": event_name,
            "payload": payload
        }
        self._log_trace(trace_payload, severity="critical" if critical else "info")

    def link_to_case(self, case_id: str):
        for evt in self.current_chain:
            link_event_to_case(case_id, evt["event_fingerprint"])

    def retrieve_chain(self, chain_id: str) -> List[Dict]:
        return retrieve_trace_chain(chain_id)

    def end_chain(self, summary: Optional[str] = None):
        self._log_trace({
            "action": "END_CHAIN",
            "summary": summary or "Trace completed."
        })
        self.chain_id = None
        self.current_chain = []

