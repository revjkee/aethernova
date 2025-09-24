import socket
import logging
import time
from datetime import datetime
from typing import List

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.threatfeeds.sinkhole_db import SinkholeDB
from blackvault_core.utils.tracing import trace_event
from blackvault_core.utils.net import get_active_dns_queries

LOG = logging.getLogger("DNSSinkholeTracker")

class DNSSinkholeTracker:
    def __init__(self, emitter: TelemetryEmitter, refresh_interval_sec: int = 30):
        self.emitter = emitter
        self.refresh_interval = refresh_interval_sec
        self.sinkhole_db = SinkholeDB.load()
        LOG.info("DNSSinkholeTracker initialized with %d sinkhole records.", len(self.sinkhole_db.entries))

    def start_monitoring(self):
        LOG.info("Starting DNS sinkhole tracking...")
        while True:
            try:
                suspicious_queries = self._scan_queries()
                for entry in suspicious_queries:
                    self._report(entry)
            except Exception as e:
                LOG.error("Error in DNS sinkhole tracking loop: %s", e)
            time.sleep(self.refresh_interval)

    def _scan_queries(self) -> List[dict]:
        active_queries = get_active_dns_queries()
        suspicious = []
        for q in active_queries:
            if self.sinkhole_db.match(q["ip"]) or self.sinkhole_db.match(q["domain"]):
                suspicious.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "domain": q["domain"],
                    "ip": q["ip"],
                    "detected_by": "DNSSinkholeTracker",
                    "resolver": q["resolver"],
                    "raw": q
                })
        return suspicious

    def _report(self, entry: dict):
        msg = f"Sinkhole DNS detection: {entry['domain']} resolved to {entry['ip']}"
        LOG.warning(msg)
        self.emitter.emit({
            "event": "dns_sinkhole_access",
            "message": msg,
            **entry
        })
        raise_alert("dns_sinkhole_contact", entry)
        trace_event("sinkhole_triggered", entry)
