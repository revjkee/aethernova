import subprocess
import logging
import re
from datetime import datetime
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("ShadowcopyAuditor")

VSS_QUERY_COMMAND = ["powershell.exe", "-Command", "Get-WmiObject Win32_ShadowCopy | Select-Object -Property ID,VolumeName,InstallDate"]
VSS_DELETE_COMMAND_REGEX = re.compile(r"vssadmin\s+delete\s+shadows", re.IGNORECASE)
EVENT_LOG_QUERY_COMMAND = [
    "powershell.exe",
    "-Command",
    "Get-WinEvent -LogName Security -MaxEvents 100 | "
    "Where-Object { $_.Message -match 'vssadmin' -or $_.Message -match 'shadowcopy' } | "
    "Select-Object -Property TimeCreated,Message"
]

class ShadowcopyAuditor:
    def __init__(self, emitter: TelemetryEmitter):
        self.emitter = emitter
        LOG.info("ShadowcopyAuditor initialized.")

    def run_audit(self):
        LOG.info("Starting VSS audit")
        self._check_shadowcopies()
        self._scan_event_logs()

    def _check_shadowcopies(self):
        try:
            result = subprocess.run(VSS_QUERY_COMMAND, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
            if not output or "ID" not in output:
                self._report_missing_copies()
            else:
                LOG.debug("Shadow copies found.")
        except Exception as e:
            LOG.warning(f"Failed to query shadow copies: {e}")

    def _report_missing_copies(self):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "shadowcopy_missing",
            "message": "No shadow copies found; potential deletion",
            "detected_by": "ShadowcopyAuditor"
        }
        LOG.warning(f"[ALERT] {alert}")
        self.emitter.emit(alert)
        raise_alert("vss_delete_suspected", alert)
        trace_event("shadowcopy_deleted", alert)

    def _scan_event_logs(self):
        try:
            result = subprocess.run(EVENT_LOG_QUERY_COMMAND, capture_output=True, text=True, timeout=15)
            logs = result.stdout.strip().splitlines()
            for line in logs:
                if VSS_DELETE_COMMAND_REGEX.search(line):
                    self._report_deletion_attempt(line)
        except Exception as e:
            LOG.warning(f"Failed to scan event logs: {e}")

    def _report_deletion_attempt(self, message: str):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "shadowcopy_deletion_attempt",
            "message": message,
            "detected_by": "ShadowcopyAuditor"
        }
        LOG.warning(f"[ALERT] {alert}")
        self.emitter.emit(alert)
        raise_alert("vss_delete_attempt", alert)
        trace_event("shadowcopy_deletion_detected", alert)
