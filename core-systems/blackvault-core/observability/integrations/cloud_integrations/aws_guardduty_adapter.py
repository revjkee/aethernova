import boto3
import logging
import threading
import time
from botocore.exceptions import BotoCoreError, ClientError
from blackvault_core.security.alerts import raise_alert
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.crypto import secure_log
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("AWSGuardDutyAdapter")

class AWSGuardDutyAdapter:
    def __init__(self, region_name="us-east-1", poll_interval=60, telemetry_emitter: TelemetryEmitter = None):
        self.region = region_name
        self.poll_interval = poll_interval
        self.client = boto3.client("guardduty", region_name=region_name)
        self.detector_id = None
        self.running = False
        self.emitter = telemetry_emitter or TelemetryEmitter()

    def start(self):
        try:
            self.detector_id = self._get_detector_id()
        except Exception as e:
            LOG.error("Failed to retrieve GuardDuty detector ID: %s", e)
            return

        self.running = True
        threading.Thread(target=self._poll_findings, daemon=True).start()
        LOG.info("AWSGuardDutyAdapter started in region: %s", self.region)

    def stop(self):
        self.running = False
        LOG.info("AWSGuardDutyAdapter stopped.")

    def _get_detector_id(self):
        response = self.client.list_detectors()
        detector_ids = response.get("DetectorIds", [])
        if not detector_ids:
            raise RuntimeError("No GuardDuty detectors found")
        return detector_ids[0]

    def _poll_findings(self):
        seen_findings = set()
        while self.running:
            try:
                findings = self.client.list_findings(DetectorId=self.detector_id, MaxResults=50)
                finding_ids = findings.get("FindingIds", [])
                if not finding_ids:
                    time.sleep(self.poll_interval)
                    continue

                response = self.client.get_findings(DetectorId=self.detector_id, FindingIds=finding_ids)
                for finding in response.get("Findings", []):
                    finding_id = finding["Id"]
                    if finding_id in seen_findings:
                        continue
                    seen_findings.add(finding_id)
                    self._handle_finding(finding)
            except (BotoCoreError, ClientError) as e:
                LOG.error("Error while polling GuardDuty: %s", e)

            time.sleep(self.poll_interval)

    def _handle_finding(self, finding):
        payload = {
            "source": "aws.guardduty",
            "region": self.region,
            "id": finding.get("Id"),
            "type": finding.get("Type"),
            "severity": finding.get("Severity"),
            "resource": finding.get("Resource", {}),
            "service": finding.get("Service", {}),
            "timestamp": finding.get("UpdatedAt"),
            "description": finding.get("Description"),
            "title": finding.get("Title"),
            "category": finding.get("Category", "Unknown"),
            "event": "cloud_threat_detected"
        }

        LOG.warning("GuardDuty finding detected: %s", payload["title"])
        secure_log("cloud_guardduty_finding", payload)
        self.emitter.emit(payload)
        raise_alert("cloud_threat_detected", payload)
        trace_event("guardduty_threat", payload)
