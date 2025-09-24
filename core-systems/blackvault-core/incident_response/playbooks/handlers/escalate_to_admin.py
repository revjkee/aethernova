import logging
import json
from typing import Optional, Dict, Literal, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid
import requests

logger = logging.getLogger("blackvault.handlers.escalate_to_admin")

# --- PRIORITY LEVELS ---

class SeverityLevel(str):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class EscalationChannel(str):
    SLACK = "slack"
    EMAIL = "email"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"

# --- REQUEST MODEL ---

class EscalationRequest(BaseModel):
    incident_id: str = Field(..., min_length=8)
    title: str = Field(..., min_length=3)
    description: str
    severity: SeverityLevel
    operator: str
    channel: EscalationChannel
    contact: str  # webhook URL, email, telegram chat ID, etc.
    context: Optional[str] = None
    dry_run: bool = False
    token: Optional[str] = None  # for secured channel (e.g. Telegram bot token or Slack)

    @validator("incident_id")
    def validate_incident(cls, v):
        if not v.isalnum():
            raise ValueError("Invalid incident ID format")
        return v


# --- RESULT MODEL ---

class EscalationResult(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    incident_id: str
    operator: str
    severity: SeverityLevel
    channel: EscalationChannel
    dry_run: bool
    delivery_trace: Optional[Dict] = None


# --- ESCALATION ROUTER ---

class AdminEscalator:
    def __init__(self, request: EscalationRequest):
        self.req = request
        self.trace: Dict = {}
        self.message_id = str(uuid.uuid4())

    def _build_message(self) -> str:
        return (
            f"[{self.req.severity.upper()}] Incident Escalation\n"
            f"ID: {self.req.incident_id}\n"
            f"Title: {self.req.title}\n"
            f"Description: {self.req.description}\n"
            f"Operator: {self.req.operator}\n"
            f"Time: {datetime.utcnow().isoformat()}Z"
        )

    def _send_slack(self):
        payload = {"text": self._build_message()}
        resp = requests.post(self.req.contact, json=payload)
        self.trace["status_code"] = resp.status_code
        self.trace["response"] = resp.text

    def _send_email(self):
        # Stub for secure SMTP relay
        self.trace["message"] = "Email escalation not implemented in this context"
        self.trace["recipient"] = self.req.contact

    def _send_telegram(self):
        if not self.req.token:
            raise PermissionError("Telegram token is required")
        url = f"https://api.telegram.org/bot{self.req.token}/sendMessage"
        payload = {
            "chat_id": self.req.contact,
            "text": self._build_message()
        }
        resp = requests.post(url, json=payload)
        self.trace["status_code"] = resp.status_code
        self.trace["response"] = resp.text

    def _send_webhook(self):
        payload = {
            "incident_id": self.req.incident_id,
            "severity": self.req.severity,
            "title": self.req.title,
            "description": self.req.description,
            "timestamp": datetime.utcnow().isoformat(),
            "operator": self.req.operator,
            "context": self.req.context,
            "message_id": self.message_id
        }
        resp = requests.post(self.req.contact, json=payload)
        self.trace["status_code"] = resp.status_code
        self.trace["response"] = resp.text

    def dispatch(self) -> EscalationResult:
        logger.info(f"Escalation request received: {self.req.dict()}")
        if self.req.dry_run:
            return EscalationResult(
                success=True,
                message="Dry-run executed. No escalation sent.",
                timestamp=datetime.utcnow(),
                incident_id=self.req.incident_id,
                operator=self.req.operator,
                severity=self.req.severity,
                channel=self.req.channel,
                dry_run=True,
                delivery_trace={"note": "dry-run mode active"}
            )

        try:
            if self.req.channel == EscalationChannel.SLACK:
                self._send_slack()
            elif self.req.channel == EscalationChannel.EMAIL:
                self._send_email()
            elif self.req.channel == EscalationChannel.TELEGRAM:
                self._send_telegram()
            elif self.req.channel == EscalationChannel.WEBHOOK:
                self._send_webhook()
            else:
                raise ValueError(f"Unsupported channel: {self.req.channel}")

            logger.info(f"Escalation sent successfully to {self.req.channel}")
            return EscalationResult(
                success=True,
                message="Escalation sent successfully",
                timestamp=datetime.utcnow(),
                incident_id=self.req.incident_id,
                operator=self.req.operator,
                severity=self.req.severity,
                channel=self.req.channel,
                dry_run=False,
                delivery_trace=self.trace
            )

        except Exception as e:
            logger.exception(f"Error during escalation: {e}")
            return EscalationResult(
                success=False,
                message="Escalation failed",
                timestamp=datetime.utcnow(),
                incident_id=self.req.incident_id,
                operator=self.req.operator,
                severity=self.req.severity,
                channel=self.req.channel,
                dry_run=False,
                delivery_trace={"error": str(e)}
            )


# --- MAIN HANDLER FUNCTION ---

def escalate_to_admin(request_data: Dict[str, Union[str, bool, Dict]]) -> Dict:
    try:
        req = EscalationRequest(**request_data)
        escalator = AdminEscalator(req)
        result = escalator.dispatch()
        audit_log = {
            "event": "escalation_triggered",
            "result": result.dict(),
            "context": req.context or "global",
            "logged_at": datetime.utcnow().isoformat()
        }
        logger.info(json.dumps(audit_log, indent=2))
        return result.dict()
    except Exception as ex:
        logger.exception(f"Unhandled escalation exception: {ex}")
        return {
            "success": False,
            "message": "Unhandled exception",
            "error": str(ex),
            "timestamp": datetime.utcnow().isoformat()
        }
