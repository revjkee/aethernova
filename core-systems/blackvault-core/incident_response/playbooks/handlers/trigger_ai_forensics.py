import logging
import json
import uuid
from typing import Dict, List, Optional, Literal, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum

logger = logging.getLogger("blackvault.handlers.trigger_ai_forensics")

# --- ENUMS ---

class ForensicsMode(str, Enum):
    FULL = "full"
    LIGHT = "light"
    RAPID = "rapid"

class EvidenceType(str, Enum):
    LOG = "log"
    PCAP = "pcap"
    MEMORY = "memory"
    PROCESS_TREE = "process_tree"
    FILE_DUMP = "file_dump"

# --- REQUEST MODEL ---

class ForensicsRequest(BaseModel):
    incident_id: str = Field(..., min_length=8)
    evidence: Dict[EvidenceType, str]
    operator: str = Field(..., min_length=3)
    mode: ForensicsMode = ForensicsMode.FULL
    context: Optional[str] = None
    dry_run: bool = False
    access_token: Optional[str] = None  # For secure AI endpoint

    @validator("incident_id")
    def validate_incident_id(cls, v):
        if not v.isalnum():
            raise ValueError("Invalid incident ID format")
        return v


# --- RESULT MODEL ---

class ForensicsResult(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    analysis_id: str
    incident_id: str
    operator: str
    mode: ForensicsMode
    triggered_agents: List[str]
    dry_run: bool
    metadata: Optional[Dict] = None


# --- AGENT TRIGGERING LOGIC ---

class AIForensicsOrchestrator:
    def __init__(self, request: ForensicsRequest):
        self.req = request
        self.analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
        self.agents_invoked: List[str] = []

    def _simulate_agents(self):
        # In production: Replace with real message-broker or gRPC dispatch
        evidence_keys = list(self.req.evidence.keys())
        mapping = {
            EvidenceType.LOG: "agent_log_classification",
            EvidenceType.PCAP: "agent_network_behavior",
            EvidenceType.MEMORY: "agent_memory_scanner",
            EvidenceType.PROCESS_TREE: "agent_execution_graph",
            EvidenceType.FILE_DUMP: "agent_file_anomaly"
        }
        for key in evidence_keys:
            agent_name = mapping.get(key, "agent_generic")
            self.agents_invoked.append(agent_name)

    def _validate_access(self):
        if self.req.access_token is None or len(self.req.access_token) < 16:
            raise PermissionError("Access token is invalid or missing")

    def execute(self) -> ForensicsResult:
        logger.info(f"Triggering AI forensic analysis for incident: {self.req.incident_id}")
        if not self.req.dry_run:
            self._validate_access()
        self._simulate_agents()

        # Logging full payload
        logger.info(json.dumps({
            "event": "ai_forensics_triggered",
            "analysis_id": self.analysis_id,
            "incident_id": self.req.incident_id,
            "agents": self.agents_invoked,
            "operator": self.req.operator,
            "mode": self.req.mode,
            "context": self.req.context or "global",
            "timestamp": datetime.utcnow().isoformat()
        }, indent=2))

        return ForensicsResult(
            success=True,
            message="AI forensics agents triggered successfully" if not self.req.dry_run else "Dry-run executed",
            timestamp=datetime.utcnow(),
            analysis_id=self.analysis_id,
            incident_id=self.req.incident_id,
            operator=self.req.operator,
            mode=self.req.mode,
            dry_run=self.req.dry_run,
            triggered_agents=self.agents_invoked,
            metadata={"agent_count": len(self.agents_invoked)}
        )


# --- MAIN HANDLER FUNCTION ---

def trigger_ai_forensics(request_data: Dict[str, Union[str, Dict]]) -> Dict:
    try:
        req = ForensicsRequest(**request_data)
        orchestrator = AIForensicsOrchestrator(req)
        result = orchestrator.execute()
        return result.dict()
    except Exception as e:
        logger.exception(f"Unhandled error during AI forensic trigger: {e}")
        return {
            "success": False,
            "message": "Unhandled exception",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
