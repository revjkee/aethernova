import uuid
import json
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Optional, List, Dict, Union

from blackvault_core.config import settings
from blackvault_core.shared.trust.signature import sign_payload_gpg
from blackvault_core.shared.graph.core import graph_sync_event
from blackvault_core.shared.audit import audit_log_event
from blackvault_core.observability.incident_response.forensic.forensic_storage import ForensicStorage, ForensicStorageError

CASE_DIR = Path(settings.CASE_DIR or "/var/lib/blackvault/cases")
CASE_DIR.mkdir(parents=True, exist_ok=True)

class CaseStatus(str, Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    CLOSED = "closed"
    ESCALATED = "escalated"

class IncidentCase:
    def __init__(self, title: str, description: str, severity: str, created_by: str):
        self.case_id = str(uuid.uuid4())
        self.title = title
        self.description = description
        self.severity = severity
        self.created_by = created_by
        self.status = CaseStatus.OPEN
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        self.evidence: List[Dict] = []
        self.history: List[Dict] = []
        self.case_dir = CASE_DIR / self.case_id
        self.case_dir.mkdir(parents=True, exist_ok=True)

        self._log_history("Case created")

    def _log_history(self, action: str, metadata: Optional[Dict] = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "metadata": metadata or {}
        }
        self.history.append(entry)
        self.updated_at = entry["timestamp"]
        audit_log_event(
            actor="case_manager",
            action=action,
            resource=self.case_id,
            metadata=entry["metadata"]
        )

    def attach_artifact(self, file_path: Path, classification: str, source: str, encryption_key: bytes):
        try:
            storage = ForensicStorage(self.case_id)
            encrypted_filename, file_hash = storage.store_artifact(
                file_path, classification, source, encryption_key
            )

            artifact_entry = {
                "original_path": str(file_path),
                "encrypted_name": encrypted_filename,
                "hash": file_hash,
                "classification": classification,
                "source": source,
                "stored_at": datetime.utcnow().isoformat()
            }

            self.evidence.append(artifact_entry)
            self._log_history("Artifact attached", artifact_entry)

            return artifact_entry
        except ForensicStorageError as e:
            raise RuntimeError(f"Failed to attach artifact: {e}")

    def update_status(self, new_status: Union[str, CaseStatus]):
        if isinstance(new_status, str):
            new_status = CaseStatus(new_status)
        self.status = new_status
        self._log_history(f"Status changed to {self.status.value}")

    def escalate(self, escalated_by: str, reason: str):
        self.update_status(CaseStatus.ESCALATED)
        self._log_history("Case escalated", {"by": escalated_by, "reason": reason})

    def close(self, closed_by: str, resolution_summary: str):
        self.update_status(CaseStatus.CLOSED)
        self._log_history("Case closed", {"by": closed_by, "summary": resolution_summary})

    def export_casefile(self) -> Path:
        case_data = {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "created_by": self.created_by,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence": self.evidence,
            "history": self.history
        }

        case_file_path = self.case_dir / "case.json"
        with case_file_path.open("w") as f:
            json.dump(case_data, f, indent=2)

        sig_path = sign_payload_gpg(case_file_path)
        self._log_history("Casefile exported and signed", {"signature": str(sig_path)})
        graph_sync_event(
            node_type="case",
            node_id=self.case_id,
            payload=case_data,
            signature_path=sig_path
        )

        return case_file_path

    def to_dict(self) -> Dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status.value,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_count": len(self.evidence)
        }
