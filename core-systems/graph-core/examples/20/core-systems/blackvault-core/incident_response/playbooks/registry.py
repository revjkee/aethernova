from typing import Dict, Optional, List, Tuple, Union, Callable
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ValidationError
from threading import Lock
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger("blackvault.playbook_registry")

# --- SECURITY MODELS ---

class PlaybookMetadata(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=3, max_length=64)
    version: str = Field(..., regex=r"^\d+\.\d+\.\d+$")
    author: str = Field(..., min_length=3)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_modified: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)
    integrity_hash: str = Field(..., min_length=64, max_length=64)  # SHA-256
    is_enabled: bool = True
    risk_level: str = Field(..., regex=r"^(low|medium|high|critical)$")
    trust_zone: str = Field(..., regex=r"^(internal|dmz|external|airgap)$")

    def __hash__(self):
        return hash(self.id)


class Playbook(BaseModel):
    metadata: PlaybookMetadata
    execute: Callable[[Dict], Dict]


# --- INTERNAL REGISTRY ---

class _PlaybookRegistry:
    def __init__(self):
        self._playbooks: Dict[UUID, Playbook] = {}
        self._lock = Lock()
        self._active_playbook_id: Optional[UUID] = None
        self._context_routing: Dict[str, UUID] = {}  # context_id -> playbook UUID

    def register_playbook(self, playbook: Playbook) -> UUID:
        with self._lock:
            self._validate_playbook(playbook)
            pid = playbook.metadata.id
            if pid in self._playbooks:
                raise ValueError(f"Playbook with id {pid} already registered")
            self._playbooks[pid] = playbook
            logger.info(f"Playbook registered: {playbook.metadata.name} ({pid})")
            return pid

    def _validate_playbook(self, playbook: Playbook) -> None:
        expected_hash = hashlib.sha256(
            playbook.metadata.name.encode() +
            playbook.metadata.version.encode()
        ).hexdigest()
        if playbook.metadata.integrity_hash != expected_hash:
            raise ValueError("Integrity check failed for playbook")
        if not callable(playbook.execute):
            raise TypeError("Playbook must have a callable `execute` method")

    def set_active(self, playbook_id: UUID) -> None:
        with self._lock:
            if playbook_id not in self._playbooks:
                raise KeyError(f"Playbook {playbook_id} not found")
            self._active_playbook_id = playbook_id
            logger.info(f"Active playbook set: {playbook_id}")

    def route_context(self, context_id: str, playbook_id: UUID) -> None:
        with self._lock:
            if playbook_id not in self._playbooks:
                raise KeyError(f"Playbook {playbook_id} not found")
            self._context_routing[context_id] = playbook_id
            logger.debug(f"Routed context {context_id} to playbook {playbook_id}")

    def get_for_context(self, context_id: str) -> Optional[Playbook]:
        with self._lock:
            pid = self._context_routing.get(context_id, self._active_playbook_id)
            return self._playbooks.get(pid)

    def list_all(self) -> List[PlaybookMetadata]:
        with self._lock:
            return [pb.metadata for pb in self._playbooks.values()]

    def disable(self, playbook_id: UUID) -> None:
        with self._lock:
            if playbook_id not in self._playbooks:
                raise KeyError(f"Playbook {playbook_id} not found")
            self._playbooks[playbook_id].metadata.is_enabled = False
            logger.warning(f"Playbook {playbook_id} disabled")

    def enable(self, playbook_id: UUID) -> None:
        with self._lock:
            if playbook_id not in self._playbooks:
                raise KeyError(f"Playbook {playbook_id} not found")
            self._playbooks[playbook_id].metadata.is_enabled = True
            logger.info(f"Playbook {playbook_id} enabled")

    def delete(self, playbook_id: UUID) -> None:
        with self._lock:
            if playbook_id in self._playbooks:
                del self._playbooks[playbook_id]
                logger.info(f"Playbook {playbook_id} deleted")
                if self._active_playbook_id == playbook_id:
                    self._active_playbook_id = None

    def verify_integrity(self) -> Dict[UUID, bool]:
        with self._lock:
            results = {}
            for pid, pb in self._playbooks.items():
                expected = hashlib.sha256(
                    pb.metadata.name.encode() +
                    pb.metadata.version.encode()
                ).hexdigest()
                results[pid] = (pb.metadata.integrity_hash == expected)
            return results

    def stats(self) -> Dict[str, Union[int, List[str]]]:
        with self._lock:
            total = len(self._playbooks)
            enabled = len([pb for pb in self._playbooks.values() if pb.metadata.is_enabled])
            tags = list({tag for pb in self._playbooks.values() for tag in pb.metadata.tags})
            return {
                "total_registered": total,
                "enabled_playbooks": enabled,
                "unique_tags": tags
            }


# --- GLOBAL INSTANCE ---

playbook_registry = _PlaybookRegistry()
