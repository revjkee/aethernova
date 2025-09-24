import asyncio
from typing import Dict, Optional
from dataclasses import dataclass, field

class ZKRegistryError(Exception):
    pass

@dataclass
class Participant:
    id: str
    public_key: str
    status: str = field(default="active")  # active, blocked, removed
    metadata: Dict = field(default_factory=dict)

class ZKRegistry:
    def __init__(self):
        self._participants: Dict[str, Participant] = {}
        self._lock = asyncio.Lock()

    async def add_participant(self, participant_id: str, public_key: str, metadata: Optional[Dict] = None):
        async with self._lock:
            if participant_id in self._participants:
                raise ZKRegistryError(f"Participant {participant_id} already registered")
            self._participants[participant_id] = Participant(
                id=participant_id,
                public_key=public_key,
                metadata=metadata or {},
            )

    async def get_participant(self, participant_id: str) -> Participant:
        async with self._lock:
            participant = self._participants.get(participant_id)
            if participant is None:
                raise ZKRegistryError(f"Participant {participant_id} not found")
            return participant

    async def update_status(self, participant_id: str, status: str):
        async with self._lock:
            participant = self._participants.get(participant_id)
            if participant is None:
                raise ZKRegistryError(f"Participant {participant_id} not found")
            if status not in ("active", "blocked", "removed"):
                raise ZKRegistryError(f"Invalid status {status}")
            participant.status = status

    async def verify_proof(self, participant_id: str, proof_data: bytes) -> bool:
        # Заглушка для реальной интеграции с zk-верификатором
        async with self._lock:
            participant = self._participants.get(participant_id)
            if participant is None or participant.status != "active":
                return False
            # Тут должна быть логика проверки proof_data с использованием public_key и zk протокола
            # Для демонстрации возвращаем True
            return True

    async def remove_participant(self, participant_id: str):
        async with self._lock:
            if participant_id in self._participants:
                self._participants[participant_id].status = "removed"

    async def list_participants(self, status_filter: Optional[str] = None) -> Dict[str, Participant]:
        async with self._lock:
            if status_filter:
                return {pid: p for pid, p in self._participants.items() if p.status == status_filter}
            return dict(self._participants)

