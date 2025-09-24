import json
import os
from typing import Optional, Dict, Any


class Proposal:
    def __init__(
        self,
        proposal_id: str,
        title: str,
        description: str,
        proposer: str,
        proposal_type: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        creation_timestamp: Optional[int] = None,
        voting_start_timestamp: Optional[int] = None,
        voting_end_timestamp: Optional[int] = None,
        created_at_block: Optional[int] = None,
        voting_start_block: Optional[int] = None,
        voting_end_block: Optional[int] = None,
        status: str = "pending",
        votes: Optional[Dict[str, int]] = None,
        quorum_reached: Optional[bool] = None,
        result: Optional[str] = None,
        zk_proof: Optional[Any] = None,
        execution: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.proposal_id = proposal_id
        self.title = title
        self.description = description
        self.proposer = proposer
        self.proposal_type = proposal_type
        self.parameters = parameters or {}
        self.creation_timestamp = creation_timestamp
        self.voting_start_timestamp = voting_start_timestamp
        self.voting_end_timestamp = voting_end_timestamp
        self.created_at_block = created_at_block
        self.voting_start_block = voting_start_block
        self.voting_end_block = voting_end_block
        self.status = status
        self.votes = votes or {"for": 0, "against": 0, "abstain": 0}
        self.quorum_reached = quorum_reached
        self.result = result
        self.zk_proof = zk_proof
        self.execution = execution or {"executed": False, "execution_block": None, "result": None}
        self.metadata = metadata or {"related_documents": [], "external_links": []}

    @classmethod
    def from_json(cls, data: Dict[str, Any]):
        # поддержка разных названий proposer/proposer_address
        proposer = data.get("proposer") or data.get("proposer_address")
        return cls(
            proposal_id=data.get("proposal_id"),
            title=data.get("title"),
            description=data.get("description"),
            proposer=proposer,
            proposal_type=data.get("proposal_type"),
            parameters=data.get("parameters"),
            creation_timestamp=data.get("creation_timestamp"),
            voting_start_timestamp=data.get("voting_start_timestamp"),
            voting_end_timestamp=data.get("voting_end_timestamp"),
            created_at_block=data.get("created_at_block"),
            voting_start_block=data.get("voting_start_block"),
            voting_end_block=data.get("voting_end_block"),
            status=data.get("status", "pending"),
            votes=data.get("votes"),
            quorum_reached=data.get("quorum_reached"),
            result=data.get("result"),
            zk_proof=data.get("zk_proof"),
            execution=data.get("execution"),
            metadata=data.get("metadata"),
        )

    def to_json(self) -> Dict[str, Any]:
        result = {
            "proposal_id": self.proposal_id,
            "title": self.title,
            "description": self.description,
            "proposer": self.proposer,
            "proposal_type": self.proposal_type,
            "parameters": self.parameters,
            "creation_timestamp": self.creation_timestamp,
            "voting_start_timestamp": self.voting_start_timestamp,
            "voting_end_timestamp": self.voting_end_timestamp,
            "created_at_block": self.created_at_block,
            "voting_start_block": self.voting_start_block,
            "voting_end_block": self.voting_end_block,
            "status": self.status,
            "votes": self.votes,
            "quorum_reached": self.quorum_reached,
            "result": self.result,
            "zk_proof": self.zk_proof,
            "execution": self.execution,
            "metadata": self.metadata,
        }
        # Удаляем None значения для чистоты JSON
        return {k: v for k, v in result.items() if v is not None}

    def update_votes(self, for_votes: int, against_votes: int, abstain_votes: int):
        self.votes["for"] = for_votes
        self.votes["against"] = against_votes
        self.votes["abstain"] = abstain_votes
        self._update_status_and_result()

    def _update_status_and_result(self):
        total_votes = sum(self.votes.values())
        quorum = self.quorum_reached if self.quorum_reached is not None else False

        if not quorum:
            self.result = "quorum_not_reached"
            self.status = "closed"
            return

        if self.votes["for"] > self.votes["against"]:
            self.result = "approved"
        else:
            self.result = "rejected"

        self.status = "closed"

    def save(self, directory: str):
        if not os.path.exists(directory):
            os.makedirs(directory)

        filepath = os.path.join(directory, f"{self.proposal_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, filepath: str):
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_json(data)
