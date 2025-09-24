import json
from datetime import datetime
from typing import Dict, Any, Optional

class ProposalProcessor:
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self.proposals = self._load_proposals()

    def _load_proposals(self) -> Dict[str, Any]:
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_proposals(self) -> None:
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(self.proposals, f, ensure_ascii=False, indent=2)

    def submit_proposal(self, proposal_id: str, proposer: str, content: Dict[str, Any], zk_proof: str) -> bool:
        if proposal_id in self.proposals:
            return False  # Proposal already exists
        self.proposals[proposal_id] = {
            "proposer": proposer,
            "content": content,
            "zk_proof": zk_proof,
            "status": "submitted",
            "submitted_at": datetime.utcnow().isoformat() + 'Z',
            "votes": {
                "for": 0,
                "against": 0,
                "abstain": 0
            }
        }
        self._save_proposals()
        return True

    def update_vote(self, proposal_id: str, vote_type: str) -> bool:
        if proposal_id not in self.proposals:
            return False
        if vote_type not in ("for", "against", "abstain"):
            return False
        self.proposals[proposal_id]["votes"][vote_type] += 1
        self._save_proposals()
        return True

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        return self.proposals.get(proposal_id)

    def set_status(self, proposal_id: str, status: str) -> bool:
        if proposal_id not in self.proposals:
            return False
        self.proposals[proposal_id]["status"] = status
        self._save_proposals()
        return True
