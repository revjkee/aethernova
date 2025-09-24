# phantommesh-core/node_network/trust_weighting.py

import hashlib
import math
import time
import logging
from typing import Dict, Optional, Tuple

TRUST_DECAY_HALFLIFE = 3600  # 1 час
DEFAULT_TRUST = 0.5
TRUST_THRESHOLD = 0.2
MAX_TRUST = 1.0
MIN_TRUST = 0.0

logger = logging.getLogger("trust_weighting")
logger.setLevel(logging.DEBUG)

class TrustEntry:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.trust_score: float = DEFAULT_TRUST
        self.last_update: float = time.time()
        self.interactions: int = 0
        self.failures: int = 0
        self.evidence_hash: str = ""

    def update_score(self, success: bool, weight: float = 1.0) -> None:
        now = time.time()
        decay_factor = math.exp(-math.log(2) * (now - self.last_update) / TRUST_DECAY_HALFLIFE)
        self.trust_score = self.trust_score * decay_factor

        if success:
            self.trust_score += (1.0 - self.trust_score) * weight * 0.1
        else:
            self.trust_score -= self.trust_score * weight * 0.2
            self.failures += 1

        self.trust_score = max(MIN_TRUST, min(MAX_TRUST, self.trust_score))
        self.interactions += 1
        self.last_update = now
        self.evidence_hash = self._generate_evidence_hash(success)

        logger.debug(f"[{self.node_id}] trust={self.trust_score:.3f} success={success} int={self.interactions}")

    def is_trusted(self) -> bool:
        return self.trust_score >= TRUST_THRESHOLD

    def _generate_evidence_hash(self, success: bool) -> str:
        base = f"{self.node_id}:{self.trust_score:.4f}:{success}:{self.last_update}"
        return hashlib.sha256(base.encode()).hexdigest()

    def export(self) -> Dict:
        return {
            "node_id": self.node_id,
            "trust_score": round(self.trust_score, 4),
            "last_update": self.last_update,
            "interactions": self.interactions,
            "failures": self.failures,
            "evidence_hash": self.evidence_hash
        }

class TrustLedger:
    def __init__(self):
        self.entries: Dict[str, TrustEntry] = {}

    def update_trust(self, node_id: str, success: bool, weight: float = 1.0) -> None:
        entry = self.entries.get(node_id)
        if not entry:
            entry = TrustEntry(node_id)
            self.entries[node_id] = entry
        entry.update_score(success, weight)

    def get_trust(self, node_id: str) -> float:
        entry = self.entries.get(node_id)
        return entry.trust_score if entry else DEFAULT_TRUST

    def is_trusted(self, node_id: str) -> bool:
        entry = self.entries.get(node_id)
        return entry.is_trusted() if entry else True

    def get_evidence_hash(self, node_id: str) -> Optional[str]:
        entry = self.entries.get(node_id)
        return entry.evidence_hash if entry else None

    def get_full_state(self) -> Dict[str, Dict]:
        return {nid: entry.export() for nid, entry in self.entries.items()}

    def prune(self, inactive_seconds: int = 86400) -> None:
        now = time.time()
        to_remove = [nid for nid, entry in self.entries.items() if (now - entry.last_update) > inactive_seconds]
        for nid in to_remove:
            del self.entries[nid]
            logger.info(f"Удалён неактивный узел: {nid}")

    def apply_penalty(self, node_id: str, severity: float) -> None:
        entry = self.entries.get(node_id)
        if entry:
            entry.trust_score -= entry.trust_score * min(severity, 1.0)
            entry.trust_score = max(MIN_TRUST, entry.trust_score)
            entry.last_update = time.time()
            entry.failures += 1
            entry.evidence_hash = entry._generate_evidence_hash(False)
            logger.warning(f"[{node_id}] применено наказание severity={severity} → trust={entry.trust_score:.3f}")

