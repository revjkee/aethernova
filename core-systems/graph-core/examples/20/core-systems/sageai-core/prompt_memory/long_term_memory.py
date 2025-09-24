# path: sageai-core/prompt_memory/long_term_memory.py

import os
import json
import uuid
import logging
import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util
import torch

logger = logging.getLogger("LongTermMemory")
logger.setLevel(logging.INFO)

class MemoryEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    prompt: str
    response: str
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)
    importance: float = 0.5

class LongTermMemory:
    def __init__(self, storage_path: str, embedding_model_name: str = "sentence-transformers/all-mpnet-base-v2"):
        self.storage_path = storage_path
        self.model = SentenceTransformer(embedding_model_name)
        self.entries: List[MemoryEntry] = []
        self.embeddings: Optional[torch.Tensor] = None
        self.load()

    def add(self, prompt: str, response: str, tags: Optional[List[str]] = None, metadata: Optional[Dict[str, str]] = None, importance: float = 0.5):
        entry = MemoryEntry(
            prompt=prompt,
            response=response,
            tags=tags or [],
            metadata=metadata or {},
            importance=importance
        )
        self.entries.append(entry)
        logger.info(f"Added long-term memory entry {entry.id}")
        self._update_embeddings()

    def _update_embeddings(self):
        texts = [e.prompt + " " + e.response for e in self.entries]
        self.embeddings = self.model.encode(texts, convert_to_tensor=True)
        logger.debug("Updated embeddings for memory entries")

    def search(self, query: str, top_k: int = 5, min_score: float = 0.5) -> List[MemoryEntry]:
        if not self.entries or self.embeddings is None:
            logger.warning("Memory is empty or not embedded")
            return []

        query_embedding = self.model.encode(query, convert_to_tensor=True)
        cos_scores = util.pytorch_cos_sim(query_embedding, self.embeddings)[0]
        top_results = torch.topk(cos_scores, k=min(top_k, len(self.entries)))

        results = []
        for score, idx in zip(top_results.values, top_results.indices):
            score_val = score.item()
            if score_val < min_score:
                continue
            entry = self.entries[idx]
            results.append(entry)
            logger.info(f"Match found: {entry.id} score={score_val:.3f}")
        return results

    def delete(self, entry_id: str):
        initial_len = len(self.entries)
        self.entries = [e for e in self.entries if e.id != entry_id]
        if len(self.entries) < initial_len:
            logger.info(f"Deleted memory entry {entry_id}")
            self._update_embeddings()

    def save(self):
        data = [e.dict() for e in self.entries]
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False, default=str)
        logger.info(f"Saved {len(self.entries)} entries to {self.storage_path}")

    def load(self):
        if not os.path.exists(self.storage_path):
            logger.warning(f"No memory file at {self.storage_path}")
            return
        with open(self.storage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.entries = [MemoryEntry(**item) for item in data]
            logger.info(f"Loaded {len(self.entries)} entries from {self.storage_path}")
            self._update_embeddings()

    def export_snapshot(self) -> Dict[str, List[Dict]]:
        return {
            "entries": [e.dict() for e in self.entries],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

    def clear_memory(self):
        self.entries.clear()
        self.embeddings = None
        logger.warning("All long-term memory entries cleared")

# END
