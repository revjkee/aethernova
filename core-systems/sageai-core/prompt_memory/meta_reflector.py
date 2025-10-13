# path: sageai-core/prompt_memory/meta_reflector.py

import uuid
import json
import logging
import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util
import torch

# Настройка логирования
logger = logging.getLogger("MetaReflector")
logger.setLevel(logging.INFO)

class ReflectiveEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    prompt: str
    response: str
    tags: List[str] = Field(default_factory=list)
    importance: float = 0.5

class Insight(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    summary: str
    related_entry_ids: List[str]
    confidence: float
    tags: List[str]

class MetaReflector:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2", threshold: float = 0.7):
        self.entries: List[ReflectiveEntry] = []
        self.insights: List[Insight] = []
        self.model = SentenceTransformer(model_name)
        self.threshold = threshold

    def add_entry(self, prompt: str, response: str, tags: Optional[List[str]] = None, importance: float = 0.5):
        entry = ReflectiveEntry(prompt=prompt, response=response, tags=tags or [], importance=importance)
        self.entries.append(entry)
        logger.info(f"Added memory entry {entry.id} with importance {importance}")

    def reflect(self):
        if len(self.entries) < 2:
            logger.warning("Not enough entries to reflect.")
            return

        embeddings = self.model.encode(
            [e.prompt + " " + e.response for e in self.entries],
            convert_to_tensor=True
        )
        cosine_scores = util.pytorch_cos_sim(embeddings, embeddings)

        seen = set()
        for i in range(len(self.entries)):
            for j in range(i + 1, len(self.entries)):
                if (i, j) in seen or i == j:
                    continue
                score = cosine_scores[i][j].item()
                if score >= self.threshold:
                    insight = self._generate_insight(i, j, score)
                    self.insights.append(insight)
                    seen.add((i, j))
                    logger.info(f"Generated insight {insight.id} with score {score:.3f}")

    def _generate_insight(self, idx1: int, idx2: int, score: float) -> Insight:
        e1 = self.entries[idx1]
        e2 = self.entries[idx2]
        summary = self._synthesize_summary(e1, e2)
        common_tags = list(set(e1.tags).intersection(set(e2.tags)))
        return Insight(
            summary=summary,
            related_entry_ids=[e1.id, e2.id],
            confidence=score,
            tags=common_tags
        )

    def _synthesize_summary(self, e1: ReflectiveEntry, e2: ReflectiveEntry) -> str:
        return (
            f"Взаимосвязь между '{e1.prompt[:64]}...' и '{e2.prompt[:64]}...'. "
            f"Ответы указывают на перекрытие в смысловых паттернах. "
            f"Значения: [{e1.importance}, {e2.importance}]"
        )

    def export_state(self) -> Dict[str, Any]:
        return {
            "entries": [e.dict() for e in self.entries],
            "insights": [i.dict() for i in self.insights],
            "threshold": self.threshold,
            "model": self.model.__class__.__name__,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

    def save_to_file(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.export_state(), f, ensure_ascii=False, indent=4)
        logger.info(f"State exported to {path}")

    def load_from_file(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.entries = [ReflectiveEntry(**e) for e in data.get("entries", [])]
        self.insights = [Insight(**i) for i in data.get("insights", [])]
        logger.info(f"State restored from {path}")

    def reset(self):
        self.entries.clear()
        self.insights.clear()
        logger.warning("MetaReflector reset to empty state")

# END
