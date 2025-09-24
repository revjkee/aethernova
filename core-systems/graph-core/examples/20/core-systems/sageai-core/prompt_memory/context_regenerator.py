# path: sageai-core/prompt_memory/context_regenerator.py

import os
import json
import logging
import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util
import torch

logger = logging.getLogger("ContextRegenerator")
logger.setLevel(logging.INFO)

class MemoryFragment(BaseModel):
    id: str = Field(...)
    timestamp: datetime.datetime
    prompt: str
    response: str
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)
    importance: float

class RegeneratedContext(BaseModel):
    context_id: str = Field(default_factory=lambda: str(datetime.datetime.utcnow().timestamp()))
    session_id: Optional[str]
    fragments: List[MemoryFragment]
    summary: Optional[str]
    relevance_score: float

class ContextRegenerator:
    def __init__(self, memory_path: str, embedding_model_name: str = "sentence-transformers/all-mpnet-base-v2"):
        self.memory_path = memory_path
        self.model = SentenceTransformer(embedding_model_name)
        self.fragments: List[MemoryFragment] = []
        self.embeddings: Optional[torch.Tensor] = None
        self._load_memory()

    def _load_memory(self):
        if not os.path.exists(self.memory_path):
            logger.warning(f"Memory file not found: {self.memory_path}")
            return
        with open(self.memory_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.fragments = [MemoryFragment(**item) for item in data]
        logger.info(f"Loaded {len(self.fragments)} memory fragments")
        self._generate_embeddings()

    def _generate_embeddings(self):
        if not self.fragments:
            self.embeddings = None
            return
        texts = [f"{frag.prompt} {frag.response}" for frag in self.fragments]
        self.embeddings = self.model.encode(texts, convert_to_tensor=True)
        logger.info("Generated embeddings for memory fragments")

    def regenerate_context(self, current_prompt: str, top_k: int = 7, relevance_threshold: float = 0.45) -> RegeneratedContext:
        if not self.fragments or self.embeddings is None:
            logger.warning("No memory fragments available for context regeneration")
            return RegeneratedContext(session_id=None, fragments=[], summary=None, relevance_score=0.0)

        query_embedding = self.model.encode(current_prompt, convert_to_tensor=True)
        scores = util.pytorch_cos_sim(query_embedding, self.embeddings)[0]
        top_results = torch.topk(scores, k=min(top_k, len(self.fragments)))

        selected_fragments = []
        for score, idx in zip(top_results.values, top_results.indices):
            score_val = score.item()
            if score_val < relevance_threshold:
                continue
            frag = self.fragments[idx]
            selected_fragments.append(frag)
            logger.info(f"Selected fragment {frag.id} with score {score_val:.3f}")

        context_summary = self._summarize_context(selected_fragments)
        relevance_avg = float(torch.mean(top_results.values).item())

        return RegeneratedContext(
            session_id=str(datetime.datetime.utcnow().timestamp()),
            fragments=selected_fragments,
            summary=context_summary,
            relevance_score=relevance_avg
        )

    def _summarize_context(self, fragments: List[MemoryFragment]) -> str:
        if not fragments:
            return ""
        sorted_fragments = sorted(fragments, key=lambda x: x.timestamp)
        summary_lines = []
        for frag in sorted_fragments:
            line = f"[{frag.timestamp.isoformat()}] {frag.prompt.strip()} → {frag.response.strip()}"
            summary_lines.append(line)
        return "\n".join(summary_lines)

    def export_context(self, context: RegeneratedContext, export_path: str):
        export_data = {
            "context_id": context.context_id,
            "session_id": context.session_id,
            "summary": context.summary,
            "relevance_score": context.relevance_score,
            "fragments": [frag.dict() for frag in context.fragments],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4, ensure_ascii=False, default=str)
        logger.info(f"Exported regenerated context to {export_path}")

# END
