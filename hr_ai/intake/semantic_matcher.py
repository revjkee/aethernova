import logging
from typing import List, Dict, Tuple
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util
from hr_ai.utils.text_normalizer import normalize_text
from hr_ai.utils.security_guard import validate_input_safe

logger = logging.getLogger("hr_ai.semantic_matcher")
logger.setLevel(logging.INFO)

class MatchCandidate(BaseModel):
    id: str = Field(..., description="Уникальный идентификатор кандидата")
    description: str = Field(..., description="Семантическое описание резюме или профиля")

class MatchTarget(BaseModel):
    id: str = Field(..., description="Уникальный идентификатор цели (позиции, роли и т.д.)")
    description: str = Field(..., description="Семантическое описание позиции")

class SemanticMatchResult(BaseModel):
    candidate_id: str
    target_id: str
    score: float

class SemanticMatcher:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        logger.info("SemanticMatcher загружен с моделью %s", model_name)

    def match(self, candidates: List[MatchCandidate], targets: List[MatchTarget], threshold: float = 0.65) -> List[SemanticMatchResult]:
        if not candidates or not targets:
            logger.warning("Пустой список кандидатов или целей")
            return []

        candidate_texts = [normalize_text(c.description) for c in candidates]
        target_texts = [normalize_text(t.description) for t in targets]

        if not all(validate_input_safe(txt) for txt in candidate_texts + target_texts):
            logger.error("Обнаружены небезопасные входные данные")
            return []

        cand_embeddings = self.model.encode(candidate_texts, convert_to_tensor=True, normalize_embeddings=True)
        targ_embeddings = self.model.encode(target_texts, convert_to_tensor=True, normalize_embeddings=True)

        similarity_matrix = util.cos_sim(cand_embeddings, targ_embeddings)

        results: List[SemanticMatchResult] = []

        for i, candidate in enumerate(candidates):
            for j, target in enumerate(targets):
                score = float(similarity_matrix[i][j])
                if score >= threshold:
                    results.append(SemanticMatchResult(
                        candidate_id=candidate.id,
                        target_id=target.id,
                        score=round(score, 3)
                    ))

        logger.info("Найдено %d релевантных сопоставлений", len(results))
        return sorted(results, key=lambda x: x.score, reverse=True)
