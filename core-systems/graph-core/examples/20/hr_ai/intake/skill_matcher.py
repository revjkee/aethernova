import logging
from typing import List
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util
from hr_ai.utils.text_normalizer import normalize_text
from hr_ai.utils.security_guard import validate_input_safe
from hr_ai.models.schema import SkillEntry, JobRequirement

logger = logging.getLogger("hr_ai.skill_matcher")
logger.setLevel(logging.INFO)

class MatchResult(BaseModel):
    skill: str = Field(..., description="Навык кандидата")
    requirement: str = Field(..., description="Требуемый навык")
    score: float = Field(..., description="Семантическая близость")

class SkillMatcher:
    def __init__(self, model_name: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2") -> None:
        self.model = SentenceTransformer(model_name)
        logger.info("SkillMatcher инициализирован с моделью %s", model_name)

    def match(self, skills: List[SkillEntry], requirements: List[JobRequirement], threshold: float = 0.7) -> List[MatchResult]:
        if not skills or not requirements:
            logger.warning("Передан пустой список навыков или требований")
            return []

        clean_skills = [normalize_text(s.name) for s in skills]
        clean_reqs = [normalize_text(r.name) for r in requirements]

        if not all(validate_input_safe(s) for s in clean_skills + clean_reqs):
            logger.error("Вход содержит небезопасные строки")
            return []

        skill_embs = self.model.encode(clean_skills, convert_to_tensor=True, normalize_embeddings=True)
        req_embs = self.model.encode(clean_reqs, convert_to_tensor=True, normalize_embeddings=True)

        cosine_scores = util.cos_sim(skill_embs, req_embs)
        results: List[MatchResult] = []

        for i, s in enumerate(clean_skills):
            for j, r in enumerate(clean_reqs):
                score = float(cosine_scores[i][j])
                if score >= threshold:
                    results.append(MatchResult(
                        skill=skills[i].name,
                        requirement=requirements[j].name,
                        score=round(score, 3)
                    ))

        logger.info("Сопоставление завершено: найдено %d совпадений", len(results))
        return sorted(results, key=lambda x: x.score, reverse=True)
