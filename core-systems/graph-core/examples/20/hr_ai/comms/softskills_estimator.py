import logging
from typing import Dict, List, Optional
from hr_ai.utils.embedding_engine import get_text_embedding
from hr_ai.llm.connector import llm_classify_traits
from hr_ai.security.input_validator import validate_input
from hr_ai.models.trait_weights import TRAIT_WEIGHTS
from hr_ai.data.normalization import normalize_score

logger = logging.getLogger("SoftSkillsEstimator")
logger.setLevel(logging.INFO)

class SoftSkillsEstimator:
    def __init__(self, language: str = "en", profile: Optional[Dict] = None):
        self.language = language
        self.candidate_profile = profile or {}
        self.default_traits = list(TRAIT_WEIGHTS.keys())

    def analyze(self, conversation_log: List[Dict[str, str]]) -> Dict[str, float]:
        if not conversation_log or not isinstance(conversation_log, list):
            logger.error("Invalid conversation log")
            raise ValueError("Conversation log must be a non-empty list.")

        validated_lines = [
            entry for entry in conversation_log
            if validate_input(entry.get("content", ""))
        ]

        if not validated_lines:
            logger.warning("No valid content for analysis")
            return {trait: 0.0 for trait in self.default_traits}

        full_text = "\n".join(entry["content"] for entry in validated_lines)
        logger.debug(f"Full conversation length: {len(full_text)} chars")

        traits_raw = llm_classify_traits(full_text, traits=self.default_traits, language=self.language)
        traits_scores = self._normalize_and_weight(traits_raw)

        logger.info(f"Soft skills evaluated: {traits_scores}")
        return traits_scores

    def _normalize_and_weight(self, raw_scores: Dict[str, float]) -> Dict[str, float]:
        weighted_scores = {}
        for trait, raw in raw_scores.items():
            norm = normalize_score(raw)
            weight = TRAIT_WEIGHTS.get(trait, 1.0)
            weighted = round(norm * weight, 3)
            weighted_scores[trait] = min(max(weighted, 0.0), 1.0)

        return weighted_scores
