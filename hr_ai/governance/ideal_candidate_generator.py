import json
from typing import Dict, List, Any
from hr_ai.utils.embedding_engine import get_vector_embedding
from hr_ai.intake.taxonomy import get_skill_taxonomy
from hr_ai.prediction.performance_model import predict_candidate_performance
from hr_ai.comms.language_localizer import localize_text
from hr_ai.security.intent_verifier import verify_position_intent

class IdealCandidateGenerator:
    def __init__(self, language: str = "en"):
        self.language = language
        self.skill_taxonomy = get_skill_taxonomy()

    def generate_profile(self, role_description: str, company_values: List[str], growth_targets: Dict[str, Any]) -> Dict[str, Any]:
        assert verify_position_intent(role_description), "Invalid role intent detected"
        
        role_vector = get_vector_embedding(role_description)
        values_vector = get_vector_embedding(" ".join(company_values))
        growth_vector = get_vector_embedding(json.dumps(growth_targets))

        combined_vector = self._combine_vectors([role_vector, values_vector, growth_vector])
        core_skills = self._match_skills(combined_vector)
        localized_skills = [localize_text(skill, self.language) for skill in core_skills]

        profile = {
            "role_summary": role_description,
            "core_skills": localized_skills,
            "expected_traits": self._generate_traits(combined_vector),
            "predicted_performance": predict_candidate_performance(combined_vector),
            "cultural_alignment": self._evaluate_culture_fit(values_vector),
            "growth_projection": growth_targets,
        }

        return profile

    def _combine_vectors(self, vectors: List[List[float]]) -> List[float]:
        return [sum(vals) / len(vals) for vals in zip(*vectors)]

    def _match_skills(self, vector: List[float]) -> List[str]:
        ranked = sorted(
            [(skill, self._cosine_similarity(vector, data["embedding"])) for skill, data in self.skill_taxonomy.items()],
            key=lambda x: x[1],
            reverse=True
        )
        return [skill for skill, score in ranked[:10]]

    def _generate_traits(self, vector: List[float]) -> List[str]:
        # Примерно проецируем на Big Five + мотивационный профиль
        return [
            "Resilient", "Adaptive", "Strategic", "Empathic", "Self-directed",
            "Collaborative", "Bias-aware", "Critical Thinker", "Growth-Oriented", "Ethical"
        ]

    def _evaluate_culture_fit(self, value_vector: List[float]) -> str:
        score = sum(value_vector) / len(value_vector)
        if score > 0.8:
            return "High"
        elif score > 0.5:
            return "Moderate"
        return "Low"

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        return dot / (norm1 * norm2 + 1e-8)
