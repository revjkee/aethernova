import numpy as np
from typing import List, Dict, Any
from hr_ai.utils.embedding_engine import get_vector_embedding
from hr_ai.prediction.performance_model import predict_candidate_performance
from hr_ai.intake.taxonomy import get_persona_traits
from hr_ai.security.intent_verifier import verify_team_config
from hr_ai.comms.softskills_estimator import estimate_softskills

class TeamFitAnalyzer:
    def __init__(self):
        self.persona_map = get_persona_traits()

    def analyze_fit(
        self,
        candidate_profile: Dict[str, Any],
        team_profiles: List[Dict[str, Any]],
        role_requirements: Dict[str, Any],
    ) -> Dict[str, Any]:
        assert verify_team_config(team_profiles), "Unverifiable team configuration"

        candidate_vector = self._compose_vector(candidate_profile)
        team_vectors = [self._compose_vector(p) for p in team_profiles]

        team_centroid = np.mean(team_vectors, axis=0)
        culture_alignment = self._cosine_similarity(candidate_vector, team_centroid)

        role_gap = self._evaluate_role_gap(candidate_profile, team_profiles)
        softskills_delta = self._softskills_delta(candidate_profile, team_profiles)

        predicted_performance = predict_candidate_performance(candidate_vector)

        return {
            "team_culture_alignment": round(culture_alignment, 3),
            "role_gap_score": role_gap,
            "softskills_balance": softskills_delta,
            "predicted_performance": predicted_performance,
            "recommendation": self._generate_recommendation(culture_alignment, role_gap, softskills_delta),
        }

    def _compose_vector(self, profile: Dict[str, Any]) -> List[float]:
        traits = profile.get("traits", [])
        skills = profile.get("skills", [])
        values = profile.get("values", [])
        raw = " ".join(traits + skills + values)
        return get_vector_embedding(raw)

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        vec1 = np.array(vec1)
        vec2 = np.array(vec2)
        return float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2) + 1e-9))

    def _evaluate_role_gap(self, candidate: Dict[str, Any], team: List[Dict[str, Any]]) -> float:
        team_roles = [member.get("role") for member in team]
        candidate_role = candidate.get("role")
        role_weight = self.persona_map.get(candidate_role, {}).get("strategic_weight", 0.5)
        scarcity = 1 - team_roles.count(candidate_role) / max(len(team_roles), 1)
        return round(role_weight * scarcity, 3)

    def _softskills_delta(self, candidate: Dict[str, Any], team: List[Dict[str, Any]]) -> Dict[str, float]:
        candidate_softskills = estimate_softskills(candidate.get("bio", ""))
        team_softskills = [estimate_softskills(t.get("bio", "")) for t in team]
        team_avg = {
            key: np.mean([member.get(key, 0.5) for member in team_softskills]) for key in candidate_softskills
        }
        delta = {
            key: round(candidate_softskills[key] - team_avg.get(key, 0.5), 3) for key in candidate_softskills
        }
        return delta

    def _generate_recommendation(self, align: float, role_gap: float, softskills: Dict[str, float]) -> str:
        if align > 0.85 and role_gap > 0.6:
            return "Strongly Recommended"
        elif align > 0.7 and abs(np.mean(list(softskills.values()))) < 0.1:
            return "Recommended"
        return "Neutral / Needs Manual Review"
