import logging
from typing import List, Dict, Any

from llmops.eval.utils import timed_block
from llmops.eval.constants import EvalError
from llmops.eval.validators.model_guard import safe_embedding_model
from llmops.eval.utils import cosine_similarity, extract_named_entities

log = logging.getLogger("hallucination_checker")


class HallucinationChecker:
    def __init__(self, retriever=None, similarity_threshold: float = 0.75):
        self.retriever = retriever or safe_embedding_model()
        self.similarity_threshold = similarity_threshold

    def check(self, predictions: List[Dict[str, Any]], references: List[str]) -> List[Dict[str, Any]]:
        """
        Проверяет наличие галлюцинаций на основе:
        - Сравнения эмбеддингов (semantic similarity)
        - Проверки именованных сущностей (NER)
        - Опциональной внешней проверки (retriever-based)
        """
        results = []
        with timed_block("Hallucination detection"):
            for i, pred in enumerate(predictions):
                hypothesis = pred.get("output", "")
                reference = references[i] if i < len(references) else ""

                sim_score = self._compare_semantically(hypothesis, reference)
                ner_divergence = self._check_named_entities(hypothesis, reference)
                retriever_flag = self._external_fact_check(hypothesis) if self.retriever else None

                is_hallucinated = (
                    sim_score < self.similarity_threshold or
                    ner_divergence > 0.5 or
                    (retriever_flag is not None and not retriever_flag)
                )

                results.append({
                    "index": i,
                    "hallucinated": is_hallucinated,
                    "similarity_score": round(sim_score, 4),
                    "ner_divergence": round(ner_divergence, 4),
                    "retriever_verified": retriever_flag
                })

        return results

    def _compare_semantically(self, hypothesis: str, reference: str) -> float:
        try:
            vec_hyp = self.retriever.embed(hypothesis)
            vec_ref = self.retriever.embed(reference)
            return cosine_similarity(vec_hyp, vec_ref)
        except Exception as e:
            log.warning(f"Semantic similarity error: {e}")
            return 0.0

    def _check_named_entities(self, hyp: str, ref: str) -> float:
        try:
            ent_hyp = set(extract_named_entities(hyp))
            ent_ref = set(extract_named_entities(ref))
            if not ent_ref:
                return 0.0
            return 1 - len(ent_hyp & ent_ref) / max(1, len(ent_ref))
        except Exception as e:
            log.warning(f"NER check error: {e}")
            return 1.0

    def _external_fact_check(self, hypothesis: str) -> bool:
        try:
            result = self.retriever.verify_fact(hypothesis)
            return bool(result)
        except Exception as e:
            log.warning(f"Retriever fact check error: {e}")
            return None


def check_factual_consistency(predictions: List[Dict[str, Any]], references: List[str]) -> List[Dict[str, Any]]:
    checker = HallucinationChecker()
    return checker.check(predictions, references)
