import re
import logging
from typing import List, Dict, Optional
from transformers import pipeline
from .toxicity_signatures import TOXIC_PATTERNS, JAILBREAK_PATTERNS
from ..utils import logger

# --- Класс защиты вывода модели ---
class ModelGuard:
    def __init__(self, enable_toxicity_filter: bool = True, enable_regex_filters: bool = True):
        self.enable_toxicity_filter = enable_toxicity_filter
        self.enable_regex_filters = enable_regex_filters

        # Модель для оценки токсичности (предобученный zero-shot классификатор)
        if self.enable_toxicity_filter:
            try:
                self.classifier = pipeline("text-classification", model="unitary/toxic-bert", top_k=None)
            except Exception as e:
                logger.error(f"Не удалось инициализировать модель токсичности: {e}")
                self.classifier = None

        # Предзагруженные регулярные шаблоны
        self.toxic_patterns = TOXIC_PATTERNS
        self.jailbreak_patterns = JAILBREAK_PATTERNS

    def check_regex_patterns(self, text: str, patterns: List[re.Pattern]) -> Optional[str]:
        for pattern in patterns:
            if pattern.search(text):
                return pattern.pattern
        return None

    def check_toxicity_score(self, text: str) -> float:
        if self.classifier is None:
            return 0.0
        try:
            result = self.classifier(text)
            toxic_scores = [r["score"] for r in result[0] if r["label"].lower() in ["toxic", "insult", "threat"]]
            return max(toxic_scores) if toxic_scores else 0.0
        except Exception as e:
            logger.error(f"Ошибка при оценке токсичности: {e}")
            return 0.0

    def evaluate_output(self, output: str) -> Dict[str, Optional[str]]:
        logger.debug("Выполняется предвалидация вывода модели")

        # Проверка токсичности по модели
        toxicity_flagged = False
        toxicity_score = 0.0
        if self.enable_toxicity_filter:
            toxicity_score = self.check_toxicity_score(output)
            toxicity_flagged = toxicity_score > 0.7

        # Проверка по регэкспам
        regex_flagged = False
        matched_signature = None
        if self.enable_regex_filters:
            for pattern_list in [self.toxic_patterns, self.jailbreak_patterns]:
                matched = self.check_regex_patterns(output, pattern_list)
                if matched:
                    regex_flagged = True
                    matched_signature = matched
                    break

        is_safe = not (toxicity_flagged or regex_flagged)

        return {
            "is_safe": is_safe,
            "toxicity_score": f"{toxicity_score:.2f}",
            "matched_pattern": matched_signature,
            "toxicity_flagged": toxicity_flagged,
            "regex_flagged": regex_flagged,
        }

    def enforce_or_raise(self, output: str):
        result = self.evaluate_output(output)
        if not result["is_safe"]:
            logger.warning(f"Заблокирован небезопасный вывод: {result}")
            raise ValueError(f"Небезопасный вывод обнаружен. Причина: {result}")
