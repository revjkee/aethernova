# llmops/eval/hallucination_checker.py

from typing import List, Optional
import difflib

class HallucinationChecker:
    """
    Модуль для проверки галлюцинаций (fabrications) в ответах LLM.
    Использует простое сравнение с эталонными данными и метрики схожести.
    """

    @staticmethod
    def similarity_ratio(text1: str, text2: str) -> float:
        """
        Вычисляет коэффициент схожести двух строк (от 0 до 1).
        """
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    @classmethod
    def check_against_reference(cls, generated: str, references: List[str], threshold: float = 0.7) -> bool:
        """
        Проверяет, есть ли в сгенерированном тексте галлюцинации,
        сравнивая с набором эталонных ответов.
        Возвращает True, если текст не совпадает с эталонами (галлюцинация).
        """
        for ref in references:
            if cls.similarity_ratio(generated, ref) >= threshold:
                return False  # Нет галлюцинации, есть хорошее совпадение
        return True  # Галлюцинация, нет достаточного совпадения

    @classmethod
    def find_mismatched_segments(cls, generated: str, reference: str) -> Optional[List[str]]:
        """
        Выделяет несоответствующие фрагменты между сгенерированным и эталонным текстом.
        Возвращает список фрагментов или None, если текст совпадает.
        """
        seq_matcher = difflib.SequenceMatcher(None, generated, reference)
        mismatches = []
        for tag, i1, i2, j1, j2 in seq_matcher.get_opcodes():
            if tag != 'equal':
                mismatches.append(generated[i1:i2])
        return mismatches if mismatches else None
