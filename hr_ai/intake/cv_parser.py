import re
import json
import logging
from pathlib import Path
from typing import List, Optional
from langdetect import detect
from pydantic import BaseModel
from spacy.language import Language
from spacy.lang.en import English
from sklearn.feature_extraction.text import TfidfVectorizer

from hr_ai.models.schema import ParsedCV, EducationEntry, WorkExperienceEntry, SkillEntry
from hr_ai.utils.security import sanitize, detect_suspicious_input
from hr_ai.utils.language import detect_language
from hr_ai.nlp.skill_model import extract_skill_vectors

logger = logging.getLogger("hr_ai.cv_parser")
logger.setLevel(logging.INFO)

class CVParser:
    def __init__(self, nlp: Optional[Language] = None):
        self.nlp = nlp or English()
        self.vectorizer = TfidfVectorizer()

    def load_text(self, path: Path) -> str:
        text = path.read_text(encoding='utf-8', errors='ignore')
        logger.info(f"Загружен файл: {path}")
        return sanitize(text)

    def parse_cv(self, text: str) -> ParsedCV:
        logger.debug("Старт анализа CV")
        if detect_suspicious_input(text):
            logger.warning("Обнаружена аномалия в тексте CV")
            raise ValueError("Аномальный ввод. CV отклонено.")

        language = detect_language(text)
        skills = self._extract_skills(text)
        education = self._extract_education(text)
        experience = self._extract_experience(text)

        return ParsedCV(
            language=language,
            skills=skills,
            education=education,
            experience=experience
        )

    def _extract_skills(self, text: str) -> List[SkillEntry]:
        logger.debug("Извлечение навыков")
        return extract_skill_vectors(text)

    def _extract_education(self, text: str) -> List[EducationEntry]:
        logger.debug("Извлечение образования")
        pattern = re.compile(r"(University|College|B\.Sc|M\.Sc|Ph\.D|Diploma|Bachelor|Master).{0,80}", re.I)
        matches = pattern.findall(text)
        return [EducationEntry(institution=m.strip(), degree="autodetected", years="n/a") for m in set(matches)]

    def _extract_experience(self, text: str) -> List[WorkExperienceEntry]:
        logger.debug("Извлечение опыта")
        pattern = re.compile(r"(?P<role>[A-Z][a-z\s]+)\s+at\s+(?P<company>[A-Z][\w\s&\-]+).*?(\d{4})", re.I)
        entries = []
        for m in pattern.finditer(text):
            entries.append(WorkExperienceEntry(
                role=m.group("role").strip(),
                company=m.group("company").strip(),
                start_year=int(m.group(3)),
                end_year=None
            ))
        return entries

if __name__ == "__main__":
    import sys
    from rich import print

    parser = CVParser()
    try:
        path = Path(sys.argv[1])
        raw = parser.load_text(path)
        result = parser.parse_cv(raw)
        print(result.json(indent=2, ensure_ascii=False))
    except Exception as e:
        logger.exception("Ошибка при обработке CV")
        print(f"[red bold]Ошибка:[/red bold] {e}")
