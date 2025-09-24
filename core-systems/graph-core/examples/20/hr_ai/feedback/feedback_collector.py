import uuid
import logging
from datetime import datetime
from typing import List, Dict, Optional, Union
from pydantic import BaseModel, Field, validator
from enum import Enum
import hashlib

# === Логирование и метрики ===
logger = logging.getLogger("feedback_collector")
logger.setLevel(logging.INFO)

# === Категории обратной связи ===
class FeedbackType(str, Enum):
    INTERVIEW = "interview"
    HR_REVIEW = "hr_review"
    MANAGER_ASSESSMENT = "manager_assessment"
    SYSTEM_SCORE = "system_score"
    EXIT_FEEDBACK = "exit_feedback"
    CULTURE_FIT = "culture_fit"

# === Структура входного фидбэка ===
class RawFeedback(BaseModel):
    feedback_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    candidate_id: str
    source: str  # e.g. "HR", "Manager", "AutomatedSystem"
    type: FeedbackType
    score: Optional[float] = Field(ge=0.0, le=1.0)
    text: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    language: str = "en"

    @validator("text")
    def sanitize_text(cls, v):
        if v and len(v) > 10000:
            raise ValueError("Feedback text too long")
        return v

# === Защита приватности (анонимизация) ===
def anonymize_candidate_id(candidate_id: str) -> str:
    return hashlib.sha256(candidate_id.encode()).hexdigest()

# === Препроцессинг: нормализация тегов ===
def normalize_tags(tags: List[str]) -> List[str]:
    return list(set(tag.lower().strip().replace(" ", "_") for tag in tags))

# === Финальная запись фидбэка для ML обучения ===
class ProcessedFeedback(BaseModel):
    anon_id: str
    type: FeedbackType
    score: Optional[float]
    text: Optional[str]
    tags: List[str]
    timestamp: datetime
    lang: str

# === Хранилище (можно заменить на базу/облако) ===
class FeedbackStorage:
    def __init__(self):
        self._data: List[ProcessedFeedback] = []

    def save(self, feedback: ProcessedFeedback):
        self._data.append(feedback)
        logger.info(f"[FeedbackStored] {feedback.anon_id} {feedback.type} {feedback.timestamp}")

    def all(self) -> List[ProcessedFeedback]:
        return self._data

    def by_type(self, feedback_type: FeedbackType) -> List[ProcessedFeedback]:
        return [f for f in self._data if f.type == feedback_type]

# === Основной сборщик ===
class FeedbackCollector:
    def __init__(self, storage: FeedbackStorage):
        self.storage = storage

    def ingest(self, raw: RawFeedback):
        logger.info(f"[Ingest] Received feedback from {raw.source} for {raw.candidate_id}")

        processed = ProcessedFeedback(
            anon_id=anonymize_candidate_id(raw.candidate_id),
            type=raw.type,
            score=raw.score,
            text=raw.text,
            tags=normalize_tags(raw.tags),
            timestamp=raw.submitted_at,
            lang=raw.language
        )

        self.storage.save(processed)

    def batch_ingest(self, items: List[RawFeedback]):
        for item in items:
            try:
                self.ingest(item)
            except Exception as e:
                logger.error(f"[BatchIngestError] {e}")

