import enum
from typing import Optional, Dict, List, Literal, Union
from pydantic import BaseModel, Field, validator
from datetime import datetime

# Метки HR-оценок (универсальные)
class HRLabel(enum.Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    HOLD = "hold"
    NEEDS_INTERVIEW = "needs_interview"
    REQUIRES_MANAGER_REVIEW = "requires_manager_review"
    RECOMMENDED = "recommended"
    NOT_RECOMMENDED = "not_recommended"
    NEEDS_MORE_INFO = "needs_more_info"
    BACKGROUND_CHECK_PENDING = "background_check_pending"


# Причины отказа (предикатные)
class RejectionReason(enum.Enum):
    LACK_OF_SKILLS = "lack_of_skills"
    POOR_SOFT_SKILLS = "poor_soft_skills"
    SALARY_MISMATCH = "salary_expectation_mismatch"
    NO_CULTURE_FIT = "no_culture_fit"
    POSITION_CLOSED = "position_closed"
    DUPLICATE_PROFILE = "duplicate_profile"
    FAILED_INTERVIEW = "failed_interview"
    NO_SHOW = "no_show"
    LANGUAGE_BARRIER = "language_barrier"
    VISA_ISSUES = "visa_issues"
    OTHER = "other"


# Уровень уверенности HR-оценки
ConfidenceLevel = Literal["high", "medium", "low"]


# Модель метки HR-фидбэка
class HRFeedbackLabel(BaseModel):
    candidate_id: str
    label: HRLabel
    assigned_by: str  # HR-username/email
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    confidence: ConfidenceLevel
    rejection_reason: Optional[RejectionReason] = None
    comments: Optional[str] = None
    locale: Optional[str] = "en-US"

    @validator("comments")
    def sanitize_comments(cls, v):
        if v and len(v) > 1000:
            raise ValueError("Comment is too long")
        return v

    @validator("rejection_reason", always=True)
    def validate_rejection_reason(cls, v, values):
        if values.get("label") == HRLabel.REJECTED and not v:
            raise ValueError("Rejection reason must be provided if label is REJECTED")
        return v


# Интерфейс для локализованных текстов (UI/Report/Email)
HR_LABEL_TEXTS: Dict[str, Dict[HRLabel, str]] = {
    "en-US": {
        HRLabel.APPROVED: "Approved for further steps",
        HRLabel.REJECTED: "Rejected",
        HRLabel.HOLD: "On Hold",
        HRLabel.NEEDS_INTERVIEW: "Interview Required",
        HRLabel.REQUIRES_MANAGER_REVIEW: "Requires Manager Review",
        HRLabel.RECOMMENDED: "Recommended",
        HRLabel.NOT_RECOMMENDED: "Not Recommended",
        HRLabel.NEEDS_MORE_INFO: "Needs More Info",
        HRLabel.BACKGROUND_CHECK_PENDING: "Pending Background Check"
    },
    "ru-RU": {
        HRLabel.APPROVED: "Одобрен для дальнейших этапов",
        HRLabel.REJECTED: "Отклонён",
        HRLabel.HOLD: "На удержании",
        HRLabel.NEEDS_INTERVIEW: "Требуется интервью",
        HRLabel.REQUIRES_MANAGER_REVIEW: "Нужна проверка руководителя",
        HRLabel.RECOMMENDED: "Рекомендован",
        HRLabel.NOT_RECOMMENDED: "Не рекомендован",
        HRLabel.NEEDS_MORE_INFO: "Нужна дополнительная информация",
        HRLabel.BACKGROUND_CHECK_PENDING: "Ожидает проверку данных"
    }
}


def get_label_text(label: HRLabel, locale: str = "en-US") -> str:
    return HR_LABEL_TEXTS.get(locale, {}).get(label, label.value)


# Хранилище (можно заменить на persistent storage или API)
class HRLabelStore:
    def __init__(self):
        self._storage: Dict[str, List[HRFeedbackLabel]] = {}

    def add_label(self, label: HRFeedbackLabel):
        self._storage.setdefault(label.candidate_id, []).append(label)

    def get_labels(self, candidate_id: str) -> List[HRFeedbackLabel]:
        return self._storage.get(candidate_id, [])

    def latest_label(self, candidate_id: str) -> Optional[HRFeedbackLabel]:
        return max(self._storage.get(candidate_id, []), key=lambda x: x.timestamp, default=None)
