# agent_mash/hr/recruiting.py
from __future__ import annotations

import dataclasses
import enum
import logging
import time
from typing import Dict, List, Optional, Protocol, Sequence


logger = logging.getLogger(__name__)


class RecruitingError(RuntimeError):
    pass


class CandidateStatus(str, enum.Enum):
    APPLIED = "applied"
    SCREENING = "screening"
    INTERVIEW = "interview"
    OFFER = "offer"
    HIRED = "hired"
    REJECTED = "rejected"


class Decision(str, enum.Enum):
    PASS = "pass"
    HOLD = "hold"
    FAIL = "fail"


@dataclasses.dataclass(frozen=True)
class Candidate:
    candidate_id: str
    full_name: str
    email: str
    skills: Sequence[str]
    experience_years: float
    applied_at_ms: int
    status: CandidateStatus = CandidateStatus.APPLIED


@dataclasses.dataclass(frozen=True)
class Vacancy:
    vacancy_id: str
    title: str
    required_skills: Sequence[str]
    min_experience_years: float
    created_at_ms: int
    is_open: bool = True


@dataclasses.dataclass(frozen=True)
class EvaluationResult:
    candidate_id: str
    vacancy_id: str
    score: float
    decision: Decision
    evaluated_at_ms: int
    notes: Optional[str] = None


class AuditSink(Protocol):
    def emit(self, event: Dict[str, object]) -> None:
        ...


class SystemClock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class RecruitingEngine:
    def __init__(
        self,
        *,
        audit_sink: Optional[AuditSink] = None,
        clock: Optional[SystemClock] = None,
    ) -> None:
        self._audit_sink = audit_sink
        self._clock = clock or SystemClock()

    def evaluate_candidate(
        self,
        *,
        candidate: Candidate,
        vacancy: Vacancy,
    ) -> EvaluationResult:
        if not vacancy.is_open:
            raise RecruitingError("Vacancy is closed")

        score = self._calculate_score(candidate, vacancy)
        decision = self._make_decision(score)

        result = EvaluationResult(
            candidate_id=candidate.candidate_id,
            vacancy_id=vacancy.vacancy_id,
            score=score,
            decision=decision,
            evaluated_at_ms=self._clock.now_ms(),
        )

        self._audit(candidate, vacancy, result)
        return result

    def _calculate_score(self, candidate: Candidate, vacancy: Vacancy) -> float:
        matched_skills = set(candidate.skills) & set(vacancy.required_skills)
        skill_score = len(matched_skills) / max(len(vacancy.required_skills), 1)

        experience_score = min(
            candidate.experience_years / max(vacancy.min_experience_years, 1.0),
            1.0,
        )

        final_score = round((skill_score * 0.7 + experience_score * 0.3) * 100, 2)
        logger.debug(
            "Score calculated",
            extra={
                "candidate_id": candidate.candidate_id,
                "vacancy_id": vacancy.vacancy_id,
                "skill_score": skill_score,
                "experience_score": experience_score,
                "final_score": final_score,
            },
        )
        return final_score

    def _make_decision(self, score: float) -> Decision:
        if score >= 80.0:
            return Decision.PASS
        if score >= 50.0:
            return Decision.HOLD
        return Decision.FAIL

    def _audit(
        self,
        candidate: Candidate,
        vacancy: Vacancy,
        result: EvaluationResult,
    ) -> None:
        if self._audit_sink is None:
            return

        event = {
            "event": "recruiting_evaluation",
            "candidate_id": candidate.candidate_id,
            "vacancy_id": vacancy.vacancy_id,
            "score": result.score,
            "decision": result.decision.value,
            "timestamp_ms": result.evaluated_at_ms,
        }

        try:
            self._audit_sink.emit(event)
        except Exception as exc:
            raise RecruitingError(str(exc)) from exc
