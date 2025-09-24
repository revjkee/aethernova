from typing import Dict, List, Union
from pydantic import BaseModel, Field
from enum import Enum


class EvalTaskType(str, Enum):
    SUMMARIZATION = "summarization"
    QA = "question_answering"
    REASONING = "reasoning"
    CHAT = "chat"
    GENERIC = "generic"


class MetricType(str, Enum):
    BLEU = "bleu"
    ROUGE = "rouge"
    METEOR = "meteor"
    BERTSCORE = "bertscore"
    FACTUALITY = "factuality"
    TOXICITY = "toxicity"
    LATENCY = "latency"
    HALLUCINATION = "hallucination"
    JUDGE = "judge_score"


class TaskWeight(BaseModel):
    task: EvalTaskType
    weight: float = Field(..., ge=0, le=1)
    active: bool = True
    tags: List[str] = Field(default_factory=list)


class MetricWeight(BaseModel):
    metric: MetricType
    weight: float = Field(..., ge=0, le=1)
    threshold: float = Field(default=0.0, ge=0, le=1)
    normalize: bool = True
    enabled: bool = True


class EvalConfig(BaseModel):
    version: str = "1.0.0"
    model_name: str
    run_id: str
    language: str = "en"
    seed: int = 42
    tasks: List[TaskWeight]
    metrics: List[MetricWeight]
    global_threshold: float = 0.5
    enable_hallucination_check: bool = True
    enable_toxicity_check: bool = True
    enable_judge_scorer: bool = True
    meta_tags: List[str] = Field(default_factory=lambda: ["default", "eval", "v1"])
    notes: str = ""


# Пример базовой конфигурации по умолчанию
DEFAULT_EVAL_CONFIG = EvalConfig(
    model_name="teslaai/genesis-v7",
    run_id="initial-baseline",
    tasks=[
        TaskWeight(task=EvalTaskType.SUMMARIZATION, weight=0.3, tags=["core", "gen"]),
        TaskWeight(task=EvalTaskType.QA, weight=0.3, tags=["factual"]),
        TaskWeight(task=EvalTaskType.REASONING, weight=0.4, tags=["logic"]),
    ],
    metrics=[
        MetricWeight(metric=MetricType.BLEU, weight=0.15),
        MetricWeight(metric=MetricType.ROUGE, weight=0.15),
        MetricWeight(metric=MetricType.METEOR, weight=0.10),
        MetricWeight(metric=MetricType.BERTSCORE, weight=0.15),
        MetricWeight(metric=MetricType.FACTUALITY, weight=0.20, threshold=0.6),
        MetricWeight(metric=MetricType.TOXICITY, weight=0.10, threshold=0.2),
        MetricWeight(metric=MetricType.HALLUCINATION, weight=0.10, threshold=0.3),
        MetricWeight(metric=MetricType.JUDGE, weight=0.05, threshold=0.5),
    ],
    global_threshold=0.5,
    enable_hallucination_check=True,
    enable_toxicity_check=True,
    enable_judge_scorer=True,
    meta_tags=["baseline", "genesis-v7"],
    notes="Initial config for TeslaAI Genesis eval baseline"
)
