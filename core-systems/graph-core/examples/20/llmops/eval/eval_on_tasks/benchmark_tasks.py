import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Callable

log = logging.getLogger("eval_tasks")

# Регистрация задач
TASK_REGISTRY: Dict[str, Callable[[], "BaseEvalTask"]] = {}


def register_task(name: str):
    def decorator(cls):
        TASK_REGISTRY[name] = cls
        return cls
    return decorator


class BaseEvalTask(ABC):
    """Абстрактный интерфейс для всех eval-задач."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def run(self, model_outputs: List[str], references: List[str]) -> Dict[str, Any]:
        """Выполняет метрику и возвращает словарь с результатами"""
        raise NotImplementedError

    @abstractmethod
    def task_name(self) -> str:
        """Название задачи"""
        raise NotImplementedError


@register_task("summarization")
class SummarizationEval(BaseEvalTask):
    def run(self, model_outputs: List[str], references: List[str]) -> Dict[str, Any]:
        from llmops.eval.quality_metrics import compute_bleu, compute_rouge

        bleu_score = compute_bleu(model_outputs, references)
        rouge_scores = compute_rouge(model_outputs, references)

        return {
            "task": self.task_name(),
            "bleu": bleu_score,
            "rouge": rouge_scores,
        }

    def task_name(self) -> str:
        return "summarization"


@register_task("qa")
class QAEval(BaseEvalTask):
    def run(self, model_outputs: List[str], references: List[str]) -> Dict[str, Any]:
        from llmops.eval.quality_metrics import compute_exact_match, compute_f1_score

        exact = compute_exact_match(model_outputs, references)
        f1 = compute_f1_score(model_outputs, references)

        return {
            "task": self.task_name(),
            "exact_match": exact,
            "f1_score": f1,
        }

    def task_name(self) -> str:
        return "qa"


@register_task("chat")
class ChatEval(BaseEvalTask):
    def run(self, model_outputs: List[str], references: List[str]) -> Dict[str, Any]:
        from llmops.eval.quality_metrics import compute_bleu

        bleu = compute_bleu(model_outputs, references)

        return {
            "task": self.task_name(),
            "bleu": bleu,
            "coherence": self._dummy_coherence(model_outputs),
        }

    def task_name(self) -> str:
        return "chat"

    def _dummy_coherence(self, outputs: List[str]) -> float:
        # Заглушка — в боевом модуле заменяется на ML-модель или RL-фидбек
        return sum(len(o.split()) for o in outputs) / (len(outputs) * 10 + 1)


def load_eval_task(task_name: str, config: Dict[str, Any]) -> BaseEvalTask:
    if task_name not in TASK_REGISTRY:
        raise ValueError(f"Unsupported task type: {task_name}")
    log.debug(f"Loaded task: {task_name}")
    return TASK_REGISTRY[task_name](config)
