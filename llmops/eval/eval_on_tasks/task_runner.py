import logging
from typing import Dict, Any, List, Callable

from llmops.eval.quality_metrics import calculate_metrics
from llmops.eval.hallucination_checker import check_hallucination
from llmops.eval.toxicity_detector import assess_toxicity
from llmops.eval.utils import safe_json_dump
from llmops.eval.constants import DEFAULT_METRICS
from llmops.eval.validators.format_validator import validate_io_format

log = logging.getLogger("task_runner")

class TaskRunner:
    """
    Запускает оценку по задачам с различными метриками, обработкой вывода и логированием.
    """

    def __init__(self, task_config: Dict[str, Any]):
        self.task_name = task_config.get("task_name", "unknown_task")
        self.samples = task_config.get("samples", [])
        self.metrics = task_config.get("metrics", DEFAULT_METRICS)
        self.eval_pipeline: List[Callable[[Dict[str, Any]], Dict[str, Any]]] = []
        self._build_pipeline()

    def _build_pipeline(self):
        """
        Формирует пайплайн оценки в зависимости от конфигурации.
        """
        self.eval_pipeline.append(self._run_quality_metrics)

        if "toxicity" in self.metrics:
            self.eval_pipeline.append(self._run_toxicity)

        if "hallucination" in self.metrics:
            self.eval_pipeline.append(self._run_hallucination)

    def run(self) -> List[Dict[str, Any]]:
        """
        Запускает пайплайн оценки по всем сэмплам.
        """
        results = []
        for idx, sample in enumerate(self.samples):
            try:
                validate_io_format(sample)
                result = sample.copy()
                for stage in self.eval_pipeline:
                    result.update(stage(result))
                results.append(result)
            except Exception as e:
                log.warning(f"[{self.task_name}] Sample #{idx} failed: {e}")
                results.append({
                    "error": str(e),
                    "original": sample
                })
        return results

    def _run_quality_metrics(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Вычисляет базовые метрики качества (BLEU, ROUGE и др.)
        """
        return calculate_metrics(
            prediction=sample.get("output", ""),
            reference=sample.get("reference", ""),
            metrics=self.metrics
        )

    def _run_toxicity(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Проверка токсичности/вредоносности генерации.
        """
        return assess_toxicity(sample.get("output", ""))

    def _run_hallucination(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Проверка галлюцинаций на основе контекста.
        """
        return check_hallucination(
            context=sample.get("context", ""),
            output=sample.get("output", "")
        )

