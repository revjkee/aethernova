import logging
from typing import Any, Dict, List, Optional

from llmops.eval.eval_on_tasks.task_loader import load_tasks
from llmops.eval.eval_on_tasks.task_runner import run_task
from llmops.eval.reports.reporter import generate_report
from llmops.eval.reports.metrics_aggregator import aggregate_metrics
from llmops.eval.validators.model_guard import safe_model_wrapper
from llmops.eval.validators.format_validator import validate_io_format
from llmops.eval.utils import load_config, timed_block, setup_logger
from llmops.eval.constants import TASK_FLAGS, EvalError
from llmops.eval.quality_metrics import compute_quality_metrics
from llmops.eval.hallucination_checker import check_factual_consistency
from llmops.eval.toxicity_detector import detect_toxicity

log = setup_logger("eval_pipeline")

class EvaluationPipeline:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.results = []

    def run(self):
        log.info("Starting centralized evaluation pipeline")
        try:
            tasks = load_tasks(self.config["tasks"])
            for task in tasks:
                with timed_block(f"Task: {task['name']}"):
                    self._run_task_pipeline(task)
        except EvalError as e:
            log.error(f"Pipeline failed: {str(e)}")
            raise
        finally:
            self._finalize()

    def _run_task_pipeline(self, task: Dict[str, Any]):
        try:
            model = safe_model_wrapper(task["model"])
            task_name = task["name"]

            log.info(f"Running task: {task_name} with model {model.name}")
            predictions = run_task(task, model)

            validate_io_format(predictions, schema=task.get("schema"))
            quality_scores = compute_quality_metrics(predictions, task.get("references"))
            hallucination_scores = check_factual_consistency(predictions, task.get("references"))
            toxicity_scores = detect_toxicity(predictions)

            task_result = {
                "task": task_name,
                "metrics": quality_scores,
                "hallucinations": hallucination_scores,
                "toxicity": toxicity_scores,
            }
            self.results.append(task_result)

            log.info(f"Finished task {task_name} — collected {len(predictions)} samples")

        except Exception as e:
            log.error(f"Failed on task {task['name']}: {e}")
            raise EvalError(f"Task failure: {e}")

    def _finalize(self):
        if not self.results:
            log.warning("No evaluation results collected.")
            return
        summary = aggregate_metrics(self.results)
        generate_report(self.results, summary)
        log.info("Evaluation completed. Report generated.")

