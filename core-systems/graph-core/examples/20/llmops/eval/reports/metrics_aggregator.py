import numpy as np
from typing import Dict, Any, List, Union, Optional
from collections import defaultdict
from ..constants import DEFAULT_METRIC_WEIGHTS, SUPPORTED_TASKS
from ..utils import logger


class MetricsAggregator:
    def __init__(
        self,
        metric_weights: Optional[Dict[str, float]] = None,
        normalize: bool = True,
        skip_nan: bool = True
    ):
        self.metric_weights = metric_weights or DEFAULT_METRIC_WEIGHTS
        self.normalize = normalize
        self.skip_nan = skip_nan

    def aggregate(self, results: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Starting metric aggregation")
        per_task_scores = {}
        global_scores = defaultdict(list)

        for task_name, task_results in results.items():
            if task_name not in SUPPORTED_TASKS:
                logger.warning(f"Task {task_name} not supported, skipping.")
                continue

            logger.debug(f"Aggregating task: {task_name}")
            task_metrics = task_results.get("metrics", {})
            if not task_metrics:
                logger.warning(f"No metrics found for task {task_name}")
                continue

            task_score = self._weighted_score(task_metrics)
            per_task_scores[task_name] = {
                "score": task_score,
                "metrics": task_metrics,
                "n_samples": task_results.get("n_samples", 0),
            }

            global_scores["all"].append(task_score)

            # Переметриковая агрегация (BLEU, ROUGE и т.д.)
            for metric_name, metric_value in task_metrics.items():
                if not self.skip_nan or not self._is_nan(metric_value):
                    global_scores[metric_name].append(metric_value)

        final_summary = {
            "overall_score": np.mean(global_scores["all"]) if global_scores["all"] else 0.0,
            "by_task": per_task_scores,
            "by_metric": {
                k: np.mean(v) if v else 0.0 for k, v in global_scores.items() if k != "all"
            },
            "weights_used": self.metric_weights,
            "normalize": self.normalize
        }

        logger.debug("Metric aggregation completed")
        return final_summary

    def _weighted_score(self, metrics: Dict[str, float]) -> float:
        score_sum = 0.0
        weight_sum = 0.0

        for name, value in metrics.items():
            if name not in self.metric_weights:
                continue

            if self.skip_nan and self._is_nan(value):
                continue

            weight = self.metric_weights[name]
            score_sum += value * weight
            weight_sum += weight

        if weight_sum == 0:
            return 0.0

        return score_sum / weight_sum

    @staticmethod
    def _is_nan(val: Union[float, Any]) -> bool:
        try:
            return np.isnan(val)
        except Exception:
            return False


def aggregate_metrics(results: Dict[str, Any]) -> Dict[str, Any]:
    aggregator = MetricsAggregator()
    return aggregator.aggregate(results)
