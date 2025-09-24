import logging
from typing import List, Dict, Any
from genius_core.utils.config import load_config
from genius_core.analytics.progress_tracker import ProgressEvaluator
from genius_core.curriculum.sampling_strategies import SamplingStrategyFactory
from genius_core.security.content_filter import ContentSanitizer
from genius_core.meta.versioning import log_curriculum_change
from genius_core.utils.logger import setup_logger

logger = setup_logger("curriculum_manager", log_level=logging.INFO)

class CurriculumManager:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.curriculum_config = self.config.get("curriculum", {})
        self.modules = self.curriculum_config.get("modules", [])
        self.strategy = SamplingStrategyFactory.get(self.curriculum_config.get("strategy", "adaptive"))
        self.progress_tracker = ProgressEvaluator(self.config["tracking"])
        self.content_sanitizer = ContentSanitizer(self.config["security"])
        self.active_curriculum = []
        self.model_stage = 0
        log_curriculum_change("initialized", self.curriculum_config)

    def get_next_batch(self, model_metrics: Dict[str, float]) -> List[Dict[str, Any]]:
        logger.debug("Selecting next batch of tasks based on model metrics.")
        priority_scores = self.strategy.evaluate_priority(self.modules, model_metrics)
        sorted_modules = sorted(self.modules, key=lambda x: priority_scores.get(x["name"], 0), reverse=True)
        selected = self._select_modules(sorted_modules)
        sanitized = [self.content_sanitizer.sanitize(module) for module in selected]
        self.active_curriculum = sanitized
        log_curriculum_change("batch_selected", {"modules": [m["name"] for m in sanitized]})
        return sanitized

    def _select_modules(self, sorted_modules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        max_modules = self.curriculum_config.get("max_active_modules", 5)
        selected = sorted_modules[:max_modules]
        logger.info(f"Selected modules for current round: {[m['name'] for m in selected]}")
        return selected

    def update_progress(self, model_outputs: Dict[str, Any]) -> None:
        logger.debug("Updating progress based on model outputs.")
        self.progress_tracker.update(model_outputs)
        progress_state = self.progress_tracker.get_state()
        logger.info(f"Progress updated: {progress_state}")
        self._adjust_difficulty(progress_state)

    def _adjust_difficulty(self, progress_state: Dict[str, Any]) -> None:
        threshold = self.curriculum_config.get("adjust_threshold", 0.85)
        if progress_state["mean_score"] > threshold and self.model_stage < self.curriculum_config.get("max_stages", 5):
            self.model_stage += 1
            self.strategy.increment_stage()
            log_curriculum_change("difficulty_increased", {"stage": self.model_stage})
            logger.info(f"Curriculum stage increased to: {self.model_stage}")
        elif progress_state["mean_score"] < 0.3 and self.model_stage > 0:
            self.model_stage -= 1
            self.strategy.decrement_stage()
            log_curriculum_change("difficulty_decreased", {"stage": self.model_stage})
            logger.info(f"Curriculum stage decreased to: {self.model_stage}")
