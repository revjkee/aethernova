# genius_core/mutation/transformer_driver.py

import logging
from typing import Dict, Any

from genius_core.mutation.mutation_engine import MutationEngine
from genius_core.mutation.optimizer import CodeOptimizer
from genius_core.mutation.lineage_tracker import LineageTracker
from genius_core.mutation.mutation_observer import MutationObserver
from genius_core.mutation.rollback_manager import RollbackManager
from genius_core.mutation.fitness_score import evaluate_fitness
from genius_core.mutation.evolution_rules import load_rules

logger = logging.getLogger("TransformerDriver")

class TransformerDriver:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.engine = MutationEngine(config)
        self.optimizer = CodeOptimizer()
        self.lineage = LineageTracker()
        self.observer = MutationObserver()
        self.rollback = RollbackManager()
        self.evolution_rules = load_rules()

        self.fitness_threshold = config.get("fitness_threshold", 0.8)
        self.rollback_enabled = config.get("enable_rollback", True)

    def execute_transformation(self, target_path: str, mutation_context: Dict[str, Any]) -> Dict[str, Any]:
        mutation_id = self.lineage.generate_id()
        logger.info(f"[{mutation_id}] Starting mutation for: {target_path}")

        self.rollback.create_snapshot(target_path, mutation_id)

        try:
            mutated_path = self.engine.run(target_path, mutation_context, mutation_id)
            optimized_path = self.optimizer.optimize(mutated_path, mutation_id)
        except Exception as e:
            logger.exception(f"[{mutation_id}] Critical failure during mutation: {str(e)}")
            if self.rollback_enabled:
                self.rollback.rollback(mutation_id, reason="engine_failure")
            return {"status": "failed", "error": str(e), "mutation_id": mutation_id}

        score = evaluate_fitness(optimized_path)
        self.lineage.record_fitness(mutation_id, score)
        self.observer.log(mutation_id, score)

        if self.rollback_enabled and self.rollback.should_rollback(mutation_id, score, self.fitness_threshold):
            self.rollback.rollback(mutation_id, reason=f"fitness_below_{self.fitness_threshold}")
            return {"status": "rolled_back", "score": score, "mutation_id": mutation_id}

        logger.info(f"[{mutation_id}] Mutation successful with fitness score: {score}")
        return {
            "status": "success",
            "score": score,
            "mutation_id": mutation_id,
            "optimized_path": optimized_path
        }

    def dry_run(self, path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Dry-run initiated — no state will be mutated.")
        simulated_output = self.engine.simulate(path, context)
        predicted_score = evaluate_fitness(simulated_output, simulate=True)
        return {
            "status": "simulated",
            "predicted_score": predicted_score,
            "details": simulated_output
        }
