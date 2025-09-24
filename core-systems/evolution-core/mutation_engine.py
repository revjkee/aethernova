import random
import copy
import logging
from typing import Dict, Any, List, Callable

# === TeslaAI Mutation Engine v3.6 ===
# Agents: ParamShuffler, MutatorLimiter, SafeMutator, TypeCaster, RangeBalancer,
# EntropyInjector, HeuristicRewriter, BooleanFlipper, DropoutTuner, DepthVariator,
# ConfigDuplicator, KeyDropper, ValueReplacer, TemplateCloner, StrategyShifter,
# FormatCorrector, RedundancyRemover, RiskWeighter, MutationValidator, ConflictResolver
# MetaGenerals: Evolver, Guardian, Architectus

logger = logging.getLogger("mutation_engine")
logger.setLevel(logging.INFO)

MUTATION_RULES: Dict[str, Callable[[Any], Any]] = {
    "learning_rate": lambda x: max(min(x * random.uniform(0.5, 1.5), 1.0), 1e-6),
    "dropout": lambda x: round(min(max(x + random.uniform(-0.1, 0.1), 0.0), 0.9), 3),
    "num_layers": lambda x: max(1, x + random.choice([-1, 1])),
    "batch_size": lambda x: max(8, int(x * random.uniform(0.5, 1.5))),
    "optimizer": lambda x: random.choice(["adam", "sgd", "rmsprop", "adamw"]),
    "activation": lambda x: random.choice(["relu", "gelu", "tanh", "leaky_relu"]),
    "use_batch_norm": lambda x: not x if isinstance(x, bool) else True,
    "use_attention": lambda x: not x if isinstance(x, bool) else True,
    "hidden_dim": lambda x: int(max(16, x * random.choice([0.5, 0.75, 1.25, 1.5]))),
    "scheduler": lambda x: random.choice(["linear", "cosine", "none"]),
}


def mutate_config(config: Dict[str, Any], max_mutations: int = 3) -> Dict[str, Any]:
    logger.info("Applying controlled mutation to configuration...")
    mutated = copy.deepcopy(config)
    available_keys = list(MUTATION_RULES.keys())
    keys_to_mutate = random.sample(available_keys, k=min(max_mutations, len(available_keys)))

    for key in keys_to_mutate:
        if key in mutated:
            old_value = mutated[key]
            try:
                mutated[key] = MUTATION_RULES[key](old_value)
                logger.debug(f"Mutated '{key}': {old_value} -> {mutated[key]}")
            except Exception as e:
                logger.warning(f"Failed to mutate '{key}': {e}")
        else:
            logger.debug(f"Key '{key}' not in config, skipping")

    return mutated


def mutate_with_context(config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    logger.info("Applying context-aware mutation...")
    base = mutate_config(config)

    # Example: if model is large, reduce dropout
    if context.get("model_size", "medium") == "large":
        if "dropout" in base:
            base["dropout"] = round(max(base["dropout"] - 0.1, 0.1), 3)

    # Example: if observed latency too high, reduce hidden_dim
    latency = context.get("latency", 0)
    if latency > 300:
        if "hidden_dim" in base:
            base["hidden_dim"] = int(max(32, base["hidden_dim"] * 0.75))

    return base


def mutate_population(pop: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    logger.info(f"Mutating population of {len(pop)} configs...")
    mutated_pop = []
    for config in pop:
        if context:
            mutated = mutate_with_context(config, context)
        else:
            mutated = mutate_config(config)
        mutated_pop.append(mutated)
    return mutated_pop


def validate_mutation(original: Dict[str, Any], mutated: Dict[str, Any]) -> bool:
    """Проверка: не нарушены ли критические инварианты."""
    # Пример: dropout ∈ [0.0, 0.9], learning_rate ∈ [1e-6, 1.0]
    if mutated.get("dropout", 0.0) > 0.9 or mutated.get("dropout", 0.0) < 0.0:
        logger.warning("Invalid dropout value after mutation.")
        return False
    if mutated.get("learning_rate", 1.0) > 1.0 or mutated.get("learning_rate", 1.0) < 1e-6:
        logger.warning("Invalid learning_rate value after mutation.")
        return False
    return True
