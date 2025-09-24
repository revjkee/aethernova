"""
llmops.tuning.constants

Централизованные константы для стратегий обучения, фреймворков, политик RLHF и кодов ошибок.
"""

# Стратегии обучения
STRATEGY_SFT = "sft"
STRATEGY_DPO = "dpo"
STRATEGY_PPO = "ppo"
STRATEGY_ORPO = "orpo"

SUPPORTED_STRATEGIES = [
    STRATEGY_SFT,
    STRATEGY_DPO,
    STRATEGY_PPO,
    STRATEGY_ORPO,
]

# Фреймворки
FRAMEWORK_TRANSFORMERS = "transformers"
FRAMEWORK_TRL = "trl"
FRAMEWORK_PEFT = "peft"
FRAMEWORK_ACCELERATE = "accelerate"
FRAMEWORK_DEEPSPEED = "deepspeed"
FRAMEWORK_LIT = "lightning"

SUPPORTED_FRAMEWORKS = [
    FRAMEWORK_TRANSFORMERS,
    FRAMEWORK_TRL,
    FRAMEWORK_PEFT,
    FRAMEWORK_ACCELERATE,
    FRAMEWORK_DEEPSPEED,
    FRAMEWORK_LIT,
]

# Политики RLHF (преференции)
POLICY_REWARD_MODEL = "reward_model"
POLICY_COMPARISON = "preference_comparison"
POLICY_KL_PENALTY = "kl_penalty"
POLICY_DIRECT_PREFERENCE = "direct_preference"

RLHF_POLICIES = [
    POLICY_REWARD_MODEL,
    POLICY_COMPARISON,
    POLICY_KL_PENALTY,
    POLICY_DIRECT_PREFERENCE,
]

# Режимы LoRA
LORA_MODE_FULL = "full"
LORA_MODE_Q = "qlora"
LORA_MODE_PREFIX = "prefix"

SUPPORTED_LORA_MODES = [
    LORA_MODE_FULL,
    LORA_MODE_Q,
    LORA_MODE_PREFIX,
]

# Категории ошибок
ERROR_INVALID_DATASET = "E001"
ERROR_INVALID_CONFIG = "E002"
ERROR_UNSUPPORTED_STRATEGY = "E003"
ERROR_TRAINING_FAILED = "E004"
ERROR_METRIC_EVAL_FAILED = "E005"
ERROR_SAFETY_VIOLATION = "E006"
ERROR_UNKNOWN = "E999"

ERROR_MESSAGES = {
    ERROR_INVALID_DATASET: "Недопустимый формат или путь датасета",
    ERROR_INVALID_CONFIG: "Ошибка в конфигурационном файле",
    ERROR_UNSUPPORTED_STRATEGY: "Неподдерживаемая стратегия обучения",
    ERROR_TRAINING_FAILED: "Ошибка во время обучения модели",
    ERROR_METRIC_EVAL_FAILED: "Ошибка в процессе оценки метрик",
    ERROR_SAFETY_VIOLATION: "Нарушение политики безопасности",
    ERROR_UNKNOWN: "Неизвестная ошибка",
}

# Метки для логгирования и трейсинга
PHASE_PREPROCESS = "preprocess"
PHASE_TRAINING = "training"
PHASE_EVALUATION = "evaluation"
PHASE_VALIDATION = "validation"
PHASE_DEPLOYMENT = "deployment"
PHASE_TELEMETRY = "telemetry"
PHASE_MONITORING = "monitoring"

# Разрешённые расширения форматов датасетов
ALLOWED_DATASET_EXT = [".json", ".jsonl", ".csv", ".parquet"]
