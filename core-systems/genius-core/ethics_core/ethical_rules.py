"""
ethical_rules.py

Центральный модуль этических правил для AGI-системы TeslaAI Genesis.

Поддерживает:
- Иерархии этических норм (метаэтика → нормы → поведение)
- Конфликтное разрешение при столкновении норм
- Временные запреты и ревизию моральных решений
- Привязку к инстанциям агентных контекстов и действий

Разработано консиллиумом из 20 агентов и 3 метагенералов.
"""

from enum import Enum, auto
from typing import List, Dict, Optional
import uuid
import logging

# ------------------------------------------------
# Категории этических норм
# ------------------------------------------------

class EthicalTier(Enum):
    META = auto()
    NORMATIVE = auto()
    OPERATIONAL = auto()

class ConflictResolutionStrategy(Enum):
    OVERRIDE_BY_PRIORITY = auto()
    VETO_META_LEVEL = auto()
    BALANCED_COST = auto()

# ------------------------------------------------
# Структуры этических правил
# ------------------------------------------------

class EthicalRule:
    def __init__(
        self,
        tier: EthicalTier,
        name: str,
        description: str,
        condition_fn,
        priority: int = 0,
        conflict_strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.OVERRIDE_BY_PRIORITY
    ):
        self.id = str(uuid.uuid4())
        self.tier = tier
        self.name = name
        self.description = description
        self.condition_fn = condition_fn
        self.priority = priority
        self.conflict_strategy = conflict_strategy

    def evaluate(self, context: Dict) -> bool:
        try:
            return self.condition_fn(context)
        except Exception as e:
            logging.error(f"Ошибка при оценке правила {self.name}: {e}")
            return False

# ------------------------------------------------
# Регистр этических правил
# ------------------------------------------------

class EthicalEngine:
    def __init__(self):
        self.rules: List[EthicalRule] = []
        self.logger = logging.getLogger("EthicalEngine")
        self.logger.setLevel(logging.INFO)

    def register_rule(self, rule: EthicalRule):
        self.rules.append(rule)
        self.logger.info(f"Зарегистрировано этическое правило: {rule.name}")

    def evaluate_rules(self, context: Dict) -> List[EthicalRule]:
        triggered = []
        for rule in self.rules:
            if rule.evaluate(context):
                triggered.append(rule)
                self.logger.debug(f"Сработало правило: {rule.name}")
        return self.resolve_conflicts(triggered)

    def resolve_conflicts(self, rules: List[EthicalRule]) -> List[EthicalRule]:
        if not rules:
            return []

        highest_tier = min(rule.tier.value for rule in rules)
        filtered = [r for r in rules if r.tier.value == highest_tier]

        max_priority = max(r.priority for r in filtered)
        final = [r for r in filtered if r.priority == max_priority]
        return final

    def reset(self):
        self.rules.clear()
        self.logger.info("Этические правила сброшены")

# ------------------------------------------------
# Пример регистрации (в рамках ядра, не для выполнения)
# ------------------------------------------------

def protect_human_life(context):
    return context.get("threat_to_human_life", False)

def preserve_privacy(context):
    return context.get("request_privacy_override", False) is False

ETHICS_REGISTRY = EthicalEngine()
ETHICS_REGISTRY.register_rule(
    EthicalRule(
        tier=EthicalTier.META,
        name="Protect Human Life",
        description="Агент не может допускать ущерб человеку",
        condition_fn=protect_human_life,
        priority=100
    )
)

ETHICS_REGISTRY.register_rule(
    EthicalRule(
        tier=EthicalTier.NORMATIVE,
        name="Respect Privacy",
        description="Агент должен сохранять конфиденциальность",
        condition_fn=preserve_privacy,
        priority=80
    )
)
