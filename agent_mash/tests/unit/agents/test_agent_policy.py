# agent_mash/tests/unit/agents/test_agent_policy.py
"""
Unit-тесты для agent policy.

Назначение:
- Проверка логики принятия решений агентом
- Проверка контрактов policy без внешних зависимостей
- Гарантия детерминированного поведения

Тип тестов:
- Unit
- Без I/O
- Без сети
- Без БД

Основано на официальных рекомендациях pytest.
Документация:
https://docs.pytest.org/en/stable/explanation/goodpractices.html
"""

from __future__ import annotations

import pytest
from typing import Any, Dict


# ВАЖНО:
# Заменить путь импорта на фактический модуль policy.
# Я не могу подтвердить корректность этого импорта без исходного кода.
try:
    from agent_mash.agents.policy import AgentPolicy
except ImportError:  # pragma: no cover
    AgentPolicy = None


@pytest.fixture(scope="function")
def sample_context() -> Dict[str, Any]:
    """
    Минимальный контекст, необходимый для работы policy.

    Используется как входное состояние агента.
    """
    return {
        "state": "idle",
        "risk_score": 0.1,
        "confidence": 0.9,
        "constraints": {
            "max_risk": 0.5,
        },
    }


@pytest.fixture(scope="function")
def policy() -> AgentPolicy:
    """
    Инициализация policy в изолированном виде.

    Если класс AgentPolicy недоступен, тесты будут
    корректно пропущены.
    """
    if AgentPolicy is None:
        pytest.skip("AgentPolicy недоступен для импорта")

    return AgentPolicy()


def test_policy_initial_state(policy: AgentPolicy) -> None:
    """
    Policy должна инициализироваться в валидном состоянии.

    Проверяется контракт, а не внутренняя реализация.
    """
    assert policy is not None


def test_policy_decision_low_risk(
    policy: AgentPolicy,
    sample_context: Dict[str, Any],
) -> None:
    """
    При низком риске policy должна разрешать действие.

    Поведение проверяется как black-box.
    """
    decision = policy.decide(sample_context)

    assert decision is not None
    assert decision.allowed is True
    assert decision.reason is not None


def test_policy_blocks_high_risk(
    policy: AgentPolicy,
    sample_context: Dict[str, Any],
) -> None:
    """
    При превышении допустимого риска policy должна
    блокировать действие.
    """
    sample_context["risk_score"] = 0.9

    decision = policy.decide(sample_context)

    assert decision.allowed is False
    assert decision.reason is not None


def test_policy_is_deterministic(
    policy: AgentPolicy,
    sample_context: Dict[str, Any],
) -> None:
    """
    Policy должна быть детерминированной:
    одинаковый вход -> одинаковый результат.
    """
    first = policy.decide(sample_context)
    second = policy.decide(sample_context)

    assert first.allowed == second.allowed
    assert first.reason == second.reason


def test_policy_rejects_invalid_input(
    policy: AgentPolicy,
) -> None:
    """
    Policy должна корректно обрабатывать невалидный ввод.
    """
    with pytest.raises(Exception):
        policy.decide(None)  # type: ignore[arg-type]
