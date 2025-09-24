# security-core/tests/unit/test_self_inhibitor.py
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

# Пропускаем, если модуль еще не подключен к проекту
mod = pytest.importorskip(
    "security_core.security.self_inhibitor",
    reason="SelfInhibitor module is required for these tests",
)

# Допускаем как dataclass/pydantic-модель с совместимыми полями
InhibitRule = getattr(mod, "InhibitRule")
SelfInhibitor = getattr(mod, "SelfInhibitor")
Decision = getattr(mod, "Decision", None)  # optional; можно проверять по атрибутам


class FakeClock:
    """Детерминированные 'часы' для проверки freeze windows и rate-limit."""
    def __init__(self, start_ts: float):
        self._now = start_ts

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _ts(dt: str) -> float:
    # '2025-08-20T23:30:00Z' -> epoch seconds
    return datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp()


def _actor(service: str, actor_id: str = "svc:api"):
    # Допускаем словарь; если модуль требует объект — он должен уметь распарсить dict
    return {
        "type": "SERVICE",
        "id": actor_id,
        "service": service,
        "roles": ["SERVICE"],
    }


def _target(service: str, resource_type: str = "deployment", rid: str = "self"):
    return {
        "service": service,
        "resource_type": resource_type,
        "resource_id": rid,
    }


@pytest.fixture()
def rules():
    """Набор правил: защита от self‑мутаций в prod, фриз‑окно и базовый rate‑limit."""
    return [
        InhibitRule(  # 1) Самозащита в проде для опасных операций
            id="prod-self-protect",
            environments={"prod"},
            actions={"DELETE", "DROP_DB", "UPGRADE", "REDEPLOY"},
            self_only=True,
            effect="DENY",
            message="self-protection in production",
        ),
        InhibitRule(  # 2) Ночное фриз-окно (22:00–06:00 UTC) для prod
            id="prod-freeze-window",
            environments={"prod"},
            freeze_windows=[
                {"tz": "UTC", "days": ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"], "from": "22:00", "to": "06:00"}
            ],
            effect="DENY",
            message="change freeze window",
        ),
        InhibitRule(  # 3) Rate-limit на DELETE: не более 2 за 60с -> дальше CHALLENGE/DENY
            id="delete-rate",
            actions={"DELETE"},
            rate_limit={"limit": 2, "per_seconds": 60, "on_exceed": "CHALLENGE"},
            effect="ALLOW",  # базовый эффект при непревышении
            message="delete rate limit",
        ),
    ]


@pytest.fixture()
def inhibitor_prod(rules):
    # Детализированные «часы»: старт вне фриз-окна
    clk = FakeClock(_ts("2025-08-20T12:00:00Z"))
    inh = SelfInhibitor(
        rules=rules,
        env="prod",
        self_service="security-core",
        time_provider=clk.now,  # модуль должен принимать кастомный time provider
    )
    return SimpleNamespace(inh=inh, clk=clk)


@pytest.fixture()
def inhibitor_staging(rules):
    clk = FakeClock(_ts("2025-08-20T12:00:00Z"))
    inh = SelfInhibitor(
        rules=rules,
        env="staging",
        self_service="security-core",
        time_provider=clk.now,
    )
    return SimpleNamespace(inh=inh, clk=clk)


def _assert_decision(dec, effect: str, rule_id: str | None = None):
    # Совместимость: если нет класса Decision — проверяем по словарю/атрибутам
    if Decision and isinstance(dec, Decision):
        assert dec.effect == effect
        if rule_id is not None:
            assert getattr(dec, "rule_id", None) == rule_id
    else:
        # Duck-typing
        eff = getattr(dec, "effect", None) or dec.get("effect")
        rid = getattr(dec, "rule_id", None) if hasattr(dec, "rule_id") else dec.get("rule_id")
        assert eff == effect
        if rule_id is not None:
            assert rid == rule_id


# ----------------------------- ТЕСТЫ ------------------------------------------

def test_allow_non_self_on_prod(inhibitor_prod):
    """В prod операция над чужим сервисом разрешена, если не попадает под freeze/rate-limit."""
    inh, clk = inhibitor_prod.inh, inhibitor_prod.clk
    dec = inh.decide(
        actor=_actor("security-core"),
        action="DELETE",
        target=_target("payments"),  # другой сервис
        context={"reason": "cleanup"},
    )
    # Не self => self_protect не срабатывает
    _assert_decision(dec, "ALLOW")


def test_deny_self_mutation_on_prod(inhibitor_prod):
    """В prod self‑операции класса опасности блокируются."""
    inh = inhibitor_prod.inh
    dec = inh.decide(
        actor=_actor("security-core"),
        action="REDEPLOY",
        target=_target("security-core"),
        context={"ticket": "CHG-123"},
    )
    _assert_decision(dec, "DENY", rule_id="prod-self-protect")


def test_deny_in_freeze_window(inhibitor_prod):
    """Изменения в фриз‑окно отклоняются, даже если операция не self."""
    inh, clk = inhibitor_prod.inh, inhibitor_prod.clk
    # Переместим время в 23:30 UTC (внутри окна 22:00–06:00)
    clk.advance(_ts("2025-08-20T23:30:00Z") - clk.now())
    dec = inh.decide(
        actor=_actor("deploy-bot"),
        action="UPGRADE",
        target=_target("payments"),
        context={"ticket": "CHG-999"},
    )
    _assert_decision(dec, "DENY", rule_id="prod-freeze-window")


def test_staging_not_affected_by_prod_rules(inhibitor_staging):
    """В staging правила prod‑самозащиты/фриза не действуют."""
    inh = inhibitor_staging.inh
    dec = inh.decide(
        actor=_actor("security-core"),
        action="REDEPLOY",
        target=_target("security-core"),
        context={"ticket": "CHG-456"},
    )
    _assert_decision(dec, "ALLOW")


def test_rate_limit_escalates(inhibitor_prod):
    """Превышение лимита приводит к CHALLENGE (или DENY в зависимости от on_exceed)."""
    inh, clk = inhibitor_prod.inh, inhibitor_prod.clk

    # 2 разрешенных в 60с
    for i in range(2):
        dec = inh.decide(
            actor=_actor("ops"),
            action="DELETE",
            target=_target("cache", "kv", f"k{i}"),
            context={"scope": "maintenance"},
        )
        _assert_decision(dec, "ALLOW")

    # 3‑й в том же окне — эскалация
    dec3 = inh.decide(
        actor=_actor("ops"),
        action="DELETE",
        target=_target("cache", "kv", "k2"),
        context={"scope": "maintenance"},
    )
    # Допускаем два варианта поведения (конфигurable): CHALLENGE или DENY.
    eff = getattr(dec3, "effect", None) or dec3.get("effect")
    assert eff in {"CHALLENGE", "DENY"}

    # Через 61 секунду лимит должен обнулиться
    clk.advance(61)
    dec4 = inh.decide(
        actor=_actor("ops"),
        action="DELETE",
        target=_target("cache", "kv", "k3"),
        context={"scope": "maintenance"},
    )
    _assert_decision(dec4, "ALLOW")


def test_decision_carries_reason_and_rule(inhibitor_prod):
    """Решение должно нести причину и ссылку на правило (для аудита и возврата пользователю)."""
    inh = inhibitor_prod.inh
    dec = inh.decide(
        actor=_actor("security-core"),
        action="DROP_DB",
        target=_target("security-core", "db", "primary"),
        context={"ticket": "INC-1"},
    )

    # проверяем, что у решения есть reason и rule_id
    reason = getattr(dec, "reason", None) or (dec.get("reason") if isinstance(dec, dict) else None)
    rule_id = getattr(dec, "rule_id", None) or (dec.get("rule_id") if isinstance(dec, dict) else None)
    assert reason and isinstance(reason, str)
    assert rule_id == "prod-self-protect"
