# cybersecurity-core/tests/unit/test_microsegmentation.py
# -*- coding: utf-8 -*-
"""
Промышленный тест-набор для модуля микросегментации.

ОЖИДАЕМЫЙ ИНТЕРФЕЙС (спецификация для реализации):
---------------------------------------------------
from cybersecurity_core.microsegmentation.engine import (
    MicrosegmentationEngine,
    PolicyRule,          # dataclass: id:str, action:Literal["allow","deny"], src:List[str], dst:List[str], ports:List[str|int], protocols:List[str], cidr_src:List[str]=[], cidr_dst:List[str]=[], meta:dict={}
    PolicyDocument,      # dataclass: id:str, rules:List[PolicyRule], version:str
    TrafficTuple,        # dataclass: src_labels:Set[str], dst_labels:Set[str], dst_port:int, protocol:str, src_ip:str|None=None, dst_ip:str|None=None
    PolicyChange,        # dataclass: added:int, updated:int, removed:int, resulting_hash:str
)

КЛЮЧЕВОЕ ПОВЕДЕНИЕ:
- default-deny: если ни одно правило не матчится → deny
- при конфликте allow/deny → priority: deny выше allow (deny-over-allow)
- идемпотентность: повторное применение той же PolicyDocument не меняет state-hash
- compute_changeset(prev_hash, doc) возвращает PolicyChange
- export(format="iptables|json") детерминированный (стабильный порядок, стабильный хэш)
- rollback(to_hash) возвращает True/False в зависимости от успеха и восстанавливает состояние
- detect_shadow_rules() возвращает список правил, которые не влияют на результат (затенены более приоритетными)
- validate() поднимает ValueError на невалидных CIDR/протоколах/портах
- evaluate_traffic(t:TrafficTuple) -> Literal["allow","deny"] и ведёт аудит-лог (struct) через logging

Эти тесты могут быть использованы как TDD-спецификация.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import List, Set

import pytest

engine_mod = pytest.importorskip(
    "cybersecurity_core.microsegmentation.engine",
    reason="Требуется реализация cybersecurity_core.microsegmentation.engine",
)
from cybersecurity_core.microsegmentation.engine import (  # type: ignore  # noqa: E402
    MicrosegmentationEngine,
    PolicyRule,
    PolicyDocument,
    TrafficTuple,
)


# ----------------------------- ФИКСТУРЫ -------------------------------------


@pytest.fixture(scope="session")
def tmp_state_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    p = tmp_path_factory.mktemp("microseg_state")
    return p


@pytest.fixture()
def engine(tmp_state_root: Path) -> MicrosegmentationEngine:
    e = MicrosegmentationEngine(state_dir=tmp_state_root, strict=True)
    # чистое состояние на старте каждого теста
    e.reset()
    return e


@pytest.fixture()
def base_policy() -> PolicyDocument:
    rules: List[PolicyRule] = [
        # Явный deny: prod -> dev запрет
        PolicyRule(
            id="R1_DENY_PROD_TO_DEV",
            action="deny",
            src=["env:prod"],
            dst=["env:dev"],
            ports=["any"],
            protocols=["any"],
        ),
        # Allow внутри prod на 443/tcp
        PolicyRule(
            id="R2_ALLOW_PROD_443",
            action="allow",
            src=["env:prod"],
            dst=["env:prod"],
            ports=[443],
            protocols=["tcp"],
        ),
        # Allow dev -> logging на 9200/tcp
        PolicyRule(
            id="R3_ALLOW_DEV_TO_LOGGING",
            action="allow",
            src=["env:dev"],
            dst=["role:logging"],
            ports=[9200],
            protocols=["tcp"],
        ),
        # Правило-ширма (теневое) — должно быть детектировано как shadowed
        PolicyRule(
            id="R4_SHADOWED_ALLOW_PROD_ANY",
            action="allow",
            src=["env:prod"],
            dst=["env:dev"],
            ports=["any"],
            protocols=["any"],
            meta={"note": "затенено R1_DENY_PROD_TO_DEV"},
        ),
    ]
    return PolicyDocument(id="POLICY_BASE_V1", version="1.0.0", rules=rules)


# -------------------------- ХЕЛПЕРЫ ТЕСТОВ ----------------------------------


def ttuple(src: Set[str], dst: Set[str], port: int, proto: str, src_ip=None, dst_ip=None) -> TrafficTuple:
    return TrafficTuple(src_labels=set(src), dst_labels=set(dst), dst_port=port, protocol=proto, src_ip=src_ip, dst_ip=dst_ip)


def stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ------------------------------ ТЕСТЫ ---------------------------------------


def test_apply_policy_idempotent(engine: MicrosegmentationEngine, base_policy: PolicyDocument) -> None:
    h1 = engine.apply_policy(base_policy)
    h2 = engine.apply_policy(base_policy)
    assert h1 == h2, "Повторное применение той же политики должно быть идемпотентным"
    # Повторная компоновка экспорта не должна менять хэш
    exp1 = engine.export(format="json")
    exp2 = engine.export(format="json")
    assert exp1["hash"] == exp2["hash"]
    assert stable_hash(json.dumps(exp1["data"], sort_keys=True)) == exp1["hash"]


def test_default_deny_and_deny_over_allow(engine: MicrosegmentationEngine, base_policy: PolicyDocument) -> None:
    engine.apply_policy(base_policy)
    # default-deny (нет матчинга) → deny
    res_default = engine.evaluate_traffic(ttuple({"env:qa"}, {"env:qa"}, 80, "tcp"))
    assert res_default == "deny"
    # конфликт: prod -> dev, любые порты/прото — должно быть deny из-за R1
    res_conflict = engine.evaluate_traffic(ttuple({"env:prod"}, {"env:dev"}, 443, "tcp"))
    assert res_conflict == "deny"
    # явный allow внутри prod: 443/tcp
    res_allow = engine.evaluate_traffic(ttuple({"env:prod"}, {"env:prod"}, 443, "tcp"))
    assert res_allow == "allow"


@pytest.mark.parametrize(
    "src_labels,dst_labels,port,proto,expected",
    [
        ({"env:prod"}, {"env:prod"}, 443, "tcp", "allow"),
        ({"env:prod"}, {"env:prod"}, 80, "tcp", "deny"),   # не разрешено правилом
        ({"env:dev"}, {"role:logging"}, 9200, "tcp", "allow"),
        ({"env:dev"}, {"role:logging"}, 9201, "tcp", "deny"),
        ({"env:prod"}, {"env:dev"}, 22, "tcp", "deny"),    # deny-over-allow
    ],
)
def test_traffic_matrix(engine: MicrosegmentationEngine, base_policy: PolicyDocument, src_labels, dst_labels, port, proto, expected) -> None:
    engine.apply_policy(base_policy)
    res = engine.evaluate_traffic(ttuple(src_labels, dst_labels, port, proto))
    assert res == expected


def test_detect_shadow_rules(engine: MicrosegmentationEngine, base_policy: PolicyDocument) -> None:
    engine.apply_policy(base_policy)
    shadows = engine.detect_shadow_rules()
    shadow_ids = {r.id for r in shadows}
    assert "R4_SHADOWED_ALLOW_PROD_ANY" in shadow_ids
    assert "R1_DENY_PROD_TO_DEV" not in shadow_ids


def test_compute_changeset_and_rollback(engine: MicrosegmentationEngine, base_policy: PolicyDocument) -> None:
    h0 = engine.state_hash()
    h1 = engine.apply_policy(base_policy)
    assert h1 != h0
    # Модифицируем политику
    modified = PolicyDocument(
        id="POLICY_BASE_V2",
        version="1.1.0",
        rules=base_policy.rules + [
            PolicyRule(
                id="R5_ALLOW_QA_TO_METRICS",
                action="allow",
                src=["env:qa"],
                dst=["role:metrics"],
                ports=[9090],
                protocols=["tcp"],
            )
        ],
    )
    change = engine.compute_changeset(prev_hash=h1, new_doc=modified)
    assert change.added >= 1 and change.resulting_hash
    h2 = engine.apply_policy(modified)
    assert h2 == change.resulting_hash
    # Откат
    ok = engine.rollback(to_hash=h1)
    assert ok is True
    assert engine.state_hash() == h1


def test_export_is_deterministic(engine: MicrosegmentationEngine, base_policy: PolicyDocument, tmp_path: Path) -> None:
    engine.apply_policy(base_policy)
    exp_json_1 = engine.export(format="json")
    exp_json_2 = engine.export(format="json")
    assert exp_json_1["hash"] == exp_json_2["hash"]
    # iptables-экспорт должен быть стабильным по строковому представлению
    exp_ipt_1 = engine.export(format="iptables")
    exp_ipt_2 = engine.export(format="iptables")
    assert exp_ipt_1["hash"] == exp_ipt_2["hash"]
    assert exp_ipt_1["data"] == exp_ipt_2["data"]
    # сохранение в файл
    out = tmp_path / "export.iptables"
    out.write_text(exp_ipt_1["data"], encoding="utf-8")
    assert out.stat().st_size > 0


def test_validation_invalid_inputs(engine: MicrosegmentationEngine) -> None:
    # Неверный порт, CIDR, протокол — validate() должна бросать ошибку
    bad = PolicyDocument(
        id="POLICY_BAD",
        version="0.0.1",
        rules=[
            PolicyRule(
                id="RX_BAD",
                action="allow",
                src=["env:prod"],
                dst=["env:dev"],
                ports=[65536],        # неверный порт
                protocols=["tcpp"],   # неверный протокол
                cidr_src=["300.1.1.1/24"],  # неверный CIDR
            )
        ],
    )
    with pytest.raises(ValueError):
        engine.validate(bad)


def test_audit_logging_on_evaluate(engine: MicrosegmentationEngine, base_policy: PolicyDocument, caplog: pytest.LogCaptureFixture) -> None:
    engine.apply_policy(base_policy)
    caplog.clear()
    res = engine.evaluate_traffic(ttuple({"env:prod"}, {"env:prod"}, 443, "tcp"))
    assert res == "allow"
    # Ищем структурированную запись аудита
    records = [r for r in caplog.records if "microsegmentation.audit" in getattr(r.__dict__, "extra", {}) or "microsegmentation" in r.name]
    # Если библиотека не использует extra, проверим текст
    if not records:
        records = [r for r in caplog.records if "audit" in r.getMessage().lower() and "evaluate" in r.getMessage().lower()]
    assert records, "Ожидалась запись аудита при оценке трафика"


def test_persist_and_reload_state(engine: MicrosegmentationEngine, base_policy: PolicyDocument, tmp_state_root: Path) -> None:
    h1 = engine.apply_policy(base_policy)
    # Создаём новый экземпляр, указываем тот же state_dir — должен поднять тот же hash
    e2 = MicrosegmentationEngine(state_dir=tmp_state_root, strict=True)
    assert e2.state_hash() == h1
    # Поведение после перезапуска должно сохраняться
    res = e2.evaluate_traffic(ttuple({"env:prod"}, {"env:dev"}, 22, "tcp"))
    assert res == "deny"


@pytest.mark.parametrize(
    "port,proto,expect",
    [
        (443, "tcp", "allow"),
        (443, "udp", "deny"),
        (9200, "tcp", "allow"),
        (9200, "udp", "deny"),
    ],
)
def test_protocol_specificity(engine: MicrosegmentationEngine, base_policy: PolicyDocument, port, proto, expect) -> None:
    engine.apply_policy(base_policy)
    labels = {"env:dev"}, {"role:logging"}
    res = engine.evaluate_traffic(ttuple(*labels, port, proto))
    assert res == expect


def test_rule_order_does_not_break_priority(engine: MicrosegmentationEngine, base_policy: PolicyDocument) -> None:
    # Даже если allow идёт раньше в списке, deny должен побеждать по приоритету
    reordered = PolicyDocument(
        id="POLICY_REORDERED",
        version="1.0.1",
        rules=[
            base_policy.rules[1],  # allow prod 443
            base_policy.rules[0],  # deny prod -> dev
            base_policy.rules[2],
            base_policy.rules[3],
        ],
    )
    engine.apply_policy(reordered)
    res = engine.evaluate_traffic(ttuple({"env:prod"}, {"env:dev"}, 443, "tcp"))
    assert res == "deny"


def test_labels_and_cidrs_combination(engine: MicrosegmentationEngine) -> None:
    # Разрешаем доступ из конкретной подсети в роль metrics
    policy = PolicyDocument(
        id="POLICY_CIDR",
        version="1.0.0",
        rules=[
            PolicyRule(
                id="R6_ALLOW_CIDR_TO_METRICS",
                action="allow",
                src=["env:qa"],
                dst=["role:metrics"],
                ports=[9090],
                protocols=["tcp"],
                cidr_src=["10.10.0.0/16"],
            ),
        ],
    )
    engine.apply_policy(policy)
    # Совпадение по CIDR и меткам
    ok = engine.evaluate_traffic(ttuple({"env:qa"}, {"role:metrics"}, 9090, "tcp", src_ip="10.10.5.7"))
    assert ok == "allow"
    # Не совпал CIDR
    no = engine.evaluate_traffic(ttuple({"env:qa"}, {"role:metrics"}, 9090, "tcp", src_ip="10.20.5.7"))
    assert no == "deny"
