# policy-core/tests/unit/test_obligations.py
# ВНИМАНИЕ: Контракт модуля задан тестами. Если у вас иные имена/сигнатуры,
# согласуйте реализацию под эти тесты либо адаптируйте импорт/фикстуры.
#
# Ожидаемый API policy_core.obligations:
# - class Decision(Enum): PERMIT, DENY
# - @dataclass class Obligation: id:str, action:str, params:dict, on:str ("Permit"|"Deny"|"Both"),
#                                priority:int=100, mandatory:bool=True, condition:Optional[Callable|str]=None
# - @dataclass class Advice: те же поля, но mandatory=False по умолчанию
# - class ObligationError(Exception)
# - class ObligationRegistry:
#       register(action:str, handler:Callable)
#       get(action:str) -> Callable
#       builtins() -> set[str]
# - @dataclass class ApplyOutcome:
#       decision:Decision
#       resource:dict
#       headers:dict
#       audit_events:list[dict]
#       applied:list[str]          # ids
#       failed:list[str]           # ids (только для advice/soft)
# - def apply_obligations(decision:Decision, obligations:list[Obligation|Advice],
#                         *, subject:dict, resource:dict, env:dict,
#                         strict:bool=True, registry:ObligationRegistry|None=None) -> ApplyOutcome
#
# Обязательные семантики:
# - Порядок применения: по возрастанию priority, затем по lexicographic id
# - on="Permit"/"Deny"/"Both" фильтрует применимость по исходному decision
# - condition (callable) -> bool. Если False, правило пропускается.
# - mandatory=True: ошибка обработчика => ObligationError при strict=True,
#                   либо outcome.decision==DENY при strict=False
# - advice (mandatory=False): ошибка НЕ должна блокировать итог, id добавляется в failed
# - Идемпотентность: повторное применение того же правила не меняет результат повторно
# - Безопасность: неизвестный action => ObligationError
# - Конкурентность: параллельное применение к независимым копиям ресурса не ведет к гонкам
# - Производительность: применение 1000 простых obligations укладывается в разумное время

import asyncio
import copy
import importlib
import time
from typing import Callable, Optional

import pytest

obligations = importlib.import_module("policy_core.obligations")

Decision = obligations.Decision
Obligation = obligations.Obligation
Advice = obligations.Advice
ObligationRegistry = obligations.ObligationRegistry
ObligationError = obligations.ObligationError
apply_obligations = obligations.apply_obligations


@pytest.fixture
def base_context():
    subject = {"id": "u123", "role": "analyst", "dept": "risk"}
    resource = {"id": "r77", "name": "customer_profile", "pii": {"ssn": "123-45-6789", "email": "a@b.c"}, "tags": ["pii", "internal"]}
    env = {"ip": "10.0.0.5", "ts": 1_700_000_000}
    return subject, resource, env


@pytest.fixture
def registry():
    # Локальный реестр с тестовыми handler'ами
    reg = ObligationRegistry()

    # mask_fields: замена значений по dot-путям на "***"
    def mask_fields(*, subject, resource, env, params):
        paths = params.get("paths", [])
        for p in paths:
            _dot_replace(resource, p, "***")
        return {"resource": resource}

    # append_header: добавление HTTP-заголовков в outcome.headers
    def append_header(*, subject, resource, env, params):
        return {"headers": {str(params["name"]): str(params["value"])}}

    # emit_audit: создать аудит-событие
    def emit_audit(*, subject, resource, env, params):
        evt = {"type": params.get("type", "policy.audit"), "attrs": {"sub": subject["id"], "res": resource["id"]}}
        return {"audit": [evt]}

    # faulty: для проверки ошибок
    def faulty(*, subject, resource, env, params):
        raise RuntimeError(params.get("msg", "boom"))

    # idempotent_tag: добавляет тег, но не дублирует
    def idempotent_tag(*, subject, resource, env, params):
        tag = str(params.get("tag", "marked"))
        tags = resource.setdefault("tags", [])
        if tag not in tags:
            tags.append(tag)
        return {"resource": resource}

    reg.register("mask_fields", mask_fields)
    reg.register("append_header", append_header)
    reg.register("emit_audit", emit_audit)
    reg.register("faulty", faulty)
    reg.register("idempotent_tag", idempotent_tag)
    return reg


# -------- helpers --------

def _dot_replace(obj: dict, path: str, value):
    parts = path.split(".")
    cur = obj
    for seg in parts[:-1]:
        if seg not in cur or not isinstance(cur[seg], dict):
            cur[seg] = {}
        cur = cur[seg]
    cur[parts[-1]] = value


def _mk_obl(id: str, action: str, *, on="Both", priority=100, mandatory=True, params=None, condition: Optional[Callable]=None):
    return Obligation(id=id, action=action, params=params or {}, on=on, priority=priority, mandatory=mandatory, condition=condition)


def _mk_adv(id: str, action: str, *, on="Both", priority=100, params=None, condition: Optional[Callable]=None):
    return Advice(id=id, action=action, params=params or {}, on=on, priority=priority, condition=condition)


# -------- tests --------

def test_unknown_action_raises_obligation_error(base_context, registry):
    subject, resource, env = base_context
    rules = [_mk_obl("o1", "no_such_action")]
    with pytest.raises(ObligationError):
        apply_obligations(Decision.PERMIT, rules, subject=subject, resource=resource, env=env, registry=registry)


def test_priority_and_deterministic_order(base_context, registry):
    subject, resource, env = base_context
    # Сымитируем порядок: сначала priority 1, потом 2; при равных — по id
    rules = [
        _mk_obl("b", "idempotent_tag", priority=2, params={"tag": "t2"}),
        _mk_obl("a", "idempotent_tag", priority=2, params={"tag": "t3"}),
        _mk_obl("c", "idempotent_tag", priority=1, params={"tag": "t1"}),
    ]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    # Ожидаем, что теги применялись в порядке: c -> a -> b  (1, затем id a, затем id b)
    assert out.resource["tags"].index("t1") < out.resource["tags"].index("t3") < out.resource["tags"].index("t2")
    assert out.applied == ["c", "a", "b"]


def test_on_permit_vs_deny_filters_rules(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_obl("p_only", "idempotent_tag", on="Permit", params={"tag": "permit"}),
        _mk_obl("d_only", "idempotent_tag", on="Deny", params={"tag": "deny"}),
        _mk_obl("both", "idempotent_tag", on="Both", params={"tag": "both"}),
    ]
    out_p = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    assert "permit" in out_p.resource["tags"] and "both" in out_p.resource["tags"]
    assert "deny" not in out_p.resource["tags"]

    out_d = apply_obligations(Decision.DENY, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    assert "deny" in out_d.resource["tags"] and "both" in out_d.resource["tags"]
    assert "permit" not in out_d.resource["tags"]


def test_condition_callable_controls_applicability(base_context, registry):
    subject, resource, env = base_context
    cond_true = lambda sub, res, e: sub["role"] == "analyst" and "pii" in res["tags"]
    cond_false = lambda sub, res, e: False
    rules = [
        _mk_obl("ok", "idempotent_tag", params={"tag": "ok"}, condition=cond_true),
        _mk_obl("skip", "idempotent_tag", params={"tag": "skip"}, condition=cond_false),
    ]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    assert "ok" in out.resource["tags"]
    assert "skip" not in out.resource["tags"]
    assert "ok" in out.applied and "skip" not in out.applied


def test_advice_failure_does_not_block_and_is_reported(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_adv("log", "emit_audit", params={"type": "log"}),
        _mk_adv("broken", "faulty", params={"msg": "adv_fail"}),
        _mk_obl("mask", "mask_fields", params={"paths": ["pii.ssn"]}, priority=1),
    ]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry, strict=True)
    # Обязательство выполнено, ssn замаскирован
    assert out.resource["pii"]["ssn"] == "***"
    # Advice сломался, но решение не заблокировано
    assert "broken" in out.failed and out.decision == Decision.PERMIT
    # Есть аудит
    assert any(evt["type"] == "log" for evt in out.audit_events)


def test_mandatory_failure_strict_raises(base_context, registry):
    subject, resource, env = base_context
    rules = [_mk_obl("oops", "faulty", params={"msg": "fail"})]
    with pytest.raises(ObligationError):
        apply_obligations(Decision.PERMIT, rules, subject=subject, resource=resource, env=env, registry=registry, strict=True)


def test_mandatory_failure_non_strict_denies(base_context, registry):
    subject, resource, env = base_context
    rules = [_mk_obl("oops", "faulty", params={"msg": "fail"})]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry, strict=False)
    assert out.decision == Decision.DENY


def test_headers_appended_and_merged(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_obl("h1", "append_header", params={"name": "X-Policy", "value": "A"}),
        _mk_obl("h2", "append_header", params={"name": "X-Policy", "value": "B"}),
    ]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    # Последнее значение имеет приоритет или реализация должна агрегировать — здесь проверяем перезапись последним
    assert out.headers["X-Policy"] in ("B", "A;B")
    # Применение обоих правил отражается в applied
    assert out.applied == ["h1", "h2"]


def test_redaction_and_idempotency(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_obl("mask1", "mask_fields", params={"paths": ["pii.ssn", "pii.email"]}),
        _mk_obl("mask2", "mask_fields", params={"paths": ["pii.ssn"]}),  # второй раз такой же путь
    ]
    out1 = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    assert out1.resource["pii"]["ssn"] == "***" and out1.resource["pii"]["email"] == "***"

    # Повторное применение того же набора правил к уже замаскированному ресурсу не меняет содержание
    out2 = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(out1.resource), env=env, registry=registry)
    assert out2.resource == out1.resource


@pytest.mark.asyncio
async def test_concurrent_application_is_race_free(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_obl("mask", "mask_fields", params={"paths": ["pii.ssn"]}, priority=1),
        _mk_adv("tag", "idempotent_tag", params={"tag": "concurrent"}),
    ]

    async def run_once():
        res_copy = copy.deepcopy(resource)
        out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=res_copy, env=env, registry=registry)
        assert out.resource["pii"]["ssn"] == "***"
        assert "concurrent" in out.resource["tags"]
        return out

    results = await asyncio.gather(*[run_once() for _ in range(32)])
    # Все независимы, applied одинаков
    for r in results:
        assert r.applied == ["mask", "tag"]


def test_performance_bulk_mask(base_context, registry):
    subject, resource, env = base_context
    # 1000 простых действий
    rules = [_mk_obl(f"m{i:04d}", "idempotent_tag", params={"tag": f"t{i}"}, priority=i) for i in range(1000)]
    start = time.time()
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    elapsed = time.time() - start
    assert len([t for t in out.resource["tags"] if t.startswith("t")]) == 1000
    # Порог производительности (подстройте под CI, тут ориентир 0.8с)
    assert elapsed < 0.8, f"Obligations application too slow: {elapsed:.3f}s"


def test_registry_builtins_exposed_and_get(registry):
    # Регистрировали 5 действий — должны присутствовать
    builtins = registry.builtins()
    for a in {"mask_fields", "append_header", "emit_audit", "faulty", "idempotent_tag"}:
        assert a in builtins
        assert callable(registry.get(a))


def test_apply_obligations_returns_full_outcome_structure(base_context, registry):
    subject, resource, env = base_context
    rules = [
        _mk_obl("mask", "mask_fields", params={"paths": ["pii.ssn"]}),
        _mk_adv("audit", "emit_audit", params={"type": "view"}),
        _mk_obl("hdr", "append_header", params={"name": "X-Policy", "value": "applied"}),
    ]
    out = apply_obligations(Decision.PERMIT, rules, subject=subject, resource=copy.deepcopy(resource), env=env, registry=registry)
    assert hasattr(out, "decision") and hasattr(out, "resource") and hasattr(out, "headers")
    assert hasattr(out, "audit_events") and hasattr(out, "applied") and hasattr(out, "failed")
    assert out.decision == Decision.PERMIT
    assert out.resource["pii"]["ssn"] == "***"
    assert out.headers.get("X-Policy") in ("applied", "applied;")  # допускаем агрегацию
    assert any(evt["type"] == "view" for evt in out.audit_events)
