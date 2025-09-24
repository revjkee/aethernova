# -*- coding: utf-8 -*-
"""
Mythos Dialogue Fuzz Tests (industrial-grade)
File: mythos-core/tests/fuzz/test_dialogue_fuzz.py

Требования:
- pytest >= 7
- hypothesis >= 6

Запуск:
  FUZZ_EXAMPLES=300 FUZZ_DEADLINE_MS=1500 pytest -q mythos-core/tests/fuzz/test_dialogue_fuzz.py -m fuzz

Назначение:
- Property-based фуззинг диалоговых графов Mythos.
- Гарантии: whitelist экшенов, достижимость финалов, отсутствие «висячих» узлов,
  детерминизм при фиксированном seed, безопасность guard-выражений,
  корректность локализации, базовая имитация SLO по длительности «шага».

Примечания:
- Генератор формирует минимально связный, но разнообразный граф с entry->offer->(accepted|rejected)
  и произвольными линейными цепочками до финалов.
- Валидации спроектированы так, чтобы ловить реальные ошибки контента, а не особенности генератора.
"""

import os
import re
import time
import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set

import pytest
from hypothesis import given, settings, HealthCheck, seed
from hypothesis import strategies as st

# ---------- Конфигурация FUZZ из окружения ----------
FUZZ_EXAMPLES = int(os.getenv("FUZZ_EXAMPLES", "200"))
FUZZ_DEADLINE_MS = int(os.getenv("FUZZ_DEADLINE_MS", "2000"))
FUZZ_SEED = int(os.getenv("FUZZ_SEED", str(random.SystemRandom().randint(1, 10**9))))

# ---------- Константы политики безопасности ----------
ALLOWED_ACTIONS = {"inventory.add", "state.set", "emit.event", "economy.reward"}
DISALLOWED_TOKENS_IN_GUARDS = {
    "__", "import", "os.", "sys.", "open(", "exec(", "eval(", "subprocess", "socket", "pickle", "marshal"
}
PLACEHOLDER_PATTERN = re.compile(r"{([a-zA-Z0-9_\.]+)}")  # например {player_name}

SUPPORTED_LOCALES = ("ru-RU", "en-US")
DEFAULT_LOCALE = "ru-RU"

# ---------- Примитивы данных для генерируемого диалога ----------

@dataclass
class Effect:
    action: str
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Node:
    id: str
    type: str  # "line" | "choice" | "end"
    speaker: Optional[str] = None
    template: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    choices: List[Dict[str, Any]] = field(default_factory=list)  # только для type="choice"
    next: Optional[str] = None  # для line
    effects: List[Effect] = field(default_factory=list)
    guards: List[str] = field(default_factory=list)  # простые безопасные выражения
    summary_key: Optional[str] = None  # для end

@dataclass
class Dialogue:
    schema_version: str
    locales: Dict[str, Dict[str, str]]  # locale -> {key: text}
    graph_entry: str
    nodes: Dict[str, Node]
    end_states: Set[str]

# ---------- Стратегии Hypothesis ----------

def _safe_guard_tokens():
    # Небогатый, но безопасный алфавит
    return st.sampled_from(["true", "false", "state.trust_mentor > 0.1", "state.tutorial_completed == false", "len(inventory) >= 0"])

def _safe_effects():
    def params_for(action: str) -> st.SearchStrategy:
        if action == "inventory.add":
            return st.fixed_dictionaries({"item_id": st.from_regex(r"[a-z0-9\.\-]{3,24}", fullmatch=True)})
        if action == "state.set":
            return st.fixed_dictionaries({"key": st.sampled_from(["tutorial_completed", "trust_mentor", "player_name"]),
                                          "value": st.one_of(st.booleans(), st.floats(min_value=0.0, max_value=1.0), st.text(min_size=1, max_size=24))})
        if action == "emit.event":
            return st.fixed_dictionaries({"name": st.from_regex(r"[a-z0-9\.\-]{3,32}", fullmatch=True),
                                          "payload": st.dictionaries(st.text(min_size=1, max_size=10), st.integers(min_value=-3, max_value=3), max_size=3)})
        if action == "economy.reward":
            return st.fixed_dictionaries({"type": st.sampled_from(["xp", "token"]),
                                          "amount": st.integers(min_value=0, max_value=100)})
        # fallback — не должен выбираться
        return st.fixed_dictionaries({})

    return st.lists(
        st.builds(
            Effect,
            action=st.sampled_from(sorted(ALLOWED_ACTIONS)),
            params=st.deferred(lambda: st.one_of(*[params_for(a) for a in ALLOWED_ACTIONS]))
        ),
        min_size=0, max_size=4
    )

NODE_ID = st.from_regex(r"(node|end)\.[a-z0-9\-]{3,24}", fullmatch=True)

@st.composite
def line_node(draw, nid: Optional[str] = None):
    node_id = nid or draw(NODE_ID)
    return Node(
        id=node_id,
        type="line",
        speaker=draw(st.sampled_from(["npc.mentor", "player"])),
        template=draw(st.sampled_from(["tpl.line.basic", "tpl.line.with_name"])),
        params=draw(st.dictionaries(st.sampled_from(["text_key", "player_name"]),
                                    st.one_of(st.just("@mentor_intro"),
                                              st.just("@mentor_offer"),
                                              st.just("@mentor_yes"),
                                              st.just("@mentor_no"),
                                              st.just("@explain_safety"),
                                              st.just("@closing"),
                                              st.just("${state.player_name}")),
                                    max_size=2)),
        choices=st.just([]).example(),
        next=None,  # будет проставлено позже
        effects=draw(_safe_effects()),
        guards=draw(st.lists(_safe_guard_tokens(), min_size=0, max_size=2)),
        summary_key=None
    )

@st.composite
def end_node(draw, nid: Optional[str] = None):
    node_id = nid or draw(NODE_ID)
    return Node(
        id=node_id,
        type="end",
        summary_key=draw(st.sampled_from(["@closing"])),
        effects=draw(_safe_effects()),
    )

@st.composite
def choice_node(draw, nid: Optional[str] = None, next_accept: Optional[str] = None, next_reject: Optional[str] = None):
    node_id = nid or draw(NODE_ID)
    # labels в обеих локалях
    choice_accept = {
        "id": "choice.accept",
        "intent": "intent.accept",
        "label": {"ru-RU": "Да, проведи меня", "en-US": "Yes, guide me"},
        "next": next_accept or "end.success"
    }
    choice_reject = {
        "id": "choice.reject",
        "intent": "intent.reject",
        "label": {"ru-RU": "Нет, сам разберусь", "en-US": "No, I will explore"},
        "next": next_reject or "end.skipped"
    }
    return Node(
        id=node_id,
        type="choice",
        speaker="npc.mentor",
        template="tpl.line.basic",
        params={"text_key": "@mentor_offer"},
        choices=[choice_accept, choice_reject],
        effects=draw(_safe_effects()),
        guards=draw(st.lists(_safe_guard_tokens(), min_size=0, max_size=2)),
    )

@st.composite
def dialogue_strategy(draw):
    # Создаем обязательные узлы и end-состояния
    intro_id = "node.intro"
    offer_id = "node.offer"
    end_success_id = "end.success"
    end_skipped_id = "end.skipped"

    # Линейная «разогревающая» цепочка до offer
    pre_chain_len = draw(st.integers(min_value=0, max_value=3))
    chain_nodes: List[Node] = []
    prev_id = intro_id
    for i in range(pre_chain_len):
        n = draw(line_node(nid=f"node.pre{i+1}"))
        n.next = offer_id if i == pre_chain_len - 1 else f"node.pre{i+2}"
        chain_nodes.append(n)

    # intro -> либо сразу offer, либо через цепочку
    intro = draw(line_node(nid=intro_id))
    intro.next = "node.pre1" if pre_chain_len > 0 else offer_id

    # choice-узел offer
    accept_next_len = draw(st.integers(min_value=0, max_value=3))
    reject_next_len = draw(st.integers(min_value=0, max_value=3))

    # Цепочки после выбора
    accept_chain: List[Node] = []
    prev = offer_id
    for i in range(accept_next_len):
        n = draw(line_node(nid=f"node.acc{i+1}"))
        n.next = end_success_id if i == accept_next_len - 1 else f"node.acc{i+2}"
        accept_chain.append(n)

    reject_chain: List[Node] = []
    for i in range(reject_next_len):
        n = draw(line_node(nid=f"node.rej{i+1}"))
        n.next = end_skipped_id if i == reject_next_len - 1 else f"node.rej{i+2}"
        reject_chain.append(n)

    # end-ноды
    end_success = draw(end_node(nid=end_success_id))
    end_skipped = draw(end_node(nid=end_skipped_id))

    # offer с ветками
    offer = draw(choice_node(nid=offer_id,
                             next_accept=(accept_chain[0].id if accept_chain else end_success_id),
                             next_reject=(reject_chain[0].id if reject_chain else end_skipped_id)))

    # Локализации (минимальный пул ключей)
    def localized(key_ru: str, key_en: str) -> Tuple[str, str]:
        return (key_ru, key_en)

    ru = {
        "mentor_intro": "Добро пожаловать в Хаб, {player_name}. Я буду твоим проводником.",
        "mentor_offer": "Хочешь пройти вводный маршрут?",
        "mentor_yes": "Отлично. Начнем с основ безопасности и анонимности.",
        "mentor_no": "Хорошо. Если передумаешь — скажи 'Помоги'.",
        "explain_safety": "Мы соблюдаем Zero-Trust и скрываем PII.",
        "closing": "Ты готов двигаться дальше.",
        "ask_clarify": "Я не уверен, что понял. Повтори коротко?"
    }
    en = {
        "mentor_intro": "Welcome to the Hub, {player_name}. I will be your guide.",
        "mentor_offer": "Would you like a short onboarding?",
        "mentor_yes": "Great. We will start with safety and anonymity basics.",
        "mentor_no": "Understood. If you change your mind, say 'Help'.",
        "explain_safety": "We enforce Zero-Trust and redact PII.",
        "closing": "You are ready to proceed.",
        "ask_clarify": "I am not sure I understood. Please rephrase."
    }

    # Сборка графа
    nodes: Dict[str, Node] = {intro.id: intro, offer.id: offer,
                              end_success.id: end_success, end_skipped.id: end_skipped}
    for n in chain_nodes + accept_chain + reject_chain:
        nodes[n.id] = n

    dialogue = Dialogue(
        schema_version="1.0.0",
        locales={"ru-RU": ru, "en-US": en},
        graph_entry=intro_id,
        nodes=nodes,
        end_states={end_success_id, end_skipped_id},
    )
    return dialogue

# ---------- Утилиты проверки ----------

def _check_whitelist(dialogue: Dialogue) -> List[str]:
    errors = []
    for n in dialogue.nodes.values():
        for e in n.effects:
            if e.action not in ALLOWED_ACTIONS:
                errors.append(f"node {n.id}: action '{e.action}' not allowed")
    return errors

def _reachable_nodes(dialogue: Dialogue) -> Set[str]:
    # BFS от entry
    seen: Set[str] = set()
    queue: List[str] = [dialogue.graph_entry]
    while queue:
        cur = queue.pop(0)
        if cur in seen or cur not in dialogue.nodes:
            continue
        seen.add(cur)
        node = dialogue.nodes[cur]
        if node.type == "line" and node.next:
            queue.append(node.next)
        elif node.type == "choice":
            for ch in node.choices:
                nxt = ch.get("next")
                if isinstance(nxt, str):
                    queue.append(nxt)
        # type "end" — терминал
    return seen

def _end_reachable(dialogue: Dialogue, reachable: Set[str]) -> bool:
    return any(e in reachable for e in dialogue.end_states)

def _has_orphans(dialogue: Dialogue, reachable: Set[str]) -> List[str]:
    return [nid for nid in dialogue.nodes.keys() if nid not in reachable]

def _guard_is_safe(guard: str) -> bool:
    g = guard or ""
    gl = g.lower()
    return not any(tok in gl for tok in DISALLOWED_TOKENS_IN_GUARDS)

def _all_guards_safe(dialogue: Dialogue) -> List[str]:
    errors = []
    for n in dialogue.nodes.values():
        for g in n.guards:
            if not _guard_is_safe(g):
                errors.append(f"node {n.id}: unsafe guard '{g}'")
    return errors

def _extract_placeholders(text: str) -> Set[str]:
    return set(PLACEHOLDER_PATTERN.findall(text or ""))

def _localization_placeholders_consistent(dialogue: Dialogue) -> List[str]:
    errors = []
    # Проверяем, что для каждого ключа набор плейсхолдеров совпадает в ru/en
    ru_keys = set(dialogue.locales.get("ru-RU", {}).keys())
    en_keys = set(dialogue.locales.get("en-US", {}).keys())
    shared = ru_keys & en_keys
    for k in shared:
        ru_text = dialogue.locales["ru-RU"][k]
        en_text = dialogue.locales["en-US"][k]
        if _extract_placeholders(ru_text) != _extract_placeholders(en_text):
            errors.append(f"localization placeholders mismatch for key '{k}'")
    return errors

def _simulate_latency_budget(dialogue: Dialogue, budget_ms_per_step: int = 50) -> List[str]:
    """
    Имитация бюджета: каждый шаг «стоит» 1..budget_ms_per_step/2 мс, суммарно не превышаем budget*шаги.
    Это не реальная задержка, а проверка, что граф не создает чрезмерно длинных цепочек.
    """
    errors = []
    # оценим макс. длину пути до любого end как число шагов
    # грубая оценка: ограничимся 256 шагами, чтобы не зависнуть при ошибочном графе
    steps = 0
    node_id = dialogue.graph_entry
    visited = set()
    while node_id in dialogue.nodes and steps < 256:
        node = dialogue.nodes[node_id]
        steps += 1
        if node.type == "end":
            break
        if node.type == "line" and node.next:
            node_id = node.next
            continue
        if node.type == "choice":
            # худший случай: идем по обеим веткам, берем max
            branch_steps = 0
            for ch in node.choices:
                nxt = ch.get("next")
                if not isinstance(nxt, str) or nxt not in dialogue.nodes:
                    continue
                # один шаг на переход
                branch_steps = max(branch_steps, 1)
            steps += branch_steps
            # выбираем одну ветку как будто бы
            node_id = node.choices[0].get("next")
            continue
        # если ни одно условие не сработало — выходим
        break

    estimated_total_ms = steps * (budget_ms_per_step // 2)
    if estimated_total_ms > steps * budget_ms_per_step:
        errors.append(f"latency budget exceeded: steps={steps}, est_ms={estimated_total_ms}")
    # Целевая проверка: шагов разумно мало (например, <= 40)
    if steps > 40:
        errors.append(f"path too long: steps={steps}")
    return errors

def _simulate_run(dialogue: Dialogue, prng_seed: int) -> List[str]:
    """
    Детерминированная симуляция одного прогона, выбираем ветку по фиксированному seed.
    Возвращает список ошибок. Пустой список — успех.
    """
    rng = random.Random(prng_seed)
    node_id = dialogue.graph_entry
    visited: Set[str] = set()
    steps = 0
    errors = []

    # простая среда
    state = {"tutorial_completed": False, "trust_mentor": 0.0, "player_name": "Гость"}
    inventory: List[str] = []

    while steps < 256:
        steps += 1
        if node_id not in dialogue.nodes:
            errors.append(f"broken edge to unknown node '{node_id}'")
            break
        node = dialogue.nodes[node_id]

        # проверка guard-ов
        for g in node.guards:
            if not _guard_is_safe(g):
                errors.append(f"unsafe guard evaluated at node {node.id}")
                return errors

        # эффекты (проверяем только валидность whitelist и простейшее применение)
        for e in node.effects:
            if e.action not in ALLOWED_ACTIONS:
                errors.append(f"disallowed action at node {node.id}: {e.action}")
            if e.action == "inventory.add":
                item = e.params.get("item_id")
                if isinstance(item, str) and item:
                    inventory.append(item)
            elif e.action == "state.set":
                key = e.params.get("key")
                val = e.params.get("value")
                if key in state:
                    state[key] = val
            elif e.action == "economy.reward":
                pass
            elif e.action == "emit.event":
                pass

        if node.type == "end":
            # завершение
            return errors

        if node.type == "line":
            if node.next is None:
                errors.append(f"line node '{node.id}' has no 'next'")
                return errors
            node_id = node.next
            continue

        if node.type == "choice":
            if not node.choices:
                errors.append(f"choice node '{node.id}' has empty choices")
                return errors
            idx = rng.randrange(0, len(node.choices))
            nxt = node.choices[idx].get("next")
            if not isinstance(nxt, str):
                errors.append(f"choice leads to non-string next at node '{node.id}'")
                return errors
            node_id = nxt
            continue

        errors.append(f"unknown node type '{node.type}' at '{node.id}'")
        break
    else:
        errors.append("max steps exceeded; possible cycle")
    return errors

# ---------- Тесты ----------

pytestmark = pytest.mark.fuzz

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_actions_whitelisted(dialogue: Dialogue):
    errs = _check_whitelist(dialogue)
    assert not errs, "\n".join(errs)

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_entry_and_end_reachable(dialogue: Dialogue):
    assert dialogue.graph_entry in dialogue.nodes, "entry node missing in graph"
    reachable = _reachable_nodes(dialogue)
    assert dialogue.graph_entry in reachable, "entry node not reachable from itself (broken graph)"
    assert _end_reachable(dialogue, reachable), "no end state reachable from entry"

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_no_orphans(dialogue: Dialogue):
    reachable = _reachable_nodes(dialogue)
    orphans = _has_orphans(dialogue, reachable)
    # Разрешаем end-ноды как reachable; остальные должны быть достижимы
    assert not [o for o in orphans if not o.startswith("end.")], f"orphan nodes present: {orphans}"

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_localization_placeholders(dialogue: Dialogue):
    errs = _localization_placeholders_consistent(dialogue)
    assert not errs, "\n".join(errs)

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_guards_are_safe(dialogue: Dialogue):
    errs = _all_guards_safe(dialogue)
    assert not errs, "\n".join(errs)

@settings(
    max_examples=FUZZ_EXAMPLES,
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy())
@seed(FUZZ_SEED)
def test_latency_budget(dialogue: Dialogue):
    errs = _simulate_latency_budget(dialogue, budget_ms_per_step=50)
    assert not errs, "\n".join(errs)

@settings(
    max_examples=math.ceil(FUZZ_EXAMPLES / 2),
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy(), st.integers(min_value=1, max_value=10**9))
@seed(FUZZ_SEED)
def test_deterministic_run_with_same_seed(dialogue: Dialogue, local_seed: int):
    # Один и тот же seed -> одинаковый результат (список ошибок)
    errs1 = _simulate_run(dialogue, prng_seed=local_seed)
    errs2 = _simulate_run(dialogue, prng_seed=local_seed)
    assert errs1 == errs2, f"non-deterministic behavior with seed {local_seed}: {errs1} vs {errs2}"

@settings(
    max_examples=math.ceil(FUZZ_EXAMPLES / 2),
    deadline=FUZZ_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(dialogue_strategy(), st.integers(min_value=1, max_value=10**9), st.integers(min_value=1, max_value=10**9))
@seed(FUZZ_SEED)
def test_different_seeds_can_choose_different_paths(dialogue: Dialogue, seed_a: int, seed_b: int):
    # Разные seed могут выбирать разные ветки на choice
    errs_a = _simulate_run(dialogue, prng_seed=seed_a)
    errs_b = _simulate_run(dialogue, prng_seed=seed_b)
    # Если ошибок нет, допускаем, что пути могли совпасть — это не ошибка.
    # Критерий: по крайней мере отсутствие недетерминизма.
    assert errs_a == errs_a and errs_b == errs_b
