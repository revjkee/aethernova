# -*- coding: utf-8 -*-
"""
Unit-tests for veilmind.synthetic.text (industrial-grade).

Зависимости: pytest.
Тесты устойчиво отключают faker для детерминизма.
"""

from __future__ import annotations

import importlib
import re
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Импорт модуля и подготовка окружения
# ---------------------------------------------------------------------------

st = pytest.importorskip("veilmind.synthetic.text")  # гарантируем наличие модуля


@pytest.fixture(autouse=True)
def _disable_faker(monkeypatch):
    """
    Отключаем faker (если установлен), чтобы детерминизм зависел только от seed.
    """
    monkeypatch.setattr(st, "_FAKER_AVAILABLE", False, raising=False)
    monkeypatch.setattr(st, "faker", None, raising=False)


# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

def _engine(
    *,
    locale: str = "en",
    seed: int | None = 123,
    templates: List[str] | None = None,
    placeholders: dict | None = None,
    forbid_terms: List[str] | None = None,
    enforce_regex: str | None = None,
    markov_weight: float = 0.5,
    min_words: int = 6,
    max_words: int = 12,
    max_chars: int = 400,
    max_words_total: int = 120,
    noise: st.NoiseSpec | None = None,
) -> st.TextSynthEngine:
    spec = st.TextSpec(
        locale=locale,
        style="support",
        target_sentences=2,
        target_paragraphs=1,
        min_words_per_sentence=min_words,
        max_words_per_sentence=max_words,
        corpus=None,
        templates=templates,
        placeholders=placeholders or {},
        forbid_terms=forbid_terms or [],
        enforce_regex=enforce_regex,
        seed=seed,
        noise=noise or st.NoiseSpec(),
        max_chars=max_chars,
        max_words=max_words_total,
        markov_order=2,
        markov_weight=markov_weight,
    )
    return st.TextSynthEngine(spec)


def _char_diffs(a: str, b: str) -> int:
    """
    Грубая оценка различий по символам (без внешних lib).
    """
    n = min(len(a), len(b))
    d = sum(1 for i in range(n) if a[i] != b[i])
    d += abs(len(a) - len(b))
    return d


# ---------------------------------------------------------------------------
# Тесты
# ---------------------------------------------------------------------------

def test_determinism_sentence():
    eng1 = _engine(seed=42, templates=["Request {uuid} processed with status {choice:ok|error}"])
    eng2 = _engine(seed=42, templates=["Request {uuid} processed with status {choice:ok|error}"])
    s1 = [eng1.sentence("e1") for _ in range(3)]
    s2 = [eng2.sentence("e1") for _ in range(3)]
    assert s1 == s2, "Одинаковый seed должен давать идентичный вывод"

    eng3 = _engine(seed=43, templates=["Request {uuid} processed with status {choice:ok|error}"])
    s3 = [eng3.sentence("e1") for _ in range(3)]
    assert s1 != s3, "Разный seed должен давать отличия"


def test_identity_consistency_same_entity():
    # Явный шаблон с именем и email, чтобы проверить консистентность
    tpl = ["Contact {name} at {email}"]
    eng = _engine(seed=101, templates=tpl)
    a = eng.sentence("user-42")
    b = eng.sentence("user-42")
    # одинаковый entity_id => одинаковые сущности, но тексты могут отличаться из-за Markov/choice,
    # поэтому проверим, что имя и email совпадают в обоих строках
    name_a = re.search(r"Contact (.+?) at", a).group(1)  # type: ignore
    name_b = re.search(r"Contact (.+?) at", b).group(1)  # type: ignore
    email_a = re.search(r" at (.+)$", a).group(1)        # type: ignore
    email_b = re.search(r" at (.+)$", b).group(1)        # type: ignore
    assert name_a == name_b and email_a == email_b, "Сущности должны быть консистентны для одного entity_id"


def test_identity_distinct_between_entities():
    tpl = ["Contact {name} at {email}"]
    eng = _engine(seed=202, templates=tpl)
    a = eng.sentence("user-A")
    b = eng.sentence("user-B")
    # высокая вероятность различий; проверим, что хотя бы одно из полей отличается
    name_a = re.search(r"Contact (.+?) at", a).group(1)  # type: ignore
    name_b = re.search(r"Contact (.+?) at", b).group(1)  # type: ignore
    email_a = re.search(r" at (.+)$", a).group(1)        # type: ignore
    email_b = re.search(r" at (.+)$", b).group(1)        # type: ignore
    assert (name_a != name_b) or (email_a != email_b), "Разные entity_id должны порождать разные сущности"


def test_forbid_terms_redaction():
    tpl = ["User message: do not share password or secret please."]
    eng = _engine(seed=7, templates=tpl, forbid_terms=["password", "secret"])
    out = eng.sentence("x")
    assert "[REDACTED]" in out
    assert "password" not in out.lower() and "secret" not in out.lower()


def test_enforce_regex_is_satisfied():
    # Добьемся наличия числа 2-3 знаков
    tpl = ["Latency {number:10..99} ms"]
    eng = _engine(seed=11, templates=tpl, enforce_regex=r"\b\d{2}\b")
    out = eng.sentence("e")
    assert re.search(r"\b\d{2}\b", out), "Должен присутствовать двухзначный номер по enforce_regex"


def test_noise_typos_bounded():
    # Сравниваем текст без шума и с шумом, ограничив max_typos_per_text
    base_tpl = ["Release note: {sentence}"]
    eng_clean = _engine(seed=55, templates=base_tpl, noise=st.NoiseSpec(typo_rate=0.0))
    eng_noisy = _engine(seed=55, templates=base_tpl, noise=st.NoiseSpec(
        typo_rate=1.0, case_flip_rate=0.0, whitespace_jitter=0.0, confusable_rate=0.0, max_typos_per_text=3
    ))
    a = eng_clean.sentence("e")
    b = eng_noisy.sentence("e")
    diffs = _char_diffs(a, b)
    assert diffs <= 6, "Различий по символам должно быть немного (<= удвоенного лимита), шум ограничен"


def test_sentence_length_and_endings():
    eng = _engine(seed=5, min_words=5, max_words=8)
    s = eng.sentence("e")
    # проверяем оканчивающий знак
    assert s[-1] in eng.spec.sentence_endings
    # проверяем, что не пусто и есть пробелы, предположительно 5..8 слов
    assert len(s.split()) >= 5


def test_paragraph_and_document_limits():
    eng = _engine(seed=77, max_chars=80, max_words_total=20)
    p = eng.paragraph("e")
    assert len(p) <= 80
    d = eng.document("e")
    # document состоит из target_paragraphs=1 параграфа по дефолту
    assert len(d) <= 160  # грубая граница (две строки с \n\n в худшем случае)


def test_stream_count_and_punctuation():
    eng = _engine(seed=99)
    items = list(eng.stream(count=5, entity_id="e"))
    assert len(items) == 5
    assert all(x and x[-1] in eng.spec.sentence_endings for x in items)


def test_markov_weight_changes_output():
    tpl = ["{sentence}"]
    # Одинаковый seed, разный markov_weight => тексты должны отличаться с высокой вероятностью
    eng_a = _engine(seed=303, templates=tpl, markov_weight=0.0)
    eng_b = _engine(seed=303, templates=tpl, markov_weight=1.0)
    a = eng_a.sentence("e")
    b = eng_b.sentence("e")
    assert a != b, "Разный вес Markov должен менять выбор слов/последовательность"


def test_placeholders_pick_and_choice():
    tpl = ["Product {pick:product} status {choice:ok|warning|error}"]
    eng = _engine(seed=404, templates=tpl, placeholders={"product": ["Core", "Gateway", "Agent"]})
    out = eng.sentence("e")
    assert any(p in out for p in ["Core", "Gateway", "Agent"])
    assert any(s in out for s in ["ok", "warning", "error"])


def test_ru_locale_basic_generation():
    eng = _engine(locale="ru", seed=13)
    txt = eng.sentence("e")
    assert isinstance(txt, str) and len(txt) > 0, "Русская локаль должна генерировать непустой текст"


def test_max_words_total_enforced():
    eng = _engine(seed=61, max_words_total=8)
    txt = eng.paragraph("e")
    assert len(txt.split()) <= 8, "Глобальный предел слов должен соблюдаться"
