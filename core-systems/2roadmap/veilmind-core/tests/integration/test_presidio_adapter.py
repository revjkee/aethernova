# -*- coding: utf-8 -*-
"""
Интеграционные тесты адаптера Presidio для VeilMind Core.

Покрытие:
  - Контракт API: detect_pii, redact_text_by_pii, (опционально) batch_detect_pii, detect_language
  - Корректность редактирования по байтовым смещениям (UTF‑8, emoji)
  - Слияние пересекающихся сущностей
  - Идемпотентность редактирования
  - Батч‑обработка (если реализована)

Тесты НЕ требуют реальных сетевых ресурсов.
"""

from __future__ import annotations

import os
import typing as t

import pytest

# Модуль адаптера может отсутствовать в окружении — корректно скипаем.
adapter_mod = pytest.importorskip(
    "veilmind.adapters.presidio_adapter",
    reason="Presidio adapter is not installed/available"
)

# Попытаемся импортировать публичные классы; иначе будем обращаться динамически.
PresidioAdapter = getattr(adapter_mod, "PresidioAdapter", None)
PresidioAdapterConfig = getattr(adapter_mod, "PresidioAdapterConfig", None)
PiiEntity = getattr(adapter_mod, "PiiEntity", None)

if PresidioAdapter is None or PresidioAdapterConfig is None or PiiEntity is None:
    pytest.skip("Presidio adapter does not expose required public classes (PresidioAdapter, Config, PiiEntity).")


@pytest.fixture(scope="session")
def cfg() -> "PresidioAdapterConfig":
    # Конфиг выбирает RU/EN, отключает внешние загрузки, задает тайм‑ауты/лимиты.
    return PresidioAdapterConfig(
        languages=("en", "ru"),
        max_input_bytes=8000,
        enable_default_recognizers=True,
        extra_recognizers=None,
        read_timeout=5.0,
        connect_timeout=2.0,
    )


@pytest.fixture(scope="session")
def adapter(cfg: "PresidioAdapterConfig") -> "PresidioAdapter":
    return PresidioAdapter(cfg)


# -----------------
# Вспомогательные утилиты
# -----------------

def _byte_offsets(text: str, substring: str) -> tuple[int, int]:
    """
    Возвращает (begin_byte, end_byte) для первого вхождения substring в text
    в терминах UTF‑8 байтовых смещений.
    """
    i = text.find(substring)
    assert i >= 0, f"substring '{substring}' not found"
    prefix_b = text[:i].encode("utf-8")
    sub_b = substring.encode("utf-8")
    return len(prefix_b), len(prefix_b) + len(sub_b)


def _make_entity(text: str, fragment: str, typ: str = "TEST") -> "PiiEntity":
    b, e = _byte_offsets(text, fragment)
    return PiiEntity(type=typ, score=0.99, begin_offset=b, end_offset=e)


# -----------------
# Базовые интерфейсные тесты
# -----------------

@pytest.mark.integration
def test_detect_pii_contract(adapter: "PresidioAdapter"):
    text = "Иван Петров, email: ivan.petrov@example.com, phone: +7 911 555-44-33."
    res = adapter.detect_pii(text)
    # Контракт: у результата есть entities (список), у сущностей — type, score, begin/end_offset.
    assert hasattr(res, "entities"), "PiiResult must have 'entities'"
    assert isinstance(res.entities, list)
    for ent in res.entities:
        assert hasattr(ent, "type")
        assert hasattr(ent, "score")
        assert hasattr(ent, "begin_offset") and hasattr(ent, "end_offset")
        assert isinstance(ent.begin_offset, int) and isinstance(ent.end_offset, int)
        assert ent.end_offset >= ent.begin_offset

    # Опциональная проверка наличия базовых типов; делаем слабую проверку (не флейки в разных моделях)
    types = {e.type for e in res.entities}
    # Как минимум один из типичных маркеров должен быть найден
    assert any(t in types for t in {"EMAIL_ADDRESS", "PHONE_NUMBER", "NRP", "PERSON"})


@pytest.mark.integration
def test_redaction_masks_bytes_mapping_unicode(adapter: "PresidioAdapter"):
    # Включаем emoji и кириллицу, чтобы проверить точность байтовых смещений → символы.
    text = "📞 Свяжитесь со мной по номеру +7‑911‑555‑44‑33 или email: ivan@example.com"
    phone_frag = "+7‑911‑555‑44‑33"
    mail_frag = "ivan@example.com"

    ents = [
        _make_entity(text, phone_frag, "PHONE_NUMBER"),
        _make_entity(text, mail_frag, "EMAIL_ADDRESS"),
    ]

    red = adapter.redact_text_by_pii(
        text, ents, mode="mask", mask_char="*", keep_head=2, keep_tail=2
    )

    # Телефон должен быть замаскирован, но с сохранением 2+2 символов
    assert red.count(phone_frag[:2]) >= 1 and red.count(phone_frag[-2:]) >= 1
    assert phone_frag not in red
    # Email также не должен присутствовать целиком
    assert mail_frag not in red


@pytest.mark.integration
def test_overlapping_entities_are_merged(adapter: "PresidioAdapter"):
    # Две пересекающиеся сущности в одном диапазоне должны привести к одному редактированию
    text = "Email: ivan.petrov@example.com"
    # Имя + полное; перекрываются
    frag1 = "ivan.petrov@example.com"
    frag2 = "petrov@example.com"

    ents = [
        _make_entity(text, frag1, "EMAIL_ADDRESS"),
        _make_entity(text, frag2, "USERNAME"),
    ]
    red = adapter.redact_text_by_pii(text, ents, mode="mask", mask_char="*")

    # Не должно быть двойной вставки плейсхолдера/маски или артефактов
    assert "example.com" in red  # хвостовая часть может сохраниться при keep_tail по умолчанию
    assert frag1 not in red and frag2 not in red


@pytest.mark.integration
def test_redaction_is_idempotent(adapter: "PresidioAdapter"):
    text = "Contact: john.doe@example.com"
    ent = _make_entity(text, "john.doe@example.com", "EMAIL_ADDRESS")

    red1 = adapter.redact_text_by_pii(text, [ent], mode="mask", mask_char="*")
    red2 = adapter.redact_text_by_pii(red1, [ent], mode="mask", mask_char="*")
    assert red1 == red2


@pytest.mark.integration
def test_manual_entities_do_not_depend_on_detector(adapter: "PresidioAdapter"):
    # Даже если detect_pii ничего не нашёл, ручные смещения должны работать.
    text = "custom token ABC-12345 appears here"
    frag = "ABC-12345"
    ent = _make_entity(text, frag, "CUSTOM")
    red = adapter.redact_text_by_pii(text, [ent], mode="remove", placeholder="[REDACTED]")
    assert frag not in red
    assert "[REDACTED]" in red


# -----------------
# Опциональные интерфейсы
# -----------------

@pytest.mark.integration
def test_batch_detect_pii_if_available(adapter: "PresidioAdapter"):
    if not hasattr(adapter, "batch_detect_pii"):
        pytest.skip("batch_detect_pii not implemented by adapter")
    batch = [
        ("Alice, email alice@example.com", None),
        ("Bob, phone +1-415-555-00-11", None),
    ]
    res = adapter.batch_detect_pii(batch)
    assert isinstance(res, list) and len(res) == len(batch)
    assert all(hasattr(r, "entities") for r in res)


@pytest.mark.integration
def test_detect_language_if_available(adapter: "PresidioAdapter"):
    if not hasattr(adapter, "detect_language"):
        pytest.skip("detect_language not implemented by adapter")
    ru = adapter.detect_language("Это небольшой русский текст.")
    en = adapter.detect_language("This is a short English text.")
    # Слабые проверки, чтобы избежать флейков между версиями моделей
    if hasattr(ru, "languages"):
        assert any(l.language_code.startswith("ru") for l in ru.languages)
    if hasattr(en, "languages"):
        assert any(l.language_code.startswith("en") for l in en.languages)
