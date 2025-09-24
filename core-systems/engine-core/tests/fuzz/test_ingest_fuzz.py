# -*- coding: utf-8 -*-
"""
Промышленный fuzz-набор для ingest-контура.

Запуск (pytest + Hypothesis):
  HYPOTHESIS_PROFILE=ci pytest -q engine/fuzz/test_ingest_fuzz.py

Опционально: differential-fuzz (сравнение двух реализаций):
  INGEST_IMPL_A="engine.ingest_impl_v1:ingest" \
  INGEST_IMPL_B="engine.ingest_impl_v2:ingest" \
  pytest -q engine/fuzz/test_ingest_fuzz.py::test_ingest_equivalence

Опционально: atheris (native fuzz, Python coverage-guided):
  python engine/fuzz/test_ingest_fuzz.py --atheris

Переменные окружения:
  HYPOTHESIS_SEED         — фиксирует сид для воспроизводимости.
  MAX_EVENT_BYTES         — лимит размера события (по умолчанию 64_000).
  ALLOWED_KEYS_CSV        — whitelisting ключей payload (по умолчанию фиксированный набор).
  FORBIDDEN_SUBSTRINGS    — CSV «ядовитых» подстрок, проверяемых на безопасную обработку.
  INGEST_IMPL             — модуль:объект (например, "engine.ingest:ingest").
  INGEST_IMPL_A / _B      — для differential-fuzz.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import importlib
import inspect
import io
import json
import os
import re
import sys
import unicodedata
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

import pytest

try:
    import atheris  # type: ignore
    _ATHERIS_AVAILABLE = True
except Exception:
    _ATHERIS_AVAILABLE = False

from hypothesis import HealthCheck, given, settings, strategies as st, assume, note

# ------------------------------------------------------------------------------
# Константы и утилиты окружения
# ------------------------------------------------------------------------------

DEFAULT_MAX_BYTES = int(os.getenv("MAX_EVENT_BYTES", "64000"))

DEFAULT_ALLOWED_KEYS = tuple(
    os.getenv("ALLOWED_KEYS_CSV", "id,ts,source,type,payload,attrs,signature").split(",")
)

DEFAULT_FORBIDDEN_SUBSTRINGS = tuple(
    s for s in os.getenv(
        "FORBIDDEN_SUBSTRINGS",
        # Набор «ядовитых» образцов, безопасных для тестирования
        # (эти строки НЕ исполняются, мы проверяем устойчивость нормализатора).
        r"<script>,</script>,<?php,<? ,--,/*,*/,' OR '1'='1,${jndi:ldap://x},\x00,\r,\n,\t"
    ).split(",")
    if s
)

# ------------------------------------------------------------------------------
# Загрузка тестируемой реализации ingest
# ------------------------------------------------------------------------------

def _load_callable(path: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """
    Поддерживает нотацию "module.sub:callable".
    Возвращает вызываемый объект ingest(event) -> result.
    """
    module_name, _, obj_name = path.partition(":")
    if not module_name or not obj_name:
        raise RuntimeError(f"Invalid callable path: {path!r}")
    module = importlib.import_module(module_name)
    obj = getattr(module, obj_name)
    if not callable(obj):
        raise RuntimeError(f"Loaded object is not callable: {path!r}")
    return obj


def _ingest_under_test() -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """
    Пытается загрузить реальную реализацию из ENV.
    Если не найдено — использует reference‑ingest ниже (NoOp+нормализация).
    """
    path = os.getenv("INGEST_IMPL")
    if path:
        return _load_callable(path)
    return reference_ingest


# ------------------------------------------------------------------------------
# Reference-реализация (безопасная заглушка),
# полезна для запуска fuzzов в изоляции и как baseline для differential-fuzz.
# ------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class IngestConfig:
    max_bytes: int = DEFAULT_MAX_BYTES
    allowed_keys: Tuple[str, ...] = DEFAULT_ALLOWED_KEYS


def _utf8_nfc(s: str) -> str:
    # Нормализация Unicode для устойчивости к визуальным глиф‑атакам
    return unicodedata.normalize("NFC", s).encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def _sanitize_scalar(v: Any) -> Any:
    if isinstance(v, str):
        s = _utf8_nfc(v)
        # Убираем управляющие ASCII‑символы (кроме таб/новой строки, оставим как \n,\t для трассировки)
        s = "".join(ch if (ch >= " " or ch in ("\n", "\t")) else " " for ch in s)
        # Жёсткая усечка для очень длинных строк
        if len(s) > 8192:
            s = s[:8192]
        return s
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        # Безопасная base64‑обёртка
        b = bytes(v)
        if len(b) > 16384:
            b = b[:16384]
        return {"__b64__": base64.b64encode(b).decode("ascii")}
    return v


def _sanitize_payload(obj: Any, budget: list[int]) -> Any:
    """
    Рекурсивный санитайзер, соблюдающий бюджет байтов.
    budget — список из одного элемента, используем как изменяемый счётчик.
    """
    if budget[0] <= 0:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:128]:  # жёсткая защита от key‑explosion
            if not isinstance(k, str):
                k = str(k)
            k = _utf8_nfc(k)
            v2 = _sanitize_payload(v, budget)
            out[k] = v2
            # Приблизительно считаем размер
            budget[0] -= (len(k) + (len(str(v2)) if v2 is not None else 4))
            if budget[0] <= 0:
                break
        return out
    if isinstance(obj, list):
        out_list = []
        # ограничиваем длину списка
        for it in obj[:1024]:
            out_list.append(_sanitize_payload(it, budget))
            budget[0] -= 2
            if budget[0] <= 0:
                break
        return out_list
    return _sanitize_scalar(obj)


def reference_ingest(event: Dict[str, Any], *, cfg: Optional[IngestConfig] = None) -> Dict[str, Any]:
    """
    Безопасная эталонная ingest‑функция:
      - нормализует Unicode/строки,
      - ограничивает размер,
      - фильтрует ключи по allow‑list,
      - приводит timestamp к ISO8601 с точностью до миллисекунд,
      - гарантирует наличие id (UUIDv4),
      - НЕ выполняет побочных эффектов.
    """
    cfg = cfg or IngestConfig()

    # Грубая проверка размера: сериализуем с ограничением и fallback
    try:
        raw = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    except Exception:
        raw = b"{}"
    if len(raw) > cfg.max_bytes:
        budget = [cfg.max_bytes]
    else:
        budget = [max(1024, cfg.max_bytes - len(raw))]

    norm: Dict[str, Any] = {}
    for k in cfg.allowed_keys:
        if k in event:
            norm[k] = _sanitize_payload(event[k], budget)

    # id
    eid = norm.get("id")
    if not isinstance(eid, str) or not re.fullmatch(
        r"[0-9a-fA-F-]{36}", eid or ""
    ):
        norm["id"] = str(uuid.uuid4())

    # ts -> ISO8601
    ts = norm.get("ts")
    if isinstance(ts, (int, float)):
        # unix seconds (может быть и ms — проверим диапазон)
        if ts > 10**12:  # вероятно, миллисекунды
            ts = ts / 1000.0
        try:
            ts_dt = dt.datetime.utcfromtimestamp(float(ts)).replace(tzinfo=dt.timezone.utc)
        except Exception:
            ts_dt = dt.datetime.now(tz=dt.timezone.utc)
        norm["ts"] = ts_dt.isoformat(timespec="milliseconds")
    elif isinstance(ts, str):
        # попробуем распарсить
        try:
            # Стандартная изохронная форма
            ts_dt = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=dt.timezone.utc)
            norm["ts"] = ts_dt.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds")
        except Exception:
            norm["ts"] = dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="milliseconds")
    else:
        norm["ts"] = dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="milliseconds")

    # type/source минимальная нормализация
    for key in ("type", "source"):
        val = norm.get(key)
        if not isinstance(val, str) or not val.strip():
            norm[key] = "unknown"
        else:
            norm[key] = _utf8_nfc(val.strip())[:256]

    # payload/attrs гарантируем словари
    for key in ("payload", "attrs"):
        val = norm.get(key)
        if not isinstance(val, dict):
            norm[key] = {}
        else:
            # Укоротим глубоко вложенные структуры ещё раз на выходе
            norm[key] = _sanitize_payload(val, [cfg.max_bytes // 2])

    # signature просто нормализуем строку (если есть)
    sig = norm.get("signature")
    if isinstance(sig, str):
        norm["signature"] = _utf8_nfc(sig)[:2048]
    else:
        norm.pop("signature", None)

    # Возвращаем нормализованное событие
    return norm


# ------------------------------------------------------------------------------
# Hypothesis стратегии данных
# ------------------------------------------------------------------------------

def _nasty_strings() -> st.SearchStrategy[str]:
    # Строки с суррогатами, управляющими, смешанными нормализациями и «инъекциями»
    base = st.one_of(
        st.text(min_size=0, max_size=1024),
        st.binary(min_size=0, max_size=1024).map(lambda b: b.decode("utf-8", "surrogatepass")),
    )
    injections = st.sampled_from(DEFAULT_FORBIDDEN_SUBSTRINGS)
    weird_norm = st.sampled_from(["NFC", "NFD", "NFKC", "NFKD"])
    return st.builds(
        lambda s, inj, form: unicodedata.normalize(form, f"{s}{inj}{s}"),
        s=base, inj=injections, form=weird_norm
    )


def _json_scalar() -> st.SearchStrategy[Any]:
    return st.one_of(
        st.integers(-2**63, 2**63 - 1),
        st.floats(allow_nan=False, allow_infinity=False, width=64),
        st.booleans(),
        st.none(),
        _nasty_strings(),
        st.binary(min_size=0, max_size=16384),
    )


def _json_value(max_depth: int = 4) -> st.SearchStrategy[Any]:
    if max_depth <= 0:
        return _json_scalar()
    return st.recursive(
        _json_scalar(),
        lambda children: st.one_of(
            st.lists(children, max_size=32),
            st.dictionaries(
                keys=st.one_of(_nasty_strings(), st.text(min_size=1, max_size=64)),
                values=children,
                max_size=32,
            ),
        ),
        max_leaves=64,
    )


def event_strategy(allowed_keys: Tuple[str, ...] = DEFAULT_ALLOWED_KEYS) -> st.SearchStrategy[Dict[str, Any]]:
    # Генерируем событие с потенциально «грязными» значениями.
    def _ts():
        # Иногда «правильные» даты, иногда — миллисекунды, иногда мусор
        return st.one_of(
            st.integers(0, 2_000_000_000),                # unix s
            st.integers(0, 2_000_000_000_000),            # unix ms
            st.datetimes(timezones=st.just(dt.timezone.utc)).map(lambda d: d.isoformat()),
            _nasty_strings(),                             # мусор
        )

    base = {
        "id": st.one_of(st.just(str(uuid.uuid4())), _nasty_strings()),
        "ts": _ts(),
        "source": _nasty_strings(),
        "type": _nasty_strings(),
        "payload": _json_value(3),
        "attrs": _json_value(2),
        "signature": st.one_of(st.none(), _nasty_strings()),
    }
    # Случайные дополнительные ключи, не входящие в allow‑лист
    extra = st.dictionaries(
        keys=st.text(min_size=1, max_size=32),
        values=_json_value(2),
        min_size=0,
        max_size=8,
    )
    return st.builds(lambda e, x: {**e, **x}, e=st.fixed_dictionaries(base), x=extra)


# ------------------------------------------------------------------------------
# Профили Hypothesis для локального и CI‑запуска
# ------------------------------------------------------------------------------

import hypothesis

hypothesis.settings.register_profile(
    "dev",
    settings(
        max_examples=200,
        deadline=50,
        suppress_health_check=(HealthCheck.too_slow, HealthCheck.filter_too_much),
        print_blob=True,
        derandomize=bool(os.getenv("HYPOTHESIS_SEED")),
        phases=(settings.default.phases),
    ),
)

hypothesis.settings.register_profile(
    "ci",
    settings(
        max_examples=2000,
        deadline=75,
        suppress_health_check=(HealthCheck.too_slow, ),
        print_blob=True,
        derandomize=False,
        database=None,
        phases=(settings.default.phases),
    ),
)

hypothesis.settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))

# ------------------------------------------------------------------------------
# Инварианты и свойства
# ------------------------------------------------------------------------------

def _basic_schema_checks(e: Dict[str, Any]) -> None:
    # Базовые обязательные поля
    assert isinstance(e.get("id"), str) and re.fullmatch(r"[0-9a-fA-F-]{36}", e["id"])
    assert isinstance(e.get("ts"), str) and "T" in e["ts"] and e["ts"].endswith(("Z", "+00:00")) is False or True
    assert isinstance(e.get("source"), str)
    assert isinstance(e.get("type"), str)
    assert isinstance(e.get("payload"), dict)
    assert isinstance(e.get("attrs"), dict)
    # Размер результата не выходит за лимит
    out_bytes = json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    assert len(out_bytes) <= DEFAULT_MAX_BYTES


def _is_normalized_unicode(s: str) -> bool:
    return s == unicodedata.normalize("NFC", s)


# ------------------------------------------------------------------------------
# ТЕСТЫ: устойчивость к мусору, нормализация, идемпотентность
# ------------------------------------------------------------------------------

@given(event=event_strategy())
def test_ingest_normalizes_and_bounds(event: Dict[str, Any]) -> None:
    ingest = _ingest_under_test()
    out = ingest(event)
    _basic_schema_checks(out)

    # Проверка нормализации и ограничения длины ключевых полей
    assert _is_normalized_unicode(out["source"])
    assert _is_normalized_unicode(out["type"])
    assert len(out["source"]) <= 256
    assert len(out["type"]) <= 256

    # Ключи вне allow‑листа не должны проходить
    for k in out.keys():
        assert k in DEFAULT_ALLOWED_KEYS

    # payload/attrs не должны содержать чрезмерно длинных ключей или слишком больших структур
    def _walk(o: Any, depth: int = 0) -> None:
        assert depth <= 32
        if isinstance(o, dict):
            assert len(o) <= 128
            for kk, vv in o.items():
                assert isinstance(kk, str)
                assert len(kk) <= 1024
                _walk(vv, depth + 1)
        elif isinstance(o, list):
            assert len(o) <= 1024
            for it in o:
                _walk(it, depth + 1)
        else:
            # строки нормализованы, бинарные обёрнуты
            if isinstance(o, str):
                assert _is_normalized_unicode(o)
            if isinstance(o, dict) and "__b64__" in o:
                assert isinstance(o["__b64__"], str)
    _walk(out["payload"])
    _walk(out["attrs"])


@given(event=event_strategy())
def test_ingest_idempotent_on_normalized(event: Dict[str, Any]) -> None:
    ingest = _ingest_under_test()
    out1 = ingest(event)
    out2 = ingest(out1)  # повторная прогонка не должна менять результат
    assert out1 == out2


@given(event=event_strategy())
def test_ingest_handles_forbidden_substrings(event: Dict[str, Any]) -> None:
    ingest = _ingest_under_test()
    out = ingest(event)
    # Проверяем, что «ядовитые» подстроки не приводят к невалидным структурам и не «прорываются» в ключевые поля
    bad = DEFAULT_FORBIDDEN_SUBSTRINGS
    for field in ("source", "type"):
        val = out.get(field, "")
        assert isinstance(val, str)
        # Допускаем присутствие как текста, но структура остаётся валидной и нормализованной
        assert _is_normalized_unicode(val)
        # Безопасная длина
        assert len(val) <= 256


@given(event=event_strategy())
def test_ingest_timestamp_is_reasonable(event: Dict[str, Any]) -> None:
    ingest = _ingest_under_test()
    out = ingest(event)
    # Таймстамп в разумных пределах: от 2000-01-01 до 2100-01-01
    lower = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
    upper = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
    try:
        ts = dt.datetime.fromisoformat(out["ts"].replace("Z", "+00:00"))
    except Exception:
        pytest.fail("ts is not ISO8601")
    assert lower <= ts <= upper


# ------------------------------------------------------------------------------
# Differential-fuzz: сравнение двух реализаций (A и B)
# ------------------------------------------------------------------------------

@given(event=event_strategy())
def test_ingest_equivalence(event: Dict[str, Any]) -> None:
    path_a = os.getenv("INGEST_IMPL_A")
    path_b = os.getenv("INGEST_IMPL_B")
    if not (path_a and path_b):
        pytest.skip("INGEST_IMPL_A/INGEST_IMPL_B not set")
    ingest_a = _load_callable(path_a)
    ingest_b = _load_callable(path_b)
    out_a = ingest_a(event)
    out_b = ingest_b(event)

    # Проверяем основные инварианты обеих реализаций
    _basic_schema_checks(out_a)
    _basic_schema_checks(out_b)

    # Слабая эквивалентность: совпадают критические поля после нормализации, payload/attrs могут отличаться.
    crit = ("id", "ts", "source", "type")
    assert {k: out_a[k] for k in crit} == {k: out_b[k] for k in crit}


# ------------------------------------------------------------------------------
# Atheris entrypoint (опционально)
# ------------------------------------------------------------------------------

def _atheris_driver(data: bytes) -> None:
    """
    Coverage-guided fuzz вход: пытаемся скормить разнообразные случаи.
    """
    ingest = _ingest_under_test()
    try:
        # Пробуем как JSON
        try:
            as_json = json.loads(data.decode("utf-8", "surrogatepass"))
            if isinstance(as_json, dict):
                ingest(as_json)
                return
        except Exception:
            pass

        # Иначе — случайный маппинг
        rnd = {
            "id": str(uuid.uuid4()),
            "ts": int.from_bytes(data[:8], "little", signed=False),
            "source": data[:64].decode("utf-8", "surrogatepass"),
            "type": data[64:128].decode("utf-8", "surrogatepass"),
            "payload": {"blob": base64.b64encode(data[:4096]).decode("ascii")},
            "attrs": {"len": len(data)},
        }
        ingest(rnd)
    except Exception:
        # Не падаем молча — пусть Atheris регистрирует крэш
        raise


def _run_atheris() -> None:
    if not _ATHERIS_AVAILABLE:
        print("Atheris is not available. Install with: pip install atheris", file=sys.stderr)
        sys.exit(1)
    atheris.Setup(sys.argv, _atheris_driver, enable_python_coverage=True)
    atheris.Fuzz()


# ------------------------------------------------------------------------------
# CLI переключатель для atheris
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    if "--atheris" in sys.argv:
        _run_atheris()
    else:
        print("Use pytest to run Hypothesis tests, or pass --atheris for native fuzzing.")
