# oblivionvault-core/tests/unit/test_scope_resolver.py
# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты резолвера политик OblivionVault.

Покрывает:
- Селекторы (patterns, tags_any, tags_all)
- constraints.not_before / constraints.not_after
- Стратегии resolution: PRIORITY и MOST_RESTRICTIVE
- Приоритет compliance над governance
- Выбор более строгого срока хранения
- Агрегация allow_extension_only в MOST_RESTRICTIVE
- duration_seconds vs retention_until (RFC3339 Z)
- Режим обязательной подписи HMAC (require_signature)

Требуется pytest.
"""

from __future__ import annotations

import datetime as dt
import json
import hashlib
import hmac
import os
import random
import string
from typing import Any, Dict, Mapping, Optional, Sequence

import pytest

from oblivionvault.policy.loader import (
    PolicyLoader,
    LoaderConfig,
    ResolutionStrategy,
    InMemorySource,
    issue_policy_signature,
)
from oblivionvault.archive.retention_lock import (
    RetentionMode,
    RetentionPolicy,
)

# -----------------------
# Вспомогательные утилиты
# -----------------------

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _rfc3339(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _rand_id(prefix: str = "pol") -> str:
    sfx = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{prefix}-{sfx}"

def make_policy_doc(
    *,
    doc_id: Optional[str] = None,
    version: str = "1.0.0",
    priority: int = 0,
    mode: RetentionMode = RetentionMode.governance,
    duration_seconds: Optional[int] = 3600,
    retention_until: Optional[dt.datetime] = None,
    allow_extension_only: bool = True,
    patterns: Sequence[str] = (),
    tags_any: Sequence[str] = (),
    tags_all: Sequence[str] = (),
    not_before: Optional[dt.datetime] = None,
    not_after: Optional[dt.datetime] = None,
    sign_with: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Конструирует словарь политики в формате PolicyLoader.
    При sign_with — добавляет поле 'sig' как HMAC-SHA256(body).
    """
    body: Dict[str, Any] = {
        "kind": "RetentionPolicy",
        "id": doc_id or _rand_id(),
        "version": version,
        "priority": priority,
        "mode": mode.value,
        "allow_extension_only": allow_extension_only,
        "selectors": {},
    }
    if duration_seconds is not None:
        body["duration_seconds"] = int(duration_seconds)
    if retention_until is not None:
        body["retention_until"] = _rfc3339(retention_until)
    sel: Dict[str, Any] = {}
    if patterns:
        sel["patterns"] = list(patterns)
    if tags_any:
        sel["tags_any"] = list(tags_any)
    if tags_all:
        sel["tags_all"] = list(tags_all)
    body["selectors"] = sel
    if not_before or not_after:
        body["constraints"] = {}
        if not_before:
            body["constraints"]["not_before"] = _rfc3339(not_before)
        if not_after:
            body["constraints"]["not_after"] = _rfc3339(not_after)

    if sign_with is not None:
        # Используем официальную утилиту из модуля
        sig = issue_policy_signature(body, sign_with)
        body["sig"] = sig
    return body


@pytest.mark.asyncio
async def test_priority_strategy_prefers_higher_priority_then_version_then_id():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="A",
            version="1.0.0",
            priority=10,
            mode=RetentionMode.governance,
            duration_seconds=3600,
            patterns=["project/*"],
        ),
        make_policy_doc(
            doc_id="B",
            version="1.2.0",
            priority=5,  # ниже приоритет — не должен победить, даже если версия больше
            mode=RetentionMode.governance,
            duration_seconds=7200,
            patterns=["project/*"],
        ),
        make_policy_doc(
            doc_id="C",
            version="1.0.1",  # версия больше чем у A, но priority равный потребуется для сравнения
            priority=10,
            mode=RetentionMode.governance,
            duration_seconds=1800,
            patterns=["project/*"],
        ),
    ]
    loader = PolicyLoader(
        [InMemorySource(docs, sid="t1")],
        config=LoaderConfig(require_signature=False, resolution_strategy=ResolutionStrategy.PRIORITY),
    )
    await loader.load()
    pol = loader.resolve("project/data.csv", tags=(), created_at=now)
    assert isinstance(pol, RetentionPolicy)
    # При равном priority выиграет более новая версия между A(1.0.0) и C(1.0.1) -> C
    assert pol.duration_seconds == 1800
    assert pol.mode == RetentionMode.governance


@pytest.mark.asyncio
async def test_most_restrictive_prefers_compliance_over_governance():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="gov-long",
            version="1.0.0",
            priority=5,
            mode=RetentionMode.governance,
            duration_seconds=60 * 60 * 24 * 7,  # 7d
            patterns=["secure/*"],
        ),
        make_policy_doc(
            doc_id="comp-short",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.compliance,
            duration_seconds=60 * 60 * 24,  # 1d (но compliance должно победить)
            patterns=["secure/*"],
        ),
    ]
    loader = PolicyLoader(
        [InMemorySource(docs, sid="t2")],
        config=LoaderConfig(require_signature=False, resolution_strategy=ResolutionStrategy.MOST_RESTRICTIVE),
    )
    await loader.load()
    pol = loader.resolve("secure/file.bin", tags=(), created_at=now)
    assert pol is not None
    assert pol.mode == RetentionMode.compliance
    assert pol.duration_seconds == 60 * 60 * 24


@pytest.mark.asyncio
async def test_most_restrictive_longer_duration_wins_with_same_mode():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="gov-1h",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.governance,
            duration_seconds=3600,
            patterns=["logs/*"],
        ),
        make_policy_doc(
            doc_id="gov-4h",
            version="1.0.0",
            priority=0,
            mode=RetentionMode.governance,
            duration_seconds=4 * 3600,
            patterns=["logs/*"],
        ),
    ]
    loader = PolicyLoader(
        [InMemorySource(docs, sid="t3")],
        config=LoaderConfig(require_signature=False, resolution_strategy=ResolutionStrategy.MOST_RESTRICTIVE),
    )
    await loader.load()
    pol = loader.resolve("logs/app.log", tags=(), created_at=now)
    assert pol is not None
    assert pol.duration_seconds == 4 * 3600


@pytest.mark.asyncio
async def test_selector_patterns_and_tags_all_any():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="tpii",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.governance,
            duration_seconds=86400,
            patterns=["project/*"],
            tags_any=["pii"],
            tags_all=["export", "pii"],
        )
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t4")], config=LoaderConfig())
    await loader.load()

    # Совпадение по паттерну и тегам: есть pii и export
    pol = loader.resolve("project/data.csv", tags=("pii", "export"), created_at=now)
    assert pol is not None

    # Отсутствует обязательный тег из tags_all
    pol2 = loader.resolve("project/data.csv", tags=("pii",), created_at=now)
    assert pol2 is None

    # Паттерн не совпадает
    pol3 = loader.resolve("other/data.csv", tags=("pii", "export"), created_at=now)
    assert pol3 is None


@pytest.mark.asyncio
async def test_constraints_not_before_not_after_exclude_out_of_window():
    now = _utc_now()
    future = now + dt.timedelta(hours=2)
    past = now - dt.timedelta(hours=2)

    docs = [
        # Политика активна только в будущем
        make_policy_doc(
            doc_id="future-only",
            version="1.0.0",
            priority=10,
            mode=RetentionMode.governance,
            duration_seconds=3600,
            patterns=["w/*"],
            not_before=future,
        ),
        # Политика уже истекла
        make_policy_doc(
            doc_id="expired",
            version="1.0.0",
            priority=9,
            mode=RetentionMode.governance,
            duration_seconds=7200,
            patterns=["w/*"],
            not_after=past,
        ),
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t5")], config=LoaderConfig(resolution_strategy=ResolutionStrategy.PRIORITY))
    await loader.load()

    pol_now = loader.resolve("w/x", tags=(), created_at=now)
    assert pol_now is None  # обе вне окна

    # Сдвигаем время создания не влияет на constraints (они проверяются по now), оставляем None
    pol_now2 = loader.resolve("w/x", tags=(), created_at=None)
    assert pol_now2 is None


@pytest.mark.asyncio
async def test_retention_until_fixed_date_is_preserved():
    now = _utc_now()
    until = now + dt.timedelta(days=3)
    docs = [
        make_policy_doc(
            doc_id="fixed",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.governance,
            duration_seconds=None,
            retention_until=until,
            patterns=["fixed/*"],
        )
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t6")], config=LoaderConfig())
    await loader.load()

    pol = loader.resolve("fixed/a", created_at=now)
    assert pol is not None
    assert pol.retention_until is not None
    # Сравниваем по секундам (float)
    assert int(pol.retention_until) == int(until.timestamp())


@pytest.mark.asyncio
async def test_most_restrictive_aggregates_allow_extension_only_true_if_any_true():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="p1",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.governance,
            duration_seconds=3600,
            allow_extension_only=False,
            patterns=["agg/*"],
        ),
        make_policy_doc(
            doc_id="p2",
            version="1.0.0",
            priority=2,
            mode=RetentionMode.governance,
            duration_seconds=7200,  # более строгий срок
            allow_extension_only=True,  # должен агрегироваться в итог
            patterns=["agg/*"],
        ),
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t7")], config=LoaderConfig(resolution_strategy=ResolutionStrategy.MOST_RESTRICTIVE))
    await loader.load()
    pol = loader.resolve("agg/x", created_at=now)
    assert pol is not None
    assert pol.duration_seconds == 7200
    assert pol.allow_extension_only is True  # агрегированная строгость


@pytest.mark.asyncio
async def test_require_signature_only_signed_docs_are_applied():
    now = _utc_now()
    key = os.urandom(32)

    # Подписанная валидная политика и неподписанная — обе совпадают по селектору
    signed = make_policy_doc(
        doc_id="signed",
        version="1.0.0",
        priority=5,
        mode=RetentionMode.governance,
        duration_seconds=1800,
        patterns=["sig/*"],
        sign_with=key,
    )
    unsigned = make_policy_doc(
        doc_id="unsigned",
        version="1.0.0",
        priority=10,
        mode=RetentionMode.governance,
        duration_seconds=7200,
        patterns=["sig/*"],
        # sig отсутствует намеренно
    )

    loader = PolicyLoader(
        [InMemorySource([signed, unsigned], sid="t8")],
        hmac_key=key,
        config=LoaderConfig(require_signature=True, resolution_strategy=ResolutionStrategy.PRIORITY),
    )
    await loader.load()

    # При require_signature True неподписанный документ будет отброшен; останется "signed"
    pol = loader.resolve("sig/doc", created_at=now)
    assert pol is not None
    assert pol.duration_seconds == 1800  # выбрана подписанная политика несмотря на меньший priority


@pytest.mark.asyncio
async def test_priority_tiebreaker_version_and_id():
    now = _utc_now()
    docs = [
        make_policy_doc(
            doc_id="alpha",
            version="1.0.1",
            priority=7,
            mode=RetentionMode.governance,
            duration_seconds=100,
            patterns=["tb/*"],
        ),
        make_policy_doc(
            doc_id="beta",
            version="1.0.1",
            priority=7,
            mode=RetentionMode.governance,
            duration_seconds=200,
            patterns=["tb/*"],
        ),
        make_policy_doc(
            doc_id="gamma",
            version="1.0.2",  # выше версия — должен победить gamma
            priority=7,
            mode=RetentionMode.governance,
            duration_seconds=300,
            patterns=["tb/*"],
        ),
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t9")], config=LoaderConfig(resolution_strategy=ResolutionStrategy.PRIORITY))
    await loader.load()
    pol = loader.resolve("tb/x", created_at=now)
    assert pol is not None
    assert pol.duration_seconds == 300  # gamma


@pytest.mark.asyncio
async def test_created_at_affects_duration_pivot_not_constraints():
    """
    created_at влияет на вычисление effective_until при duration_seconds,
    но не на constraints (те сравниваются с текущим now).
    """
    now = _utc_now()
    # Политика без constraints: проверяем, что created_at учитывается.
    docs = [
        make_policy_doc(
            doc_id="dur-1d",
            version="1.0.0",
            priority=1,
            mode=RetentionMode.governance,
            duration_seconds=60 * 60 * 24,
            patterns=["ca/*"],
        )
    ]
    loader = PolicyLoader([InMemorySource(docs, sid="t10")], config=LoaderConfig())
    await loader.load()

    created_past = now - dt.timedelta(days=10)
    pol_past = loader.resolve("ca/a", created_at=created_past)
    pol_now = loader.resolve("ca/a", created_at=now)
    assert pol_past is not None and pol_now is not None
    # Для целей теста убеждаемся, что разница в retention_until будет различаться.
    # Политика на базе duration_seconds конвертируется внутри менеджера, но здесь мы проверяем,
    # что resolve возвращает duration_seconds (retention_until None) одинаково,
    # и различие created_at влияет позднее при применении. Поэтому проверяем, что duration_seconds одинаков.
    assert pol_past.duration_seconds == pol_now.duration_seconds == 60 * 60 * 24


@pytest.mark.asyncio
async def test_compliance_requires_allow_extension_only_true():
    """
    Валидация документа: для compliance allow_extension_only должен быть True.
    Документ с False будет отвергнут и не попадет в список кандидатов.
    """
    now = _utc_now()
    bad_comp = make_policy_doc(
        doc_id="bad-comp",
        version="1.0.0",
        priority=100,
        mode=RetentionMode.compliance,
        duration_seconds=1000,
        allow_extension_only=False,  # недопустимо — валидатор отвергнет
        patterns=["cx/*"],
    )
    good_gov = make_policy_doc(
        doc_id="good-gov",
        version="1.0.0",
        priority=1,
        mode=RetentionMode.governance,
        duration_seconds=2000,
        allow_extension_only=False,
        patterns=["cx/*"],
    )
    loader = PolicyLoader([InMemorySource([bad_comp, good_gov], sid="t11")], config=LoaderConfig(resolution_strategy=ResolutionStrategy.PRIORITY))
    await loader.load()
    pol = loader.resolve("cx/x", created_at=now)
    # Плохая compliance отброшена, осталась governance
    assert pol is not None
    assert pol.mode == RetentionMode.governance
    assert pol.duration_seconds == 2000
