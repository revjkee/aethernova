# tests/fuzz/test_ingest_fuzz.py
# -*- coding: utf-8 -*-
"""
Fuzz / property-based tests for DataFabric ingestion surfaces:
- NDJSON → cli.tools.emit_lineage (backend=stdout, dry-run)
- PII redaction idempotence and stream==batch equivalence

Инварианты:
  1) CLI ndjson: не падает на произвольном валидном JSON (и корректно переживает мусорные строки).
  2) PII redact: повторное редактирование даёт тот же результат (идемпотентность).
  3) PII redact_stream эквивалентен redact для любых границ чанков.
"""

import io
import json
import os
import sys
import types
import pytest
from typing import Any, Dict, List, Optional

from hypothesis import given, strategies as st, settings, HealthCheck

# ---------------------------
# Helpers: flexible imports
# ---------------------------

# emit_lineage CLI (optional path aliasing)
try:
    import cli.tools.emit_lineage as emit_mod  # project layout
except Exception:
    emit_mod = None
    try:
        import datafabric.cli.tools.emit_lineage as emit_mod  # package layout
    except Exception:
        emit_mod = None

# PII detector (optional)
try:
    from datafabric.governance.pii_detection import (
        build_default_detector,
        redact_pii,
        PIIDetector,
        Config as PiiConfig,
        Policy as PiiPolicy,  # type: ignore
        Rule as PiiRule,      # type: ignore
    )
except Exception:
    build_default_detector = None
    redact_pii = None
    PIIDetector = None
    PiiConfig = None

# ---------------------------
# Strategies
# ---------------------------

def _s_str(label="s"):
    # printable, including wide/unicode, but limit length for CI
    return st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=64)

def _s_small_dict():
    key = st.text(min_size=1, max_size=16, alphabet=st.characters(whitelist_categories=("Ll","Lu","Nd")))
    val = st.one_of(
        st.integers(min_value=-(10**6), max_value=10**6),
        st.floats(allow_nan=False, allow_infinity=False, width=32),
        st.booleans(),
        _s_str(),
    )
    return st.dictionaries(keys=key, values=val, max_size=5)

def ds_strategy():
    # DatasetRef as dict compatible with emit_lineage NDJSON
    system = _s_str().filter(lambda s: len(s) > 0)
    name = _s_str().filter(lambda s: len(s) > 0)
    namespace = st.one_of(st.none(), _s_str().filter(lambda s: len(s) > 0))
    schema = st.one_of(st.none(), _s_small_dict())
    facets = st.one_of(st.none(), _s_small_dict())
    return st.builds(
        lambda sys, nm, ns, sch, fac: {
            "system": sys,
            "name": nm,
            **({"namespace": ns} if ns else {}),
            **({"schema": sch} if sch else {}),
            **({"facets": fac} if fac else {}),
        },
        system, name, namespace, schema, facets
    )

def graph_payload_strategy():
    ds = ds_strategy()
    edge = st.builds(
        lambda s, t, tr, rid, ts, props, idem: {
            "source": s, "target": t,
            **({"transformation": tr} if tr else {}),
            **({"run_id": rid} if rid else {}),
            **({"ts_ms": ts} if ts else {}),
            **({"props": props} if props else {}),
            **({"idempotency_key": idem} if idem else {}),
        },
        ds, ds, st.one_of(st.none(), _s_str()), st.one_of(st.none(), _s_str()),
        st.one_of(st.none(), st.integers(min_value=0, max_value=2**31)),
        st.one_of(st.none(), _s_small_dict()),
        st.one_of(st.none(), _s_str()),
    )
    arr_edges = st.lists(edge, min_size=0, max_size=3)
    return st.builds(
        lambda pipe, run, inputs, outputs, edges, attrs, s_ms, e_ms, parent: {
            "pipeline": pipe, "run_id": run,
            "inputs": inputs, "outputs": outputs, "edges": edges,
            **({"attrs": attrs} if attrs else {}),
            **({"start_ms": s_ms} if s_ms else {}),
            **({"end_ms": e_ms} if e_ms else {}),
            **({"parent_context": parent} if parent else {}),
        },
        _s_str().filter(lambda s: len(s) > 0),
        _s_str().filter(lambda s: len(s) > 0),
        st.lists(ds, min_size=0, max_size=3),
        st.lists(ds, min_size=0, max_size=3),
        arr_edges,
        st.one_of(st.none(), _s_small_dict()),
        st.one_of(st.none(), st.integers(min_value=0, max_value=2**31)),
        st.one_of(st.none(), st.integers(min_value=0, max_value=2**31)),
        st.one_of(st.none(), _s_str()),
    )

def edge_payload_strategy():
    ds = ds_strategy()
    return st.builds(
        lambda pipe, run, s, t, tr, ts, props, idem, parent: {
            "pipeline": pipe, "run_id": run,
            "source": s, "target": t,
            **({"transformation": tr} if tr else {}),
            **({"ts_ms": ts} if ts else {}),
            **({"props": props} if props else {}),
            **({"idempotency_key": idem} if idem else {}),
            **({"parent_trace": parent} if parent else {}),
        },
        _s_str().filter(lambda s: len(s) > 0),
        _s_str().filter(lambda s: len(s) > 0),
        ds, ds, st.one_of(st.none(), _s_str()),
        st.one_of(st.none(), st.integers(min_value=0, max_value=2**31)),
        st.one_of(st.none(), _s_small_dict()),
        st.one_of(st.none(), _s_str()),
        st.one_of(st.none(), _s_str()),
    )

# ---------------------------
# NDJSON CLI fuzz tests
# ---------------------------

@pytest.mark.skipif(emit_mod is None, reason="emit_lineage module not available")
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=60)
@given(st.lists(graph_payload_strategy().map(lambda d: {"type":"graph","data":d}), min_size=1, max_size=10))
def test_ndjson_cli_accepts_random_graphs(monkeypatch, capsys, payloads):
    """
    Генерируем корректные объекты graph и подаём их построчно в ndjson режим.
    Ожидаем код возврата 0 и отсутствие исключений.
    """
    buf = io.StringIO("\n".join(json.dumps(x, ensure_ascii=False) for x in payloads) + "\n")
    monkeypatch.setenv("DF_LINEAGE_BACKEND", "stdout")
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")
    monkeypatch.setattr(emit_mod.sys, "stdin", buf, raising=True)
    rc = emit_mod.main(["ndjson", "--backend", "stdout", "--dry-run"])
    assert rc == 0

@pytest.mark.skipif(emit_mod is None, reason="emit_lineage module not available")
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=60)
@given(
    st.lists(
        st.one_of(
            graph_payload_strategy().map(lambda d: {"type":"graph","data":d}),
            edge_payload_strategy().map(lambda d: {"type":"edge","data":d}),
            _s_str().map(lambda s: s),  # мусорная строка (не JSON)
            _s_small_dict().map(lambda d: {"nonsense": d}),  # не тот формат
        ),
        min_size=3, max_size=20
    )
)
def test_ndjson_cli_survives_mixed_junk(monkeypatch, payloads):
    """
    Перемешиваем валидные и мусорные строки: утилита не должна падать.
    Ожидаемый код: 0 (если все валидны) или 3 (частичные ошибки).
    """
    lines: List[str] = []
    for item in payloads:
        if isinstance(item, str):
            lines.append(item)  # мусор
        else:
            lines.append(json.dumps(item, ensure_ascii=False))
    buf = io.StringIO("\n".join(lines) + "\n")
    monkeypatch.setenv("DF_LINEAGE_BACKEND", "stdout")
    monkeypatch.setattr(emit_mod.sys, "stdin", buf, raising=True)
    rc = emit_mod.main(["ndjson", "--backend", "stdout", "--dry-run"])
    assert rc in (0, 3)

# ---------------------------
# PII redaction fuzz tests
# ---------------------------

need_pii = pytest.mark.skipif(build_default_detector is None or redact_pii is None, reason="PII detector not available")

# простые стратегии для типичных PII
email_local = st.text(min_size=1, max_size=16, alphabet=st.characters(whitelist_categories=("Ll","Lu","Nd")))
email_domain = st.text(min_size=1, max_size=16, alphabet=st.characters(whitelist_categories=("Ll","Lu","Nd")))\
                 .filter(lambda s: not s.startswith("-")).map(lambda s: s.lower())
email_strategy = st.builds(lambda a,b: f"{a}@{b}.com", email_local, email_domain)
digits = st.text(min_size=6, max_size=15, alphabet=st.characters(whitelist_categories=("Nd",)))
phone_strategy = st.builds(lambda d: "+%s" % d, digits)
ipv4_octet = st.integers(min_value=0, max_value=255).map(str)
ipv4_strategy = st.builds(lambda a,b,c,d: ".".join([a,b,c,d]), ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet)

composite_text = st.builds(
    lambda prefix, pii, suffix: f"{prefix} {pii} {suffix}",
    _s_str(), st.one_of(email_strategy, phone_strategy, ipv4_strategy), _s_str()
)

@need_pii
@settings(deadline=None, max_examples=100)
@given(composite_text)
def test_pii_redaction_idempotent(sample):
    """
    Повторное редактирование текста с PII не меняет результат второго раза.
    """
    det = build_default_detector()
    red1, dets = redact_pii(sample, detector=det)
    red2, _ = redact_pii(red1, detector=det)
    assert red1 == red2
    # Ни одно исходное значение не должно встретиться в редактированном тексте
    for d in dets:
        assert d.value not in red1

@need_pii
@pytest.mark.parametrize("chunk_size,overlap", [(8,4),(16,8),(32,8),(64,16)])
def test_pii_stream_equals_batch_on_boundaries(chunk_size, overlap):
    """
    Потоковая обработка с малыми чанками эквивалентна пакетной, включая совпадения на границах.
    """
    # Сконструируем строку с PII на стыке чанков
    text = "A"* (chunk_size - 3) + " user@example.com " + "B"*(chunk_size - 5) + " +1234567890 " + "C"*10
    # Собственный конфиг с малым чанкованием
    policy = PiiPolicy(actions={"email": "hash", "phone":"mask", "ip":"tokenize"}, default_threshold=0)  # type: ignore
    cfg = PiiConfig(rules=build_default_detector().cfg.rules, policy=policy, chunk_size=chunk_size, chunk_overlap=overlap)  # type: ignore
    det = PIIDetector(cfg)
    red_batch, _ = det.redact(text)
    out_stream = "".join(det.redact_stream(io=io.StringIO(text)) if False else [  # guard for mypy
        # note: redact_stream expects TextIOBase; io.StringIO подходит
    ])
    # Правильный вызов redact_stream — генератор
    out_stream = "".join(det.redact_stream(io.StringIO(text)))  # type: ignore
    assert red_batch == out_stream

# ---------------------------
# Smoke: empty / pathological inputs
# ---------------------------

@pytest.mark.skipif(emit_mod is None, reason="emit_lineage module not available")
def test_cli_ndjson_handles_empty_input(monkeypatch):
    monkeypatch.setenv("DF_LINEAGE_BACKEND", "stdout")
    monkeypatch.setattr(emit_mod.sys, "stdin", io.StringIO(""), raising=True)
    rc = emit_mod.main(["ndjson", "--backend", "stdout", "--dry-run"])
    assert rc == 0

@need_pii
def test_pii_handles_pathological_unicode():
    s = "𝔘𝔫𝔦𝔠𝔬𝔡𝔢 ✉ test@example.com ☎ +380501112233 🧪"
    det = build_default_detector()
    red, dets = redact_pii(s, detector=det)
    assert isinstance(red, str)
    assert len(dets) >= 1
