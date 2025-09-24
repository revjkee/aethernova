# zero-trust-core/tests/e2e/test_zero_trust_end2end.py
# -*- coding: utf-8 -*-
"""
End-to-End tests for Zero-Trust risk scoring CLI and optional PEP cache integration.

Covers:
- CLI `self-test` health.
- `evaluate` JSON I/O, deterministic ALLOW case, and hard-rule DENY for geo-velocity using shared SQLite state.
- `gen-defaults` + override usage path.
- `batch` NDJSON processing with partial failure signaling (exit code 2).
- Correlation ID format (ULID 26 chars or UUID hex 32 chars).
- Optional integration with PEP cache (skipped if module not available).

Requirements:
- Python 3.10+
- pytest
- Project layout:
    zero-trust-core/
      ├── cli/tools/risk_score.py
      └── tests/e2e/test_zero_trust_end2end.py  (this file)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Tuple, Optional

import pytest


# ---------------------------
# Path discovery & helpers
# ---------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]  # .../zero-trust-core
RISK_SCORE = PROJECT_ROOT / "cli" / "tools" / "risk_score.py"

@pytest.mark.usefixtures()
def _assert_layout() -> None:
    assert RISK_SCORE.exists(), f"risk_score.py not found at {RISK_SCORE}"


def run_cli(args: list[str],
            stdin: Optional[str] = None,
            cwd: Optional[Path] = None,
            env: Optional[dict] = None,
            timeout: float = 10.0) -> Tuple[int, str, str]:
    """Run risk_score.py as a separate process and capture output."""
    cmd = [sys.executable, str(RISK_SCORE), *args]
    proc = subprocess.run(
        cmd,
        input=stdin.encode("utf-8") if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8")


def parse_json(s: str) -> dict:
    return json.loads(s.strip())


def is_ulid_or_uuid_hex(s: str) -> bool:
    # ULID Crockford Base32 is 26 chars; fallback is uuid4().hex length 32
    return (len(s) == 26 and s.isalnum()) or (len(s) == 32 and all(c in "0123456789abcdef" for c in s))


# ---------------------------
# Tests: CLI health
# ---------------------------

def test_cli_exists_and_self_test_ok():
    assert RISK_SCORE.exists(), f"risk_score.py missing at {RISK_SCORE}"
    rc, out, err = run_cli(["self-test"])
    assert rc == 0, f"self-test exit {rc}, stderr={err}"
    data = parse_json(out)
    assert data.get("ok") is True, f"self-test not ok: {out}"


# ---------------------------
# Tests: evaluate ALLOW decision (deterministic low risk)
# ---------------------------

def test_evaluate_allow_json_output(tmp_path: Path):
    event = {
        "actor_id": "u-allow",
        "device_id": "d-allow",
        "timestamp": "2025-08-21T12:00:00Z",
        "identity_risk": 0,
        "device_posture": 0,
        "network_risk": 0,
        "resource_sensitivity": 0,
        "behavior_risk": 0,
        "threat_intel": 0,
        "time_risk": 0
    }
    rc, out, err = run_cli(["evaluate", "--format", "json"], stdin=json.dumps(event))
    assert rc == 0, f"evaluate exit {rc}, stderr={err}"
    data = parse_json(out)
    assert data["decision"] == "ALLOW", f"expected ALLOW, got {data}"
    assert "score" in data and "score_raw" in data
    cid = data["correlation_id"]
    assert is_ulid_or_uuid_hex(cid), f"unexpected correlation_id format: {cid}"


# ---------------------------
# Tests: hard-rule DENY via impossible travel using shared SQLite state
# ---------------------------

def test_impossible_travel_hard_rule_deny(tmp_path: Path):
    state_file = tmp_path / "state.sqlite"

    event1 = {
        "actor_id": "traveler",
        "device_id": "dev1",
        "timestamp": "2025-08-21T12:00:00Z",
        "identity_risk": 10,
        "device_posture": 10,
        "network_risk": 10,
        "resource_sensitivity": 10,
        "behavior_risk": 10,
        "threat_intel": 0,
        "time_risk": 0,
        "geo": {"lat": 59.3293, "lon": 18.0686}  # Stockholm
    }
    rc1, out1, err1 = run_cli([
        "evaluate", "--format", "json", "--state", str(state_file)
    ], stdin=json.dumps(event1))
    assert rc1 == 0, f"evaluate #1 failed: {err1}"
    data1 = parse_json(out1)
    assert data1["decision"] in ("ALLOW", "MFA", "LIMITED", "DENY", "QUARANTINE")

    # 10 секунд спустя "перелёт" в NYC -> сверхвысокая скорость => сработает жесткое правило deny_if_geo_velocity_ge
    event2 = dict(event1)
    event2["timestamp"] = "2025-08-21T12:00:10Z"
    event2["geo"] = {"lat": 40.7128, "lon": -74.0060}  # New York

    rc2, out2, err2 = run_cli([
        "evaluate", "--format", "json", "--state", str(state_file)
    ], stdin=json.dumps(event2))
    assert rc2 == 0, f"evaluate #2 failed: {err2}"
    data2 = parse_json(out2)
    assert data2["hard_rule_triggered"] == "deny_if_geo_velocity_ge", f"expected geo hard-rule, got {data2}"
    assert data2["decision"] == "DENY", f"expected DENY by hard rule, got {data2}"


# ---------------------------
# Tests: gen-defaults + evaluate with device posture MFA hard-rule
# ---------------------------

def test_gen_defaults_and_mfa_hard_rule(tmp_path: Path):
    cfg_path = tmp_path / "weights.json"
    rc, out, err = run_cli(["gen-defaults", "--output", str(cfg_path)])
    assert rc == 0, f"gen-defaults failed: {err}"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    # Убедимся, что правило MFA срабатывает при высокой device_posture
    event = {
        "actor_id": "u-mfa",
        "device_id": "d-mfa",
        "timestamp": "2025-08-21T12:00:00Z",
        "identity_risk": 0,
        "device_posture": 90,  # >= 70 по умолчанию => MFA
        "network_risk": 0,
        "resource_sensitivity": 0,
        "behavior_risk": 0,
        "threat_intel": 0,
        "time_risk": 0
    }
    rc2, out2, err2 = run_cli(["evaluate", "--format", "json", "--weights", str(cfg_path)],
                              stdin=json.dumps(event))
    assert rc2 == 0, f"evaluate with weights failed: {err2}"
    data = parse_json(out2)
    assert data["hard_rule_triggered"] in (None, "mfa_if_device_posture_ge")
    # Даже при низком суммарном риске правило эскалирует до MFA
    assert data["decision"] in ("MFA", "DENY", "QUARANTINE")
    # Если решением стал DENY/QUARANTINE, это допустимо при крайне агрессивной калибровке; при дефолте — обычно MFA.
    # Фиксируем инвариант: не должно быть ALLOW/LIMITED.
    assert data["decision"] not in ("ALLOW", "LIMITED"), f"unexpected decision: {data}"


# ---------------------------
# Tests: batch NDJSON with partial failure -> exit code 2, valid lines parsed
# ---------------------------

def test_batch_ndjson_partial_failure(tmp_path: Path):
    ndjson_in = tmp_path / "in.ndjson"
    ndjson_out = tmp_path / "out.ndjson"

    lines = [
        json.dumps({
            "actor_id": "b1", "device_id": "d1",
            "timestamp": "2025-08-21T12:00:00Z",
            "identity_risk": 0, "device_posture": 0, "network_risk": 0,
            "resource_sensitivity": 0, "behavior_risk": 0, "threat_intel": 0, "time_risk": 0
        }, ensure_ascii=False),
        "this is not json",  # ошибка
        json.dumps({
            "actor_id": "b2", "device_id": "d2",
            "timestamp": "2025-08-21T12:01:00Z",
            "identity_risk": 50, "device_posture": 20, "network_risk": 10,
            "resource_sensitivity": 30, "behavior_risk": 10, "threat_intel": 0, "time_risk": 0
        }, ensure_ascii=False),
    ]
    ndjson_in.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc, out, err = run_cli(["batch", "--input", str(ndjson_in), "--output", str(ndjson_out)])
    # При некорректной строке batch должен вернуть 2
    assert rc == 2, f"batch should signal partial failure (2), got {rc}, stderr={err}"
    out_lines = [l for l in ndjson_out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(out_lines) == 2, f"expected 2 valid outputs, got {len(out_lines)}"
    # Проверим, что это корректные JSON и есть score/decision
    for l in out_lines:
        obj = json.loads(l)
        assert "decision" in obj and "score" in obj
        assert is_ulid_or_uuid_hex(obj.get("correlation_id", ""))


# ---------------------------
# Optional: PEP cache integration (skip if module not present)
# ---------------------------

def test_optional_integration_with_pep_cache_if_available(tmp_path: Path):
    try:
        from zero_trust.pep.cache import PepDecisionCache, Decision  # type: ignore
    except Exception:
        pytest.skip("PEP cache module not available; skipping integration test")

    # Рассчитываем решение через CLI, записываем в PEP-кэш, проверяем TTL/доступ
    event = {
        "actor_id": "pep-user",
        "device_id": "pep-dev",
        "timestamp": "2025-08-21T12:00:00Z",
        "identity_risk": 5,
        "device_posture": 5,
        "network_risk": 5,
        "resource_sensitivity": 5,
        "behavior_risk": 5,
        "threat_intel": 0,
        "time_risk": 0
    }
    rc, out, err = run_cli(["evaluate", "--format", "json"], stdin=json.dumps(event))
    assert rc == 0, f"evaluate failed: {err}"
    data = parse_json(out)
    decision = Decision(effect=data["decision"], policy_id="e2e-cli", reason="cli-evaluate")

    cache = PepDecisionCache(capacity=8, default_ttl=1.0, allow_negative=True)
    key = f"{event['actor_id']}|{event['device_id']}|resA"
    cache.put(key, decision, ttl=0.5, actor_id=event["actor_id"])
    got = cache.get(key)
    assert got is not None and got.effect == decision.effect

    # По истечении TTL запись должна протухнуть
    import time as _t
    _t.sleep(0.6)
    assert cache.get(key) is None
