# policy-core/tests/unit/test_rego_eval.py
# PyTest suite for industrial-grade Rego/OPA evaluation checks.
# Focus: correctness, robustness, and CI-friendliness.
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest


# -----------------------------
# Environment & availability
# -----------------------------

OPA_BIN = os.getenv("OPA_BIN", "opa")
OPA_PATH = shutil.which(OPA_BIN)

pytestmark = pytest.mark.skipif(
    OPA_PATH is None,
    reason="opa binary not found in PATH and OPA_BIN not provided"
)


# -----------------------------
# Helper runner/wrapper
# -----------------------------

@dataclass
class OpaResult:
    rc: int
    stdout: str
    stderr: str
    json: Optional[Dict[str, Any]]


class OpaRunner:
    """
    Minimal, robust wrapper around `opa eval` for tests.
    - Writes Rego modules and data files to tmp folder
    - Sends input via stdin when provided
    - Parses JSON output when -f json is used
    """
    def __init__(self, opa_bin: str) -> None:
        self.opa_bin = opa_bin

    def eval(
        self,
        *,
        query: str,
        tmpdir: Path,
        modules: Optional[List[Tuple[str, str]]] = None,  # (filename, content)
        data_files: Optional[List[Tuple[str, str]]] = None,  # (filename, JSON string)
        input_obj: Optional[Dict[str, Any]] = None,
        partial: bool = False,
        unknowns: Optional[List[str]] = None,
        metrics: bool = False,
        timeout_s: Optional[float] = None,
        format_json: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> OpaResult:
        args: List[str] = [self.opa_bin, "eval"]
        if format_json:
            args += ["-f", "json"]
        else:
            args += ["-f", "pretty"]

        if metrics:
            args.append("--metrics")

        if partial:
            args.append("--partial")

        if unknowns:
            for u in unknowns:
                args += ["--unknowns", u]

        if timeout_s is not None:
            # OPA expects duration with unit, e.g., "0.05s"
            # Keep at least milliseconds resolution.
            args += ["--timeout", f"{timeout_s:.3f}s"]

        # Write modules & data
        if modules:
            for name, content in modules:
                p = tmpdir / name
                p.write_text(content, encoding="utf-8")
                args += ["-d", str(p)]

        if data_files:
            for name, content in data_files:
                p = tmpdir / name
                p.write_text(content, encoding="utf-8")
                args += ["-d", str(p)]

        # Use stdin for input if provided
        stdin_bytes = None
        if input_obj is not None:
            stdin_bytes = json.dumps(input_obj, ensure_ascii=False).encode("utf-8")
            args.append("--stdin-input")

        # Query
        args.append(query)

        if extra_args:
            args += list(extra_args)

        proc = subprocess.run(
            args,
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )

        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        parsed: Optional[Dict[str, Any]] = None
        if format_json:
            try:
                parsed = json.loads(stdout) if stdout.strip() else None
            except json.JSONDecodeError:
                parsed = None

        return OpaResult(proc.returncode, stdout, stderr, parsed)


@pytest.fixture(scope="module")
def opa() -> OpaRunner:
    assert OPA_PATH, "OPA must be available for this test module"
    return OpaRunner(OPA_PATH)


# -----------------------------
# Utilities for assertions
# -----------------------------

def _first_value(parsed: Dict[str, Any]) -> Any:
    """
    Extract first expression value from OPA JSON output:
    {
      "result": [
        { "expressions": [ { "value": <here>, "text": "..." } ] }
      ],
      "metrics": { ... }?
    }
    """
    assert parsed is not None, "Expected JSON output"
    res = parsed.get("result", [])
    assert isinstance(res, list), f"Unexpected 'result' type: {type(res)}"
    assert len(res) >= 1, "No evaluation results"
    exprs = res[0].get("expressions", [])
    assert isinstance(exprs, list) and len(exprs) >= 1, "No expressions in result"
    return exprs[0].get("value")


def _has_metrics(parsed: Dict[str, Any]) -> bool:
    m = parsed.get("metrics")
    return isinstance(m, dict) and len(m) >= 1


# -----------------------------
# Tests
# -----------------------------

def test_eval_basic_allow(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.auth

        default allow := false

        allow {
          input.user == "admin"
          input.method == "GET"
        }
        """
    )
    input_obj = {"user": "admin", "method": "GET"}
    r = opa.eval(
        query="data.app.auth.allow",
        tmpdir=tmp_path,
        modules=[("auth.rego", rego)],
        input_obj=input_obj,
        metrics=True,
    )
    assert r.rc == 0, f"OPA failed: {r.stderr}"
    val = _first_value(r.json)
    assert val is True
    assert _has_metrics(r.json)


def test_eval_default_false_on_non_admin(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.auth

        default allow := false

        allow {
          input.user == "admin"
        }
        """
    )
    input_obj = {"user": "alice"}
    r = opa.eval(
        query="data.app.auth.allow",
        tmpdir=tmp_path,
        modules=[("auth.rego", rego)],
        input_obj=input_obj,
    )
    assert r.rc == 0, f"OPA failed: {r.stderr}"
    val = _first_value(r.json)
    assert val is False


def test_eval_with_data_json_merge(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.auth

        default allow := false

        allow {
          some u
          u := input.user
          u == data.roles.admin
        }
        """
    )
    data_json = json.dumps({"roles": {"admin": "root"}}, ensure_ascii=False)
    r = opa.eval(
        query="data.app.auth.allow",
        tmpdir=tmp_path,
        modules=[("auth.rego", rego)],
        data_files=[("roles.json", data_json)],
        input_obj={"user": "root"},
    )
    assert r.rc == 0
    assert _first_value(r.json) is True


def test_partial_eval_produces_queries(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.auth

        default allow := false

        allow {
          input.method == "GET"
          input.user == data.roles.admin
        }
        """
    )
    data_json = json.dumps({"roles": {"admin": "root"}}, ensure_ascii=False)
    r = opa.eval(
        query="data.app.auth.allow",
        tmpdir=tmp_path,
        modules=[("auth.rego", rego)],
        data_files=[("roles.json", data_json)],
        partial=True,
        unknowns=["input"],
        metrics=True,
    )
    assert r.rc == 0, f"OPA failed: {r.stderr}"
    # For partial eval, the JSON shape differs: result[0].expressions[0].value.queries is present
    val = _first_value(r.json)
    assert isinstance(val, dict), "Partial eval should return a dict with 'queries' and 'support'"
    assert "queries" in val, "Partial eval must include residual queries"
    assert isinstance(val["queries"], list) and len(val["queries"]) >= 1
    assert _has_metrics(r.json)


def test_invalid_rego_syntax_reports_error(tmp_path: Path, opa: OpaRunner):
    bad_rego = "package app\n allow { input.user = }"  # syntax error
    r = opa.eval(
        query="data.app.allow",
        tmpdir=tmp_path,
        modules=[("bad.rego", bad_rego)],
    )
    # OPA exits with non-zero on compile errors
    assert r.rc != 0
    # stderr should carry compiler diagnostics
    assert "error" in r.stderr.lower() or "compile" in r.stderr.lower()


def test_json_format_parsing_and_boolean_result(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.x

        default ok := false
        ok { input.flag == true }
        """
    )
    r = opa.eval(
        query="data.app.x.ok",
        tmpdir=tmp_path,
        modules=[("x.rego", rego)],
        input_obj={"flag": True},
        metrics=False,
    )
    assert r.rc == 0
    parsed = r.json
    assert isinstance(parsed, dict)
    assert _first_value(parsed) is True


@pytest.mark.parametrize(
    "method,expected",
    [
        ("GET", True),
        ("POST", False),
    ],
)
def test_parametrized_allow_matrix(tmp_path: Path, opa: OpaRunner, method: str, expected: bool):
    rego = textwrap.dedent(
        """
        package app.m

        default allow := false
        allow { input.method == "GET" }
        """
    )
    r = opa.eval(
        query="data.app.m.allow",
        tmpdir=tmp_path,
        modules=[("m.rego", rego)],
        input_obj={"method": method},
    )
    assert r.rc == 0
    assert _first_value(r.json) is expected


def test_metrics_presence_when_requested(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.metrics

        p := input.n + 1
        """
    )
    r = opa.eval(
        query="data.app.metrics.p",
        tmpdir=tmp_path,
        modules=[("m.rego", rego)],
        input_obj={"n": 41},
        metrics=True,
    )
    assert r.rc == 0
    assert _has_metrics(r.json)
    # value should be arithmetic result
    assert _first_value(r.json) == 42


@pytest.mark.skipif(
    not bool(int(os.getenv("OPA_ENABLE_SLOW_TESTS", "0"))),
    reason="Enable with OPA_ENABLE_SLOW_TESTS=1 to run timeout stress test"
)
def test_timeout_on_expensive_recursion(tmp_path: Path, opa: OpaRunner):
    # Recursive Fibonacci to induce CPU work
    # Note: This is intentionally expensive for moderate n
    rego = textwrap.dedent(
        """
        package app.slow

        fib(n) := n { n <= 1 }
        fib(n) := x {
          n > 1
          x := fib(n-1) + fib(n-2)
        }
        """
    )
    # Query fib(38) is usually heavy enough to hit a tiny timeout
    r = opa.eval(
        query="data.app.slow.fib(38)",
        tmpdir=tmp_path,
        modules=[("slow.rego", rego)],
        timeout_s=0.01,  # 10ms
        format_json=False,  # simpler to check stderr
    )
    # Either non-zero RC with a timeout message, or extremely fast machine might still finish.
    # In the latter case, we accept RC==0 but assert there is some output.
    if r.rc != 0:
        assert "time" in r.stderr.lower() or "timeout" in r.stderr.lower()
    else:
        assert r.stdout.strip() != ""


def test_input_via_stdin_and_large_payload(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.large

        default ok := false

        ok {
          count(input.items) >= 1000
          input.items[10] == 10
        }
        """
    )
    input_obj = {"items": list(range(2000))}
    r = opa.eval(
        query="data.app.large.ok",
        tmpdir=tmp_path,
        modules=[("large.rego", rego)],
        input_obj=input_obj,
        metrics=False,
    )
    assert r.rc == 0
    assert _first_value(r.json) is True


def test_multiple_modules_and_packages(tmp_path: Path, opa: OpaRunner):
    rego_a = textwrap.dedent(
        """
        package a

        val := 10
        """
    )
    rego_b = textwrap.dedent(
        """
        package b

        inc(x) := x + data.a.val
        """
    )
    r = opa.eval(
        query="data.b.inc(5)",
        tmpdir=tmp_path,
        modules=[("a.rego", rego_a), ("b.rego", rego_b)],
        metrics=True,
    )
    assert r.rc == 0
    assert _first_value(r.json) == 15
    assert _has_metrics(r.json)


def test_undefined_without_default_yields_empty_result(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.undefined

        # No default 'allow', rule holds only when condition true
        allow { input.x == 1 }
        """
    )
    r = opa.eval(
        query="data.app.undefined.allow",
        tmpdir=tmp_path,
        modules=[("u.rego", rego)],
        input_obj={"x": 2},
    )
    assert r.rc == 0
    parsed = r.json
    assert isinstance(parsed, dict)
    # For undefined, OPA returns result with expressions value 'undefined' in pretty mode,
    # but for JSON it returns result with boolean? Actually, with no default, query value is undefined
    # and OPA represents it by empty 'result' array.
    # See: https://www.openpolicyagent.org/docs/latest/#evaluation
    assert parsed.get("result", []) == [], "Expected empty result for undefined rule"


def test_compile_error_clear_diagnostics_location(tmp_path: Path, opa: OpaRunner):
    bad_rego = textwrap.dedent(
        """
        package bad

        # Missing closing brace
        p {
          input.a == 1
        """
    )
    r = opa.eval(
        query="data.bad.p",
        tmpdir=tmp_path,
        modules=[("bad.rego", bad_rego)],
        format_json=False,
    )
    assert r.rc != 0
    # OPA typically reports file name and line/col in diagnostics
    assert "bad.rego" in r.stderr
    assert "line" in r.stderr.lower() or ":" in r.stderr


def test_partial_eval_unknowns_list_shape(tmp_path: Path, opa: OpaRunner):
    rego = textwrap.dedent(
        """
        package app.p

        allow {
          input.a == 1
          input.b == 2
        }
        """
    )
    r = opa.eval(
        query="data.app.p.allow",
        tmpdir=tmp_path,
        modules=[("p.rego", rego)],
        partial=True,
        unknowns=["input.a", "input.b"],
    )
    assert r.rc == 0
    val = _first_value(r.json)
    assert isinstance(val, dict)
    qs = val.get("queries")
    assert isinstance(qs, list) and len(qs) >= 1


def test_metrics_flag_not_present_when_not_requested(tmp_path: Path, opa: OpaRunner):
    rego = "package app.q\n ok := true"
    r = opa.eval(
        query="data.app.q.ok",
        tmpdir=tmp_path,
        modules=[("q.rego", rego)],
        metrics=False,
    )
    assert r.rc == 0
    assert "metrics" not in (r.json or {})


def test_pretty_format_human_friendly_output(tmp_path: Path, opa: OpaRunner):
    rego = "package app.pretty\n p := 2 + 2"
    r = opa.eval(
        query="data.app.pretty.p",
        tmpdir=tmp_path,
        modules=[("pretty.rego", rego)],
        format_json=False,
    )
    assert r.rc == 0
    # Pretty format is textual; ensure number present
    assert "4" in r.stdout.strip()
