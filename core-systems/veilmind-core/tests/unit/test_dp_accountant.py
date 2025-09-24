# SPDX-License-Identifier: MIT
# tests/test_dp_accountant.py
import json
import math
import sys
from pathlib import Path
from importlib import import_module

import pytest


def _import_dp():
    """
    Robust importer for cli.tools.dp_epsilon regardless of project layout.
    """
    candidates = [
        "cli.tools.dp_epsilon",
        "veilmind.cli.tools.dp_epsilon",
        "veilmind_core.cli.tools.dp_epsilon",
        "dp_epsilon",
    ]
    for name in candidates:
        try:
            return import_module(name)
        except Exception:
            continue
    # Fallback: add repository root (two levels up from tests/)
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return import_module("cli.tools.dp_epsilon")


dp = _import_dp()


# ----------------------------- Pure function tests -----------------------------

def test_laplace_roundtrip():
    eps = 1.7
    delta = 0.0  # not used for Laplace
    sens = 2.5
    b = dp.laplace_scale_from_epsilon(eps, sens)
    eps2 = dp.laplace_epsilon_from_scale(b, sens)
    assert math.isclose(eps, eps2, rel_tol=1e-12, abs_tol=0.0)
    assert b > 0
    assert delta == 0.0  # ensure unchanged in this context


@pytest.mark.parametrize("epsilon,delta,sens", [(2.0, 1e-6, 1.0), (0.9, 1e-8, 3.0), (0.2, 1e-5, 0.5)])
def test_gaussian_roundtrip_via_zcdp(epsilon, delta, sens):
    # Calibrate sigma from (epsilon, delta), then recover epsilon back for same delta.
    sigma = dp.gaussian_sigma_from_eps_delta(epsilon, delta, sens)
    assert sigma > 0
    eps_back = dp.gaussian_eps_from_sigma_delta(sigma, delta, sens)
    # zCDP inversion here is analytically consistent; allow tiny numeric error
    assert math.isclose(eps_back, epsilon, rel_tol=1e-10, abs_tol=1e-12)

    # Also check rho conversion symmetry
    rho = dp.gaussian_rho_from_sigma(sigma, sens)
    eps_from_rho = dp.eps_from_rho_delta(rho, delta)
    assert math.isclose(eps_from_rho, epsilon, rel_tol=1e-10, abs_tol=1e-12)

    # And inverse rho from (eps, delta)
    rho2 = dp.rho_from_eps_delta(epsilon, delta)
    assert rho2 >= 0
    # Converting that rho back to eps at same delta yields the target
    eps_from_rho2 = dp.eps_from_rho_delta(rho2, delta)
    assert math.isclose(eps_from_rho2, epsilon, rel_tol=1e-10, abs_tol=1e-12)


def test_basic_composition_sums():
    mechs = [dp.Mechanism(0.5, 1e-7), dp.Mechanism(1.2, 3e-7), dp.Mechanism(0.3, 0.0)]
    res = dp.compose_basic(mechs)
    assert math.isclose(res.epsilon, 0.5 + 1.2 + 0.3, rel_tol=0, abs_tol=0)
    assert math.isclose(res.delta, 1e-7 + 3e-7 + 0.0, rel_tol=0, abs_tol=0)
    assert res.kind == "composition_basic"


def test_advanced_composition_monotonicity_and_delta_agg():
    mechs = [dp.Mechanism(0.2, 1e-8), dp.Mechanism(0.4, 2e-8), dp.Mechanism(0.1, 0)]
    # epsilon should be >= sqrt-term; and depend on delta_prime monotonically
    delta_prime_small = 1e-12
    delta_prime_large = 1e-6
    res_small = dp.compose_advanced(mechs, delta_prime_small)
    res_large = dp.compose_advanced(mechs, delta_prime_large)
    # δ aggregates
    assert math.isclose(res_small.delta, 1e-8 + 2e-8 + 0 + delta_prime_small)
    assert math.isclose(res_large.delta, 1e-8 + 2e-8 + 0 + delta_prime_large)
    # ε must be larger for smaller δ' (stricter guarantee)
    assert res_small.epsilon > res_large.epsilon
    # Lower bound by the sqrt-term
    sum_sq = sum(m.epsilon ** 2 for m in mechs)
    sqrt_term = math.sqrt(2.0 * math.log(1.0 / delta_prime_large) * sum_sq)
    assert res_large.epsilon >= sqrt_term - 1e-12


def test_zcdp_compose_and_convert_to_eps():
    # Compose two Gaussian mechanisms via rho
    gs = [{"sigma": 1.1, "sensitivity": 1.0}, {"sigma": 0.7, "sensitivity": 2.0}]
    rhos = [dp.gaussian_rho_from_sigma(g["sigma"], g["sensitivity"]) for g in gs]
    R = dp.zcdp_compose(rhos)
    assert R > 0
    delta = 1e-6
    eps = dp.eps_from_rho_delta(R, delta)
    # For sanity, eps should be finite and positive
    assert eps > 0 and math.isfinite(eps)


# ----------------------------- CLI integration tests ---------------------------

def _run_cli(monkeypatch, capsys, argv):
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setattr(sys, "argv", ["dp_epsilon.py"] + argv, raising=True)
    code = dp._cli()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_laplace_calibrate_json(monkeypatch, capsys):
    code, out, err = _run_cli(monkeypatch, capsys, ["--json", "laplace", "calibrate", "--epsilon", "1.0", "--sensitivity", "2"])
    assert code == 0
    j = json.loads(out)
    assert j["mechanism"] == "laplace"
    assert math.isclose(j["scale"], 2.0, rel_tol=0, abs_tol=0)


def test_cli_gaussian_roundtrip_json(monkeypatch, capsys):
    args = ["--json", "gaussian", "calibrate", "--epsilon", "2.0", "--delta", "1e-6", "--sensitivity", "1.0"]
    code, out, err = _run_cli(monkeypatch, capsys, args)
    assert code == 0
    j = json.loads(out)
    sigma = float(j["sigma"])
    # Feed sigma back to epsilon
    args2 = ["--json", "gaussian", "epsilon", "--sigma", f"{sigma}", "--delta", "1e-6", "--sensitivity", "1.0"]
    code2, out2, err2 = _run_cli(monkeypatch, capsys, args2)
    assert code2 == 0
    j2 = json.loads(out2)
    assert math.isclose(j2["epsilon"], 2.0, rel_tol=1e-10, abs_tol=1e-12)


def test_cli_compose_basic_from_inline_json(monkeypatch, capsys):
    mechs = json.dumps([{"epsilon": 0.5, "delta": 1e-7}, {"epsilon": 1.0, "delta": 2e-7}])
    code, out, err = _run_cli(monkeypatch, capsys, ["--json", "compose", "basic", "--mech", mechs])
    assert code == 0
    j = json.loads(out)
    assert j["mode"] == "basic"
    assert math.isclose(j["epsilon"], 1.5, rel_tol=0, abs_tol=0)
    assert math.isclose(j["delta"], 3e-7, rel_tol=0, abs_tol=0)


def test_cli_compose_advanced_from_file_json(tmp_path, monkeypatch, capsys):
    policy = {
        "mechanisms": [
            {"kind": "laplace", "epsilon": 0.2, "delta": 0.0},
            {"kind": "gaussian", "epsilon": 0.4, "delta": 1e-8},
        ]
    }
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(policy), encoding="utf-8")
    code, out, err = _run_cli(monkeypatch, capsys, ["--json", "compose", "advanced", "--delta_prime", "1e-9", "--mech-file", str(f)])
    assert code == 0
    j = json.loads(out)
    assert j["mode"] == "advanced"
    assert "epsilon" in j and j["epsilon"] > 0
    assert math.isclose(j["delta"], 1e-8 + 1e-9, rel_tol=0, abs_tol=0)


@pytest.mark.skipif(pytest.importorskip("yaml") is None, reason="PyYAML not installed")
def test_cli_policy_yaml(tmp_path, monkeypatch, capsys):
    # Create YAML policy file
    yml = """
mechanisms:
  - kind: laplace
    epsilon: 0.3
    delta: 0.0
  - kind: gaussian
    epsilon: 0.2
    delta: 1e-7
"""
    p = tmp_path / "policy.yaml"
    p.write_text(yml, encoding="utf-8")
    code, out, err = _run_cli(monkeypatch, capsys, ["--json", "policy", "--file", str(p), "--mode", "advanced", "--delta_prime", "1e-9"])
    assert code == 0
    j = json.loads(out)
    assert j["mode"] == "advanced"
    assert j["epsilon"] > 0
    assert math.isclose(j["delta"], 1e-7 + 1e-9, rel_tol=0, abs_tol=0)


def test_cli_gaussian_rho_requires_one_of_sigma_or_rho(monkeypatch, capsys):
    # Providing both should trigger usage error (SystemExit with code 2)
    with pytest.raises(SystemExit) as ex:
        _run_cli(monkeypatch, capsys, ["gaussian", "rho", "--rho", "0.1", "--sigma", "1.0", "--delta", "1e-6"])
    assert ex.value.code == 2


def test_cli_zcdp_compose_with_gaussian_list(monkeypatch, capsys):
    gs = json.dumps([{"sigma": 1.2, "sensitivity": 1.0}, {"sigma": 0.8, "sensitivity": 2.0}])
    code, out, err = _run_cli(monkeypatch, capsys, ["--json", "zcdp", "compose", "--gaussian", gs, "--delta", "1e-6"])
    assert code == 0
    j = json.loads(out)
    assert j["rho_total"] > 0
    assert j["epsilon"] > 0


# ----------------------------- Edge/validation tests ---------------------------

def test_rho_from_eps_delta_behaves_reasonably():
    # As delta decreases (more strict), rho must increase for fixed epsilon
    eps = 0.9
    r1 = dp.rho_from_eps_delta(eps, 1e-3)
    r2 = dp.rho_from_eps_delta(eps, 1e-9)
    assert r2 > r1 > 0.0


def test_eps_from_rho_delta_monotonic_in_rho():
    delta = 1e-6
    e1 = dp.eps_from_rho_delta(0.01, delta)
    e2 = dp.eps_from_rho_delta(0.05, delta)
    assert e2 > e1 > 0.0
