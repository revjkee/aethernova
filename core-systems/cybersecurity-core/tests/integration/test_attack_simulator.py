# -*- coding: utf-8 -*-
"""
Integration tests for adversary emulation profiles and optional GCP integration.

Facts and rationale (verified sources):
- pytest fixtures & usage: https://docs.pytest.org/en/stable/how-to/fixtures.html
- pytest skip/xfail guidance: https://docs.pytest.org/en/stable/how-to/skipping.html
- pytest assertion introspection: https://docs.pytest.org/en/stable/how-to/assert.html
- PyYAML safe_load (and deprecation of unsafe load): https://pyyaml.org/wiki/PyYAMLDocumentation
  and advisory on avoiding yaml.load for untrusted input: https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load%28input%29-Deprecation
- MITRE ATT&CK knowledge base reference: https://attack.mitre.org/
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Tuple

import pytest

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    pytest.skip(f"PyYAML is required for these tests: {e}", allow_module_level=True)

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
# project root assumed as .../cybersecurity-core/
PROJECT_ROOT = THIS_FILE.parents[2]
PROFILES_DIR = PROJECT_ROOT / "cybersecurity" / "adversary_emulation" / "attack_simulator" / "profiles"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Commonly dangerous patterns that should never appear in simulate.run content
DESTRUCTIVE_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"rm\s+-rf\s+/",
        r"\bmkfs(\.| |\Z)",
        r"\bdd\s+if=/dev/zero\s+of=/dev/sd",
        r"\bshutdown\b",
        r"systemctl\s+stop\s+.*audit.*",
        r":\(\)\s*{\s*:\s*\|\s*:\s*;\s*}\s*;\s*:"  # fork bomb
    )
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def profile_paths() -> List[Path]:
    """Collect all YAML profiles in the profiles directory."""
    if not PROFILES_DIR.exists():
        pytest.skip(f"Profiles directory not found: {PROFILES_DIR}")
    files = sorted(p for p in PROFILES_DIR.rglob("*.yaml") if p.is_file())
    if not files:
        pytest.skip(f"No YAML profiles found under: {PROFILES_DIR}")
    return files


@pytest.fixture(scope="session")
def loaded_profiles(profile_paths: List[Path]) -> List[Tuple[Path, Dict[str, Any]]]:
    """
    Safely load all profiles using PyYAML safe_load.
    Using safe_load is required for untrusted YAML (see PyYAML docs).
    """
    loaded: List[Tuple[Path, Dict[str, Any]]] = []
    for path in profile_paths:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)  # safe_load is the secure choice for untrusted YAML
            assert isinstance(data, dict), f"YAML root must be a mapping: {path}"
            loaded.append((path, data))
    return loaded


# ---------------------------------------------------------------------------
# Tests: structure & schema-ish checks (lightweight, non-breaking)
# ---------------------------------------------------------------------------

def test_profiles_exist_nonempty(profile_paths: List[Path]) -> None:
    assert profile_paths, "Expected at least one profile file"
    for p in profile_paths:
        assert p.stat().st_size > 0, f"Empty profile file: {p}"


@pytest.mark.parametrize(
    "required_top_level",
    [
        "schema_version",
        "profile",
        "target",
        "safety",
        "telemetry",
        "lifecycle",
        "phases",
    ],
)
def test_profile_top_level_keys(loaded_profiles: List[Tuple[Path, Dict[str, Any]]], required_top_level: str) -> None:
    for path, data in loaded_profiles:
        assert required_top_level in data, f"Missing top-level key '{required_top_level}' in {path}"


def test_profile_core_metadata(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        prof = data.get("profile", {})
        assert isinstance(prof, dict), f"profile must be map in {path}"
        for k in ("id", "name", "version", "description"):
            assert k in prof and prof[k], f"Missing profile.{k} in {path}"


def test_safety_defaults_and_policies(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        safety = data.get("safety", {})
        assert isinstance(safety, dict), f"safety must be map in {path}"
        assert safety.get("simulation_mode") is True, f"safety.simulation_mode must default to true in {path}"

        # env gate must require explicit opt-in to run anything beyond simulation
        envreq = safety.get("env_requirements", {}).get("must_set", [])
        assert isinstance(envreq, list), f"safety.env_requirements.must_set must be a list in {path}"
        assert any("ATTACK_SIM_OK=true" in str(x) for x in envreq), f"Expected 'ATTACK_SIM_OK=true' requirement in {path}"

        # destructive patterns blocklist exists
        bl = safety.get("blocklist_command_patterns", [])
        assert isinstance(bl, list) and bl, f"safety.blocklist_command_patterns must be non-empty in {path}"


def _iter_steps(data: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Yield (phase_name, step_dict)."""
    for phase in data.get("phases", []) or []:
        phase_name = phase.get("name") or phase.get("tactic") or "unknown"
        for step in phase.get("steps", []) or []:
            yield phase_name, step


def test_steps_structure_and_fields(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        found_any = False
        for phase_name, step in _iter_steps(data):
            found_any = True
            assert "id" in step and step["id"], f"Each step needs an id ({path} / {phase_name})"
            # technique may be missing for pure placeholders; when present must match MITRE format
            tech = step.get("technique")
            if tech:
                assert isinstance(tech, str) and MITRE_TECHNIQUE_PATTERN.match(tech), \
                    f"Invalid MITRE technique ID '{tech}' in {path} / {phase_name}"

            # simulate.run must be present and be a string (benign operations/logging)
            sim = step.get("simulate", {})
            assert isinstance(sim, dict) and isinstance(sim.get("run", ""), str) and sim.get("run"), \
                f"simulate.run must be non-empty string in {path} / {phase_name}"

            # execute must be gated and present
            exe = step.get("execute", {})
            assert isinstance(exe, dict), f"execute must be map in {path} / {phase_name}"
            assert exe.get("gated") in (True, False), f"execute.gated must be boolean in {path} / {phase_name}"
        assert found_any, f"No steps found in any phase for {path}"


def test_simulate_runs_do_not_contain_destructive_commands(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        for phase_name, step in _iter_steps(data):
            sim = step.get("simulate", {})
            run = sim.get("run", "") if isinstance(sim, dict) else ""
            for patt in DESTRUCTIVE_PATTERNS:
                assert not patt.search(run), f"Destructive pattern '{patt.pattern}' in simulate.run at {path} / {phase_name}"


def test_variables_and_workdir_present(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        vars_ = data.get("variables", {})
        assert isinstance(vars_, dict) and vars_, f"variables section must exist in {path}"
        for k in ("WORKDIR", "TAG", "MARKER"):
            assert k in vars_ and vars_[k], f"variables.{k} missing or empty in {path}"


def test_lifecycle_has_setup_and_teardown(loaded_profiles: List[Tuple[Path, Dict[str, Any]]]) -> None:
    for path, data in loaded_profiles:
        lifecycle = data.get("lifecycle", {})
        assert isinstance(lifecycle, dict), f"lifecycle must be map in {path}"
        assert lifecycle.get("setup") and lifecycle.get("teardown"), f"Both setup and teardown must be present in {path}"


# ---------------------------------------------------------------------------
# Optional smoke test for GCP integration (safe simulation only)
# Skips gracefully when environment or dependencies are not available.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    "GOOGLE_CLOUD_PROJECT" not in os.environ,
    reason="GOOGLE_CLOUD_PROJECT not set; skipping GCP smoke test (pytest skip guidance).",
)
def test_gcp_integration_smoke_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Smoke test for cloud integration in simulate mode only.
    - Imports GCP integration if present.
    - Validates connectivity (read-only IAM + benign log) and emits a few safe simulations.

    This follows pytest's recommended skip pattern for unavailable external resources.
    See: https://docs.pytest.org/en/stable/how-to/skipping.html
    """
    try:
        gcp_mod = importlib.import_module(
            "cybersecurity.adversary_emulation.integrations.cloud.gcp"
        )
    except Exception as e:
        pytest.skip(f"GCP module not present/ import failed: {e}")

    # Build config in simulate_mode (true by default). This must not mutate cloud state.
    GCPConfig = getattr(gcp_mod, "GCPConfig")
    GCPIntegration = getattr(gcp_mod, "GCPIntegration")

    cfg = GCPConfig(project_id=os.environ["GOOGLE_CLOUD_PROJECT"], simulate_mode=True)
    integ = GCPIntegration(config=cfg)

    # Validate connectivity (read-only IAM + structured log)
    out = integ.validate_connectivity()
    assert isinstance(out, dict)
    assert "iam_bindings" in out and isinstance(out["iam_bindings"], int)

    # Emit benign ATT&CK-tagged simulation events
    integ.simulate_valid_accounts_cloud(principal="tester@example.com", context={"source": "integration-test"})
    integ.simulate_account_manipulation(principal="tester@example.com", target_member="user:auditor@example.com")
    integ.simulate_data_from_cloud_storage(bucket_hint="gs://nonexistent-bucket-sim", object_hint="path/to/object")


# ---------------------------------------------------------------------------
# End
# ---------------------------------------------------------------------------
