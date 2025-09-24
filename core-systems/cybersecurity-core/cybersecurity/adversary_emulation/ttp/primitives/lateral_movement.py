# file: cybersecurity-core/cybersecurity/adversary_emulation/ttp/primitives/lateral_movement.py
"""
Safe Lateral Movement Primitives (Simulation-Only)

Purpose
-------
This module provides INDUSTRIAL, simulation-only primitives to emulate
Lateral Movement (MITRE ATT&CK tactic TA0008) without performing any
real network authentication or remote execution. It emits structured
events for detections, SIEM pipelines, and ATT&CK mapping tests.

Key Standards / References (for analysts and auditors)
------------------------------------------------------
- MITRE ATT&CK TA0008 Lateral Movement (tactic).       # see sources
- MITRE ATT&CK T1021 Remote Services (+ sub-techniques: RDP/SMB/DCOM/SSH/VNC/WinRM/Cloud).  # see sources
- MITRE ATT&CK T1550.002 Pass-the-Hash.                # see sources
- MITRE guidance on adversary emulation & red teaming. # see sources
- NIST SP 800-115 Technical Guide (testing methodology).  # see sources

HARD SAFETY GUARANTEES
----------------------
- No socket creation, no subprocess remote exec, no OS credential use.
- "NullTransport" only: simulates outcomes and timestamps deterministically.
- Any attempt to plug real transports MUST occur in other modules and
  pass explicit code review. This file is intentionally self-contained,
  import-safe and side-effect-free.

Intended Use
------------
- Generate synthetic, high-fidelity events that *look like* lateral movement
  attempts for rules testing and pipeline validation (ATT&CK mapping, ECS/OTel).
- Exercise incident-response playbooks without touching production systems.

ATT&CK Mapping Examples
-----------------------
- TA0008  : Lateral Movement (tactic)
- T1021   : Remote Services (technique), sub-techniques include:
            T1021.001 RDP, T1021.002 SMB/Windows Admin Shares,
            T1021.003 DCOM, T1021.004 SSH, T1021.005 VNC,
            T1021.006 WinRM, T1021.007 Cloud Services, T1021.008 Direct Cloud VM Connections
- T1550.002: Use Alternate Authentication Material: Pass-the-Hash
(See sources at end of file docstring.)

NOTE: This simulator is designed for blue-team validation and training.
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# ATT&CK mapping & data structures (strongly typed, explicit IDs)
# -----------------------------------------------------------------------------

class Tactic(str, enum.Enum):
    TA0008 = "TA0008"  # Lateral Movement


class Technique(str, enum.Enum):
    # Representative, commonly used techniques in lateral movement workflows
    T1021 = "T1021"          # Remote Services (parent)
    T1021_001 = "T1021.001"  # Remote Desktop Protocol (RDP)
    T1021_002 = "T1021.002"  # SMB / Windows Admin Shares
    T1021_003 = "T1021.003"  # DCOM
    T1021_004 = "T1021.004"  # SSH
    T1021_005 = "T1021.005"  # VNC
    T1021_006 = "T1021.006"  # Windows Remote Management (WinRM)
    T1021_007 = "T1021.007"  # Cloud Services
    T1021_008 = "T1021.008"  # Direct Cloud VM Connections
    T1550_002 = "T1550.002"  # Use Alternate Authentication Material: Pass-the-Hash


TECHNIQUE_NAMES: Dict[Technique, str] = {
    Technique.T1021: "Remote Services",
    Technique.T1021_001: "Remote Desktop Protocol",
    Technique.T1021_002: "SMB/Windows Admin Shares",
    Technique.T1021_003: "Distributed Component Object Model",
    Technique.T1021_004: "SSH",
    Technique.T1021_005: "VNC",
    Technique.T1021_006: "Windows Remote Management",
    Technique.T1021_007: "Cloud Services",
    Technique.T1021_008: "Direct Cloud VM Connections",
    Technique.T1550_002: "Use Alternate Authentication Material: Pass-the-Hash",
}


class AuthMaterialKind(str, enum.Enum):
    CLEARTEXT = "cleartext"
    HASH = "hash"            # e.g., NTLM hash (simulation only)
    TICKET = "ticket"        # e.g., Kerberos ticket (simulation only)
    TOKEN = "token"          # e.g., cloud/API tokens (simulation only)
    NONE = "none"            # unauthenticated (should fail in simulator)


@dataclass(frozen=True)
class CredentialMaterial:
    kind: AuthMaterialKind
    value_redacted: str = "***"  # never store secrets; simulator only


@dataclass(frozen=True)
class MovementStep:
    """
    One synthetic lateral movement attempt.

    No real side-effects: this is a contract for telemetry generation only.
    """
    source: str               # hostname or logical label
    target: str               # hostname or logical label
    technique: Technique
    objective: str            # natural-language objective, e.g. "enumerate admin shares"
    creds: CredentialMaterial = field(default_factory=lambda: CredentialMaterial(AuthMaterialKind.NONE))
    requires_admin: bool = True
    expected_to_succeed: bool = True
    dwell_s: float = 0.2      # simulated time on step (seconds)


@dataclass(frozen=True)
class LateralMovementPlan:
    correlation_id: str
    steps: Sequence[MovementStep]
    actor: str = "adversary-sim"
    scenario_name: str = "default-lateral-movement"
    annotations: Dict[str, Any] = field(default_factory=dict)


# -----------------------------------------------------------------------------
# Event schema (compatible with ECS/OTel-style pipelines)
# -----------------------------------------------------------------------------

def _now_unix_ms() -> int:
    return int(time.time() * 1000)


def build_event(
    plan: LateralMovementPlan,
    step: MovementStep,
    outcome: str,
    severity: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    data = {
        "timestamp": _now_unix_ms(),
        "event": {
            "dataset": "adversary_emulation.lateral_movement",
            "category": ["intrusion_sim"],
            "kind": "simulation",
            "type": ["start" if outcome == "attempt" else "end"],
            "outcome": outcome,  # "attempt" | "success" | "failure"
            "severity": severity,
        },
        "attack": {
            "tactic": {"id": Tactic.TA0008.value, "name": "Lateral Movement"},
            "technique": {"id": step.technique.value, "name": TECHNIQUE_NAMES.get(step.technique, "unknown")},
        },
        "source": {"asset": {"name": step.source}},
        "target": {"asset": {"name": step.target}},
        "labels": {
            "scenario": plan.scenario_name,
            "correlation_id": plan.correlation_id,
            "actor": plan.actor,
        },
        "detail": {
            "objective": step.objective,
            "requires_admin": step.requires_admin,
            "auth_material_kind": step.creds.kind.value,
        },
    }
    if extra:
        data["detail"].update(extra)
    return data


# -----------------------------------------------------------------------------
# Transport interface (SIMULATION ONLY)
# -----------------------------------------------------------------------------

class NullTransport:
    """
    Simulation-only transport. Performs NO networking.

    Contract:
    - connect(): returns deterministic bool according to "creds.kind" and "requires_admin".
    - execute(): returns synthetic stdout/stderr payloads; never runs anything.
    """

    name = "null-transport"

    async def connect(self, step: MovementStep) -> bool:
        # Deterministic policy for simulation:
        # - if expected_to_succeed and creds != NONE -> success
        # - if requires_admin but creds is NONE -> failure
        if not step.expected_to_succeed:
            return False
        if step.requires_admin and step.creds.kind == AuthMaterialKind.NONE:
            return False
        return True

    async def execute(self, step: MovementStep) -> Dict[str, str]:
        # Never execute real commands; return synthetic payloads
        technique = step.technique.value
        return {
            "stdout": json.dumps(
                {
                    "technique": technique,
                    "message": f"[SIMULATED] Executed objective: {step.objective}",
                    "transport": self.name,
                },
                separators=(",", ":"),
            ),
            "stderr": "",
        }


# -----------------------------------------------------------------------------
# Simulator
# -----------------------------------------------------------------------------

class LateralMovementSimulator:
    """
    Orchestrates simulation-only lateral movement steps and emits events.

    Usage:
        sim = LateralMovementSimulator(event_sink=my_sink)
        await sim.run(plan)

    Where "event_sink" is an async function: async def sink(event: Dict[str, Any]) -> None
    """

    def __init__(self, event_sink: Callable[[Dict[str, Any]], Any], transport: Optional[NullTransport] = None):
        self._sink = event_sink
        self._transport = transport or NullTransport()

    async def run(self, plan: LateralMovementPlan) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for idx, step in enumerate(plan.steps):
            logger.info("Simulating lateral step %s/%s: %s -> %s (%s)",
                        idx + 1, len(plan.steps), step.source, step.target, step.technique.value)

            # Attempt event
            attempt = build_event(plan, step, outcome="attempt", severity="info", extra={"transport": self._transport.name})
            await self._emit(attempt, events)

            # Simulated connect/execute
            ok = await self._transport.connect(step)
            await asyncio.sleep(step.dwell_s)

            if not ok:
                failure = build_event(
                    plan, step, outcome="failure", severity="high",
                    extra={"reason": "simulated_authz_or_policy_denied"}
                )
                await self._emit(failure, events)
                continue

            exec_payload = await self._transport.execute(step)
            success = build_event(
                plan, step, outcome="success", severity="medium",
                extra={"exec": exec_payload}
            )
            await self._emit(success, events)

        return events

    async def _emit(self, event: Dict[str, Any], bag: List[Dict[str, Any]]) -> None:
        bag.append(event)
        try:
            maybe_coro = self._sink(event)
            if asyncio.iscoroutine(maybe_coro):
                await maybe_coro
        except Exception as e:  # do not break simulation on sink failures
            logger.warning("Event sink failed: %s", e)


# -----------------------------------------------------------------------------
# Convenience builders for common ATT&CK lateral techniques (SIMULATION)
# -----------------------------------------------------------------------------

def step_remote_services(source: str, target: str, objective: str,
                         subtech: Technique,
                         creds: Optional[CredentialMaterial] = None,
                         expected_to_succeed: bool = True,
                         dwell_s: float = 0.2) -> MovementStep:
    assert subtech in {
        Technique.T1021_001, Technique.T1021_002, Technique.T1021_003,
        Technique.T1021_004, Technique.T1021_005, Technique.T1021_006,
        Technique.T1021_007, Technique.T1021_008
    }, "subtech must be a T1021.* sub-technique"
    return MovementStep(
        source=source,
        target=target,
        technique=subtech,
        objective=objective,
        creds=creds or CredentialMaterial(AuthMaterialKind.NONE),
        requires_admin=True,
        expected_to_succeed=expected_to_succeed,
        dwell_s=dwell_s,
    )


def step_pass_the_hash(source: str, target: str, objective: str,
                       expected_to_succeed: bool = True,
                       dwell_s: float = 0.2) -> MovementStep:
    # Simulation-only: represent PtH by credential kind HASH; never contains real hash
    return MovementStep(
        source=source,
        target=target,
        technique=Technique.T1550_002,
        objective=objective,
        creds=CredentialMaterial(AuthMaterialKind.HASH, value_redacted="NTLM:***"),
        requires_admin=True,
        expected_to_succeed=expected_to_succeed,
        dwell_s=dwell_s,
    )


# -----------------------------------------------------------------------------
# Example (SAFE): build a plan without any side effects
# -----------------------------------------------------------------------------

def example_plan() -> LateralMovementPlan:
    """
    Returns a minimal, deterministic simulation plan covering:
    - T1021.002 (SMB Admin Shares)
    - T1021.006 (WinRM)
    - T1550.002 (Pass-the-Hash)

    This function only constructs data; it does not perform I/O.
    """
    steps = [
        step_remote_services(
            source="ws-01", target="srv-files-01",
            subtech=Technique.T1021_002,  # SMB/Admin Shares
            objective="list admin shares",
            creds=CredentialMaterial(AuthMaterialKind.CLEARTEXT),
        ),
        step_remote_services(
            source="ws-01", target="srv-app-01",
            subtech=Technique.T1021_006,  # WinRM
            objective="query service status",
            creds=CredentialMaterial(AuthMaterialKind.CLEARTEXT),
        ),
        step_pass_the_hash(
            source="ws-02", target="dc-01",
            objective="simulate lateral auth using hash material",
        ),
    ]
    return LateralMovementPlan(
        correlation_id="corr-0001",
        steps=steps,
        actor="adversary-sim",
        scenario_name="lm-basic-simulation",
    )
