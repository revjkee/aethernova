# cybersecurity-core/cybersecurity/adversary_emulation/scenarios/library/scenario_phishing.py
"""
Scenario: Phishing (Safety-first Adversary Emulation)
Status: Industrial-grade, safe-mode by default

Description
-----------
This scenario simulates a controlled phishing campaign end-to-end without
sending real emails or contacting external networks. It generates realistic
artifacts (RFC 5322-compliant .eml, decoy landing page), emits structured
telemetry (JSON Lines), and documents detection hypotheses.

Compliance and References
-------------------------
- MITRE ATT&CK:
  * T1566 Phishing
  * T1566.001 Spearphishing Attachment
  * T1204 User Execution
- NIST:
  * SP 800-115 (Technical Guide to Information Security Testing and Assessment)
  * SP 800-61r3 (Computer Security Incident Handling Guide)
  * SP 800-53r5 relevant controls: AT-2 (Awareness), IR-4 (Incident Handling), SI-3 (Malicious Code Protection)
- RFC:
  * RFC 5322 (Internet Message Format) for EML artifact structure

Hard Safety Guardrails
----------------------
- safe_mode=True by default: no SMTP, DNS, HTTP, or C2 egress.
- Artifacts are written locally under an operator-specified output directory.
- Payloads are inert placeholders; no exploitation, no macros, no obfuscated code.
- All external identifiers (domains, IPs, URLs) are synthetic and reserved-safe.

Usage
-----
$ python scenario_phishing.py --output-dir ./out --seed 1337
$ python scenario_phishing.py --output-dir ./out --seed 1337 --unsafe    # only in isolated lab nets you control

Outputs
-------
- out/artifacts/phishing_email.eml                RFC 5322-compliant sample
- out/artifacts/landing_page.html                 Decoy credential page (non-functional)
- out/logs/telemetry.jsonl                        ECS-like JSON events with MITRE mappings
- out/reports/summary.json                        Run metadata and KPIs

Copyright
---------
(c) 2025 Aethernova / Cybersecurity Core. Licensed under the project license.

"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import random
import secrets
import string
import sys
import uuid


# --------------------------- Logging (JSON) ----------------------------------


class JsonFormatter(logging.Formatter):
    """Minimal, dependency-free JSON formatter with ECS-leaning fields."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.datetime.utcfromtimestamp(record.created).isoformat(timespec="milliseconds") + "Z"
        base = {
            "@timestamp": ts,
            "log.level": record.levelname.lower(),
            "message": record.getMessage(),
            "logger.name": record.name,
        }
        # Merge extra fields if present
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            base.update(record.extra)
        # Include exception info if any
        if record.exc_info:
            base["error.kind"] = str(record.exc_info[0].__name__)
            base["error.message"] = str(record.exc_info[1])
        return json.dumps(base, ensure_ascii=False)


def get_logger(name: str = "scenario") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


log = get_logger("scenario.phishing")


# --------------------------- MITRE / NIST Metadata ---------------------------


@dataclass(frozen=True)
class MitreTechnique:
    id: str
    name: str


@dataclass(frozen=True)
class NistControl:
    id: str
    name: str


@dataclass
class ScenarioMetadata:
    scenario_id: str
    name: str
    description: str
    version: str
    techniques: List[MitreTechnique]
    controls: List[NistControl]
    references: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "techniques": [t.__dict__ for t in self.techniques],
            "controls": [c.__dict__ for c in self.controls],
            "references": dict(self.references),
        }


METADATA = ScenarioMetadata(
    scenario_id="ADV-EMUL-PHISHING-001",
    name="Phishing (safe emulation)",
    description="End-to-end safe emulation of a phishing campaign producing artifacts and telemetry.",
    version="1.2.0",
    techniques=[
        MitreTechnique("T1566", "Phishing"),
        MitreTechnique("T1566.001", "Spearphishing Attachment"),
        MitreTechnique("T1204", "User Execution"),
    ],
    controls=[
        NistControl("AT-2", "Security and Privacy Awareness and Training"),
        NistControl("IR-4", "Incident Handling"),
        NistControl("SI-3", "Malicious Code Protection"),
    ],
    references={
        "ATTACK_T1566": "https://attack.mitre.org/techniques/T1566/",
        "ATTACK_T1566_001": "https://attack.mitre.org/techniques/T1566/001/",
        "ATTACK_T1204": "https://attack.mitre.org/techniques/T1204/",
        "NIST_SP_800_115": "https://csrc.nist.gov/pubs/sp/800/115/final",
        "NIST_SP_800_61R3": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf",
        "NIST_SP_800_53R5": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf",
        "RFC_5322": "https://datatracker.ietf.org/doc/html/rfc5322",
    },
)


# --------------------------- Utilities ---------------------------------------


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def stable_random(seed: int) -> random.Random:
    rnd = random.Random()
    rnd.seed(seed)
    return rnd


def random_ipv4(rnd: random.Random) -> str:
    # Reserved TEST-NET-1 192.0.2.0/24 for documentation/examples (RFC 5737)
    net = ipaddress.ip_network("192.0.2.0/24")
    host = list(net.hosts())[rnd.randint(0, net.num_addresses - 3)]
    return str(host)


def random_username(rnd: random.Random) -> str:
    base = rnd.choice(["alex", "maria", "sam", "jo", "lee", "nina", "max", "ivan"])
    suffix = rnd.randint(10, 9999)
    return f"{base}.{suffix}"


def random_domain(rnd: random.Random) -> str:
    # Use reserved example TLDs per RFC 2606: .test .example .invalid .localhost
    sub = "".join(rnd.choice(string.ascii_lowercase) for _ in range(8))
    return f"{sub}.example"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_utc() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


# --------------------------- Scenario Steps ----------------------------------


@dataclass
class RunConfig:
    output_dir: Path
    seed: int = 1337
    safe_mode: bool = True
    operator: str = "operator@lab.local"
    campaign_name: str = "Q3 Awareness Test"
    organization: str = "Acme Corp"


@dataclass
class StepResult:
    name: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)


class ScenarioError(RuntimeError):
    pass


class Step:
    name: str = "base"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        raise NotImplementedError


class GeneratePhishingEmail(Step):
    name = "generate_phishing_email"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        # Prepare paths
        artifacts_dir = cfg.output_dir / "artifacts"
        ensure_dir(artifacts_dir)
        eml_path = artifacts_dir / "phishing_email.eml"

        # Synthetic attribution
        sender_domain = random_domain(rnd)
        recipient = f"{random_username(rnd)}@{cfg.organization.lower().replace(' ', '')}.example"
        sender = f"alerts@{sender_domain}"

        # Compose RFC 5322 email
        msg = EmailMessage()
        msg["From"] = f"Security Alerts <{sender}>"
        msg["To"] = recipient
        msg["Subject"] = f"Mandatory security update - {cfg.campaign_name}"
        msg["Date"] = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg["Message-ID"] = f"<{uuid.uuid4().hex}@{sender_domain}>"

        # Inert PDF attachment placeholder bytes
        pdf_bytes = ("%PDF-1.4\n% Inert training artifact, no active content.\n"
                     "1 0 obj<<>>endobj\nxref\n0 1\n0000000000 65535 f \ntrailer<<>>\nstartxref\n0\n%%EOF\n").encode("utf-8")
        attachment_name = "SecurityUpdate.pdf"

        # Body
        tracking_token = b64u(secrets.token_bytes(12))
        landing_host = random_domain(rnd)
        landing_url = f"https://{landing_host}/update?campaign={b64u(cfg.campaign_name.encode())}&t={tracking_token}"

        body = (
            f"Dear user,\n\n"
            f"As part of the {cfg.campaign_name} program, please review the attached security update memo.\n"
            f"Alternatively, you can access the information via the secure portal:\n"
            f"{landing_url}\n\n"
            f"Regards,\nIT Security\n"
        )
        msg.set_content(body)

        # Attach inert artifact
        msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=attachment_name)

        with open(eml_path, "wb") as f:
            f.write(msg.as_bytes())

        eml_sha256 = sha256_hex(msg.as_bytes())

        log.info(
            "Generated phishing EML artifact",
            extra={
                "extra": {
                    "event.kind": "artifact",
                    "event.category": "email",
                    "event.action": "generate",
                    "event.outcome": "success",
                    "file.path": str(eml_path),
                    "file.hash.sha256": eml_sha256,
                    "email.to": recipient,
                    "email.from": sender,
                    "mitre.attack.techniques": ["T1566", "T1566.001", "T1204"],
                }
            },
        )

        return StepResult(
            name=self.name,
            success=True,
            details={
                "eml_path": str(eml_path),
                "recipient": recipient,
                "sender": sender,
                "landing_url": landing_url,
                "attachment_name": attachment_name,
                "eml_sha256": eml_sha256,
            },
        )


class GenerateDecoyLandingPage(Step):
    name = "generate_decoy_landing_page"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        artifacts_dir = cfg.output_dir / "artifacts"
        ensure_dir(artifacts_dir)
        html_path = artifacts_dir / "landing_page.html"

        # Static, non-functional page. No live posts. Form posts to "about:blank".
        csrf = b64u(secrets.token_bytes(16))
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{cfg.organization} Secure Portal</title>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
  <meta name="robots" content="noindex,nofollow">
</head>
<body style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px;">
  <h1>{cfg.organization} Single Sign-On</h1>
  <p>This is a training artifact used for awareness testing.</p>
  <form method="post" action="about:blank" autocomplete="off">
    <input type="hidden" name="csrf" value="{csrf}">
    <label>Username<br><input name="username" type="text" required></label><br><br>
    <label>Password<br><input name="password" type="password" required></label><br><br>
    <button type="submit" disabled>Sign in (disabled for training)</button>
  </form>
  <footer style="margin-top: 24px; font-size: 12px; color: #555;">
    Training use only. No data is transmitted.
  </footer>
</body>
</html>
"""
        html_bytes = html.encode("utf-8")
        with open(html_path, "wb") as f:
            f.write(html_bytes)

        log.info(
            "Generated decoy landing page",
            extra={
                "extra": {
                    "event.kind": "artifact",
                    "event.category": "web",
                    "event.action": "generate",
                    "event.outcome": "success",
                    "file.path": str(html_path),
                    "file.hash.sha256": sha256_hex(html_bytes),
                    "http.response.status_code": 200,
                    "mitre.attack.techniques": ["T1566", "T1204"],
                }
            },
        )

        return StepResult(name=self.name, success=True, details={"landing_page_path": str(html_path)})


class SimulateUserInteraction(Step):
    name = "simulate_user_interaction"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        username = random_username(rnd)
        src_ip = random_ipv4(rnd)
        click_id = uuid.uuid4().hex

        log.info(
            "Simulated user clicked phishing link",
            extra={
                "extra": {
                    "event.kind": "event",
                    "event.category": "web",
                    "event.action": "click",
                    "event.outcome": "success",
                    "user.name": username,
                    "source.ip": src_ip,
                    "url.original": "<local_training_link>",
                    "mitre.attack.techniques": ["T1204"],
                }
            },
        )

        return StepResult(
            name=self.name,
            success=True,
            details={"user": username, "source_ip": src_ip, "click_id": click_id},
        )


class SimulateCredentialHarvest(Step):
    name = "simulate_credential_harvest"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        # This is a simulation; generate synthetic credential hashes locally
        username = random_username(rnd)
        password = "P@" + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(10))
        cred_hash = sha256_hex(f"{username}:{password}".encode())

        log.info(
            "Simulated credential submission on decoy page",
            extra={
                "extra": {
                    "event.kind": "event",
                    "event.category": "authentication",
                    "event.action": "credential_submit",
                    "event.outcome": "success",
                    "user.name": username,
                    "related.hash": cred_hash,
                    "mitre.attack.techniques": ["T1566", "T1204"],
                }
            },
        )

        return StepResult(
            name=self.name,
            success=True,
            details={"username": username, "credential_hash_sha256": cred_hash},
        )


class SimulatePayloadExecution(Step):
    name = "simulate_payload_execution"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        # Inert "payload" marker: no execution; just a marker file to emulate telemetry
        artifacts_dir = cfg.output_dir / "artifacts"
        ensure_dir(artifacts_dir)
        marker_path = artifacts_dir / "payload_marker.bin"
        payload_bytes = b"INERT_PAYLOAD_MARKER_FOR_T1204"
        with open(marker_path, "wb") as f:
            f.write(payload_bytes)

        log.info(
            "Simulated user execution of inert attachment",
            extra={
                "extra": {
                    "event.kind": "event",
                    "event.category": "process",
                    "event.action": "execute",
                    "event.outcome": "success",
                    "file.path": str(marker_path),
                    "file.hash.sha256": sha256_hex(payload_bytes),
                    "mitre.attack.techniques": ["T1204"],
                }
            },
        )

        return StepResult(name=self.name, success=True, details={"payload_marker": str(marker_path)})


class SimulateC2Beacon(Step):
    name = "simulate_c2_beacon"

    def run(self, cfg: RunConfig, rnd: random.Random) -> StepResult:
        # No network. We just log that a "beacon event" would be attempted.
        c2_host = f"c2.{random_domain(rnd)}"
        interval_s = rnd.randint(30, 90)

        log.info(
            "Simulated C2 beacon attempt (no egress in safe_mode)",
            extra={
                "extra": {
                    "event.kind": "event",
                    "event.category": "network",
                    "event.action": "beacon",
                    "event.outcome": "blocked" if cfg.safe_mode else "success",
                    "network.interval.sec": interval_s,
                    "destination.domain": c2_host,
                    "mitre.attack.techniques": ["T1204"],
                }
            },
        )

        if not cfg.safe_mode:
            # Still: do not actually connect; even in unsafe we avoid egress by design.
            pass

        return StepResult(name=self.name, success=True, details={"c2_domain": c2_host, "interval_s": interval_s})


# --------------------------- Runner ------------------------------------------


class PhishingScenario:
    def __init__(self, cfg: RunConfig):
        self.cfg = cfg
        self.rnd = stable_random(cfg.seed)
        self.steps: List[Step] = [
            GeneratePhishingEmail(),
            GenerateDecoyLandingPage(),
            SimulateUserInteraction(),
            SimulateCredentialHarvest(),
            SimulatePayloadExecution(),
            SimulateC2Beacon(),
        ]

    def _prepare_output(self) -> Dict[str, Path]:
        logs_dir = self.cfg.output_dir / "logs"
        artifacts_dir = self.cfg.output_dir / "artifacts"
        reports_dir = self.cfg.output_dir / "reports"
        ensure_dir(logs_dir)
        ensure_dir(artifacts_dir)
        ensure_dir(reports_dir)
        return {"logs": logs_dir, "artifacts": artifacts_dir, "reports": reports_dir}

    def _setup_file_logging(self, logs_dir: Path) -> None:
        file_handler = logging.FileHandler(logs_dir / "telemetry.jsonl", encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        root = get_logger("scenario.phishing")
        root.addHandler(file_handler)

    def run(self) -> Dict[str, Any]:
        dirs = self._prepare_output()
        self._setup_file_logging(dirs["logs"])

        summary: Dict[str, Any] = {
            "metadata": METADATA.to_dict(),
            "config": {
                "output_dir": str(self.cfg.output_dir),
                "seed": self.cfg.seed,
                "safe_mode": self.cfg.safe_mode,
                "operator": self.cfg.operator,
                "campaign_name": self.cfg.campaign_name,
                "organization": self.cfg.organization,
                "started": now_utc(),
            },
            "results": [],
            "kpi": {},
            "finished": None,
        }

        log.info("Scenario start", extra={"extra": {"event.kind": "state", "event.action": "start", "scenario.id": METADATA.scenario_id}})

        for step in self.steps:
            try:
                res = step.run(self.cfg, self.rnd)
                summary["results"].append({"step": step.name, "success": res.success, "details": res.details})
            except Exception as e:
                log.error(
                    "Step failed",
                    extra={"extra": {"event.kind": "state", "event.action": "error", "scenario.step": step.name}},
                    exc_info=True,
                )
                raise ScenarioError(f"Step {step.name} failed") from e

        # KPI synthesis
        total = len(self.steps)
        succeeded = sum(1 for r in summary["results"] if r["success"])
        summary["kpi"] = {"steps_total": total, "steps_succeeded": succeeded, "success_rate": round(100.0 * succeeded / total, 2)}
        summary["finished"] = now_utc()

        # Persist summary
        with open(dirs["reports"] / "summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        log.info(
            "Scenario finished",
            extra={
                "extra": {
                    "event.kind": "state",
                    "event.action": "finish",
                    "event.outcome": "success",
                    "kpi.steps_total": total,
                    "kpi.steps_succeeded": succeeded,
                    "kpi.success_rate": summary["kpi"]["success_rate"],
                }
            },
        )

        return summary


# --------------------------- CLI ---------------------------------------------


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phishing adversary emulation scenario (safe by default). Generates artifacts and telemetry locally."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write artifacts, logs, and reports.")
    parser.add_argument("--seed", type=int, default=1337, help="Deterministic seed for reproducibility.")
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Disable safe_mode. Note: networking is still disabled in code; flag only alters outcomes for testing.",
    )
    parser.add_argument("--campaign", default="Q3 Awareness Test", help="Campaign name string.")
    parser.add_argument("--org", default="Acme Corp", help="Organization name.")
    parser.add_argument("--operator", default="operator@lab.local", help="Operator identifier for provenance.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    cfg = RunConfig(
        output_dir=Path(args.output_dir),
        seed=args.seed,
        safe_mode=not args.unsafe,
        operator=args.operator,
        campaign_name=args.campaign,
        organization=args.org,
    )
    try:
        scenario = PhishingScenario(cfg)
        summary = scenario.run()
        # Print minimal operator-friendly line to stdout
        print(json.dumps({"ok": True, "report": str(Path(cfg.output_dir) / "reports" / "summary.json")}))
        return 0
    except ScenarioError as se:
        log.error("ScenarioError", extra={"extra": {"event.kind": "state", "event.action": "fatal"}}, exc_info=True)
        print(json.dumps({"ok": False, "error": str(se)}), file=sys.stderr)
        return 2
    except Exception as e:
        log.error("Unhandled exception", extra={"extra": {"event.kind": "state", "event.action": "fatal"}} , exc_info=True)
        print(json.dumps({"ok": False, "error": str(e)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
