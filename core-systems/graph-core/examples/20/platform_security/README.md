
---

## Components

### 1. Audit Layer

- `audit_logger.py` – Centralized logger for audit trails.
- `siem_exporter.py` – Routes logs to SIEM systems.
- `log_formatter.py` – ECS and OTEL formatters.

### 2. Enforcement

- `policy_enforcer.py` – Applies ZT policies.
- `session_token_hardener.py` – Secures session tokens via AI.
- `privilege_manager.py` – Manages runtime privilege elevation.
- `network_segmentation.py` – Applies microsegmentation.
- `behavior_graph.py` – Observes agent behavior across contexts.

### 3. Deception Engine

- `honeypot.py` – Deploys dynamic honeypots.
- `defense_layers.py` – Tiered deception responses.
- `deception_engine.py` – Orchestrates decoys and traps.

### 4. ZTNA (Zero Trust Network Access)

- `anomaly_detector.py` – Behavioral AI detector.
- `policy_engine.py` – Loads dynamic zero-trust rules.
- `traffic_filter.py` – Drops traffic per policy.
- `zero_trust_ai.py` – Adaptive policy engine using RL.
- `perimeter_controller.py` – Isolates lateral movement vectors.

### 5. RBAC System

- `roles.py`, `permissions.py`, `enforcer.py` – Fine-grained role policy control.

### 6. Validators

- `domain_delegate_checker.py` – Verifies domain provenance.
- `header_validator.py` – Inspects request headers.
- `payload_validator.py` – Validates input payloads.
- `utils/` – Shared helpers (time windowing, hash context, vote-based thresholds)

---

## Configuration

Добавить `zero_trust_policy.yaml` в `zero-trust/config/` (можно создать директорию), например:

```yaml
default_policy: deny
session:
  idle_timeout: 10m
  ai_token_protection: true
rbac:
  default_role: Guest
  roles:
    - Admin
    - Operator
    - Analyst
audit:
  enabled: true
  forward_to: siem
deception:
  honeypot_dynamic: true
