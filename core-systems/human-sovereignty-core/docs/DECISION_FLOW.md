<!-- human-sovereignty-core/docs/DECISION_FLOW.md -->

# Human Sovereignty Core: Decision Flow

## Scope

This document defines the operational decision flow for Human Sovereignty Core (HSC): how a Decision Packet is created, reviewed, approved, executed, observed, and, if necessary, rolled back. The goal is to ensure that human authority is preserved end-to-end while keeping execution deterministic, auditable, and fail-closed.

This is a project-internal specification for the repository.

## Definitions

### Decision Packet
A structured, immutable description of a proposed change. A packet must be:
- Deterministic: same input yields the same diff / plan.
- Reviewable: includes a human-readable diff view.
- Auditable: produces traceable events.
- Reversible: includes rollback plan or rollback capability metadata.

### Approval
A human-controlled authorization step that gates execution. Approvals are evaluated against policy rules, identity constraints, and challenge requirements.

### Execution
Controlled application of the approved change, with strict idempotency and concurrency guarantees.

### Rollback
A compensating execution that attempts to revert effects of a prior execution, under the same governance and audit rules.

### Observability
The telemetry and alerting layer for detecting anomalies, policy violations, and execution failures.

## Non-Goals

- This document does not define a public API contract.
- This document does not define cryptographic primitives; it references them as requirements.
- This document does not replace formal security policies; it is an execution flow spec.

## Security Model (High-Level)

- Fail-closed by default: if identity, approval, or plan validation cannot be established, execution must not proceed.
- Trust boundaries must be explicit:
  - Identity evidence must originate from a trusted termination point (mTLS proxy boundary).
  - Approval must be attributable to a known principal.
- Every state transition emits audit events.

## Lifecycle Overview

1. Create Decision Packet
2. Generate Diff View
3. Validate Packet and Policy Preflight
4. Submit for Approval
5. Challenge (optional, policy-driven)
6. Evaluate Approval Rules
7. Approve or Reject
8. Execute Approved Plan
9. Observe and Alert
10. Rollback (if required)
11. Finalize and Archive

## Step-by-Step Flow

### 1. Packet Creation

Input:
- Change proposal (configuration change, policy update, deployment, permission update).
- Actor intent metadata.

Process:
- Normalize input into a canonical representation.
- Produce a packet id (stable).
- Store packet as immutable.

Outputs:
- Decision Packet object
- Packet metadata (created_at, author, domain, environment)

Required properties:
- Packet must include domain and environment.
- Packet must be hashable and reproducible.
- Packet must pass structural validation.

### 2. Diff View Generation

Goal:
- Provide a human-readable summary of what will change.

Process:
- Derive diff view from canonical input.
- Include:
  - Added/removed/modified elements
  - Risk markers (sensitive scope changes, permission escalations)
  - Rollback feasibility info

Output:
- Diff View artifact linked to the packet id

### 3. Policy Preflight Validation

Goal:
- Detect policy violations before asking for approval.

Checks:
- Packet integrity and schema validation
- TTL policy constraints (decision packet validity window)
- Permission and scope constraints
- Rate/volume constraints
- Required challenges for risk tier

If any check fails:
- Mark packet as invalid
- Emit audit event
- Stop flow

### 4. Approval Submission

Process:
- Create an Approval Request linked to packet id.
- Attach:
  - Diff view
  - Risk summary
  - Proposed execution plan
  - Rollback plan metadata

State:
- Approval Request becomes `pending`.

### 5. Challenge (Optional)

Policy may require additional proof depending on risk tier, e.g.:
- Device-bound identity confirmation
- Time-based challenge
- Offline/hardware challenge with QR payload
- Multi-person approval

Challenge must be:
- Time-bounded
- Bound to request_id and packet_id
- Audited

### 6. Approval Rules Evaluation

Rules evaluate:
- Principal identity and roles
- Device posture constraints (if available)
- Required number of approvers
- Separation of duties constraints
- Timing constraints (TTL, blackout windows)
- Domain restrictions

Outputs:
- `approved` or `rejected` decision
- Rule evaluation report (for audit)

### 7. Decision Outcome

If rejected:
- Mark approval request as rejected
- Emit audit event
- End flow

If approved:
- Mark approval request as approved
- Move to execution gate

### 8. Execution of Approved Plan

Requirements:
- Idempotency: repeated execution requests for same execution_id must not re-apply changes.
- Concurrency control: only one executor may run per packet/plan in the environment.
- Deterministic ordering: execution steps must be deterministic.

Process:
- Acquire execution lock
- Execute steps
- Emit step-level audit events
- Emit completion audit event

Failure handling:
- If a step fails and policy is fail-closed:
  - Stop execution
  - Emit failure audit
  - Trigger alerts
  - Optionally propose rollback

### 9. Observability and Alerts

Telemetry:
- Request/Execution ids in logs
- Step durations and outcome counters
- Error taxonomy
- Audit event stream

Alerts should cover:
- Repeated failures on same packet
- Policy validation failures
- Unauthorized identity attempts
- Rollback invoked
- Unexpected execution durations
- Anomalous approval patterns (if detection exists)

### 10. Rollback Flow

Rollback may be triggered by:
- Execution failure requiring compensation
- Post-deployment regression
- Manual override decision

Requirements:
- Same governance constraints as execution
- Idempotent rollback key
- Reverse order compensation steps
- Full audit trail

Process:
- Acquire rollback lock
- Run rollback steps with retry/backoff policy
- Emit rollback audit events
- Emit final status

Rollback outcomes:
- succeeded: system restored to prior expected state
- partial: some compensation steps failed in best-effort mode
- failed: rollback could not restore state

### 11. Finalization and Archival

Finalize:
- Mark packet lifecycle end state
- Store:
  - Packet
  - Diff view
  - Approval record and challenge transcript
  - Execution logs and audit events
  - Rollback records (if any)

Retention:
- Determined by compliance policy.

## State Machines

### Approval Request States
- pending
- challenged
- approved
- rejected
- expired
- cancelled

### Execution States
- pending
- running
- succeeded
- failed
- cancelled

### Rollback States
- pending
- running
- succeeded
- partial
- failed
- cancelled

## Audit Event Taxonomy (Recommended)

- decision_packet.created
- decision_packet.validated
- decision_packet.invalid
- diff_view.generated
- approval.requested
- approval.challenged
- approval.approved
- approval.rejected
- execution.started
- execution.step_started
- execution.step_succeeded
- execution.step_failed
- execution.finished
- rollback.started
- rollback.step_started
- rollback.step_succeeded
- rollback.step_failed
- rollback.finished
- alert.raised

Each event should include:
- request_id, packet_id, execution_id
- actor and device identity
- environment and domain
- timestamp
- status and reason

## Failure Modes and Defaults

- Unknown identity: deny
- Missing approval: deny
- TTL expired: deny
- Validation error: deny
- Lock acquisition failure: deny
- Unexpected exception: deny and alert

## Implementation Notes

- WebUI server should treat identity as coming from a trusted proxy boundary only.
- Executor and rollback must use explicit idempotency and locks.
- Alerts should be emitted for any policy or execution anomaly.

