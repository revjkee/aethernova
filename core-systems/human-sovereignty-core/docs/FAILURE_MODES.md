<!-- human-sovereignty-core/docs/FAILURE_MODES.md -->

# Failure Modes and Safe Degradation
Human Sovereignty Core

## Scope
This document enumerates failure modes for the Human Sovereignty Core and defines expected system behavior under partial failures. The primary objective is to preserve human control, prevent unsafe execution, and keep auditability intact.

Core principles:
- Fail closed for authorization, approval, and veto paths.
- Never execute irreversible actions without verifiable approval.
- Preserve audit trail integrity even under degraded observability.
- Prefer explicit denial over implicit allow.

## Definitions
- Decision: a structured intent to perform an action.
- Execution: an attempt to realize a decision through one or more steps.
- Approval: a human confirmation gate that must be satisfied for protected operations.
- Veto: a human or policy-triggered stop signal that must block execution.
- Rollback: compensating actions or execution cancellation to revert to a safe state.
- WebUI: administrative interface. Browser must not hold JWT for admin operations.

## Global Invariants
1. No protected execution proceeds without an approval record or an approved session state on the server.
2. Veto blocks execution immediately and must be observable through audit events.
3. Audit chain integrity must be verifiable offline from exported records.
4. Non-interactive or ambiguous approval channels must deny by default.
5. Any failure to validate identities, policies, or integrity signals must deny.

## Failure Mode Taxonomy
Each failure mode includes:
- Trigger: how it happens.
- Detection: how we detect it.
- Impact: what breaks.
- Safe behavior: mandatory system response.
- Observability: required events/metrics/logs.

Severity levels (informational):
- Sev0: safety or sovereignty breach risk.
- Sev1: protected execution blocked or audit compromised.
- Sev2: degraded operations but safe.
- Sev3: minor degradation.

## Identity and Session Failures

### FM-ID-001: Session store unavailable (server-side)
Trigger:
- In-memory store lost on restart.
- External store (future Redis/DB) unavailable.

Detection:
- Session lookup failures.
- Sudden drop to zero active sessions after restart.

Impact:
- Admin sessions invalidated.

Safe behavior:
- Deny admin actions requiring a session.
- Force re-authentication.
- Never fall back to client JWT for admin.

Observability:
- Emit auth/session failure counters.
- Log event: session_lookup_failed, session_store_unavailable.

### FM-ID-002: Session fixation attempt
Trigger:
- Attacker tries to force a known session id.
- Replay of old cookie.

Detection:
- Rotation logic invoked after privilege changes.
- Mismatch of session metadata or invalid/unknown sid.

Impact:
- Potential takeover attempt.

Safe behavior:
- Rotate session id upon privilege elevation.
- Revoke suspicious session.
- Require re-authentication if integrity signals are inconsistent.

Observability:
- Log event: session_rotated, session_revoked_suspicious.
- Metric: session_rotation_total, session_revoke_total.

### FM-ID-003: mTLS client certificate missing or invalid
Trigger:
- Client without certificate hits mTLS endpoint.
- Invalid chain, expired certificate, revoked certificate.

Detection:
- NGINX ssl_client_verify not SUCCESS.

Impact:
- WebUI access blocked.

Safe behavior:
- Reject request at the edge (mTLS fail).
- Do not forward to app.

Observability:
- Edge logs count 495/4xx mTLS failures.
- Optional: rate limit repeated failures.

## Approval Failures

### FM-APP-001: Approval channel non-interactive
Trigger:
- CLI invoked without TTY and without explicit auto decision.

Detection:
- stdin/stdout not TTY.

Impact:
- Approval cannot be obtained.

Safe behavior:
- Deny by default (fail closed).
- If configured, return timeout or rejected, never approve implicitly.

Observability:
- Log event: approval_denied_non_interactive.
- Metric: approval_requests_total, approval_denied_total.

### FM-APP-002: Approval input timeout
Trigger:
- Operator does not respond within timeout.

Detection:
- Alarm timeout or elapsed time limit.

Impact:
- Decision blocked.

Safe behavior:
- Mark as timeout.
- Treat timeout as rejection for protected execution.

Observability:
- Event: approval_timeout.
- Metric: approval_timeouts_total.

### FM-APP-003: Conflicting auto-approve and auto-reject flags
Trigger:
- Both env flags set.

Detection:
- Validation check in channel.

Impact:
- Ambiguous configuration.

Safe behavior:
- Return error outcome.
- Deny protected execution.

Observability:
- Event: approval_config_conflict.

### FM-APP-004: Override token missing for auto-decision
Trigger:
- Auto mode requested but no override token available.

Detection:
- Missing env token.

Impact:
- Auto path blocked.

Safe behavior:
- Deny.
- Require interactive approval.

Observability:
- Event: approval_missing_override_token.

## Veto Failures

### FM-VETO-001: Veto event emission fails
Trigger:
- Logging pipeline down.
- Event sink unavailable.

Detection:
- Exception during event export or publish.

Impact:
- Reduced audit visibility.

Safe behavior:
- Execution must still halt on veto.
- Store veto event locally/in memory for retry if applicable.
- Do not proceed due to observability failure.

Observability:
- Local error log: veto_emit_failed.
- Metric: veto_emit_failures_total.

### FM-VETO-002: Veto reason malformed or missing references
Trigger:
- Bad event payload.
- Missing decision/execution reference.

Detection:
- Schema validation failure.

Impact:
- Event cannot be recorded.

Safe behavior:
- Block the corresponding action (fail closed).
- Produce a minimal safe event with OTHER reason if allowed by code policy; otherwise error and deny.

Observability:
- Event: veto_schema_invalid.
- Metric: veto_validation_failures_total.

## Policy and Decision Integrity Failures

### FM-POL-001: Policy evaluation engine unavailable
Trigger:
- Policy module crash.
- Dependency error.

Detection:
- Policy call exception.

Impact:
- Cannot assert allow/deny.

Safe behavior:
- Deny protected execution.
- Require human approval if policy fails but operation is critical and explicitly configured.

Observability:
- Event: policy_engine_error.
- Metric: policy_eval_errors_total.

### FM-POL-002: Contradiction or low-confidence signals detected
Trigger:
- Contradiction checker flags inconsistency.
- Low confidence path triggers.

Detection:
- Explicit flags in decision packet or evaluation output.

Impact:
- Execution risk increases.

Safe behavior:
- Raise veto (recommended) or require explicit human approval.
- Prefer block until clarified.

Observability:
- Veto event: contradiction_detected or low_confidence.
- Metric: contradictions_total, low_confidence_total.

## Execution and Rollback Failures

### FM-EXE-001: Execution step partially applied
Trigger:
- Crash mid-step.
- Network interruption.

Detection:
- Missing completion marker.
- Idempotency key indicates incomplete step.

Impact:
- System may be in intermediate state.

Safe behavior:
- Stop further steps.
- Trigger rollback plan if defined.
- Require human approval for rollback if rollback is unsafe or irreversible.

Observability:
- Audit record: execution_interrupted.
- Rollback audit record appended.

### FM-EXE-002: Rollback fails
Trigger:
- Compensating action cannot be applied.
- Dependency unavailable.

Detection:
- Rollback exception.
- Non-OK rollback status.

Impact:
- Residual state persists.

Safe behavior:
- Enter degraded safe mode.
- Block further execution for the affected resource scope.
- Escalate to human review.

Observability:
- Rollback audit: rollback_failed.
- Metric: rollback_failures_total.

### FM-AUD-001: Rollback audit integrity broken
Trigger:
- Record tampering.
- Missing record hash or mismatched previous hash.

Detection:
- verify_integrity returns false.

Impact:
- Audit trail untrustworthy.

Safe behavior:
- Freeze protected execution.
- Require operator intervention.
- Export raw records for forensic review.

Observability:
- Event: audit_integrity_failed.
- Metric: audit_integrity_failures_total.

## WebUI and Health Failures

### FM-WEB-001: Health endpoint reports OK but dependencies degraded
Trigger:
- Checks not registered.
- Misconfigured env.

Detection:
- Missing checks in output.
- Unexpectedly empty readiness checks.

Impact:
- Orchestrator may route traffic to unhealthy instance.

Safe behavior:
- Treat missing critical checks as degraded or fail if configured.
- Ensure readiness includes disk and optionally tcp checks.

Observability:
- Health payload contains checks list and statuses.

### FM-WEB-002: mTLS enforced but internal upstream misconfigured
Trigger:
- Proxy pass wrong port
