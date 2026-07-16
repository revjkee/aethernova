# Human Sovereignty Core WebUI

## Purpose

WebUI is the privileged control plane for Human Sovereignty Core. It provides:
- Policy authoring and review for RED domains and related network identifiers.
- Approval workflows (challenge/response with anti-replay) for high-impact actions.
- Execution controls, including rollback plan creation, validation, and audited execution.
- Observability dashboards and audit exploration for incident response and compliance.

This WebUI must be safe-by-default, auditable, and policy-driven.

## Non-Goals

- No direct “raw infrastructure control” without policy and approvals.
- No long-lived secrets in the browser.
- No anonymous access.
- No bypass channels around audit logging.

## Security Posture

WebUI is a high-value target. The system must assume:
- Credential stuffing and session theft attempts.
- UI-driven privilege escalation attempts.
- CSRF, XSS, clickjacking, and SSRF attempts.
- Supply-chain risks via dependencies and build pipeline.
- Replay attacks against approval challenges.

WebUI must enforce:
- Strong authentication and strict authorization.
- Immutable audit logging for critical operations.
- Mandatory approvals for high-risk operations.
- Defense-in-depth at UI, API, and infrastructure layers.

## Core Capabilities

### Policy Management
- View, diff, and audit policy revisions.
- Propose changes via pull-request style workflow.
- Apply policies only through approval gates.

### RED Domains
- Maintain RED domain rule sets with references to verified sources.
- Enforce strict change control and approvals.
- Export/import with deterministic canonicalization and hashing.

### Approvals
- Challenge generation and validation.
- TTL enforcement.
- Nonce anti-replay.
- Constant-time comparison for sensitive verifications.
- Break-glass approvals for critical-risk actions.

### Rollback
- Build rollback plans with explicit safety rails.
- Validate plan feasibility before execution.
- Execute in dry-run and enforce modes.
- Record outcomes with immutable audit trails.

### Observability
- Health, error rate, latency and policy hit metrics.
- Audit event exploration with correlation identifiers.
- Snapshot exports for incident response.

## Architecture Contract

### Frontend
- Runs as a static client application (SPA) or SSR shell (deployment decision outside this document).
- Communicates with backend via authenticated API calls.
- Stores no long-lived secrets.
- Uses short-lived access tokens and refresh strategy defined by IAM integration.

### Backend
- Provides:
  - Policy endpoints
  - Approval endpoints
  - Rollback endpoints
  - Observability endpoints
  - Audit endpoints
- Enforces RBAC and policy decisions server-side.
- Emits structured audit logs for every privileged action.

## Authentication and Sessions

Requirements:
- Strong authentication (OIDC recommended where available).
- Short-lived access tokens.
- Secure cookie strategy if cookies are used:
  - HttpOnly
  - Secure
  - SameSite=Strict
- Session binding to device/browser fingerprint where appropriate.
- Forced re-authentication or step-up auth for critical actions.

## Authorization (RBAC)

Role model:
- Owner/Governor roles for global governance.
- Policy Admin for scoped policy operations.
- Auditor for read-only access with export capabilities.
- Operator for operational decision recording and mitigations.
- Service principals for automated read-only decisions.

Rules:
- Least privilege by default.
- Server-side enforcement only.
- All sensitive actions require explicit permissions and scopes.

## Audit Logging

Audit events must include:
- Who: subject, roles, auth context
- What: action, object identifiers, policy/plan fingerprints
- When: timestamps
- Where: service, environment, request correlation id
- Result: allow/deny, reason, error details (sanitized)

Audit logging must be:
- Immutable or append-only at sink.
- Correlated across UI and backend.
- Resistant to tampering.

## Approval Challenges

High-risk operations must require:
- Challenge creation with:
  - TTL
  - nonce
  - subject binding
  - context binding
- Validation with:
  - anti-replay nonce store
  - strict TTL enforcement
  - constant-time verification

## Rollback Requirements

Rollback plans must be:
- Deterministic and fingerprinted.
- Validated against safety rails before execution.
- Executable in dry-run and enforce modes.
- Audited with per-step outcomes.

Safety rails:
- Fail closed by default.
- Require approvals for non-trivial actions.
- Prevent irreversible steps in enforce unless explicitly allowed.
- Restrict data migrations in enforce unless explicitly allowed.

## Observability Requirements

WebUI and backend must expose:
- Request count, error rate, and latency distributions.
- Policy hits and denies.
- Approval validations:
  - allow/deny counts by reason
  - replay detections
  - TTL expirations
- Rollback execution outcomes and durations.

Metrics must be:
- Exportable via snapshot and compatible with external collectors.
- Low-cardinality by design.

## Supply Chain and CI Requirements

Build pipeline must include:
- Dependency pinning and integrity checks.
- Static analysis and SAST.
- SBOM generation.
- Signed artifacts (where supported by your platform policy).
- Reproducible builds where feasible.

## Browser and UI Security Controls

Required:
- CSP with strict policies.
- XSS prevention through safe templating and output encoding.
- CSRF protection for state-changing endpoints.
- Clickjacking protection (frame-ancestors / X-Frame-Options).
- Secure handling of redirects (open redirect prevention).
- Input validation and size limits.

## Operational Requirements

- Environment separation:
  - dev, staging, prod
- Configuration:
  - via environment variables and config files
- Rate limiting on auth and sensitive endpoints.
- Emergency controls:
  - break-glass mode with elevated audit and alerts
  - rapid rollback strategy

## Data Handling

- No sensitive personal data is required for core functionality.
- Any identifiers must be minimized and redacted in logs by default.
- Exports must support redaction rules.

## Testing Requirements

Minimum test categories:
- Unit tests:
  - RBAC decisions
  - policy serialization and hashing
  - challenge validation (TTL, nonce, replay)
  - rollback plan validation
- Integration tests:
  - end-to-end approvals
  - policy apply workflow
  - rollback execution dry-run
- Security tests:
  - CSRF, XSS, authZ bypass attempts
  - replay attack simulations

## Runbook Expectations

Operators must have:
- Clear procedures for:
  - policy rollback
  - emergency disable of enforcement mode
  - nonce store failures
  - audit sink degradation
- Alerts for:
  - approval replay spikes
  - deny spikes
  - 5xx spikes
  - audit pipeline failures

## Compatibility Notes

This README defines the WebUI contract. Backend and infrastructure specifics are implemented in their respective modules.
