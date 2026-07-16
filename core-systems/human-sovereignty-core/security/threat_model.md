# human-sovereignty-core Threat Model

Version: 1.0.0
Last updated: 2026-01-27
Owners: Security Core, Human Sovereignty Core

## 1. Scope

This threat model covers the human-sovereignty-core subsystem, including:
- decision_packets validation layer
- approval subsystem (requests, challenges, human token issuance and verification)
- approval channels (messenger_channel notifications)
- audit subsystem (append-only ledger writer)
- observability subsystem (security events taxonomy and sinks)
- WebUI server routes for approval requests and challenge retrieval
- WebUI RBAC model with roles VIEWER and REVIEWER

Out of scope:
- external IdP, OAuth/OIDC provider, SSO infrastructure
- client-side WebUI frontend code
- network perimeter appliances and cloud-specific controls
- database implementations if replaced from in-memory to external stores

Methodology:
- STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is used as a threat taxonomy.
Source: Microsoft STRIDE overview. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats

## 2. Security invariants

Invariant A: WebUI must never be able to approve.
- WebUI roles are limited to VIEWER and REVIEWER.
- No APPROVER role exists and must not be introduced.
- WebUI routes create approval requests and expose challenges only.

Invariant B: Approval requires a human action outside of any automatic server side effect.
- messenger_channel only notifies and requests, never approves.

Invariant C: Audit is append-only and tamper-evident.
- Each audit record must chain to previous_hash and include its own event_hash.

Invariant D: Security observability events must be structured, redacted, deduplicated, and safe to emit.

## 3. Assets

A1. Approval request records
- request_id, status, policy_id, action_id, actor_id, reason, context, challenge, TTLs

A2. Challenge secret material
- challenge HMAC secret used to mint challenge payloads

A3. Human approval tokens
- compact signed tokens used as proof of human approval (HS256 as implemented)

A4. Audit ledger
- append-only file or equivalent storage for audit events and hashes

A5. Security events stream
- auth failures, CSRF blocks, rate-limit hits, anomalies

A6. Decision packets
- structured packets that drive gating decisions and policy evaluation

A7. RBAC role assignment signals
- request.state.role or equivalent upstream claims

## 4. Actors

- Legitimate user (VIEWER)
- Legitimate user (REVIEWER)
- External attacker without credentials
- Attacker with stolen credentials
- Malicious insider with limited access
- Compromised service account or CI agent
- Supply chain attacker (dependency, build pipeline)

## 5. Trust boundaries

TB1. Browser to WebUI server boundary
- Requests over HTTPS
- Inputs: JSON payloads, headers (Idempotency-Key), user-agent, client IP

TB2. WebUI server to approval store boundary
- In-memory store or external datastore
- Must preserve idempotency semantics

TB3. WebUI server to messenger transport boundary
- Transport is a pluggable integration (Telegram, email, etc.)
- Must be one-way, no approve side effects

TB4. human_token codec boundary
- Token signing and verification with HMAC secret key(s)

TB5. audit ledger boundary
- File system boundary and write permissions
- Append-only semantics must be enforced operationally

TB6. observability sink boundary
- External log aggregator, SIEM, metrics system

## 6. Assumptions

- HTTPS termination is correctly configured and enforced.
- Upstream authentication is present and sets request.state.role reliably.
- Secrets are provided securely via environment or secret manager and not committed to source control.
- Time source is reasonably accurate on servers.

These assumptions must be verified during deployment review.
References:
- OWASP ASVS sections on authentication and session management. https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-53 Rev. 5 controls on access control and audit. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

## 7. Attack surface

- POST /approvals/requests
- GET  /approvals/requests/{request_id}
- Any route protected by RBAC dependencies
- messenger transport integration endpoints or APIs
- audit ledger file path and OS permissions
- secrets injection mechanism
- log sinks and telemetry pipelines

## 8. Threats and mitigations (STRIDE)

### 8.1 Spoofing

Threat S1: Attacker spoofs role assignment (request.state.role) to gain REVIEWER access.
Impact: unauthorized access to review-only endpoints, data exposure.
Mitigations:
- Do not trust client-provided role headers; role must be derived from verified auth token/session.
- Bind role to verified identity claims (JWT signature validation).
- Enforce 401 when role missing or invalid.
References:
- OWASP ASVS authentication and access control requirements. https://owasp.org/www-project-application-security-verification-standard/
- RFC 7519 JSON Web Token. https://www.rfc-editor.org/rfc/rfc7519

Threat S2: Attacker spoofs client identity via X-Forwarded-For.
Impact: rate limiting bypass, incorrect fingerprint binding.
Mitigations:
- Only honor X-Forwarded-For from trusted reverse proxies.
- Prefer server-provided client IP metadata from the edge.
References:
- OWASP guidance on proxy headers and client IP trust. https://cheatsheetseries.owasp.org/

### 8.2 Tampering

Threat T1: Tampering with approval request payload to alter policy_id or action_id.
Impact: request misbinding, approval for wrong action.
Mitigations:
- Validate all fields server-side with strict schemas.
- Canonicalize and hash key fields for stable identifiers.
- Store immutable policy_id and action_id within the request record.
References:
- OWASP ASVS input validation requirements. https://owasp.org/www-project-application-security-verification-standard/

Threat T2: Tampering with audit ledger file contents.
Impact: cover tracks, invalidate investigation.
Mitigations:
- Hash chaining with previous_hash and event_hash.
- OS-level append-only enforcement where supported.
- Run ledger writer under least privilege, dedicated user.
References:
- NIST SP 800-53 AU family (Audit and Accountability). https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

### 8.3 Repudiation

Threat R1: Actor denies requesting approval or denies actions taken.
Impact: dispute, forensic failure.
Mitigations:
- Audit records include timestamps, actor identifiers, trace/request IDs.
- Append-only chain allows detection of removal or modification.
References:
- NIST SP 800-53 AU controls. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

Threat R2: Messenger delivery disputes (not received).
Impact: inability to prove request was sent.
Mitigations:
- Store delivery receipts with transport message_id.
- Log send attempts and failures as security events.
References:
- OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

### 8.4 Information Disclosure

Threat I1: Leakage of secrets in logs (tokens, authorization headers).
Impact: credential compromise.
Mitigations:
- Redaction of sensitive fields in security events and notifications.
- Never log full tokens or secrets; log hashes or truncated IDs only.
References:
- OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

Threat I2: Unauthorized access to approval request data.
Impact: exposure of operational decision context.
Mitigations:
- RBAC enforcement for all sensitive endpoints.
- Minimum role access for viewing request details.
References:
- OWASP ASVS access control requirements. https://owasp.org/www-project-application-security-verification-standard/

### 8.5 Denial of Service

Threat D1: Flood POST /approvals/requests to exhaust store capacity.
Impact: service degradation, denial of approvals.
Mitigations:
- Per-IP rate limiting (token bucket).
- Hard cap on store items, garbage collection of expired records.
- Consider external store with eviction policies in distributed deployments.
References:
- OWASP DoS guidance. https://cheatsheetseries.owasp.org/

Threat D2: Flood security event pipeline or audit ledger writes.
Impact: storage growth, performance collapse.
Mitigations:
- Dedupe of events by hash for a time window.
- Maximum payload size enforcement.
- Backpressure or drop policy for non-critical events.
References:
- OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

### 8.6 Elevation of Privilege

Threat E1: Introduction of APPROVER role via code drift.
Impact: bypass invariant A, unauthorized approvals.
Mitigations:
- Explicit absence of APPROVER role in RBAC enum and defensive guards.
- Unit tests that fail build if "approver" appears in role config.
- Policy-as-code checks in CI.
References:
- NIST SP 800-53 AC controls. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

Threat E2: Abuse of challenge endpoint to mint approvals.
Impact: converting challenge into approval token without human action.
Mitigations:
- Challenge is not an approval token and has no approve semantics.
- Separate approval token issuance into dedicated flow requiring explicit human confirmation.
- Ensure WebUI routes do not call token issuance functions.
References:
- RFC 7515 JSON Web Signature (for signed tokens behavior). https://www.rfc-editor.org/rfc/rfc7515

## 9. Security requirements

SR1. Authentication and role injection must be cryptographically verified upstream.
- WebUI must reject missing or invalid roles with 401.

SR2. Authorization must be deny by default.
- Only VIEW and REVIEW permissions exist.

SR3. Approval request creation must be idempotent.
- Support Idempotency-Key and dedupe semantics.

SR4. Rate limiting is mandatory on approval endpoints.
- Enforce per IP or per identity.

SR5. Challenges must be tamper-evident.
- HMAC over canonical content, time bound.

SR6. No server-side approve operations in WebUI.
- No endpoints that mark approved or issue approval tokens.

SR7. Audit ledger must be append-only and tamper-evident.
- Hash chain required.

SR8. Observability events must redact secrets and enforce size limits.

## 10. Logging and auditing

- All approval request creates and reads must emit audit events.
- All auth failures, csrf blocks, rate-limit hits, anomalies must emit security events.

References:
- OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST SP 800-53 AU controls. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

## 11. Privacy considerations

- Minimize PII in context (IP, user agent). Store only what is necessary.
- Apply redaction and truncation rules.
Reference:
- NIST Privacy Framework overview. https://www.nist.gov/privacy-framework

## 12. Supply chain threats

- Dependency tampering, malicious packages, compromised build agents.
Mitigations:
- Pin dependencies, verify hashes, use SBOM, sign artifacts, enforce CI provenance.
References:
- SLSA framework. https://slsa.dev/
- NIST guidance on software supply chain risk management (SSCRM). https://csrc.nist.gov/projects/sscrm

## 13. Verification and testing

Minimum required tests:
- RBAC: VIEWER cannot access REVIEW routes; REVIEWER can; any "approver" role triggers failure.
- Approvals: POST creates request, GET returns same; idempotency returns same request_id.
- Rate limiting: exceeds threshold returns 429.
- Challenge: cannot be used to approve; no endpoints exist for approving.
- Audit: chain integrity validation on appended records.
- Observability: redaction removes known secret fields.

References:
- OWASP ASVS verification approach. https://owasp.org/www-project-application-security-verification-standard/

## 14. Residual risks

- In-memory stores are single-node and volatile; risk of loss on restart.
- Trust in upstream auth and proxy headers must be validated in deployment.
- Audit ledger file protection depends on OS configuration and deployment environment.

These must be addressed as part of deployment hardening and operational runbooks.
