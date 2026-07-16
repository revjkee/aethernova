# human-sovereignty-core/security/misuse_cases.md

## Scope and purpose

This document enumerates misuse and abuse cases for Human Sovereignty Core (HSC).
It is intended to be used as:
- a security requirements baseline,
- a test-plan seed for security QA,
- an audit reference for governance controls.

System in scope (high level):
- Decision packets lifecycle (creation, hashing/immutability, approval, execution)
- Audit trace (events, spans, integrity)
- WebUI session management (login/logout/refresh)
- Read-only decision storage interface for WebUI
- Interfaces to external coordinators (e.g., Genius Core)

Assumptions:
- HSC is a security-critical system and must prioritize integrity and auditability.
- HSC may operate in hostile networks and must assume malicious clients.
- Secrets (keys, tokens) must never be logged in plaintext.

Definitions:
- Misuse case: unintended use by legitimate user (accidental or negligent).
- Abuse case: intentional malicious activity by an adversary.

Severity:
- Critical: compromises decision integrity, approval integrity, or audit integrity.
- High: compromises authentication/session integrity or sensitive metadata at scale.
- Medium: localized impact or requires privileged access.
- Low: nuisance, limited scope.

## Security invariants

INVARIANT-1: Decision packets must be immutable after issuance and verifiable via stable hashing.
INVARIANT-2: Approval must be explicit and attributable; forged approvals must be detectable.
INVARIANT-3: Audit trace must be append-only and tamper-evident; deletion/reordering must be detectable.
INVARIANT-4: WebUI session controls must resist common web attacks (CSRF, token theft, fixation).
INVARIANT-5: Read paths must be safe by default (redaction, least privilege, bounded output).
INVARIANT-6: External interfaces must be contract-driven; no implicit trust in payloads.

## Threat actors

TA-1: External attacker (unauthenticated internet client)
TA-2: Authenticated low-privilege user (insider or compromised account)
TA-3: Privileged operator (misconfigured or malicious)
TA-4: Supply chain attacker (dependency or build pipeline compromise)
TA-5: Network attacker (MITM, replay, downgrade attempts)
TA-6: Client-side attacker (XSS via WebUI supply, malicious browser extensions)

## Misuse and abuse cases catalog

### UC-01: Credential stuffing against WebUI login
Type: Abuse
Severity: High
Entry points:
- POST /sessions/login
Preconditions:
- Attacker has credential dumps, attempts many logins.
Impact:
- Account takeover, session issuance.
Signals:
- High rate of failed logins per IP or per identifier.
Mitigations:
- Rate limiting per IP and per identifier.
- Uniform error messages to prevent user enumeration.
- Optional MFA in upstream IAM.
- Monitoring: alert on unusual failed login patterns.

### UC-02: User enumeration via login error detail
Type: Abuse
Severity: Medium
Entry points:
- POST /sessions/login
Preconditions:
- Server returns different messages for “user not found” vs “wrong password”.
Impact:
- Enables targeted attacks.
Signals:
- Correlation between probe identifiers and response differences.
Mitigations:
- Single generic error response.
- Consistent timing (minimum processing duration).

### UC-03: Session fixation via attacker-controlled session identifier
Type: Abuse
Severity: High
Entry points:
- Login flow, session cookies
Preconditions:
- Session id is accepted from client or reused across logins.
Impact:
- Attacker pre-sets session and forces victim to authenticate into it.
Signals:
- Same session id observed across different clients before login.
Mitigations:
- Session id is server-generated only.
- Rotate session identifiers on login.

### UC-04: CSRF on refresh/logout in cookie mode
Type: Abuse
Severity: High
Entry points:
- POST /sessions/refresh
- POST /sessions/logout
Preconditions:
- Cookies auto-sent, no CSRF token validation.
Impact:
- Attacker can refresh tokens or log out victim, or chain to other actions.
Signals:
- Refresh/logout requests with missing/invalid CSRF token.
Mitigations:
- CSRF cookie + header double-submit token for cookie mode.
- Reject requests missing CSRF header value matching CSRF cookie.

### UC-05: Refresh token replay (no rotation)
Type: Abuse
Severity: Critical
Entry points:
- POST /sessions/refresh
Preconditions:
- Refresh tokens are long-lived and reusable.
Impact:
- Persistent takeover by replaying stolen refresh tokens.
Signals:
- Same refresh token used multiple times from different IP/UA.
Mitigations:
- Refresh rotation (one-time use) with server-side tracking (jti).
- Revoke token family on suspicious reuse.

### UC-06: Token theft via XSS on WebUI
Type: Abuse
Severity: Critical
Entry points:
- WebUI pages rendering user-controlled content.
Preconditions:
- Access/refresh tokens are accessible to JS or stored in localStorage.
Impact:
- Full account takeover.
Signals:
- Unusual token usage patterns, anomalous UA.
Mitigations:
- Use HttpOnly cookies for tokens.
- Content Security Policy (CSP) and strict input sanitization.
- Avoid storing tokens in localStorage/sessionStorage.

### UC-07: Open redirect used to leak tokens
Type: Abuse
Severity: High
Entry points:
- Any redirect endpoint.
Preconditions:
- Redirect URLs accept unvalidated external domains.
Impact:
- Tokens or sensitive state leak.
Signals:
- Redirects to unexpected origins.
Mitigations:
- Allow-list redirect targets; never include tokens in URL.

### UC-08: Decision packet tampering in transit
Type: Abuse
Severity: Critical
Entry points:
- Packet ingestion endpoints (not detailed here), internal RPC.
Preconditions:
- No TLS or no integrity verification, or weak canonicalization.
Impact:
- Changes decision semantics; breaks sovereignty.
Signals:
- Hash mismatch between stored/received packet.
Mitigations:
- Stable canonical hashing of packet.
- Reject if computed hash differs.
- Enforce TLS/mTLS on service boundaries.

### UC-09: Hash canonicalization ambiguity
Type: Misuse/Abuse
Severity: High
Entry points:
- decision packet hashing
Preconditions:
- Different JSON encodings produce different hashes for same semantic content.
Impact:
- Inability to verify immutability reliably; false negatives.
Signals:
- Same logical packet yields different digests across nodes.
Mitigations:
- Deterministic JSON canonicalization (sorted keys, fixed separators, no NaN).
- Document canonicalization rules and test vectors.

### UC-10: Approval forgery by client-side “approved=true”
Type: Abuse
Severity: Critical
Entry points:
- Approval submission endpoints or internal message bus.
Preconditions:
- Approval is accepted based only on client-provided flag.
Impact:
- Unauthorized execution.
Signals:
- Approvals lacking signature/authority attribution.
Mitigations:
- Approval must be signed or verifiable via trusted authority.
- Store approval metadata: who, when, why, what was approved (packet hash binding).

### UC-11: Replay of prior approval on a different packet
Type: Abuse
Severity: Critical
Entry points:
- Approval handling
Preconditions:
- Approval not bound to packet hash and decision id.
Impact:
- Approves unintended decision.
Signals:
- Approval references mismatch between packet hash and approval record.
Mitigations:
- Bind approval to (decision_packet_id, decision_packet_hash, trace_id).
- Reject if mismatch.

### UC-12: Audit tampering by deleting or reordering events
Type: Abuse
Severity: Critical
Entry points:
- Audit storage or transport
Preconditions:
- Audit trace stored without integrity chain.
Impact:
- Loss of accountability; stealthy compromise.
Signals:
- Gaps in sequence, inconsistent prev_hash chain.
Mitigations:
- Append-only hash chain for events (prev_event_hash).
- Optional HMAC over event hashes (keyed integrity).
- Periodic anchoring of trace root hash into immutable store.

### UC-13: Audit injection with secrets
Type: Misuse
Severity: High
Entry points:
- Logging/audit emitters, trace attrs
Preconditions:
- Developers log tokens, passwords, private keys.
Impact:
- Credential exposure and lateral movement.
Signals:
- Presence of high-entropy strings in logs; known secret patterns.
Mitigations:
- Deterministic redaction policy for deny-listed keys and patterns.
- CI lint rules for logging secrets.
- Runtime guardrails: block known secret keys from being persisted.

### UC-14: WebUI read endpoint leaks full decision packet
Type: Misuse/Abuse
Severity: High
Entry points:
- Decision store read/list
Preconditions:
- WebUI request asks for full packet by default.
Impact:
- Sensitive evidence or internal metadata exposed.
Signals:
- Large payloads returned; requests from low-priv roles.
Mitigations:
- Safe defaults: do not include full packet unless explicitly allowed.
- Redaction on all outputs.
- Enforce least privilege in access policy.

### UC-15: Over-fetch DoS via unbounded list limit
Type: Abuse
Severity: Medium
Entry points:
- Decision list endpoints
Preconditions:
- limit parameter is unbounded or large.
Impact:
- CPU/memory exhaustion.
Signals:
- Large response sizes, increased latency.
Mitigations:
- Hard bounds on limit (e.g., max 200).
- Cursor pagination.
- Server-side timeouts.

### UC-16: Cursor tampering to bypass pagination constraints
Type: Abuse
Severity: Medium
Entry points:
- list cursor token
Preconditions:
- Cursor is not validated or can request arbitrary indices.
Impact:
- Out-of-range scans, potential data exposure patterns.
Signals:
- Invalid cursor decode errors.
Mitigations:
- Validate cursor base64url + JSON schema.
- Treat cursor as opaque; optionally sign cursor values.

### UC-17: Privilege escalation via role/scope confusion
Type: Abuse
Severity: Critical
Entry points:
- AccessContext / RBAC enforcement
Preconditions:
- Confusing roles and scopes or trusting client-supplied roles.
Impact:
- Unauthorized read or execution approval.
Signals:
- AccessContext roles appear client-controlled.
Mitigations:
- Roles/scopes must be derived from server-side verified token claims.
- Centralize authorization checks in access policy.

### UC-18: Time-based attacks on token expiration or clock skew
Type: Misuse/Abuse
Severity: Medium
Entry points:
- session issuance, refresh
Preconditions:
- Node clocks drift, leading to invalid tokens or extended validity.
Impact:
- Availability issues or unintended long-lived sessions.
Signals:
- Spikes in “token expired” errors correlated to one node.
Mitigations:
- NTP synchronization; accept limited leeway; rotate keys carefully.

### UC-19: Dependency confusion or malicious package update
Type: Abuse
Severity: Critical
Entry points:
- Build pipeline, dependencies
Preconditions:
- Unpinned dependencies, unsafe registries.
Impact:
- Remote code execution in build/runtime; key theft.
Signals:
- Unexpected dependency versions; SBOM changes.
Mitigations:
- Pin dependencies, use lockfiles.
- SBOM generation + signature verification.
- Restrict registries, use allow-lists.

### UC-20: Leakage of refresh token via server logs
Type: Misuse
Severity: Critical
Entry points:
- Access logs, exception traces
Preconditions:
- Logging request bodies or headers containing tokens.
Impact:
- Token theft from logs.
Signals:
- Tokens appear in logs; large entropy strings.
Mitigations:
- Never log Authorization header or cookies.
- Structured logging with explicit allow-list fields.

### UC-21: Decision packet hash mismatch not enforced
Type: Misuse
Severity: Critical
Entry points:
- Packet read/verify path
Preconditions:
- UI/store does not verify integrity.
Impact:
- UI displays tampered packets as valid.
Signals:
- No integrity checks performed; missing hash validation metrics.
Mitigations:
- Verify integrity by default where feasible; fail closed for privileged views.
- Surface integrity status to UI.

### UC-22: Unsafe deserialization in evidence/audit fields
Type: Abuse
Severity: High
Entry points:
- Evidence rendering in WebUI
Preconditions:
- Evidence contains HTML/JS rendered unsafely.
Impact:
- XSS, token theft, UI compromise.
Signals:
- Script tags or suspicious markup in evidence.
Mitigations:
- Treat all evidence as untrusted; render as text.
- Strict escaping and CSP.

### UC-23: Cross-core interface trust without validation
Type: Abuse
Severity: High
Entry points:
- Genius Core interface calls
Preconditions:
- Accepts guidance/approval without schema or sanity checks.
Impact:
- Malicious/compromised Genius Core pushes unsafe instructions.
Signals:
- Guidance payload anomalies, unexpected directives.
Mitigations:
- Validate interface payloads.
- Apply policy and intent validation before execution.
- Record all cross-core interactions in audit trace.

### UC-24: Insider modifies limits configuration to weaken security
Type: Abuse
Severity: High
Entry points:
- config/limits.yaml
Preconditions:
- No change control, no signature.
Impact:
- Increased limits enabling DoS or reduced verification.
Signals:
- Config changes without approval trace.
Mitigations:
- Immutable config distribution; signed configs; change approval process.

## Mapping to controls

Controls categories:
- Authentication and session security: UC-01..UC-07, UC-18, UC-20
- Packet integrity: UC-08..UC-11, UC-21
- Audit integrity: UC-12..UC-13
- Data exposure prevention: UC-14, UC-22
- Availability controls: UC-15..UC-16
- Authorization and governance: UC-17, UC-23, UC-24
- Supply chain: UC-19

## Testability notes

Minimum tests:
- CSRF required in cookie mode for refresh/logout (UC-04).
- Refresh rotation rejects replay (UC-05).
- Canonical hash stable across runs (UC-09).
- Audit hash chain verification fails on tampering (UC-12).
- Redaction removes deny-listed keys (UC-13).
- List limit bounded and cursor validated (UC-15, UC-16).
- Authorization denies reads without required scope (UC-17).
