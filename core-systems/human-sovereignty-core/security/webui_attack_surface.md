<!-- path: human-sovereignty-core/security/webui_attack_surface.md -->

# WebUI Attack Surface for Human Sovereignty Core

Version: 1.0  
Owner: Human Sovereignty Security  
Scope: WebUI (client + server), authentication, sessioning, API boundary, browser execution context  
Confidentiality: Internal (security)

## 1. Purpose

This document enumerates the WebUI attack surface for Human Sovereignty Core and defines mandatory controls to ensure:
- Human mandate cannot be bypassed by UI-originated actions.
- No agent or remote origin can coerce privileged actions via browser context.
- Security posture is deny-by-default, fail-closed on ambiguity.

## 2. System Overview

WebUI consists of:
- Client: browser application (renders human control surfaces, submits approvals/decisions, visualizes audit).
- Server: WebUI backend (ASGI) with middleware (CSRF, auth, rate-limit, headers), and API proxy/bindings.
- Security modules: sanitization, anti-CSRF, session hardening, audit chain integration, command freezer integration.

Primary security goal: preserve human sovereignty under active web threat model (XSS/CSRF/session theft/supply chain).

## 3. Trust Boundaries

### 3.1 Boundaries
- B1: Internet origin -> WebUI server (TLS termination, mTLS optional)
- B2: WebUI server -> Core APIs (internal network boundary)
- B3: Browser execution context (untrusted runtime; extensions, injected scripts, compromised device)
- B4: Identity boundary (session cookies, tokens, MFA)
- B5: Storage boundary (localStorage/sessionStorage/IndexedDB, cookies)
- B6: Build and dependency boundary (client bundler, npm ecosystem, CI artifacts)

### 3.2 Assets
- A1: Human approvals (signatures, approvals, expiration)
- A2: Decision packets and lifecycle state
- A3: Audit chain and ledger proofs
- A4: Admin controls and bindings
- A5: Secrets and credentials (session tokens, API tokens, mTLS keys)
- A6: WebUI configuration (bind address, allowlists, CSP policy)

### 3.3 Attackers
- E1: Remote web attacker (phishing, CSRF, clickjacking)
- E2: Network attacker (MITM if TLS compromised, DNS attacks)
- E3: Supply chain attacker (dependency compromise)
- E4: Local attacker (malware/extension, compromised browser profile)
- E5: Insider attacker (misuse of privileges)
- E6: Automated agents attempting to escalate privileges via UI

## 4. Entry Points

### 4.1 Client Entry Points
- Rendering of any untrusted content (HTML, markdown, logs, error messages)
- Dynamic links (href), navigation, file downloads
- Form submissions (approvals, policy edits)
- WebSocket/SSE streams (live audit, incidents)
- Clipboard operations (copy tokens)
- File upload (if present): config import, evidence attachments

### 4.2 Server Entry Points
- HTTP endpoints (login, session refresh, approve/deny, audit export)
- API proxy endpoints (if WebUI proxies core APIs)
- WebSocket/SSE endpoints
- Static assets hosting (JS bundles, source maps)
- CORS preflight handling (OPTIONS)
- Health endpoints (if exposed)

## 5. High-Risk Threat Classes (WebUI)

### 5.1 XSS (Stored, Reflected, DOM)
Impact:
- Steal session/CSRF tokens.
- Trigger approvals invisibly.
- Alter displayed audit state.
- Exfiltrate sensitive decisions.

Mandatory controls:
- Strict sanitization for any rich content.
- Prefer text rendering over HTML.
- Content Security Policy (CSP) with nonces or strict-dynamic.
- Trusted Types for sinks when feasible.
- Disable inline script and dangerous sinks.

### 5.2 CSRF
Impact:
- Unauthorized state changes under victim session.

Mandatory controls:
- CSRF middleware for unsafe methods.
- Double-submit or synchronizer token required.
- Origin/Referer validation with strict allowlist.
- SameSite cookies (Strict preferred).
- Reject requests missing required headers.

### 5.3 Session Hijacking / Fixation
Impact:
- Attacker gains control of approval surface.

Mandatory controls:
- Short session TTL, rotation, device binding where possible.
- HttpOnly + Secure cookies.
- Re-auth or step-up for high-risk actions.
- Detect anomalous session usage.

### 5.4 Clickjacking / UI Redress
Impact:
- Trick human into confirming actions.

Mandatory controls:
- Frame-ancestors restriction (CSP) and/or X-Frame-Options deny.
- High-risk actions require explicit UI confirmation with anti-automation cues.
- Disable cross-origin embedding.

### 5.5 CORS Misconfiguration
Impact:
- Unauthorized JS access to APIs.

Mandatory controls:
- Default deny CORS.
- Explicit allowlist of origins; no wildcard with credentials.
- Separate origins for admin vs user if possible.

### 5.6 Supply Chain Attacks (Client)
Impact:
- Malicious dependency executes in browser, steals approvals.

Mandatory controls:
- Lockfiles, integrity verification, SBOM.
- Dependency allowlist and automated auditing.
- Signed builds and provenance checks.
- Avoid loading third-party scripts at runtime.

### 5.7 SSRF and Server-Side Proxy Abuse
Impact:
- WebUI server used to reach internal services.

Mandatory controls:
- Strict allowlist for outbound calls if proxying.
- Block link-local, metadata endpoints, internal ranges unless explicit.
- Normalize and validate URLs and redirects.

### 5.8 Sensitive Data Exposure
Impact:
- Audit/approvals leak via logs, cache, or client storage.

Mandatory controls:
- Never store secrets in localStorage.
- Redact tokens in logs and UI.
- Set Cache-Control for sensitive endpoints.
- Strip source maps in production.

### 5.9 DoS / Resource Exhaustion
Impact:
- WebUI unavailable, approvals delayed.

Mandatory controls:
- Rate limiting, request size caps.
- WebSocket message limits.
- Circuit breakers for downstream calls.

## 6. Mandatory Security Headers (Server)

The server must enforce:
- Strict transport security (HSTS) when applicable
- CSP with tight directives and no unsafe-inline
- Referrer policy to avoid token leakage
- X-Content-Type-Options nosniff
- Permissions policy to reduce browser capabilities
- Frame embedding restrictions

## 7. Client-Side Hardening Requirements

- Use sanitization utilities for all untrusted strings.
- Avoid dangerouslySetInnerHTML; if unavoidable, require Trusted Types and sanitizer.
- Sanitize URLs before assigning to href/src.
- Never interpolate untrusted data into style attributes.
- Avoid eval/new Function and dynamic script injection.
- Do not persist auth tokens in localStorage.

## 8. Human Sovereignty Specific Threats

### 8.1 Approval Coercion
Scenario:
- UI shows altered context to trick human into approval.

Controls:
- Canonical “decision summary” rendered from server-signed payload.
- Display immutable audit fingerprint (hash) for action being approved.
- Require explicit human action sequence for approval (no single-click approvals).
- Timeout and re-auth for sensitive approvals.

### 8.2 Replay of Approvals
Scenario:
- Captured approval request replayed.

Controls:
- Nonce + expiration on approval packets.
- Server rejects reused nonce.
- Bind approval to session and device context where possible.

### 8.3 Confused Deputy via UI Bindings
Scenario:
- UI endpoint proxies action that bypasses policy.

Controls:
- Every WebUI action must map to a policy-checked decision packet.
- Server must enforce invariants independent of client intent.
- Deny if any invariant cannot be verified.

## 9. Abuse Cases Checklist

- Untrusted HTML rendering from logs
- Link injection in audit entries
- Mixed content (http resources)
- Cross-origin redirects
- File upload leading to stored XSS
- Export endpoints leaking data
- Misconfigured CORS allowing credentials
- Overly permissive CSP
- Cookies without SameSite/Secure/HttpOnly
- Weak session rotation

## 10. Security Testing Requirements

Minimum:
- Automated linting for XSS sinks.
- Unit tests for sanitizer and CSRF middleware.
- Integration tests for session cookies and headers.
- Negative tests for CORS and clickjacking.
- Dependency scanning and SBOM verification.

## 11. Operational Controls

- Separate dev and prod configs; prod binds to loopback or mTLS-only listener.
- Structured audit logs without secrets.
- Alerting on repeated CSRF failures and login anomalies.
- Emergency “freeze UI actions” switch (deny all unsafe methods).

## 12. Release Gate

A release is blocked if any of:
- CSP is permissive (unsafe-inline) without nonces/Trusted Types and documented exception.
- CSRF is disabled for unsafe methods.
- Cookies are not Secure/HttpOnly in production.
- CORS is wildcard with credentials.
- Untrusted HTML is rendered without sanitizer.

## 13. Appendix: Definitions

- XSS: Script execution in user browser from untrusted data.
- CSRF: Unauthorized state change by abusing browser credentials.
- Clickjacking: UI overlay to trick user interaction.
- CSP: Policy restricting resource loading and script execution.

