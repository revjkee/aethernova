# WebUI Security Policy

## Scope

This document defines mandatory security requirements for all WebUI components
within the human sovereignty core.

These rules apply to:
- administrative WebUI
- internal dashboards
- operator and governance interfaces
- any browser-accessible control surface

## Threat Model

The WebUI is considered a high-risk attack surface due to:
- direct user interaction
- browser execution context
- exposure to XSS, CSRF, clickjacking, and session attacks
- potential privilege escalation paths

The default assumption is a hostile client environment.

## Access Model

- WebUI access is restricted by default.
- Public internet exposure is prohibited unless explicitly approved.
- All access must be authenticated and authorized.
- Anonymous access is forbidden.
- Role-based access control is mandatory.

## Network Restrictions

- WebUI must bind to loopback or private network interfaces by default.
- Direct exposure on 0.0.0.0 is prohibited.
- Reverse proxy access requires explicit security review.
- mTLS is recommended for administrative interfaces.

## Authentication and Sessions

- Strong authentication is mandatory.
- Session identifiers must be cryptographically random.
- Session expiration must be enforced.
- Idle timeout is required.
- Session fixation protection is mandatory.

## CSRF Protection

- CSRF protection is mandatory for all state-changing actions.
- Tokens must be bound to session and origin.
- SameSite cookie policy must be enforced.

## XSS Protection

- Output encoding is mandatory.
- User input must never be rendered as raw HTML.
- Inline scripts are prohibited.
- Dangerous DOM APIs must be avoided.

## Content Security Policy

A strict Content Security Policy is mandatory.

Minimum requirements:
- default-src 'none'
- script-src restricted to trusted origins
- object-src 'none'
- frame-ancestors 'none'

## Clickjacking Protection

- X-Frame-Options must deny framing.
- Frame embedding is prohibited.

## File Uploads and Downloads

- File uploads must be explicitly whitelisted.
- MIME type validation is mandatory.
- File size limits must be enforced.
- Uploaded content must never be executed.

## Logging and Auditing

- All authentication events must be logged.
- Privileged actions must be auditable.
- Logs must not expose secrets or tokens.

## Error Handling

- Error messages must not leak internal details.
- Stack traces must never be exposed in WebUI.
- Generic error responses are required.

## Prohibited Practices

The following are strictly prohibited:
- hardcoded credentials
- client-side authorization decisions
- trusting client-provided role or identity data
- exposing debug or development endpoints
- bypassing authentication for convenience

## Compliance

This policy aligns with:
- ISO IEC 27001
- OWASP ASVS
- Zero Trust security principles

Deviation from this policy requires documented architectural approval.

## Enforcement

This document is authoritative.
Violations are considered security defects and must be remediated immediately.

## Revision Policy

Changes to this document require security review.
This policy must not be weakened to accommodate implementation shortcuts.
