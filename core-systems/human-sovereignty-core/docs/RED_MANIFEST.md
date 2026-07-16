# RED Manifest

Version: 1.0
Status: Normative
Scope: human-sovereignty-core

## 1. Purpose

RED Manifest defines the authoritative rules for building and governing the RED domain set.
RED domains are high-risk network identifiers that require special handling in enforcement,
approval, rollback, observability, and audit layers.

This document is written to be:
- Verifiable: every entry must be backed by sources that a reviewer can independently check.
- Auditable: changes must be attributable and reproducible.
- Deterministic: entries and their hashes must be stable across environments.
- Abuse-resistant: the process must prevent sabotage and unauthorized additions.

## 2. Definitions

RED domain:
A domain name or related network identifier (including subdomain patterns and IDNA forms)
classified as high-risk under the criteria in this manifest.

Entry:
A single structured record in `config/red_domains.yaml`.

Source:
A verifiable external reference used to justify classification.
Sources must be stored as machine-checkable references (URL, title, publisher, date, and
optional archive pointers) and must be reviewable without relying on personal judgement alone.

Reviewer:
A person or automated gate that validates evidence and policy compliance.

## 3. What is NOT allowed

- Adding entries without sources.
- Using vague or unverifiable claims as justification.
- Adding entries based on rumors, social media posts without primary confirmation, or private hearsay.
- Adding entries that are ambiguous, overly broad, or likely to cause collateral blocking without explicit scope and rationale.
- Adding entries that encode political, ethnic, religious, or other sensitive targeting criteria.
- Including personal data in entries.

If a classification cannot be verified, it must not enter RED.

## 4. Classification Criteria

An entry may be classified as RED only if it matches one or more criteria below AND the evidence
requirements in Section 5 are met.

Allowed criteria categories:

C1. Confirmed malicious infrastructure
- Domains used for malware distribution, C2, phishing, credential theft, or exploit delivery.

C2. Confirmed impersonation and fraud infrastructure
- Domains that impersonate legitimate brands or services for financial or account compromise.

C3. High-confidence abuse infrastructure
- Domains repeatedly associated with abuse campaigns with corroboration across independent sources.

C4. Explicitly restricted domains by internal policy
- Domains blocked due to internal safety policy, contractual obligations, or compliance requirements.
These must be tied to a documented policy decision and approvals.

C5. Emergency temporary blocking
- Short-lived entries introduced for incident containment.
Must include expiry and a mandatory review date.

## 5. Evidence and Source Requirements

### 5.1 Source quality rules

A RED entry MUST have at least:
- 2 independent sources for non-emergency additions (C1-C4)
- 1 source for emergency temporary blocking (C5), plus incident record

Sources MUST:
- Be independently checkable (publicly accessible or archived).
- Include publisher identity.
- Include publication date or observed date.
- Specify the domain (or unambiguous pattern) referenced.

Sources MUST NOT:
- Be anonymous claims with no backing.
- Be copy-paste mirrors with no primary provenance.
- Be unverifiable screenshots without traceable origin.

### 5.2 Archiving and durability

For each source, the record SHOULD include at least one durable pointer:
- Archive URL
- Snapshot hash
- Internal evidence bundle reference id

If a durable pointer is missing, the entry MUST have a short review interval.

### 5.3 Non-verified cases

If evidence is incomplete:
- The entry MUST NOT be added to RED.
- Use a separate “watchlist” mechanism (out of scope for this document).

## 6. Data Model Contract for red_domains.yaml

This manifest defines mandatory fields for each entry.

### 6.1 Required fields

- id: Stable identifier for the entry (string, unique).
- domain: Domain name or pattern (string).
- match: One of:
  - exact
  - suffix
  - wildcard
  - regex
- risk: One of:
  - low
  - medium
  - high
  - critical
- category: One of C1..C5.
- rationale: Short, factual explanation.
- sources: Array of sources (see 6.2).
- created_at: ISO-8601 date.
- created_by: Actor identifier.
- review:
  - next_review_at: ISO-8601 date
  - max_review_interval_days: integer
- enforcement:
  - action: block | challenge | allow_with_monitoring
  - severity: integer 1..10

### 6.2 Source object fields

Each source object MUST include:
- url: Source URL
- title: Source title
- publisher: Publisher / organization name
- published_at: ISO-8601 date (or observed_at if not published)
Optional:
- archive_url
- evidence_ref (internal reference id)
- notes (short)

### 6.3 Optional fields

- expires_at: ISO-8601 date (mandatory for C5)
- incident_id: For C5 or incident-linked entries
- tags: Array of strings
- ioc_bundle_ref: Internal bundle reference id
- confidence: integer 1..100

## 7. Canonicalization and Integrity

To keep enforcement deterministic:
- All domains must be stored in lower-case ASCII or IDNA A-label form.
- No trailing dot.
- No whitespace.
- The YAML must be canonicalizable for stable hashing.
- Each entry SHOULD have a computed fingerprint in audit logs derived from canonical JSON.

If canonicalization rules are violated, the entry must be rejected in CI.

## 8. Change Control and Approvals

### 8.1 Standard changes (C1-C4)

Required:
- Pull request with diff
- At least two approvals
- One reviewer must be security-qualified
- All sources validated by automated checks where possible

### 8.2 Emergency changes (C5)

Allowed only for incident containment.
Required:
- Incident id
- Single approver (break-glass allowed)
- Mandatory expiry
- Mandatory review date within a short interval

Emergency entries must be automatically surfaced to audit and alerts.

## 9. Review and Expiry Rules

- Every entry MUST have `next_review_at`.
- Entries MUST be re-validated at or before `next_review_at`.
- C5 entries MUST expire by `expires_at` unless explicitly renewed with evidence and approvals.
- Expired entries must be removed or transitioned to a non-enforcing list.

## 10. Observability Requirements

Systems enforcing RED MUST emit:
- decision metrics by category and action
- deny and challenge counts
- top denied domains, with cardinality controls
- correlation with request_id / trace_id for audit

The system MUST be able to provide a decision explanation:
- which rule id matched
- why it matched
- what sources and approvals exist for the entry

## 11. Audit Requirements

Every change MUST be recorded with:
- who made the change
- approvals
- timestamps
- entry fingerprint before/after
- linked incident id if applicable

Audit must be immutable or append-only at sink.

## 12. Compliance and Neutrality

RED is a technical safety mechanism.
Entries must never be used to implement discriminatory targeting.
Decisions must be based on verifiable evidence and documented policy.

## 13. Implementation Notes

This manifest is the normative contract for:
- `config/red_domains.yaml`
- WebUI policy workflows
- Approval challenge system
- Rollback planning and execution
- Observability and audit correlation

Any deviation requires a versioned update to this manifest and approval under the same rules.
