# ADR 0007: Loyalty and Rewards Architecture

## Status

Accepted

## Date

2026-03-22

## Owners

Architecture
Backend
Product

## Related ADRs

- 0001-system-overview.md
- 0002-modular-monolith-strategy.md
- 0003-tenancy-model.md
- 0004-auth-and-rbac.md
- 0005-booking-consistency.md
- 0006-payments.md

## Context

Reva Studio requires a loyalty and rewards subsystem that is reliable, auditable, tenant-safe, financially predictable, and compatible with the future evolution of the platform into a multi-tenant Beauty SaaS product.

The system must support:

- bonus accrual after completed services
- bonus redemption on eligible bookings or checkout
- reward rules per tenant
- expiration policies
- manual adjustments by authorized staff
- promotional campaigns
- anti-fraud controls
- complete auditability of all balance-affecting operations
- integration with bookings, payments, notifications, analytics, and admin back office

The architecture must avoid silent balance corruption, duplicate accrual, duplicate redemption, race conditions, and weak auditability. For high-value or balance-affecting operations, an audit trail with integrity controls is a recognized security requirement, and OWASP explicitly recommends such auditability for important transactions. :contentReference[oaicite:1]{index=1}

The design must also follow secure-by-design principles at the architecture level rather than treating security as a later implementation detail. OWASP Secure by Design explicitly positions security decisions in the architecture phase as a first-class concern. :contentReference[oaicite:2]{index=2}

Where loyalty interacts with payments, the platform must not store raw card data. PCI SSC publishes tokenization guidance specifically to reduce exposure and support safer payment architectures. :contentReference[oaicite:3]{index=3}

## Decision

We will implement loyalty as an internal ledger-based bounded context with append-only balance transactions and derived balances.

Core decision points:

1. Loyalty balance will not be stored as the primary source of truth.
2. The source of truth will be an append-only loyalty transaction ledger.
3. The current balance will be represented as a derived value, materialized for read performance and rebuilt from the ledger when necessary.
4. All balance-affecting commands must be idempotent.
5. Accrual will occur only after a booking reaches a terminal business status that qualifies for accrual.
6. Redemption will create a reservation first and a final debit only after booking/payment confirmation rules are satisfied.
7. Each tenant owns its own loyalty program configuration, rule set, campaigns, and financial limits.
8. All privileged mutations require RBAC authorization and immutable audit records.
9. Loyalty and rewards will remain provider-agnostic and payment-provider-neutral.
10. Raw payment card data must never enter the loyalty subsystem.

This decision is aligned with three externally supported constraints:

- idempotent requests are the recommended pattern to safely retry operations without creating duplicates; Stripe documents idempotency for exactly this purpose. :contentReference[oaicite:4]{index=4}
- asynchronous payment confirmation via webhooks is a standard integration pattern for external payment systems; Stripe documents webhook-driven handling for payment state changes. :contentReference[oaicite:5]{index=5}
- transaction and audit logs should be preserved distinctly and with sufficient integrity for investigation and monitoring; OWASP explicitly recommends this. :contentReference[oaicite:6]{index=6}

## Decision Drivers

### Business drivers

- increase retention and repeat visits
- support personalized promotions
- allow tenant-level differentiation
- control reward cost and liability
- support future marketplace and partner scenarios

### Technical drivers

- strong consistency for balance-affecting operations
- resilience to retries and webhook duplication
- high observability
- clean modular boundaries
- compatibility with modular monolith architecture
- future extraction into a dedicated service if needed

### Security and compliance drivers

- RBAC for privileged operations
- append-only auditability
- separation of payment-sensitive data from loyalty domain
- deterministic recalculation capability
- tenant isolation

## Scope

This ADR covers:

- loyalty points
- reward rules
- redemptions
- adjustments
- expirations
- promotions
- audit and analytics integration

This ADR does not define:

- gift cards
- external coalition loyalty across unrelated merchants
- on-chain tokenization of bonus points
- full accounting treatment in the general ledger

## Architecture Overview

The loyalty subsystem is implemented as a bounded context inside the modular monolith.

Primary modules:

- loyalty.domain
- loyalty.application
- loyalty.infrastructure
- loyalty.api

Key integrations:

- bookings
- payments
- users
- tenants
- notifications
- analytics
- admin

Primary architectural pattern:

- command side writes append-only transactions
- query side reads materialized balances and summaries
- domain events propagate state changes internally

## Domain Model

### Aggregate roots

#### LoyaltyAccount

Represents the loyalty state of a customer within a tenant.

Key fields:

- loyalty_account_id
- tenant_id
- customer_id
- status
- current_balance_cached
- reserved_balance_cached
- total_earned
- total_redeemed
- total_expired
- version

Notes:

- `current_balance_cached` is a performance optimization only
- the canonical value is the ledger sum
- one customer can have at most one active loyalty account per tenant

#### RewardRuleSet

Represents tenant-specific rules for earning and redeeming points.

Key fields:

- reward_rule_set_id
- tenant_id
- version
- status
- valid_from
- valid_to
- accrual_policy
- redemption_policy
- expiration_policy
- rounding_policy
- minimum_spend_policy
- eligible_service_scope
- excluded_service_scope

#### RewardCampaign

Represents a temporary or segmented promotion.

Key fields:

- reward_campaign_id
- tenant_id
- status
- audience_filter
- multiplier
- bonus_fixed_amount
- start_at
- end_at
- stack_policy
- budget_limit
- usage_limit

### Entities

#### LoyaltyLedgerEntry

Append-only transaction entry.

Types:

- earn
- redeem_reserve
- redeem_commit
- redeem_release
- expire
- adjust_credit
- adjust_debit
- reverse

Fields:

- loyalty_ledger_entry_id
- tenant_id
- loyalty_account_id
- entry_type
- points_delta
- monetary_reference_amount
- booking_id nullable
- payment_id nullable
- source_module
- source_event
- source_reference_id
- idempotency_key
- correlation_id
- causation_id
- created_by_type
- created_by_id
- reason_code
- metadata_json
- created_at

#### LoyaltyRedemption

Represents the lifecycle of a redemption request.

Statuses:

- pending
- reserved
- committed
- released
- cancelled
- failed

Fields:

- loyalty_redemption_id
- tenant_id
- loyalty_account_id
- booking_id
- reserved_points
- committed_points
- requested_discount_amount
- applied_discount_amount
- status
- idempotency_key
- expires_at
- created_at
- updated_at

#### LoyaltyBalanceSnapshot

Materialized read model for fast queries and analytics.

Fields:

- loyalty_account_id
- tenant_id
- available_points
- reserved_points
- lifetime_earned_points
- lifetime_redeemed_points
- lifetime_expired_points
- last_transaction_at
- rebuilt_at

## Invariants

The following invariants are mandatory:

1. A loyalty account belongs to exactly one tenant and one customer.
2. Ledger entries are immutable after commit.
3. A balance cannot be changed outside the ledger.
4. Available points cannot go below zero.
5. Reserved points cannot exceed available points at reservation time.
6. A single business operation must not create multiple accrual or redemption effects when retried.
7. A redemption commit must reference an existing reservation unless performed by an explicit administrative override.
8. Manual adjustments must include actor, reason code, and audit metadata.
9. Expiration must be deterministic and reproducible from rule version plus ledger history.
10. Cached balances may be rebuilt from the ledger at any time.

## Consistency Model

### Write consistency

Balance-affecting writes use strong transactional consistency inside the primary database transaction.

Inside one transaction the system must:

- lock the loyalty account row
- validate current state
- apply the domain command
- append ledger entries
- update cached counters
- write audit record
- emit outbox event

### Read consistency

User-facing balance screens may read from materialized snapshots that are near-real-time.
Administrative reconciliation and financial investigation views must support ledger-based exact reconstruction.

## Idempotency Strategy

All external and internal commands that may be retried must include an idempotency key.

Covered operations:

- accrue points for completed booking
- reserve points for redemption
- commit redemption
- release reservation
- manual adjustment
- expiration batch mutation
- compensation or reversal command

The system stores the idempotency key together with:

- command type
- tenant_id
- source_reference_id
- request hash
- resulting entity reference

If the same command is replayed with the same semantic payload, the system returns the original result.
If the key is reused with a different payload, the system rejects the request.

This follows the documented purpose of idempotency in Stripe: safe retries without duplicate object creation or duplicate side effects. :contentReference[oaicite:7]{index=7}

## Accrual Model

### Rule

Points are earned only after a booking becomes eligible for accrual.

Default eligible states:

- completed
- paid and completed

Non-eligible states:

- created
- pending
- cancelled
- no_show
- refunded in full

### Calculation

Default accrual formula:

`earned_points = floor(eligible_amount * earn_rate) + campaign_bonus`

Where:

- `eligible_amount` excludes tips, taxes, and excluded service lines unless tenant policy says otherwise
- `earn_rate` is defined per tenant rule version
- `campaign_bonus` may be fixed or multiplicative
- rounding policy is explicit and versioned

### Anti-duplication

Accrual command uniqueness:

`tenant_id + booking_id + accrual_rule_version + idempotency_key`

### Refund handling

Refund policy is configurable per tenant:

- no reversal for already consumed service
- partial reversal proportional to refunded eligible amount
- full reversal for fully reversed purchase if points were not already spent
- negative adjustment path if reversal occurs after redemption spending

## Redemption Model

### Two-phase redemption

We choose a two-phase model:

1. reserve points
2. commit or release reservation

Rationale:

- prevents overspending during booking/payment races
- supports checkout retries
- supports timeout-based reservation release
- keeps user-visible balance accurate as available versus reserved

### Redemption constraints

- redemption allowed only for active loyalty accounts
- minimum points threshold may apply
- maximum discount cap per booking may apply
- excluded services may block redemption
- campaign rules may disable stacking with other promotions
- reservation expires automatically after configured TTL

### Booking flow

1. client requests booking quote
2. system calculates redeemable amount
3. client chooses redemption amount
4. system creates reservation
5. booking/payment proceeds
6. on successful finalization, reservation is committed
7. on cancellation, failure, or timeout, reservation is released

### Payment interaction

Payment confirmation may arrive asynchronously through provider callbacks or webhooks. This is a normal pattern in payment APIs, and webhook-based asynchronous confirmation is explicitly documented by Stripe. :contentReference[oaicite:8]{index=8}

Therefore:

- redemption commit must react to confirmed business outcome
- reservation must survive temporary uncertainty
- duplicate webhook deliveries must not cause duplicate commits

## Expiration Policy

Expiration is configured per tenant rule set.

Supported policies:

- fixed days from accrual
- end of calendar month
- end of quarter
- rolling expiration by activity window
- no expiration

Expiration job characteristics:

- batch-oriented
- idempotent
- deterministic
- dry-run capable
- auditable

Each expiration entry must reference:

- original earning entry or earning cohort
- rule version used
- job execution id
- actor type system

## Manual Adjustments

Manual adjustments are allowed only to privileged roles defined by RBAC.

Required fields:

- tenant_id
- loyalty_account_id
- points_delta
- reason_code
- human-readable comment
- actor_id
- correlation_id

Controls:

- dual visibility in account history and admin audit
- optional approval workflow for large adjustments
- configurable adjustment thresholds per tenant
- anomaly alerts for burst or out-of-hours adjustments

## Security

### Access control

- customer may read only own loyalty data
- staff may read only tenant-scoped customer loyalty data according to role
- only privileged roles may issue adjustments or override reservations
- service-to-service internal access must be authenticated and authorized

### Data minimization

The loyalty subsystem stores only loyalty-relevant references to payments, never raw payment card data.
PCI SSC publishes tokenization guidance precisely because tokenization can reduce the exposure of sensitive payment data and improve safety when implementing payment-adjacent systems. :contentReference[oaicite:9]{index=9}

### Auditability

OWASP documents the importance of audit and transaction logs, and further recommends audit trails with integrity controls for high-value transactions. Loyalty debits and credits qualify as value-affecting business events in this architecture. :contentReference[oaicite:10]{index=10}

Therefore:

- all balance-affecting mutations create audit records
- audit records are append-only
- before-and-after snapshots are recorded for administrative changes
- correlation ids connect API request, domain command, ledger entry, and emitted event
- suspicious patterns feed observability and alerting

### Tamper resistance

- append-only ledger table
- immutable audit log
- restricted direct database write permissions
- outbox event signatures optional for future hardening
- reconciliation jobs detect drift between cached balance and ledger-derived balance

## Observability

The subsystem emits structured events and metrics.

Metrics:

- loyalty_accrual_total
- loyalty_redemption_reserve_total
- loyalty_redemption_commit_total
- loyalty_redemption_release_total
- loyalty_expiration_total
- loyalty_adjustment_total
- loyalty_idempotency_replay_total
- loyalty_balance_rebuild_total
- loyalty_rule_eval_latency_ms
- loyalty_reservation_timeout_total

Logs must separate transaction/audit concerns from security monitoring where appropriate, consistent with OWASP logging guidance. :contentReference[oaicite:11]{index=11}

Tracing attributes:

- tenant_id
- customer_id
- loyalty_account_id
- booking_id
- payment_id
- idempotency_key
- correlation_id
- rule_version

## Data Model

### Tables

#### loyalty_accounts

- id
- tenant_id
- customer_id
- status
- current_balance_cached
- reserved_balance_cached
- total_earned
- total_redeemed
- total_expired
- version
- created_at
- updated_at

Constraints:

- unique `(tenant_id, customer_id)`

#### loyalty_ledger_entries

- id
- tenant_id
- loyalty_account_id
- entry_type
- points_delta
- monetary_reference_amount
- booking_id nullable
- payment_id nullable
- source_module
- source_event
- source_reference_id
- idempotency_key
- correlation_id
- causation_id
- created_by_type
- created_by_id
- reason_code
- metadata_json
- created_at

Constraints:

- index `(tenant_id, loyalty_account_id, created_at)`
- unique `(tenant_id, entry_type, source_reference_id, idempotency_key)`

#### loyalty_redemptions

- id
- tenant_id
- loyalty_account_id
- booking_id
- reserved_points
- committed_points
- requested_discount_amount
- applied_discount_amount
- status
- idempotency_key
- expires_at
- created_at
- updated_at

Constraints:

- unique `(tenant_id, booking_id, idempotency_key)`

#### loyalty_rule_sets

- id
- tenant_id
- version
- status
- valid_from
- valid_to
- rules_json
- created_at

Constraints:

- unique `(tenant_id, version)`

#### loyalty_campaigns

- id
- tenant_id
- status
- priority
- stack_policy
- audience_filter_json
- campaign_rules_json
- budget_limit
- usage_limit
- start_at
- end_at
- created_at
- updated_at

#### loyalty_audit_logs

- id
- tenant_id
- actor_type
- actor_id
- action
- entity_type
- entity_id
- correlation_id
- before_json
- after_json
- metadata_json
- created_at

#### outbox_events

- id
- aggregate_type
- aggregate_id
- event_type
- payload_json
- occurred_at
- published_at nullable

## Domain Events

Published internal events:

- loyalty.account.created
- loyalty.points.earned
- loyalty.points.redeem_reserved
- loyalty.points.redeem_committed
- loyalty.points.redeem_released
- loyalty.points.expired
- loyalty.points.adjusted
- loyalty.balance.rebuilt
- loyalty.rule_set.activated
- loyalty.campaign.activated
- loyalty.campaign.finished

Consumers:

- notifications
- analytics
- crm segmentation
- admin dashboards
- finance reporting

## Public Application Contracts

### Customer-facing queries

#### GET /api/v1/me/loyalty

Returns:

- available_points
- reserved_points
- pending_expiration_points optional
- tier optional
- next_expiration_at optional
- currency_equivalent optional
- last_transactions

#### GET /api/v1/me/loyalty/history

Filters:

- from
- to
- type
- limit
- cursor

### Booking and checkout commands

#### POST /api/v1/loyalty/redemptions/reserve

Request:

- booking_id
- requested_points
- idempotency_key

Response:

- redemption_id
- reserved_points
- discount_amount
- expires_at
- balance_after_reservation

#### POST /api/v1/loyalty/redemptions/commit

Request:

- redemption_id
- payment_id optional
- idempotency_key

#### POST /api/v1/loyalty/redemptions/release

Request:

- redemption_id
- reason_code
- idempotency_key

### Administrative commands

#### POST /api/v1/admin/loyalty/adjustments

Request:

- loyalty_account_id
- points_delta
- reason_code
- comment
- idempotency_key

#### POST /api/v1/admin/loyalty/rule-sets

Creates a new versioned rule set.

#### POST /api/v1/admin/loyalty/campaigns

Creates or schedules a campaign.

## Rule Evaluation Strategy

Rule resolution order:

1. tenant active base rule set
2. audience-specific overrides
3. campaign overlays
4. booking line eligibility filters
5. discount stacking policy
6. monetary caps
7. rounding and final normalization

Rules are versioned.
Every accrual or redemption persists the exact rule version applied.
This guarantees historical reproducibility.

## Reconciliation

Nightly and on-demand reconciliation processes must compare:

- cached account balances
- ledger-derived balances
- redemption reservation totals
- booking-linked accruals
- payment-linked commits

If drift is detected:

1. mark account for review
2. emit alert
3. optionally rebuild snapshot
4. require administrative investigation for unexplained variance

## Failure Handling

### Duplicate command

Handled by idempotency table and original result replay.

### Payment uncertainty

Keep reservation active until webhook or timeout resolves final state.

### Webhook duplication

Deduplicate by provider event id and internal idempotency strategy.

### Partial outage

Persist command outcome and outbox event in same transaction.
Publish asynchronously after commit.

### Rule change during in-flight booking

Reservation stores rule version and price basis used at reservation time.
Commit uses stored reservation contract unless explicit re-price policy exists.

## Rejected Alternatives

### Simple balance field without ledger

Rejected because it weakens auditability, reconstruction, and dispute investigation.

### Immediate one-phase redemption debit

Rejected because payment and booking confirmation may be asynchronous and retried, increasing overspend and inconsistency risk.

### Loyalty logic embedded directly inside bookings module

Rejected because it creates tight coupling, limits future extraction, and complicates independent rule evolution.

### Storing raw payment artifacts in loyalty

Rejected because loyalty does not need raw cardholder data, and minimizing exposure is consistent with PCI tokenization guidance and safer payment-adjacent design. :contentReference[oaicite:12]{index=12}

## Consequences

### Positive

- strong auditability
- deterministic rebuild capability
- resilience to retries
- clean tenant isolation
- easier fraud investigation
- future extraction path to dedicated service
- compatible with asynchronous payment workflows
- safer separation from payment-sensitive data

### Negative

- more tables and process complexity
- reservation lifecycle adds operational overhead
- reconciliation jobs are mandatory
- rule versioning requires disciplined admin UX and migration support

### Accepted trade-off

We accept additional architectural complexity in exchange for correctness, auditability, and long-term scalability.

## Implementation Notes

Recommended module structure:

- `backend/modules/loyalty/domain/`
- `backend/modules/loyalty/application/commands/`
- `backend/modules/loyalty/application/queries/`
- `backend/modules/loyalty/infrastructure/models/`
- `backend/modules/loyalty/infrastructure/repositories/`
- `backend/modules/loyalty/infrastructure/outbox/`
- `backend/modules/loyalty/api/http/`
- `backend/modules/loyalty/tests/`

Recommended technical patterns:

- optimistic version field plus row lock for critical writes
- outbox pattern for event publication
- idempotency store for retried commands
- materialized balance snapshot for fast reads
- scheduled expiration and reconciliation jobs

## Verification Criteria

This ADR is considered implemented only when all conditions below are satisfied:

1. duplicate accrual retry does not create duplicate points
2. duplicate redemption commit does not double-spend points
3. ledger can reconstruct balance exactly
4. reservation timeout releases points correctly
5. refund policy executes deterministically
6. all admin adjustments are auditable
7. tenant A cannot access tenant B loyalty data
8. payment webhook duplication is harmless
9. balance drift detection and rebuild path exist
10. raw card data is absent from loyalty persistence

## References

1. OWASP Logging Cheat Sheet. Guidance on audit, transaction logging, monitoring, and separation of logging concerns. :contentReference[oaicite:13]{index=13}
2. OWASP Top 10 2021 A09: Security Logging and Monitoring Failures. Recommends audit trails with integrity controls for high-value transactions. :contentReference[oaicite:14]{index=14}
3. OWASP Application Security Verification Standard. Security controls should be verifiable and designed systematically. :contentReference[oaicite:15]{index=15}
4. OWASP Secure by Design Framework. Security decisions should be embedded at architecture phase. :contentReference[oaicite:16]{index=16}
5. Stripe API Reference, Idempotent requests. Idempotency is used for safe retries without duplicate side effects. :contentReference[oaicite:17]{index=17}
6. Stripe Payments, Payment Intents. Recommends idempotency keys to prevent duplicate PaymentIntents. :contentReference[oaicite:18]{index=18}
7. Stripe Webhooks documentation. Webhook endpoints are used to receive asynchronous payment events. :contentReference[oaicite:19]{index=19}
8. PCI SSC Tokenization Product Security Guidelines. Tokenization guidance for safer payment-related architectures. :contentReference[oaicite:20]{index=20}
9. PCI SSC Tokenization Guidelines Information Supplement and release notice. Tokenization can reduce exposure and support PCI DSS efforts. :contentReference[oaicite:21]{index=21}