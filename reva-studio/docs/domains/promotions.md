# Promotions Domain

## Purpose

The Promotions domain is responsible for defining, validating, activating, evaluating, auditing, and retiring all commercial incentive mechanisms in Reva Studio.

This domain exists to support controlled revenue growth without breaking pricing integrity, financial reporting, booking consistency, or loyalty accounting.

The domain must answer these questions:

- Which promotion can be applied to a booking, cart, service, staff member, tenant, or client
- When a promotion is active and for whom it is available
- Whether multiple promotions can be combined
- What exact monetary effect a promotion has produced
- Why a promotion was accepted, rejected, limited, capped, or overridden
- How promotion usage is tracked for analytics, abuse control, and rollback scenarios

---

## Domain Goals

1. Preserve pricing correctness and deterministic calculation.
2. Allow controlled marketing flexibility without hidden side effects.
3. Support auditability for every discount decision.
4. Prevent invalid stacking and abuse.
5. Keep promotion evaluation reproducible across API, admin panel, bot, mini app, and background jobs.
6. Separate commercial rules from payment execution and booking orchestration.
7. Allow future multi-tenant scaling and partner-specific campaigns.

---

## Core Responsibilities

The Promotions domain owns:

- promotion definitions
- eligibility rules
- activation windows
- usage limits
- segment targeting
- promo codes
- automatic discounts
- stacking policy
- priority resolution
- cap and floor enforcement
- evaluation result explanation
- promotion audit trail
- promotion lifecycle state transitions

The Promotions domain does not own:

- service base price catalog
- final payment capture
- loyalty point balance ledger
- booking slot reservation
- notification delivery
- accounting ledger entries

These concerns are coordinated through other domains and application services.

---

## Domain Boundaries

### Upstream dependencies

The Promotions domain reads from or depends on:

- Pricing inputs from Services Catalog
- Booking context from Bookings
- Client context from Users or CRM
- Loyalty context when bonus redemption affects discountability
- Tenant configuration in multi-tenant mode
- Current time, timezone, and business calendar rules

### Downstream consumers

The Promotions domain is used by:

- booking preview calculation
- checkout calculation
- admin promotion simulator
- campaign analytics
- promo validation in Telegram bot and Mini App
- backoffice reporting
- refund and dispute review workflows
- scheduled activation and expiration jobs

---

## Ubiquitous Language

### Promotion

A commercial rule that changes the payable amount or grants a non-cash benefit under specific conditions.

### Promo Code

A code entered by a client or attached automatically to context, linked to one or more promotion rules.

### Campaign

A business grouping of one or more promotions managed under a common goal, schedule, channel, or budget.

### Eligibility

A set of conditions that must be true before a promotion can be considered.

### Qualification

A runtime result showing that context satisfies all required conditions.

### Stacking

The ability for multiple promotions to be applied together to the same pricing context.

### Priority

An ordering rule used when multiple promotions are eligible but not all can be applied.

### Cap

A maximum discount amount or usage ceiling.

### Floor

A minimum payable amount below which discounts may not reduce the booking.

### Redemption

A successful usage event of a promotion in a business transaction.

### Evaluation Context

The full set of runtime inputs used to decide promotion applicability.

### Evaluation Result

A deterministic output describing applied promotions, rejected promotions, reasons, totals, and audit data.

---

## Business Scope

Promotions in Reva Studio may affect:

- a single service
- a bundle of services
- a full booking
- first visit flows
- return visit flows
- specific staff members
- specific categories
- specific weekdays or hours
- low-demand slots
- campaigns by traffic source
- client segments
- seasonal events
- abandoned booking recovery
- referral scenarios
- subscription or membership benefits
- corporate or partner agreements

---

## Promotion Types

### Automatic Discount

Applied without client input when context qualifies.

Examples:

- first visit discount
- birthday week discount
- weekday morning discount
- lash and brow bundle discount

### Promo Code Discount

Applied only when a valid code is provided and context qualifies.

Examples:

- WELCOME10
- SPRING2026
- MASTER-ANNA-15

### Conditional Threshold Discount

Activated only if a price or quantity threshold is met.

Examples:

- discount above minimum booking amount
- gift on second service in same booking

### Segment-Based Promotion

Available only for a pre-defined audience.

Examples:

- VIP clients
- inactive clients for 45 days
- clients from a specific partner channel

### Slot Fill Promotion

Used to increase occupancy of selected dates or hours.

Examples:

- last-minute booking discount
- same-day gap fill offer

### Staff Promotion

Bound to one or more staff members.

Examples:

- new master introduction campaign
- personal branding campaign for a specialist

### Non-Monetary Promotion

Does not reduce payable amount directly, but grants value.

Examples:

- free add-on
- priority slot access
- complimentary consultation
- post-visit care package

---

## Lifecycle

A promotion moves through the following states.

### Draft

Promotion is editable and not visible in runtime evaluation.

### Scheduled

Promotion is approved and waiting for start window.

### Active

Promotion is available for evaluation if all runtime conditions match.

### Paused

Promotion is temporarily disabled without deletion.

### Exhausted

Promotion has reached a hard budget, usage, or redemption limit.

### Expired

Promotion ended due to time window completion.

### Archived

Promotion is retained for analytics and audit but no longer operational.

### Cancelled

Promotion was withdrawn before or during runtime and should not be used going forward.

State transitions must be explicit and auditable.

---

## Core Aggregates

### Promotion Aggregate

Primary aggregate representing a promotion definition.

Suggested attributes:

- promotion_id
- tenant_id
- campaign_id
- code
- name
- description
- type
- status
- priority
- is_combinable
- stack_group
- start_at
- end_at
- timezone
- usage_limit_total
- usage_limit_per_client
- budget_limit_minor
- currency
- max_discount_minor
- min_payable_minor
- created_at
- updated_at
- created_by
- updated_by
- archived_at

### Eligibility Rule Set

Rules attached to a promotion.

Suggested rule dimensions:

- allowed services
- excluded services
- allowed categories
- allowed staff
- allowed weekdays
- allowed time ranges
- allowed channels
- allowed client segments
- allowed booking amount range
- allowed visit count range
- allowed location
- first visit only
- returning client only
- birthday window
- inactivity window
- custom predicates through policy layer

### Promotion Redemption

Immutable record of a successful usage.

Suggested attributes:

- redemption_id
- promotion_id
- booking_id
- client_id
- payment_id
- applied_amount_minor
- currency
- redeemed_at
- source_channel
- promo_code_snapshot
- evaluation_hash
- idempotency_key

### Promotion Evaluation Log

Immutable audit record for each evaluation attempt when required by policy.

Suggested attributes:

- evaluation_id
- correlation_id
- booking_context_hash
- evaluated_at
- eligible_promotions
- rejected_promotions
- rejection_reasons
- applied_promotions
- subtotal_minor
- final_discount_minor
- final_total_minor
- policy_version

---

## Value Objects

### Money

Represents monetary values in minor units.

Fields:

- amount_minor
- currency

Rules:

- no floating-point arithmetic
- all calculations in integer minor units
- currency consistency is mandatory inside one evaluation context

### Time Window

Represents the active period.

Fields:

- start_at
- end_at
- timezone

Rules:

- start_at must be earlier than end_at
- evaluation must use business timezone rules consistently

### Promotion Code

Fields:

- raw
- normalized

Rules:

- case-insensitive normalization
- whitespace trimmed
- uniqueness scoped by tenant and active collision policy

### Discount Effect

Fields:

- promotion_id
- effect_type
- amount_minor
- explanation
- priority_applied

---

## Invariants

The domain must enforce these invariants.

1. A promotion cannot be active without a valid time window unless explicitly marked as always active.
2. A promotion cannot reduce payable total below the configured minimum payable amount.
3. A promotion cannot exceed its own maximum discount cap.
4. A promotion cannot be redeemed after exhaustion or expiration.
5. A promotion with per-client limits cannot exceed those limits for the same client identity.
6. A non-combinable promotion cannot be stacked with another incompatible promotion.
7. A redemption record must be idempotent relative to the business transaction.
8. Promotion evaluation must be deterministic for identical context and policy version.
9. Archived or cancelled promotions must never re-enter active runtime accidentally.
10. A promo code must not resolve ambiguously within the same tenant and active window.

---

## Evaluation Model

Promotion evaluation should be deterministic and explainable.

### Inputs

- tenant_id
- client_id
- booking_id or provisional cart id
- service lines
- assigned staff
- subtotal
- channel
- timestamp
- timezone
- client segment data
- visit history summary
- promo code list
- loyalty redemption intent
- campaign attribution metadata

### Evaluation Steps

1. Load candidate promotions by tenant, state, time window, channel, and code presence.
2. Filter by hard eligibility conditions.
3. Filter by exhaustion and redemption limits.
4. Build conflict groups.
5. Order by priority and policy rules.
6. Simulate allowed combinations.
7. Enforce discount caps and minimum payable floors.
8. Produce deterministic applied set.
9. Emit full explanation including rejected candidates and reasons.
10. Persist audit event if policy requires it.

### Outputs

- candidate_promotions
- eligible_promotions
- rejected_promotions
- applied_promotions
- per-promotion effect
- total_discount_minor
- subtotal_minor
- final_total_minor
- explanation
- evaluation_hash
- policy_version

---

## Rejection Reasons

The system should produce explicit machine-readable rejection reasons.

Suggested examples:

- promotion_not_active
- promotion_expired
- promotion_paused
- code_required
- code_invalid
- code_usage_exceeded
- client_usage_exceeded
- budget_exhausted
- not_first_visit
- wrong_channel
- service_not_allowed
- staff_not_allowed
- below_minimum_amount
- incompatible_with_other_promotion
- minimum_payable_floor_hit
- tenant_mismatch
- timezone_window_mismatch
- segment_not_eligible

These reasons should be available to application services and optionally mapped to user-facing messages.

---

## Stacking Policy

Stacking is one of the highest-risk areas in the domain and must be explicit.

### Recommended strategy

Use a policy model based on:

- combinable or non-combinable flag
- stack_group
- hard exclusions
- priority ordering
- best-price versus business-priority mode
- maximum simultaneous promotions
- per-line versus cart-level application order

### Default policy recommendation

For Reva Studio, a conservative default is recommended:

- allow at most one cart-level monetary promotion
- allow one service-level promotion per line
- allow one non-monetary add-on promotion if explicitly combinable
- loyalty redemption must be evaluated after promotional discounts unless a stricter finance rule overrides this
- manual admin override must be separately audited

---

## Pricing Order of Operations

Suggested deterministic order:

1. Build subtotal from price catalog
2. Apply service-level promotions
3. Recalculate intermediate total
4. Apply cart-level promotions
5. Apply caps and floor rules
6. Apply loyalty redemption if allowed by finance policy
7. Compute final payable amount
8. Freeze calculation snapshot for booking and payment

This order must be centrally owned by application orchestration and not duplicated across clients.

---

## Abuse Prevention

The Promotions domain must defend against predictable abuse patterns.

### Risks

- repeated code attempts
- multi-account first-visit exploitation
- concurrent redemption race conditions
- leaked influencer or staff codes
- stale client apps recalculating with old policy
- replay of booking confirmation with duplicate discount application
- admin misuse through unrestricted overrides

### Countermeasures

- idempotency keys on redemption and booking confirmation
- normalized client identity checks where legally permitted
- rate limiting for promo validation endpoints
- promotion usage counters with transactional protection
- immutable redemption ledger
- audit logs for manual overrides
- policy version stamping
- expiration checks at both preview and commit time
- server-side recalculation before payment initiation
- server-side recalculation again before booking confirmation if needed

---

## Consistency Rules

### Preview versus Commit

Preview may show a promotional estimate.
Commit must always re-evaluate on the server using the latest valid policy and authoritative booking context.

### Payment Boundary

Promotion evaluation used for payment creation must be snapshotted.
Later webhook processing must not silently mutate the original commercial decision unless an explicit correction workflow exists.

### Booking Boundary

A booking should store a commercial snapshot:

- subtotal
- applied promotions
- total discount
- loyalty effect
- final payable amount
- pricing policy version

This snapshot preserves explainability during refunds, disputes, and analytics.

---

## Admin Capabilities

The backoffice should support:

- draft creation
- scheduling
- pausing and resuming
- promo code generation
- usage monitoring
- redemption history
- simulation against synthetic carts
- conflict inspection
- manual override with reason
- rollback or early stop
- export for finance and marketing
- segmentation preview
- A B testing support where legally and operationally allowed

All write actions should be permissioned and auditable.

---

## Observability

The domain should expose these operational signals.

### Metrics

- promotion_evaluations_total
- promotion_evaluation_failures_total
- promotion_redemptions_total
- promotion_rejections_total
- promotion_discount_minor_sum
- promotion_budget_remaining_minor
- promotion_conflict_events_total
- promo_code_validation_latency_ms
- promotion_preview_commit_mismatch_total

### Logs

Structured logs should include:

- correlation_id
- tenant_id
- booking_id
- client_id when policy allows
- code list
- applied promotion ids
- rejected promotion ids
- rejection reasons
- policy version
- final totals

### Traces

Critical spans:

- load_candidates
- evaluate_eligibility
- resolve_conflicts
- apply_discounts
- persist_snapshot
- persist_redemption

---

## Analytics Questions This Domain Must Support

- Which promotions generate paid bookings, not just previews
- Which staff-specific campaigns increase retention
- Which channels produce abusive promo behavior
- Which campaigns reduce margin too aggressively
- Which codes are shared outside intended audience
- Which promotions improve occupancy in weak time windows
- Which promotions cannibalize full-price demand
- Which campaigns lead to repeat visits after 30, 60, 90 days

---

## Data Retention and Audit

Promotion definitions, lifecycle events, and redemption records should be retained according to finance, dispute, and legal requirements of the operating jurisdiction.

At minimum, these artifacts should be preserved:

- promotion versions
- approval changes
- activation and pause events
- redemption ledger
- pricing snapshots on committed bookings
- manual override events
- rejection reason telemetry where needed for support and fraud analysis

Audit records should be append-only wherever feasible.

---

## Recommended Domain Events

Suggested events:

- PromotionCreated
- PromotionUpdated
- PromotionScheduled
- PromotionActivated
- PromotionPaused
- PromotionExpired
- PromotionArchived
- PromotionExhausted
- PromotionCodeIssued
- PromotionEvaluated
- PromotionApplied
- PromotionRejected
- PromotionRedeemed
- PromotionRedemptionReversed
- PromotionBudgetThresholdReached
- PromotionOverrideApplied

Events should carry tenant scope, policy version, correlation identifiers, and timestamps.

---

## Error Model

Expected error classes:

- PromotionNotFound
- PromotionNotActive
- PromotionNotEligible
- PromotionConflict
- PromotionBudgetExceeded
- PromotionUsageExceeded
- PromotionCodeInvalid
- PromotionCodeAmbiguous
- PromotionSnapshotMismatch
- PromotionPolicyViolation
- PromotionCurrencyMismatch

Errors should be distinguishable from user-facing validation responses.

---

## Security and Access Control

The Promotions domain requires strict access separation.

### Roles with write capability

- owner
- finance_admin
- marketing_admin
- restricted operations admin

### Sensitive operations

- changing budget limits
- editing active promotions
- overriding stack rules
- force-redeeming
- reversing redemptions
- mass code generation
- exporting redemption datasets

These operations should require elevated authorization and enhanced audit logging.

---

## Multi-Tenant Rules

For SaaS evolution, every promotion object must be tenant-scoped by default.

Requirements:

- no cross-tenant code collision leakage
- no cross-tenant analytics mixing
- tenant-specific timezone support
- tenant-specific currency and taxation compatibility
- isolated usage counters
- isolated admin visibility
- isolated archival and export workflows

Shared campaign templates, if introduced later, must still materialize into tenant-owned promotion entities.

---

## Integration Contracts

### With Bookings Domain

The Promotions domain receives booking context and returns a commercial decision.
It must not reserve slots or mutate booking status directly.

### With Payments Domain

The Promotions domain provides a frozen financial snapshot used to create payment intent.
It must not capture or refund money.

### With Loyalty Domain

The Promotions domain may coordinate calculation order with loyalty policies, but loyalty ledger ownership remains outside this domain.

### With Notifications Domain

The Promotions domain may emit events that later trigger notifications, but it does not send messages itself.

### With Analytics Domain

The Promotions domain provides structured events and snapshots for reporting and experimentation analysis.

---

## Testing Strategy

### Unit tests

Cover:

- eligibility evaluation
- time window handling
- stacking conflicts
- caps and floors
- per-client usage limits
- deterministic ordering
- promo code normalization
- currency mismatch rejection

### Property tests

Use for:

- deterministic evaluation across input permutations
- discount never below floor
- cap never exceeded
- no illegal combination slips through policy

### Concurrency tests

Cover:

- concurrent redemption attempts
- retry and idempotency behavior
- double-submit booking confirmation race

### Integration tests

Cover:

- preview to commit consistency
- booking snapshot persistence
- payment initiation with frozen totals
- reversal and refund review workflows

---

## Future Extensions

Designed extension points:

- rule DSL for advanced targeting
- experimentation engine
- coupon batches
- partner-funded campaigns
- referral trees
- geo-targeting
- corporate contracts
- subscription entitlements
- AI-assisted campaign recommendations
- margin-aware promotion optimization

These extensions must not break determinism or auditability.

---

## Architectural Decision Summary

For Reva Studio, the Promotions domain should be implemented as a dedicated bounded context or at minimum as a strongly isolated domain module with:

- explicit aggregates
- deterministic evaluation service
- immutable redemption records
- auditable state transitions
- centralized stacking policy
- server-side recalculation before commit
- tenant isolation by design

This is the minimum acceptable shape for a production-grade promotions subsystem in a booking and beauty SaaS platform.

---

## Open Questions to Resolve in Implementation

These are implementation decisions, not confirmed facts:

1. Whether loyalty redemption is applied before or after promotional discounts.
2. Whether staff-specific promotions can override global tenant campaigns.
3. Whether first-visit detection relies only on client account or on stronger identity resolution.
4. Whether non-monetary promotions are represented in the same aggregate model or a parallel benefit model.
5. Whether campaign budgeting is soft-limit or hard-stop.
6. Whether admin overrides are allowed in production at all or only through a two-person approval flow.

Until these are decided, application behavior must not hardcode assumptions silently.