# Loyalty Token Model

## Document Status

Target product specification for Reva Studio.

This document defines the desired loyalty token model for the platform.
It is a product and system design artifact, not a statement that the feature is already implemented in production.

---

## Purpose

The loyalty token model defines how Reva Studio rewards client behavior, increases retention, improves repeat bookings, supports personalized offers, and creates a measurable incentive layer across the platform.

The model must solve five business goals:

1. Increase repeat visits.
2. Raise client lifetime value.
3. Improve booking frequency in weak demand windows.
4. Strengthen client attachment to a specific salon, staff member, or tenant.
5. Provide a product foundation for future SaaS expansion, partner rewards, and tokenized engagement mechanics.

---

## Product Vision

Reva Studio loyalty tokens are not a speculative crypto asset inside the core beauty product.
They are a controlled reward unit used to represent earned client value within the platform.

At the product level, a loyalty token acts as:

- a reward for desired behavior
- a balance unit for future redemption
- a retention instrument
- a segmentation signal
- a campaign delivery channel
- a measurable behavioral incentive

The loyalty token system must remain understandable to end users.
The client should perceive the token as a simple reward currency tied to real benefits.

---

## Product Principles

### 1. Simplicity for clients

The user should understand:

- how tokens are earned
- how many tokens they have
- what tokens can be used for
- when tokens expire
- why tokens were granted or debited

### 2. Financial safety for the business

Tokens must not create uncontrolled liabilities.
Every earning and redemption rule must be bounded by explicit policy.

### 3. Deterministic server-side accounting

Token balances must never be inferred from the client application.
The balance must be derived from an authoritative ledger.

### 4. Explainability

Every token movement must have a clear reason.

### 5. Abuse resistance

The system must protect against duplicate rewards, fake referrals, booking churn abuse, and concurrent redemption errors.

### 6. Multi-tenant readiness

The model must support future scaling where each salon or tenant has isolated loyalty settings and balances.

---

## Core Product Definition

### Loyalty Token

A non-cash reward unit earned by a client after qualifying actions within Reva Studio.

### Token Balance

The currently available amount of loyalty tokens a client can use according to active policy.

### Token Ledger

The authoritative append-only history of all accruals, debits, expirations, reversals, and adjustments.

### Token Policy

The configurable business rules that determine how tokens are earned, spent, limited, and expired.

### Redemption

A product action where tokens are consumed in exchange for a defined benefit.

### Token Wallet

The client-visible representation of token balance, history, upcoming expirations, and available redemption actions.

---

## Product Scope

The loyalty token model may be used for:

- repeat booking rewards
- first visit rewards
- referral rewards
- birthday campaigns
- off-peak demand stimulation
- staff-specific retention campaigns
- membership mechanics
- service bundles
- seasonal campaigns
- abandoned booking recovery
- milestone rewards
- premium client programs
- gamified product mechanics in future versions

The loyalty token model must not be treated as:

- legal tender
- a direct fiat equivalent displayed as a bank account
- an uncontrolled discount instrument
- an externally tradable asset by default
- a substitute for accounting revenue records

---

## User-Facing Product Promise

For clients, the system should feel like this:

- visit and earn tokens
- use tokens for discounts or exclusive benefits
- get rewarded for loyalty and engagement
- see a clear balance and history
- never be confused about what happened

For administrators, the system should provide:

- predictable economics
- configurable rules
- full auditability
- clear analytics
- safe abuse controls
- tenant isolation for future SaaS use

---

## Business Model Rationale

The loyalty token model exists because simple percentage discounts are often too blunt.
A token system gives the product more flexibility:

- reward today, redeem later
- influence next booking behavior
- create milestone loops
- separate reward issuance from immediate discount pressure
- support personalized campaigns without changing base prices
- make engagement measurable at the ledger level

This enables better retention design than one-time coupons alone.

---

## Product Outcomes

### Primary outcomes

- higher repeat booking rate
- higher 30-day and 90-day retention
- increased booking frequency per client
- better occupancy in weak periods
- increased average customer lifetime value

### Secondary outcomes

- improved referral conversion
- stronger staff-client stickiness
- better client segmentation
- better campaign testing
- improved reactivation of dormant clients

---

## Token Utility Model

Tokens can be used for one or more of the following benefits.

### Monetary utility

- partial discount on eligible bookings
- service add-on reduction
- threshold-based price reduction

### Non-monetary utility

- priority booking access
- exclusive campaign access
- free upgrade eligibility
- birthday bonus activation
- access to premium time slots
- loyalty-only bundles
- referral reward unlocks

### Future utility

- membership tier progression
- partner ecosystem rewards
- gamified achievements
- digital collectibles or profile status
- tokenized loyalty marketplace inside the broader platform

Not all utilities must be launched at once.

---

## Core Product Rules

### Rule 1. Tokens are earned only from qualifying events

Examples:

- completed paid booking
- first completed visit
- successful referral
- birthday claim
- promotional campaign trigger
- retention milestone reached

### Rule 2. Tokens are never finally granted on provisional actions alone

Examples of provisional actions:

- booking created but not paid
- booking scheduled but not completed
- referral link opened but not converted

### Rule 3. Tokens should usually be confirmed only after the qualifying business event is finalized

Typical confirmation point:

- completed booking
- paid and non-reversed transaction
- confirmed referral completion

### Rule 4. Tokens are stored in a ledger, not just as a mutable balance number

### Rule 5. Redemptions must be checked against policy at commit time, not only at preview time

### Rule 6. Expiration, reversal, and manual adjustment must be first-class operations

---

## Earning Model

## Base earning mechanisms

### A. Spend-based accrual

Client earns tokens based on amount spent.

Example policy shape:

- fixed tokens per currency unit
- percentage-equivalent reward converted into tokens
- category-specific earning rates

### B. Action-based accrual

Client earns fixed tokens for a qualifying action.

Examples:

- first completed booking
- fifth visit milestone
- review submission if enabled by policy
- referral completion

### C. Campaign-based accrual

Temporary earning multipliers or bonuses.

Examples:

- double tokens in low-demand slots
- new master launch campaign
- birthday week multiplier
- reactivation bonus for dormant clients

### D. Segment-based accrual

Different segments may earn different reward rates.

Examples:

- VIP segment
- new clients
- inactive clients
- partner channel users

---

## Recommended Initial Product Policy

For a safe production launch, a conservative initial policy is recommended.

### Initial earning rules

- tokens are granted only after completed paid bookings
- referrals reward only after the referred client completes a paid booking
- no token grant on cancelled or no-show bookings
- no token grant on refunded revenue unless policy explicitly allows partial retention
- one business event can produce only one final accrual outcome per policy version

### Initial redemption rules

- tokens can cover only a limited percentage of eligible booking value
- tokens cannot reduce payable amount below a configured minimum floor
- tokens cannot be combined with every promotion by default
- token redemption must be recalculated on server before payment confirmation
- expired tokens are not redeemable

### Initial operational rules

- ledger is append-only
- all balance changes are auditable
- all admin adjustments require reason
- all manual grants are flagged in analytics separately
- all reversal flows are supported explicitly

---

## Economic Safety Model

The token system creates a future service liability.
Therefore the product must define economic guardrails.

### Guardrail 1. Redemption cap

A booking may allow token redemption only up to a configured percentage or absolute amount.

### Guardrail 2. Minimum payable floor

The business can require that every booking retains a minimum payable amount after token use.

### Guardrail 3. Service eligibility

Some services may be excluded from token redemption.

Examples:

- already deeply discounted services
- low-margin services
- third-party pass-through items

### Guardrail 4. Expiration policy

Tokens may expire after a defined period to limit indefinite liability and encourage usage.

### Guardrail 5. Anti-stacking policy

Token redemption may be restricted when other promotions are active.

### Guardrail 6. Earning exclusions

No accrual on cancelled, fraudulent, refunded, or policy-disallowed events.

---

## Token Lifecycle

### 1. Issued Pending

Tokens are provisionally created but not yet spendable.

### 2. Confirmed Available

Tokens become spendable after the qualifying event is finalized.

### 3. Reserved

Tokens are temporarily locked during checkout or booking confirmation.

### 4. Redeemed

Tokens are consumed as part of a successful redemption.

### 5. Expired

Tokens exceeded their validity window.

### 6. Reversed

Previously granted or redeemed tokens are negated due to refund, dispute, correction, or fraud action.

### 7. Adjusted

Administrative correction with explicit audit reason.

The system should represent state transitions through ledger events, not hidden balance mutation.

---

## Ledger Model

The loyalty token system must be ledger-based.

Each ledger event should represent a single immutable fact.

Suggested event types:

- accrual_pending
- accrual_confirmed
- accrual_reversed
- redemption_reserved
- redemption_committed
- redemption_released
- expiration_applied
- admin_adjustment_credit
- admin_adjustment_debit
- migration_credit
- referral_reward_confirmed
- campaign_bonus_confirmed

Suggested ledger fields:

- ledger_entry_id
- tenant_id
- client_id
- wallet_id
- token_amount
- direction
- event_type
- reason_code
- related_booking_id
- related_payment_id
- related_referral_id
- related_campaign_id
- correlation_id
- idempotency_key
- policy_version
- expires_at
- created_at
- created_by

Balance should be derived from confirmed ledger state, not trusted from a cached client payload.

---

## Balance Semantics

The product should expose multiple balance views.

### Available Balance

Tokens currently spendable.

### Pending Balance

Tokens earned but not yet confirmed.

### Reserved Balance

Tokens currently locked for an in-progress redemption.

### Expiring Soon

Tokens that will expire within a configured window.

### Lifetime Earned

Total confirmed token accrual in client history.

### Lifetime Redeemed

Total tokens consumed historically.

This provides better product transparency than a single number.

---

## Expiration Model

Expiration is both a financial and behavioral mechanism.

Possible strategies:

- rolling expiration per accrual batch
- fixed campaign expiration window
- no expiration for premium tier
- shortest-expiry-first consumption
- oldest-first consumption

Recommended initial approach:

- each confirmed accrual receives an explicit expires_at
- redemption consumes oldest eligible tokens first
- expired tokens are removed through ledger expiration events
- users receive pre-expiry reminders

This model is operationally predictable and user-explainable.

---

## Redemption Model

Tokens may be redeemed only on eligible bookings or benefits.

### Redemption flow

1. Client chooses redemption option.
2. System checks available eligible balance.
3. System checks service and policy eligibility.
4. System reserves tokens for a short period.
5. System recalculates final payable amount on server.
6. On successful booking or payment commit, redemption is finalized.
7. On timeout, failure, or cancellation, reservation is released.

### Redemption constraints

- no negative balance
- no spending pending tokens
- no spending expired tokens
- no double-spend under concurrency
- no hidden client-side balance trust
- no redemption beyond per-booking policy cap

---

## Booking Integration

The loyalty token system must integrate with booking in a deterministic manner.

### At preview time

The product may show:

- available balance
- estimated redeemable amount
- projected earning from this booking
- incompatible offers if relevant

### At commit time

The server must re-evaluate:

- eligibility
- token balance
- reservation validity
- promotional compatibility
- final payable amount
- policy version

Booking snapshots should persist:

- subtotal
- applied promotions
- token redemption amount
- token earning amount
- final payable
- policy version
- ledger correlation identifier

---

## Payments Integration

The token system must not replace money movement.
It only changes the payable amount or grants benefits according to policy.

### Required payment interactions

- payment creation must use server-calculated totals after redemption
- webhook completion must commit reserved redemption if payment succeeds
- failed or expired payments must release reservation
- refunded payments may trigger accrual reversal and possibly redemption correction according to policy

The payment domain remains the source of truth for money capture.
The loyalty domain remains the source of truth for token ledger state.

---

## Promotions Integration

Tokens and promotions must be coordinated by policy.

Possible modes:

- promotions first, tokens second
- tokens first, promotions second
- mutually exclusive for some campaigns
- staff-specific exceptions
- admin override with audit

Recommended initial rule:

- apply promotions first
- apply token redemption second
- enforce minimum payable floor after both
- block token usage on explicitly excluded promotions

This minimizes hidden discount compounding.

---

## Referral Model

Referral is one of the highest-value token use cases.

### Standard referral shape

- existing client receives a referral code or link
- new client books using that referral source
- referred client completes a paid eligible booking
- referrer earns tokens
- referred client may also receive a welcome reward if policy allows

### Referral controls

- self-referral prevention
- duplicate identity checks where legally allowed
- no final reward before completed qualifying booking
- one referred user counted once per referral policy
- reversal support for refunded or fraudulent completion

---

## Tier and Status Model

Tokens may feed a future loyalty tier system.

Example future tiers:

- Base
- Silver
- Gold
- Platinum

Tier progression may depend on:

- lifetime earned tokens
- confirmed visits
- revenue contribution
- referral success
- premium membership status

Important rule:
Tier status and spendable balance are different concepts and must not be conflated.

---

## Segmentation Model

The token system should enrich product segmentation.

Derived segments may include:

- high-balance clients
- at-risk clients with expiring tokens
- high-frequency clients
- dormant clients
- referral advocates
- high-redemption clients
- high-earning low-redemption clients
- promo-sensitive clients
- premium loyalty segment

These segments can be used for CRM and campaign delivery.

---

## Abuse and Fraud Controls

The loyalty token system must defend against common abuse scenarios.

### Risks

- duplicate booking completion rewards
- referral farming
- self-referrals
- booking then cancellation loops
- payment retry duplication
- concurrent redemption attempts
- manual admin over-crediting
- stale mobile state reusing old balance
- scripted promo and token exploitation

### Required controls

- idempotency keys on all reward-triggering flows
- append-only ledger
- reservation model for redemption
- server-side recalculation at commit
- explicit reversal events
- suspicious referral detection
- admin role restrictions
- audit trail on manual adjustments
- rate limiting where applicable
- anomaly monitoring for token issuance and redemption

---

## Analytics Model

The token system should support product and business analytics.

### Core metrics

- tokens_issued_total
- tokens_confirmed_total
- tokens_redeemed_total
- tokens_expired_total
- tokens_reversed_total
- available_balance_total
- redemption_rate
- repeat_booking_rate_with_tokens
- average_days_to_redemption
- referral_reward_conversion_rate
- dormant_reactivation_rate_from_token_campaigns
- token_liability_estimate
- tier_upgrade_rate
- booking_conversion_with_redemption

### Key business questions

- Do token users rebook more often
- Which campaigns generate profitable repeat visits
- How many issued tokens are never redeemed
- Which redemption rules maximize retention without hurting margin
- Which clients are at risk but can be reactivated with token nudges
- Which staff or services correlate with strong token-driven loyalty

---

## Notifications and UX

The loyalty model must have strong UX support.

### User-facing surfaces

- wallet screen
- booking preview
- checkout flow
- booking success screen
- profile area
- campaign cards
- reminder notifications

### Critical user messages

- tokens earned
- tokens confirmed
- tokens reserved
- tokens spent
- tokens released after failed checkout
- tokens expiring soon
- tokens expired
- tokens adjusted with reason if user-facing policy allows

### UX rules

- never show ambiguous balances
- always explain pending versus available
- always explain why redemption is unavailable
- show expiry dates clearly
- show booking-linked token activity

---

## Administrative Controls

The backoffice should support:

- view wallet and ledger history
- view token policy versions
- create campaign-based token boosts
- perform manual credit or debit with reason
- reverse ledger effects through approved workflows
- inspect booking-linked token events
- inspect referral-linked token events
- configure expiration policy
- configure earning rates
- configure redemption caps
- configure exclusion rules
- export token activity
- flag suspicious accounts

Manual operations must be permissioned and auditable.

---

## Multi-Tenant Model

For SaaS expansion, the loyalty token system must be tenant-aware.

Each tenant should be able to define:

- token display name
- earning rules
- redemption rules
- expiration policy
- service eligibility
- campaign rules
- referral rewards
- tier logic
- notification templates

Isolation requirements:

- tenant-scoped wallets
- tenant-scoped policies
- tenant-scoped campaigns
- tenant-scoped ledgers
- tenant-scoped analytics
- no cross-tenant balance leakage

Shared templates may exist later, but the active policy must still materialize as tenant-owned configuration.

---

## Product Policy Versioning

Every meaningful commercial rule change must be versioned.

Examples:

- earning rate changed
- redemption cap changed
- expiration duration changed
- service eligibility changed
- referral amount changed
- anti-stacking logic changed

Why this matters:

- repeatable support investigations
- refund and dispute explainability
- analytics correctness
- safe rollback
- deterministic recomputation where needed

Every ledger event and booking snapshot should reference policy_version where relevant.

---

## Recommended Initial MVP

A safe first production version should include only the essentials.

### MVP capabilities

- token accrual after completed paid booking
- token wallet view
- token redemption on eligible booking with cap
- expiration support
- append-only ledger
- admin adjustment with reason
- server-side recalculation
- booking and payment integration
- basic analytics
- pre-expiry notifications

### MVP exclusions

- external blockchain transfer
- peer-to-peer transfers
- token trading
- public marketplace utility
- complex tiering
- advanced partner ecosystem
- speculative economics
- cross-tenant pooled liquidity

This keeps launch risk manageable.

---

## Future Expansion Path

After the MVP is stable, the model may expand into:

### Phase 2

- referral engine
- tier system
- campaign multipliers
- personalized token offers
- staff loyalty campaigns
- reactivation campaigns

### Phase 3

- memberships
- partner rewards
- bundle unlocks
- achievement mechanics
- advanced segmentation
- AI-assisted loyalty optimization

### Phase 4

- marketplace-linked utility
- tenant federation scenarios
- interoperable profile reputation
- optional tokenized external rails only if legally and product-wise justified

Future expansion must not compromise auditability or financial control.

---

## Non-Goals

The following are explicitly out of scope for the initial Reva Studio loyalty token model:

- public speculative token trading
- uncontrolled token minting
- client-to-client token transfers
- opaque conversion logic
- hidden admin interventions
- loyalty logic embedded only in frontend
- non-audited manual balance edits
- discounting without server-side policy checks

---

## Open Product Decisions

These are not confirmed facts.
They must be explicitly decided during implementation.

1. What exact token-to-discount conversion rule should be used.
2. What maximum share of a booking may be covered by tokens.
3. Whether tokens expire after 90, 180, or 365 days, or by campaign policy.
4. Whether refunded bookings reverse both accrual and redemption effects symmetrically.
5. Whether referral rewards are single-sided or double-sided.
6. Whether loyalty redemption is allowed together with all promotions or only selected ones.
7. Whether each tenant may rename the token or only customize presentation.
8. Whether tier status is introduced in MVP or postponed.
9. Whether manual admin adjustments require one approver or dual control.
10. Whether future external blockchain representation is needed at all.

These decisions must not be silently hardcoded.

---

## Product Summary

The correct product shape for Reva Studio is a controlled loyalty token system built on these foundations:

- ledger-first accounting
- deterministic server-side policy evaluation
- safe redemption limits
- explainable client UX
- auditable admin actions
- booking and payment integration
- promotion compatibility rules
- multi-tenant readiness
- phased expansion without speculative complexity

This is the minimum acceptable product model for a production-grade loyalty token subsystem in Reva Studio.