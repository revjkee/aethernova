# Settings Domain

Status: Accepted
Last Updated: 2026-03-23
Owner: Architecture / Platform
Bounded Context: settings

## 1. Purpose

The `settings` domain defines how Reva Studio stores, validates, versions and exposes configurable behavior for a tenant.

This domain exists to answer one question:

How can the platform change studio behavior safely without changing code?

Inside Reva Studio, `settings` is responsible for business and tenant-facing configuration, not for low-level infrastructure wiring. Runtime configuration that varies between deploys should remain external to code and should be loaded from environment variables or secrets sources, which matches Twelve-Factor guidance and is directly supported by Pydantic Settings. :contentReference[oaicite:1]{index=1}

## 2. Scope

The `settings` domain includes:

- tenant identity-facing settings
- booking policy settings
- loyalty policy settings
- notification policy settings
- localization settings
- operational studio defaults that affect business behavior
- versioning and auditability of settings changes

The `settings` domain does not include:

- deployment-time infrastructure config
- database DSN management
- Redis host or broker addresses
- secrets storage format
- JWT private keys
- external provider credentials
- feature code implementation itself

These runtime and secret concerns belong to platform configuration, not to tenant business settings. Twelve-Factor defines config as values that vary between deploys and recommends keeping them in the environment rather than in code. Pydantic Settings explicitly supports loading settings from environment variables and secrets files. :contentReference[oaicite:2]{index=2}

## 3. Domain intent

The `settings` domain is not a "misc" bucket.

It is a first-class bounded context whose job is to provide:

- deterministic studio behavior
- safe defaults
- explicit validation
- traceable changes
- separation between product policy and runtime platform config
- stable read access for other modules

This domain must prevent hidden configuration drift and protect other modules from directly encoding mutable business rules.

## 4. Ubiquitous language

### 4.1 Tenant Settings

The complete current configuration of one tenant that affects business behavior.

### 4.2 Settings Revision

An immutable historical version of tenant settings stored for audit, rollback analysis and change comparison.

### 4.3 Settings Policy

A logically grouped subset of settings such as booking policy or notification policy.

### 4.4 Effective Settings

The fully resolved settings used by the application after applying:
- global defaults
- product defaults
- tenant overrides
- temporary controlled feature flags if explicitly allowed

### 4.5 Mutable Setting

A setting whose value may change through an administrative workflow.

### 4.6 Locked Setting

A setting that exists in the model but cannot be changed by normal tenant administrators because it is controlled by platform governance.

## 5. Domain boundaries

The `settings` domain publishes stable read contracts to other modules.

Other domains may read effective settings, but they must not mutate settings state directly.

Examples:

- `bookings` may read booking slot step, cancellation deadline and overbooking policy
- `loyalty` may read accrual and redemption policy
- `notifications` may read reminder offsets and enabled channels
- `services_catalog` may read localization defaults if needed for formatting
- `analytics` may read timezone and locale to produce tenant-correct reports

Other modules must not:
- update settings tables directly
- store shadow copies of canonical settings as independent truth
- implement their own fallback resolution rules
- bypass settings validation

## 6. Strategic separation: runtime config vs business settings

Reva Studio separates configuration into two layers.

### 6.1 Runtime Config

Runtime config changes deployment behavior and environment attachment.

Examples:
- database DSN
- Redis URL
- SMTP credentials
- S3 bucket credentials
- JWT secret references
- log level
- tracing exporter endpoint

These values belong to application configuration, should vary by deploy, and should be loaded externally from environment variables or secrets sources, following Twelve-Factor and Pydantic Settings guidance. :contentReference[oaicite:3]{index=3}

### 6.2 Business Settings

Business settings change tenant-visible product behavior.

Examples:
- slot granularity
- cancel deadline
- reminder offsets
- loyalty earn rate
- studio timezone
- studio locale
- default currency
- whether overbooking is allowed

These values belong to the `settings` domain and are part of business state.

## 7. Core design decision

For Reva Studio, business settings are stored as domain data and versioned per tenant.

This is the central rule of the domain.

That means:
- business settings are persisted in the transactional database
- every change is auditable
- values are validated against domain rules
- consumers read effective settings through explicit contracts
- runtime config is not reused as a substitute for tenant policy

## 8. Canonical standards used by the domain

The domain uses the following external standards.

### 8.1 Timestamp format

All persisted and API-exposed timestamps must use RFC 3339 compatible date-time strings in UTC unless a field explicitly carries a local time or wall-clock value. RFC 3339 defines a timestamp profile for Internet protocols and is the canonical source for this format. :contentReference[oaicite:4]{index=4}

### 8.2 Timezone identifiers

All timezones must be stored as IANA time zone database identifiers such as `Europe/Riga` or `Europe/Stockholm`. IANA documents the Time Zone Database as the maintained source representing local time history and rules. :contentReference[oaicite:5]{index=5}

### 8.3 Locale identifiers

Locale and language tags must use BCP 47 style tags such as `ru-RU` or `en-US`. W3C documents that language tag syntax is defined by the IETF BCP 47 series. :contentReference[oaicite:6]{index=6}

### 8.4 Currency identifiers

Currency codes must use ISO 4217 alphabetic codes such as `RUB`, `EUR` and `USD`. ISO documents ISO 4217 as the standard for internationally recognized currency codes. :contentReference[oaicite:7]{index=7}

## 9. Aggregate model

The primary aggregate is:

- `TenantSettings`

Supporting historical aggregate or entity set:

- `SettingsRevision`

### 9.1 Aggregate: TenantSettings

`TenantSettings` is the source of truth for the current effective business settings of one tenant.

Suggested identity:
- `tenant_id`

Suggested fields:
- `tenant_id`
- `revision`
- `studio_name`
- `timezone`
- `locale`
- `currency`
- `booking_policy`
- `loyalty_policy`
- `notification_policy`
- `updated_at`
- `updated_by`
- `schema_version`

### 9.2 Entity: SettingsRevision

`SettingsRevision` stores immutable historical snapshots.

Suggested fields:
- `revision_id`
- `tenant_id`
- `revision`
- `payload`
- `changed_at`
- `changed_by`
- `change_reason`
- `request_id`

### 9.3 Why revision history exists

Revision history is required to:
- reconstruct the exact policy active at any point in time
- investigate incidents
- compare changes
- support safe rollback analysis
- produce audit evidence

## 10. Value objects

The following value objects are recommended.

### 10.1 StudioIdentitySettings

Fields:
- `studio_name`
- `timezone`
- `locale`
- `currency`

### 10.2 BookingPolicy

Fields:
- `slot_step_minutes`
- `cancel_deadline_hours`
- `allow_overbooking`
- `max_booking_horizon_days`
- `min_booking_lead_minutes`
- `default_buffer_minutes`
- `reschedule_deadline_hours`

### 10.3 LoyaltyPolicy

Fields:
- `enabled`
- `earn_rate_points_per_100_currency`
- `redeem_min_points`
- `redeem_step_points`
- `points_rounding_mode`
- `points_expiration_days`
- `allow_negative_adjustments`

### 10.4 NotificationPolicy

Fields:
- `reminders_enabled`
- `reminder_offsets_minutes`
- `enabled_channels`
- `marketing_opt_in_required`
- `quiet_hours_start_local`
- `quiet_hours_end_local`

### 10.5 SettingsAuditMeta

Fields:
- `updated_by`
- `updated_at`
- `reason`
- `request_id`

## 11. Invariants

The aggregate must enforce the following invariants.

### 11.1 Global invariants

- one active current settings record per tenant
- `revision` must increase monotonically
- every successful mutation must create exactly one new revision
- every change must have actor and timestamp metadata
- unknown fields must not be silently persisted

### 11.2 Identity invariants

- `studio_name` must be non-empty after normalization
- `timezone` must be a valid IANA identifier
- `locale` must be a valid BCP 47 style tag accepted by platform policy
- `currency` must be a valid ISO 4217 code accepted by platform policy

### 11.3 Booking invariants

- `slot_step_minutes` must be positive
- `slot_step_minutes` must divide one hour cleanly unless architecture explicitly approves a wider set
- `cancel_deadline_hours` must be zero or greater
- `max_booking_horizon_days` must be greater than zero
- `min_booking_lead_minutes` must be zero or greater
- `default_buffer_minutes` must be zero or greater
- if `allow_overbooking = true`, this must be explicitly auditable because it changes operational risk

### 11.4 Loyalty invariants

- if loyalty is disabled, accrual and redemption settings remain defined but inactive
- earn rate must be zero or greater
- redemption minimum must be zero or greater
- redemption step must be positive when redemption is enabled
- expiration days must be zero or greater
- negative adjustments require higher permission than routine settings edits

### 11.5 Notification invariants

- reminder offsets must contain only positive integers
- reminder offsets must be unique after normalization
- reminder offsets must be sorted descending in effective representation
- quiet hours may not define an impossible interval representation
- disabled channels must not be scheduled by downstream modules

## 12. Suggested persistence model

This document defines the logical model first.

A relational implementation can use:

### 12.1 Table: tenant_settings

Columns:
- `tenant_id` PK
- `revision`
- `studio_name`
- `timezone`
- `locale`
- `currency`
- `booking_policy_json`
- `loyalty_policy_json`
- `notification_policy_json`
- `schema_version`
- `updated_at`
- `updated_by`

### 12.2 Table: tenant_settings_revisions

Columns:
- `revision_id` PK
- `tenant_id`
- `revision`
- `payload_json`
- `changed_at`
- `changed_by`
- `change_reason`
- `request_id`

### 12.3 Storage rule

The current row is optimized for reads.
The revision table is optimized for audit and history.

## 13. Why grouped policy objects are preferred

Grouped policy objects are preferred over a flat uncontrolled key-value bag because they provide:
- type safety
- explicit ownership
- schema evolution
- easier validation
- lower ambiguity for consumers

A free-form settings bag may be acceptable only for strictly namespaced experimental flags with expiry dates and governance.

## 14. Public use cases

The domain should expose the following use cases.

### 14.1 Read use cases

- `GetTenantSettings`
- `GetEffectiveBookingPolicy`
- `GetEffectiveLoyaltyPolicy`
- `GetEffectiveNotificationPolicy`
- `ListSettingsRevisions`
- `GetSettingsRevisionByNumber`
- `DiffSettingsRevisions`

### 14.2 Write use cases

- `InitializeTenantSettings`
- `UpdateStudioIdentitySettings`
- `UpdateBookingPolicy`
- `UpdateLoyaltyPolicy`
- `UpdateNotificationPolicy`
- `RestoreSettingsFromRevision`
- `LockSetting`
- `UnlockSetting`

## 15. Domain events

The domain should emit explicit events after successful committed mutations.

Recommended event set:
- `TenantSettingsInitialized`
- `TenantSettingsUpdated`
- `BookingPolicyUpdated`
- `LoyaltyPolicyUpdated`
- `NotificationPolicyUpdated`
- `TenantSettingsRestored`
- `TenantSettingsLockChanged`

Each event should include:
- `tenant_id`
- `revision`
- `changed_fields`
- `changed_at`
- `changed_by`
- `request_id`

## 16. Consumers of events

The following downstream reactions are allowed:

- `bookings` invalidates cached booking policy
- `notifications` reschedules future reminders if reminder policy changed
- `analytics` records policy change markers
- `audit` stores immutable event evidence
- `admin` refreshes settings projection

No consumer may mutate the settings aggregate in reaction to these events without an explicit orchestrated command.

## 17. Read model rules

Other modules should consume settings through read contracts.

Recommended contract shape:

```python
class EffectiveSettingsReader(Protocol):
    async def get_tenant_settings(self, tenant_id: UUID) -> TenantSettingsDTO: ...
    async def get_booking_policy(self, tenant_id: UUID) -> BookingPolicyDTO: ...
    async def get_loyalty_policy(self, tenant_id: UUID) -> LoyaltyPolicyDTO: ...
    async def get_notification_policy(self, tenant_id: UUID) -> NotificationPolicyDTO: ...