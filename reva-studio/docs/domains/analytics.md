# Analytics Domain

Status: Draft
Version: 1.0
Owner: Reva Studio Platform Team
Bounded Context: Analytics
Last Updated: 2026-03-23

## 1. Purpose

The Analytics domain is responsible for collecting, validating, aggregating, storing, and exposing business and operational metrics for Reva Studio.

This bounded context exists to answer five classes of questions:

1. Revenue and profitability
2. Bookings and capacity utilization
3. Staff and service performance
4. Client behavior, retention, and loyalty effectiveness
5. Platform health and conversion funnel quality

This document defines the target industrial architecture and domain model for analytics inside Reva Studio.

## 2. Business Goal

The analytics subsystem must provide a reliable decision layer for:

- studio owner and management
- administrators
- analysts
- future AI-assistant features
- automated recommendation engines
- financial and operational reporting

The primary goal is not only to display charts, but to create a single source of truth for measurable business outcomes.

## 3. Domain Scope

### In Scope

The Analytics domain includes:

- event collection from core business domains
- metric definitions and KPI formulas
- time-based aggregations
- dimension-based slicing and drill-down
- dashboard query models
- cohort and retention reporting
- loyalty and marketing effectiveness analytics
- operational analytics for staff, bookings, and cancellations
- data quality checks for analytical events
- analytical read models optimized for reporting

### Out of Scope

The Analytics domain does not own:

- booking creation and booking lifecycle rules
- payment authorization and settlement logic
- loyalty accrual execution rules
- notification sending logic
- CRM source-of-truth ownership
- raw observability stack ownership such as logs, traces, and infrastructure metrics

Those concerns belong to their own bounded contexts and publish analytical facts into Analytics.

## 4. Strategic Role in Reva Studio

Analytics is a downstream bounded context.

It consumes business facts from upstream domains:

- users
- clients
- staff
- services catalog
- bookings
- payments
- loyalty
- promotions
- notifications

Analytics does not mutate upstream business state.
Analytics transforms domain events and snapshots into analytical read models.

## 5. Architectural Principles

### 5.1 Source of Truth Separation

Operational tables are not the final analytical contract.
Operational state answers "what is true now".
Analytical state answers "what happened over time and why".

### 5.2 Event-First Thinking

Every meaningful business action should become an analytical fact.
Examples:

- booking_created
- booking_confirmed
- booking_completed
- booking_cancelled
- payment_authorized
- payment_captured
- loyalty_points_accrued
- loyalty_points_redeemed
- client_registered
- review_received
- no_show_detected

### 5.3 Immutable Facts, Rebuildable Projections

Raw analytical events should be append-only where practical.
Aggregates, dashboards, and materialized read models are rebuildable projections.

### 5.4 Explicit Metric Definitions

Every KPI must have:

- canonical name
- business meaning
- formula
- grain
- dimensions
- ownership
- allowed filters
- freshness target
- caveats

### 5.5 Reproducibility

The same input events and the same metric definition must produce the same result for the same time range and filter set.

### 5.6 Explainability

A metric must be traceable back to:

- its definition
- its source events
- its calculation window
- its filters
- its exclusions
- its data freshness timestamp

## 6. Ubiquitous Language

### Analytical Event

An immutable record of a business-significant action emitted for analytics.

### Metric

A named measurable quantity derived from events or facts.

### KPI

A metric explicitly used to assess business success.

### Dimension

An attribute used to group or filter metrics.
Examples: staff member, service category, branch, booking source, day, week, month.

### Grain

The lowest level of detail at which a metric is stored or computed.
Examples: per booking, per day, per staff per day.

### Fact Table

A storage model centered on measurable events or amounts.

### Snapshot

A time-bound representation of state at a given moment.

### Projection

A read model optimized for reporting.

### Cohort

A set of clients grouped by the same start condition, usually first booking month or registration month.

### Retention

The share of a cohort that returns in subsequent periods.

### Attribution Window

The time interval in which an action may be credited to a campaign, promotion, or source.

## 7. Primary Consumers

### 7.1 Studio Owner

Needs:

- revenue trend
- occupancy and utilization
- staff productivity
- service profitability
- repeat client rate
- loyalty ROI
- cancellation and no-show losses

### 7.2 Administrator

Needs:

- upcoming workload trends
- unconfirmed booking rate
- source conversion
- promotion effectiveness
- staff schedule pressure

### 7.3 Analyst

Needs:

- raw facts
- reproducible definitions
- cohort analysis
- period-over-period comparisons
- exportable aggregates

### 7.4 AI Assistant

Needs:

- high-signal features
- normalized KPIs
- trend detection
- anomaly inputs
- recommendation-ready summaries

## 8. Core Business Questions

The Analytics domain must answer at minimum:

1. What is total revenue for a selected period?
2. What share of bookings becomes completed services?
3. Which services drive the highest revenue and margin?
4. Which staff members have the highest utilization and retention?
5. What is the cancellation and no-show rate by source and by staff?
6. What percentage of new clients returns within 30, 60, and 90 days?
7. What promotions increase conversion without destroying margin?
8. What is the effect of loyalty points on repeat bookings?
9. Which channels bring the highest LTV clients?
10. What time slots and days underperform and need intervention?

## 9. Capability Map

### 9.1 Event Ingestion

Responsibilities:

- accept analytical events from application domains
- validate schema and mandatory dimensions
- enforce idempotency
- reject malformed or duplicate payloads where required
- stamp ingestion metadata

### 9.2 Metric Catalog

Responsibilities:

- maintain metric registry
- describe formulas and dimensions
- define ownership and freshness
- version metric definitions

### 9.3 Aggregation

Responsibilities:

- derive daily, weekly, and monthly rollups
- produce staff, service, and client aggregates
- maintain cohort tables
- calculate trend deltas

### 9.4 Reporting Read Models

Responsibilities:

- expose optimized query models for dashboards
- keep response latency predictable
- provide drill-down paths to source facts

### 9.5 Data Quality

Responsibilities:

- detect missing events
- detect broken dimensions
- detect impossible states
- expose quality status and freshness metadata

## 10. Domain Boundaries and Upstream Contracts

Analytics depends on these upstream facts.

### 10.1 Bookings Domain Publishes

- booking_id
- client_id
- staff_id
- service_id
- scheduled_at
- source
- status changes
- cancellation reason
- no_show flag
- completion timestamp

### 10.2 Payments Domain Publishes

- payment_id
- booking_id
- amount
- currency
- payment status
- refund amount
- captured_at

### 10.3 Loyalty Domain Publishes

- client_id
- accrual event
- redemption event
- balance changes
- reason and reference

### 10.4 Promotions Domain Publishes

- campaign_id
- promo_code
- attribution source
- discount value
- applicable services
- validity window

### 10.5 Users and Clients Domains Publish

- registration facts
- profile lifecycle facts
- segmentation dimensions if allowed by policy

Analytics must treat upstream domains as authoritative for business facts.
Analytics may enrich data for reporting but must not redefine upstream truth.

## 11. Domain Model

## 11.1 Entities

### MetricDefinition

Represents the canonical definition of a metric.

Attributes:

- metric_key
- display_name
- description
- status
- owner
- formula_expression
- numerator_definition
- denominator_definition
- grain
- supported_dimensions
- default_filters
- freshness_sla_minutes
- version
- effective_from
- effective_to
- deprecated_at

### AnalyticsReport

Represents a named report contract exposed to UI or API.

Attributes:

- report_key
- display_name
- consumer_type
- allowed_filters
- allowed_dimensions
- default_period
- default_sort
- freshness_policy
- visibility_scope

### AnalyticalEvent

Represents an immutable business fact.

Attributes:

- event_id
- event_type
- occurred_at
- ingested_at
- source_domain
- aggregate_type
- aggregate_id
- actor_id
- client_id
- staff_id
- service_id
- branch_id
- payload
- idempotency_key
- schema_version

### DataQualityIssue

Represents a detected analytics integrity problem.

Attributes:

- issue_id
- issue_type
- severity
- detected_at
- affected_metric_key
- affected_source
- affected_window_start
- affected_window_end
- issue_details
- resolved_at

## 11.2 Value Objects

### TimeRange

- start_at
- end_at
- timezone
- granularity

### MetricValue

- metric_key
- value
- unit
- computed_at
- confidence_status
- freshness_status

### DimensionSet

- staff_id
- service_id
- category_id
- source
- campaign_id
- weekday
- hour_bucket
- period_bucket

### MoneyAmount

- amount
- currency

### PercentageValue

- numerator
- denominator
- percentage

## 11.3 Domain Services

### MetricComputationService

Computes a metric from facts under a defined formula.

### CohortAnalysisService

Builds and serves retention and return-rate cohorts.

### RevenueAttributionService

Allocates revenue or bookings to source, campaign, or loyalty driver according to business rules.

### DashboardQueryService

Serves optimized analytical read models to consumers.

### DataQualityService

Evaluates event completeness, freshness, and integrity.

## 12. Aggregate Design

The Analytics domain is projection-heavy and usually read-optimized.
Not every concept needs a transactional aggregate in the DDD sense.

Recommended consistency roots:

### Aggregate: MetricDefinition

Invariants:

- metric_key is unique
- versioning is monotonic
- formula fields are not empty for computed metrics
- supported dimensions are explicit
- only one active version exists for a metric at a point in time

### Aggregate: AnalyticsReport

Invariants:

- report_key is unique
- only supported metrics can appear in a report
- every report declares allowed filters and dimensions
- visibility scope is explicit

### Aggregate: DataQualityIssue

Invariants:

- issue type and severity are mandatory
- resolution metadata is required on close
- linked metric or source must be identifiable

Raw analytical events usually do not require rich aggregate behavior.
They are primarily append-only facts with validation and idempotency guarantees.

## 13. Canonical KPIs

The following KPI set is the minimum industrial baseline.

## 13.1 Revenue KPIs

### Gross Revenue

Definition:
Sum of captured payment amounts for the selected time range.

### Net Revenue

Definition:
Gross revenue minus refunds and discounts recognized in the same business policy window.

### Average Order Value

Definition:
Gross revenue divided by completed paid bookings.

### Revenue per Staff Hour

Definition:
Revenue divided by booked productive staff hours.

## 13.2 Booking KPIs

### Booking Creation Count

Definition:
Count of bookings created in period.

### Completion Rate

Definition:
Completed bookings divided by created bookings for the same cohort or attribution rule.

### Cancellation Rate

Definition:
Cancelled bookings divided by created bookings.

### No-Show Rate

Definition:
No-show bookings divided by confirmed bookings or scheduled visits according to agreed policy.

### Rebooking Rate

Definition:
Share of completed bookings followed by another booking from the same client within a defined window.

## 13.3 Client KPIs

### New Clients

Definition:
Count of clients with first completed booking in the period.

### Repeat Clients

Definition:
Count of clients with more than one completed booking in the analysis horizon.

### Client Retention 30d, 60d, 90d

Definition:
Share of a cohort that returns with at least one completed booking within 30, 60, or 90 days.

### Client Lifetime Value

Definition:
Cumulative realized value attributed to a client over a selected horizon.

## 13.4 Loyalty KPIs

### Points Accrued

Definition:
Total loyalty points accrued in period.

### Points Redeemed

Definition:
Total loyalty points redeemed in period.

### Redemption Rate

Definition:
Redeeming clients divided by eligible clients, or redeemed points divided by accrued points, depending on business definition.
The chosen formula must be fixed in `MetricDefinition`.

### Loyalty-Assisted Repeat Rate

Definition:
Repeat booking rate among clients exposed to loyalty mechanics.

## 13.5 Marketing KPIs

### Source Conversion Rate

Definition:
Completed bookings divided by acquired leads, visits, registrations, or booking creations according to source contract.

### Campaign ROI

Definition:
Incremental attributable value divided by campaign spend, only if spend data is governed and present.

### Promo Usage Rate

Definition:
Share of bookings using a valid promotion.

## 13.6 Staff KPIs

### Utilization Rate

Definition:
Booked productive time divided by available working time.

### Fill Rate

Definition:
Booked slots divided by available slots.

### Revenue per Staff Member

Definition:
Revenue attributed to a staff member in period.

### Repeat Rate by Staff Member

Definition:
Share of returning clients who rebook the same staff member.

## 14. KPI Definition Rules

Every KPI must specify:

- business owner
- formula
- units
- denominator semantics
- inclusion rules
- exclusion rules
- timezone
- late-arrival policy
- refund policy
- reprocessing policy
- rounding strategy

A KPI is invalid for production use if any of the above is missing.

## 15. Analytical Event Catalog

Recommended minimal event catalog:

- client_registered
- client_profile_completed
- booking_created
- booking_rescheduled
- booking_confirmed
- booking_cancelled
- booking_completed
- booking_no_show
- payment_initiated
- payment_captured
- payment_refunded
- loyalty_points_accrued
- loyalty_points_redeemed
- promotion_applied
- review_submitted
- referral_registered

Each event must include:

- stable event name
- schema version
- occurred_at timestamp
- unique event id
- idempotency key if replay risk exists
- domain source
- traceability identifiers

## 16. Data Contracts

## 16.1 Event Envelope

```json
{
  "event_id": "uuid",
  "event_type": "booking_completed",
  "schema_version": 1,
  "occurred_at": "2026-03-23T10:30:00Z",
  "ingested_at": "2026-03-23T10:30:03Z",
  "source_domain": "bookings",
  "aggregate_type": "booking",
  "aggregate_id": "booking_123",
  "idempotency_key": "booking_completed:booking_123:v1",
  "payload": {}
}