# ADR 0009: Observability Strategy

- Status: Accepted
- Date: 2026-03-22
- Owners: Platform Architecture
- Deciders: Backend, Infrastructure, Product Engineering, Security
- Supersedes: None
- Superseded by: None

## TL;DR

Reva Studio adopts a unified observability model based on three core telemetry signals: metrics, logs, and traces. OpenTelemetry is the standard instrumentation layer for application telemetry. Prometheus is the primary metrics system and alert rule evaluation engine. Alertmanager is the alert routing, grouping, deduplication, silencing, and notification component. Loki is the primary log storage backend with strict low-cardinality label policy. Tempo is the primary distributed tracing backend. Sentry is used as the product-facing exception and performance monitoring system for faster developer feedback and release-level issue triage.

This ADR defines:
- what we collect;
- how we correlate telemetry;
- what we alert on;
- how we separate product signals from platform signals;
- retention and cardinality rules;
- how observability is embedded into the Reva Studio architecture.

## Context

Reva Studio is being designed as a production-grade beauty SaaS platform with:
- API layer;
- background jobs;
- Telegram bot flows;
- relational database;
- Redis-backed asynchronous workflows;
- object storage;
- future multi-tenant growth.

In this architecture, a simple "logs only" approach is insufficient. Official OpenTelemetry documentation defines telemetry as traces, metrics, and logs. Prometheus documents a model based on scraping and time-series collection, with alerting rules evaluated from metrics. Alertmanager is the official notification routing component. Loki documentation explicitly recommends low-cardinality labels. Tempo documentation defines distributed tracing as a backend that links traces with metrics and logs. Sentry documents Python SDK support for automatic error and performance reporting.

References:
- [R1] OpenTelemetry overview: <https://opentelemetry.io/docs/what-is-opentelemetry/>
- [R2] OpenTelemetry Python: <https://opentelemetry.io/docs/languages/python/>
- [R3] OpenTelemetry Python instrumentation: <https://opentelemetry.io/docs/languages/python/instrumentation/>
- [R4] OpenTelemetry logs specification: <https://opentelemetry.io/docs/specs/otel/logs/>
- [R5] Prometheus overview: <https://prometheus.io/docs/introduction/overview/>
- [R6] Prometheus client libraries: <https://prometheus.io/docs/instrumenting/clientlibs/>
- [R7] Prometheus metric types: <https://prometheus.io/docs/concepts/metric_types/>
- [R8] Prometheus instrumentation practices: <https://prometheus.io/docs/practices/instrumentation/>
- [R9] Prometheus alerting rules: <https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/>
- [R10] Prometheus alerting overview: <https://prometheus.io/docs/alerting/latest/overview/>
- [R11] Alertmanager: <https://prometheus.io/docs/alerting/latest/alertmanager/>
- [R12] Alertmanager configuration: <https://prometheus.io/docs/alerting/latest/configuration/>
- [R13] Loki labels best practices: <https://grafana.com/docs/loki/latest/get-started/labels/bp-labels/>
- [R14] Loki label cardinality: <https://grafana.com/docs/loki/latest/get-started/labels/cardinality/>
- [R15] Loki labels: <https://grafana.com/docs/loki/latest/get-started/labels/>
- [R16] Tempo overview: <https://grafana.com/docs/tempo/latest/>
- [R17] Tempo in Grafana: <https://grafana.com/docs/tempo/latest/introduction/tempo-in-grafana/>
- [R18] Tempo metrics from traces: <https://grafana.com/docs/tempo/latest/metrics-from-traces/>
- [R19] Trace correlations: <https://grafana.com/docs/grafana/latest/datasources/tempo/traces-in-grafana/trace-correlations/>
- [R20] Sentry docs overview: <https://docs.sentry.io/>
- [R21] Sentry Python SDK: <https://docs.sentry.io/platforms/python/>
- [R22] Sentry alerts: <https://docs.sentry.io/product/alerts/>
- [R23] Sentry performance basics: <https://docs.sentry.io/product/sentry-basics/>

## Decision

### 1. Observability model

We standardize on the following model:

1. Metrics for service health, latency, throughput, saturation, queue depth, infrastructure state, and business counters.
2. Logs for forensic detail, audit context, workflow transitions, integration failures, and security-relevant events.
3. Traces for end-to-end request flow, dependency timing, async task lineage, and root cause analysis.
4. Error monitoring for developer productivity, release regression detection, issue grouping, and stack-trace triage.

### 2. Primary stack

#### 2.1 Instrumentation
- OpenTelemetry is the canonical instrumentation standard for application-generated telemetry.
- OpenTelemetry Resource attributes are mandatory for all services.
- Manual instrumentation is allowed and encouraged where automatic instrumentation is not enough.

Why:
- OpenTelemetry is a vendor-neutral framework for traces, metrics, and logs.
- OpenTelemetry Python documentation explicitly supports generating and collecting telemetry using SDKs and APIs.
- The logs specification states that logs should carry resource context for correlation.

References: [R1], [R2], [R3], [R4]

#### 2.2 Metrics
- Prometheus is the primary metrics backend for platform and application metrics.
- Prometheus exporters and application metrics endpoints are scraped on a pull model wherever possible.
- Metrics must use Prometheus-native types: Counter, Gauge, Histogram, Summary only when justified.

Why:
- Prometheus documents the server, client libraries, alert rules, and metric types as the core monitoring model.
- Prometheus instrumentation guidance recommends exposing metrics directly from applications and avoiding missing series where possible.

References: [R5], [R6], [R7], [R8]

#### 2.3 Alerting
- Prometheus alerting rules are the only authoritative source of metric-based alert creation.
- Alertmanager is the only authoritative routing layer for Prometheus-originated alerts.
- Alert routing must support grouping, deduplication, silencing, inhibition, and multiple receivers.

Why:
- Prometheus documents alerting rules as conditions evaluated from expressions.
- Alertmanager documentation defines deduplication, grouping, silencing, inhibition, and routing as core behavior.

References: [R9], [R10], [R11], [R12]

#### 2.4 Logging
- Loki is the primary log backend for centralized operational logs.
- Logs are structured JSON by default.
- Loki labels must remain low-cardinality.
- Dynamic values such as trace_id, order_id, user_id, request_id, chat_id, phone, email, and booking_id must not become Loki labels. They belong in structured log fields, not index labels.

Why:
- Loki documentation explicitly recommends low-cardinality labels and warns against ephemeral or high-cardinality values such as trace IDs, customer IDs, and similar identifiers.
- Loki documentation also states that labels should describe the source of logs and that frequently searched high-cardinality data should go into structured metadata.

References: [R13], [R14], [R15]

#### 2.5 Tracing
- Tempo is the primary distributed tracing backend.
- Traces must be queryable in Grafana and correlated with logs and metrics.
- Metrics from traces may be used as a supplemental source for latency and error analysis, but not as a replacement for primary service metrics.

Why:
- Tempo documentation states that Tempo is a distributed tracing backend that supports trace search, metrics generation from spans, and linking tracing data with logs and metrics.
- Grafana documentation supports trace correlations between spans and other telemetry systems.

References: [R16], [R17], [R18], [R19]

#### 2.6 Error and release monitoring
- Sentry is mandatory for exception monitoring in user-facing application components.
- Sentry is also used for release-level issue grouping and developer-facing performance triage.
- Sentry does not replace Prometheus, Loki, or Tempo. It complements them.

Why:
- Sentry documentation states that it provides end-to-end tracing, error visibility, alerts, and Python SDK support for automatic error and performance reporting.

References: [R20], [R21], [R22], [R23]

## Architecture principles

### Principle 1. One request, one correlation chain
Every externally visible request or asynchronous workflow must be traceable across:
- ingress;
- API;
- service layer;
- database call;
- queue publication;
- worker execution;
- third-party integration;
- outbound notification.

Mandatory correlation fields:
- `trace_id`
- `span_id`
- `service.name`
- `deployment.environment`
- `tenant.id` if multi-tenant context exists
- `request_id` where HTTP exists
- `job_name` for async workers
- `telegram_update_id` for Telegram ingestion when applicable

### Principle 2. Logs are structured, not free-form
All application logs must be emitted as structured JSON with stable keys.

Mandatory top-level fields:
- `timestamp`
- `level`
- `message`
- `service`
- `environment`
- `logger`
- `trace_id`
- `span_id`
- `request_id`
- `tenant_id`
- `event_name`

Recommended fields:
- `user_id`
- `booking_id`
- `staff_id`
- `chat_id`
- `task_name`
- `duration_ms`
- `error_type`
- `error_code`
- `integration`
- `release`

### Principle 3. Metrics are for trends and alerts, not raw event storage
Metrics must answer:
- is the system healthy;
- is it fast enough;
- is it overloaded;
- is money-impacting functionality failing;
- are background jobs draining correctly.

Metrics are not a replacement for logs or traces.

### Principle 4. Alerts must be actionable
No alert should fire unless:
- someone owns it;
- it has a runbook;
- there is a meaningful remediation path;
- the severity is defined;
- the alert threshold is deliberate and reviewable.

This follows Prometheus alerting guidance that alerting should remain simple and actionable.

Reference:
- [R24] Prometheus alerting practices: <https://prometheus.io/docs/practices/alerting/>

### Principle 5. Observability must protect privacy
Personally identifiable data and secrets must not appear in:
- metrics labels;
- log labels;
- trace attributes that leave the process boundary;
- exception payloads sent to third-party systems.

Sensitive fields must be redacted or hashed before export.

## Scope

This ADR applies to:
- backend API;
- admin API;
- Telegram bot;
- task workers;
- schedulers;
- database and cache exporters;
- reverse proxy and gateway layers;
- future frontend telemetry integration.

This ADR does not define:
- BI analytics warehouse;
- marketing attribution analytics;
- product event taxonomy for growth;
- long-term legal archive retention.

## Signal taxonomy

## Metrics taxonomy

### Platform metrics
- CPU
- memory
- disk
- filesystem saturation
- network errors
- container restarts
- database availability
- database connections
- Redis memory and eviction state
- queue depth

### Service metrics
- request rate
- request duration
- error rate
- in-flight requests
- DB query duration
- external API duration
- retry count
- worker task duration
- worker success and failure count
- scheduler lag
- webhook processing time

### Business metrics
- bookings created
- bookings cancelled
- booking payment attempts
- booking payment success
- notification delivery success
- reminder send latency
- no-show count
- loyalty accrual count
- loyalty redemption count

Business metrics must not contain personal data.

## Logging taxonomy

### Audit-worthy logs
- authentication success and failure
- role changes
- booking state transitions
- payment status transitions
- notification dispatch and delivery failures
- integration credential failures
- admin actions
- bulk data exports
- destructive operations

### Diagnostic logs
- unhandled exceptions
- upstream timeout details
- database slow query events
- cache misses for critical paths
- circuit breaker state changes
- retry exhaustion
- external provider degradation

### Security logs
- rate limit trigger
- suspicious repeated auth failures
- privilege escalation attempt
- malformed webhook payloads
- forbidden access attempts

## Tracing taxonomy

The following flows must be traced end-to-end:
- create booking
- reschedule booking
- cancel booking
- send reminder
- calculate loyalty balance
- staff schedule update
- payment initiation
- payment confirmation callback
- Telegram update processing
- async job fan-out
- file upload and media attachment pipeline

## Standard resource attributes

Every process must export at minimum:
- `service.name`
- `service.namespace`
- `service.version`
- `deployment.environment`
- `host.name`
- `process.pid`
- `process.runtime.name`
- `process.runtime.version`

Recommended additional attributes:
- `service.instance.id`
- `cloud.region`
- `container.id`
- `git.commit.sha`
- `git.branch`
- `build.id`

## SLI and SLO model

Reva Studio adopts a practical SLI and SLO model centered on user-visible reliability.

### Core SLIs

#### API availability
Definition:
- percentage of successful health-serving requests from the user perspective.

#### Booking write success rate
Definition:
- ratio of successful booking creation requests to total valid booking creation attempts.

#### Booking p95 latency
Definition:
- p95 duration for booking creation endpoints and dependent workflows.

#### Reminder delivery success
Definition:
- ratio of successful reminder dispatch outcomes to total reminder dispatch attempts.

#### Worker execution success
Definition:
- ratio of successfully completed background tasks to total started tasks.

#### Payment callback processing success
Definition:
- ratio of accepted and processed payment callbacks to total valid callbacks.

### Initial SLO baselines

These are internal engineering targets, not facts about current production state:

- API monthly availability target: 99.9 percent
- Booking write success target: 99.95 percent
- Booking p95 target: under 500 ms for standard read paths and under 1200 ms for booking write paths
- Reminder dispatch success target: 99.5 percent
- Critical worker queue delay target: under 60 seconds p95

These targets are adopted as design objectives and must be reviewed after real load data appears.

## Alert severity model

### Severity levels
- `critical`: immediate user impact, revenue impact, or data integrity risk
- `high`: serious degradation requiring urgent response
- `medium`: meaningful degradation or growing risk
- `low`: non-urgent operational signal
- `info`: visibility only, no page

### Critical alerts
- API unavailable
- booking creation error spike
- payment callback failure spike
- database unavailable
- Redis unavailable where it blocks critical workflows
- worker queue stalled for critical queue
- migration mismatch causing application startup failure

### High alerts
- p95 latency breach sustained
- elevated Telegram webhook failure rate
- sustained reminder send failures
- external provider timeout spike
- disk pressure on stateful observability backends

### Medium alerts
- elevated restart frequency
- Sentry issue regression after release
- low storage headroom
- exporter scrape failures

### Info alerts
- deployment started
- deployment finished
- new release health window entered
- temporary rate-limit increase

## Cardinality rules

### Metrics label policy
Allowed stable labels:
- `service`
- `environment`
- `route` with normalized templates only
- `method`
- `status_class`
- `queue`
- `operation`
- `provider`
- `result`

Forbidden high-cardinality labels:
- raw `user_id`
- raw `booking_id`
- raw `staff_id`
- `trace_id`
- `span_id`
- `request_id`
- `chat_id`
- phone
- email
- full URL
- full SQL query
- full Telegram message text

### Loki label policy
Allowed Loki labels:
- `service`
- `environment`
- `level`
- `stream`
- `component`
- `job`

Recommended structured fields instead of labels:
- `trace_id`
- `tenant_id`
- `user_id`
- `booking_id`
- `request_id`
- `error_code`
- `provider_response_code`

This follows Loki official guidance that labels should be low-cardinality and stable.

## Sampling policy

### Traces
- Default head sampling in production: 10 percent
- Error traces: always keep
- Slow traces above latency threshold: always keep
- Critical business flows:
  - booking creation
  - payment callback
  - reminder dispatch pipeline
  - admin destructive actions
  sampled at elevated rate or fully retained during early production maturity

### Logs
- Error logs: retain
- Warning logs: retain
- Info logs: retain with bounded retention
- Debug logs: disabled in production unless temporary incident mode is enabled

### Metrics
- Metrics are not sampled in the same way as traces; scrape intervals and histogram bucket design must be deliberate.

## Retention policy

Initial minimum policy:

- Prometheus high-resolution metrics: 15 to 30 days
- Loki operational logs: 14 to 30 days
- Tempo traces: 7 to 14 days by default, longer for critical incident windows
- Sentry issues and release-linked event retention: according to active plan and internal compliance policy

These are engineering defaults and may be revised based on cost, compliance, and incident data.

## Data flow architecture

### Application telemetry flow
1. Reva service emits metrics, logs, and traces.
2. Metrics are exposed for Prometheus scrape or exported through OpenTelemetry-compatible path if later centralized.
3. Logs are shipped in structured form to Loki pipeline.
4. Traces are exported to Tempo through OpenTelemetry.
5. Errors are additionally sent to Sentry for issue tracking and release diagnostics.
6. Grafana is the primary operator console for metrics, logs, and traces.
7. Alertmanager handles routing of Prometheus-originated alerts.
8. Sentry handles Sentry-native issue and performance alerts.

## Mandatory dashboards

### Executive service health dashboard
- availability
- error rate
- p95 and p99 latency
- request volume
- booking success rate
- payment success rate
- reminder success rate

### API dashboard
- request rate by route template
- latency histograms
- error breakdown
- DB duration
- Redis duration
- external dependency duration
- saturation indicators

### Worker dashboard
- queue depth
- task runtime
- success and failure counts
- retry counts
- oldest queued job age
- scheduler lag

### Database dashboard
- connections
- locks
- deadlocks
- slow queries
- replication state if introduced later
- checkpoint pressure
- disk growth

### Telegram bot dashboard
- update intake rate
- command failure rate
- callback query latency
- webhook or polling failures
- user-visible interaction failure rate

### Business operations dashboard
- bookings by status
- no-show trend
- reminder success
- loyalty issuance and redemption
- payment funnel success rate

## Mandatory runbook contract

Every production alert must include:
- alert name
- summary
- severity
- owner team
- probable impact
- probable causes
- first checks
- Grafana links
- Loki query template
- Tempo trace exploration hint
- rollback or mitigation steps
- escalation path

## Developer instrumentation requirements

### Python API services
Must expose:
- request count
- request duration histogram
- exception count
- DB query duration
- external HTTP client duration
- queue publish count
- business counters for critical operations

### Background workers
Must expose:
- task started count
- task completed count
- task failed count
- retry count
- task duration histogram
- queue lag gauge where possible

### Telegram bot
Must expose:
- updates received count
- handler duration
- handler failure count
- outbound message send duration
- provider-specific response failure count

## Logging requirements

### Required rules
- logs must be JSON in production;
- timestamps must be UTC or explicitly normalized;
- stack traces must be structured;
- secrets must be redacted;
- personally identifiable fields must be masked or hashed where export is necessary;
- duplicate exception logging must be minimized;
- every error log must include stable machine-parsable context.

### Forbidden rules
- no multiline ad hoc logs for application events;
- no raw SQL with user data in logs;
- no raw provider credentials;
- no metrics-like counters hidden inside free text logs.

## Trace requirements

Every root span must include:
- route or operation name
- service identity
- environment
- release version
- tenant context where available

Every child span should exist for:
- DB call
- Redis call
- outbound HTTP call
- message publish
- message consume
- template render if expensive
- file storage call

## Sentry usage policy

Sentry is used for:
- exception aggregation
- release regression detection
- developer triage
- performance hotspots visible to engineering

Sentry is not the authoritative source for:
- infrastructure alerting
- queue health
- scrape-based system metrics
- centralized log analytics
- long-range time-series capacity analysis

## Security and compliance controls

- redact secrets before export;
- avoid personal data in labels and span attributes;
- restrict observability backend access by role;
- production dashboards with sensitive business signals must require authenticated access;
- audit access to observability admin functions;
- treat observability systems as production-critical assets.

## Multi-tenant readiness

When multi-tenant mode becomes active:
- tenant context must be present in traces and structured logs;
- tenant context must not explode cardinality in metrics;
- per-tenant metrics should exist only where bounded and aggregated;
- tenant-specific dashboards must be derived from structured queries, not from uncontrolled label growth.

## Failure policy

If part of the observability stack fails:
- the application must continue serving traffic where safe;
- telemetry export must degrade gracefully;
- telemetry exporters must avoid crashing request paths;
- local logging fallback must exist for critical startup failures;
- temporary loss of tracing must not block the product path.

## Implementation roadmap

### Phase 1
- structured JSON logging
- Prometheus metrics endpoint
- baseline Grafana dashboards
- Alertmanager routing
- Sentry Python integration
- core API and worker alerts

### Phase 2
- OpenTelemetry tracing for API, worker, and Telegram flows
- Tempo integration
- log-trace correlation
- release-level service overview

### Phase 3
- business SLIs and SLO burn-rate alerts
- multi-tenant observability conventions
- capacity and saturation forecasting
- runbook automation and incident templates

## Consequences

### Positive
- consistent cross-service telemetry model
- faster incident triage
- actionable alert routing
- developer-facing error visibility
- safer scale-up for Reva Studio
- clearer separation between platform signals and product signals

### Negative
- additional operational cost
- more engineering discipline required
- risk of noisy alerts if thresholds are poor
- need for cardinality governance
- ongoing dashboard and runbook maintenance overhead

## Rejected alternatives

### A. Logs only
Rejected because logs alone do not provide time-series alerting behavior equivalent to Prometheus metrics, nor distributed request-flow visibility equivalent to tracing.

### B. Sentry only
Rejected because Sentry is valuable for application error and performance monitoring, but it is not a replacement for Prometheus-based metrics monitoring, Loki-style centralized logs, or Tempo-based distributed tracing.

### C. Prometheus plus logs without tracing
Rejected because asynchronous workflows, third-party integrations, and end-to-end user journeys require distributed traces for efficient root-cause analysis.

## Acceptance criteria

This ADR is considered implemented when:
- all production services emit structured logs;
- all critical services expose Prometheus metrics;
- Prometheus scrapes all required targets;
- Alertmanager routes alerts by severity and owner;
- Loki receives centralized structured logs;
- Tempo receives traces from critical flows;
- Sentry receives exceptions from user-facing services;
- Grafana contains required dashboards;
- all critical alerts have runbooks.

## Review policy

This ADR must be reviewed:
- before first production launch;
- after first real incident involving booking, payment, reminder, or Telegram delivery failures;
- when multi-tenant isolation is introduced;
- when frontend telemetry becomes first-class;
- when compliance requirements change.

## Source notes

This ADR uses the following external facts:
- OpenTelemetry is a vendor-neutral observability framework for traces, metrics, and logs. [R1]
- OpenTelemetry Python supports application telemetry generation and instrumentation. [R2], [R3]
- OpenTelemetry logs are designed to correlate with resource context. [R4]
- Prometheus defines a monitoring model with server, client libraries, rules, and alerting ecosystem. [R5], [R6], [R9], [R10]
- Alertmanager is responsible for grouping, deduplication, silencing, inhibition, and routing. [R11], [R12]
- Loki recommends low-cardinality labels and warns against high-cardinality identifiers. [R13], [R14], [R15]
- Tempo supports trace search, metrics from spans, and correlation with logs and metrics. [R16], [R17], [R18], [R19]
- Sentry supports Python error and performance monitoring and alerting. [R20], [R21], [R22], [R23]