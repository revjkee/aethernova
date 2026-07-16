# Observability Runbook

- Document status: Approved
- Service: Reva Studio
- Domain: Platform / Observability
- Owners: Platform Engineering, Backend Engineering, On-Call
- Last updated: 2026-03-23
- Related ADR: `docs/architecture/0009-observability.md`

## 1. Purpose

This runbook defines how to detect, triage, investigate, mitigate, and close observability-related incidents in Reva Studio.

It covers:
- metrics incidents;
- alert routing incidents;
- log ingestion and query incidents;
- trace collection and correlation incidents;
- application exception monitoring incidents;
- telemetry quality regressions;
- degraded visibility during production incidents.

This document is operational. It is not an ADR and it is not a tool setup guide.

## 2. Scope

This runbook applies to:
- API services;
- admin services;
- Telegram bot services;
- background workers;
- schedulers;
- PostgreSQL and Redis monitoring signals;
- Prometheus-based alerting;
- Alertmanager routing;
- Loki log storage and querying;
- Tempo trace storage and querying;
- Sentry exception and application alerting.

This runbook does not cover:
- business analytics dashboards;
- marketing attribution tooling;
- legal evidence retention;
- cost optimization policy beyond emergency mitigation.

## 3. Observability stack

Reva Studio standardizes on the following roles:

- OpenTelemetry for application instrumentation and telemetry emission.
- Prometheus for metrics scraping, storage, PromQL-based alerting rules, and time-series monitoring.
- Alertmanager for grouping, deduplication, routing, silencing, and inhibition of Prometheus alerts.
- Loki for centralized logs and LogQL-based querying.
- Tempo for distributed traces and trace search.
- Sentry for error monitoring, release-linked issue tracking, and product-facing performance alerting.

These roles are defined by the official product documentation. OpenTelemetry documents traces, metrics, and logs as core telemetry signals. Prometheus documents alerting rules. Alertmanager documents grouping, routing, silencing, and inhibition. Loki documents label-based querying and log pipelines. Tempo documents TraceQL and trace navigation. Sentry documents issue, metric, and uptime alerts. :contentReference[oaicite:1]{index=1}

## 4. Operational principles

### 4.1 Observability must degrade gracefully

Loss of telemetry must not become the primary cause of product downtime. If exporters, collectors, or backends degrade, the product path should continue where safe.

OpenTelemetry documents instrumentation as application code that emits telemetry, which means instrumentation is part of runtime behavior and must be treated carefully in failure handling. :contentReference[oaicite:2]{index=2}

### 4.2 Alerting must be actionable

Prometheus alerting guidance recommends keeping alerting simple, alerting on symptoms, and avoiding pages where there is nothing to do. This runbook follows that rule. :contentReference[oaicite:3]{index=3}

### 4.3 Log labels must stay low-cardinality

Loki query and label documentation is built around label selectors and pipelines. High-cardinality labels harm query performance and storage efficiency. Use stable labels such as service, environment, level, job, component. Keep request identifiers, booking identifiers, user identifiers, and trace identifiers in structured fields, not index labels. Loki’s official documentation explicitly centers querying on labels and pipelines. :contentReference[oaicite:4]{index=4}

### 4.4 Traces are for request flow and causality

Tempo and Grafana document trace navigation, exemplars, metrics-from-traces, and TraceQL. Use traces to answer why and where latency or failures occur across service boundaries. Do not use traces as the only source for SLI math. :contentReference[oaicite:5]{index=5}

### 4.5 Sentry complements, not replaces, platform telemetry

Sentry officially supports issue alerts, metric alerts, and uptime alerts. It is valuable for developer-facing triage, but not a replacement for Prometheus alerting or centralized log analysis. :contentReference[oaicite:6]{index=6}

## 5. Severity model

### SEV-1
Critical customer-facing outage or major revenue-impacting degradation.
Examples:
- API unavailable;
- booking creation unavailable;
- payment callback processing failing systemically;
- all critical logs unavailable during an ongoing incident;
- metrics and traces simultaneously unavailable during an incident window.

Target actions:
- acknowledge immediately;
- create incident channel;
- assign incident commander;
- start 15-minute update cadence;
- apply safe mitigation first, root cause second.

### SEV-2
Major degradation with partial functionality loss.
Examples:
- Telegram bot command failures above baseline;
- worker queue stalled for critical reminder or booking jobs;
- Prometheus scraping critical services failing broadly;
- Loki ingestion delayed enough to block incident diagnosis.

### SEV-3
Operational degradation with workaround available.
Examples:
- single dashboard broken;
- one exporter down;
- one non-critical alert route misconfigured;
- traces missing for one service.

### SEV-4
Low urgency maintenance or quality issue.
Examples:
- noisy alert;
- missing labels in logs;
- bad dashboard variable;
- non-blocking Sentry rule misconfiguration.

## 6. Ownership and routing

### Primary owners
- Platform Engineering: Prometheus, Alertmanager, Loki, Tempo, Grafana, collectors, dashboards.
- Backend Engineering: application metrics, structured logs, tracing spans, Sentry SDK configuration.
- Bot/Workflow Engineering: Telegram bot telemetry, workers, schedulers, retry visibility.
- Incident Commander: incident coordination during SEV-1 and SEV-2.

### Escalation
1. On-call owner acknowledges alert.
2. If no acknowledgement within defined SLA, escalate to secondary.
3. If customer impact is visible or uncertainty is high, escalate to incident commander.
4. If telemetry failure blocks diagnosis during production impact, treat observability outage itself as customer-impacting.

## 7. Source-of-truth order during incidents

Use evidence in the following order:

1. Prometheus alerts and service health metrics
2. Loki logs for event chronology
3. Tempo traces for request path and dependency timing
4. Sentry for grouped application exceptions and release correlation
5. Direct service health endpoints and infra checks
6. Recent deploy history and config changes

Rationale:
- Prometheus alerting rules are the primary metric-based alert source. :contentReference[oaicite:7]{index=7}
- Loki is designed for log querying through selectors and pipelines. :contentReference[oaicite:8]{index=8}
- Tempo is designed for distributed tracing and trace querying. :contentReference[oaicite:9]{index=9}
- Sentry provides issue and metric/uptime alerting centered on application errors and performance. :contentReference[oaicite:10]{index=10}

## 8. Golden signals to check first

Check these first for every suspected product incident:

- traffic;
- errors;
- latency;
- saturation.

Then check domain-specific signals:
- booking_create_success_rate;
- booking_create_duration_p95;
- telegram_update_failures_total;
- worker_queue_oldest_job_seconds;
- reminder_delivery_failures_total;
- payment_callback_failures_total.

## 9. First 5 minutes checklist

1. Confirm whether the alert is real, duplicated, or stale.
2. Identify impacted service, environment, and customer surface.
3. Check whether there was a deployment or configuration change in the last 30 minutes.
4. Open:
   - Grafana service overview dashboard
   - Prometheus target health view
   - Loki logs for affected service
   - Tempo trace search for affected route or operation
   - Sentry issues filtered by release and environment
5. Classify severity.
6. If impact is customer-visible, begin incident communications.
7. If the alert is observability-only, determine whether diagnosis capability is degraded enough to escalate severity.

## 10. Standard dashboards to open

### 10.1 API incident
Open:
- Service Overview
- API Latency and Errors
- Database Health
- Redis Health
- Deployment Timeline
- Sentry release health
- Tempo traces for affected endpoint

### 10.2 Worker incident
Open:
- Worker Queue Health
- Queue Depth
- Retry and Failure Rates
- Oldest Job Age
- Redis Health
- Sentry worker issues
- Tempo traces for enqueue-to-consume flow

### 10.3 Telegram bot incident
Open:
- Telegram Update Intake
- Handler Error Rate
- Outbound Send Latency
- Worker Queue Health
- Sentry bot issues
- Loki filtered by update_id or request correlation field

### 10.4 Observability platform incident
Open:
- Prometheus target health
- Alertmanager status
- Loki ingestion health
- Tempo ingestion health
- Grafana datasource health
- Collector/exporter health
- Sentry ingest status if used

## 11. Standard triage flows

## 11.1 Alert fired in Prometheus

Prometheus alerting rules create alerts from PromQL expressions, and Alertmanager manages notifications, grouping, silencing, inhibition, and routing. :contentReference[oaicite:11]{index=11}

Do:
1. Inspect alert labels:
   - alertname
   - severity
   - service
   - environment
   - instance
   - runbook_url
2. Verify whether the alert is still firing in Prometheus.
3. Check whether Alertmanager grouped it with related alerts.
4. Identify whether inhibition should have suppressed a secondary alert.
5. Determine if this is symptom or cause.

Common causes:
- exporter down;
- scrape endpoint changed;
- network partition;
- actual service degradation;
- bad rule threshold;
- cardinality or query regression.

Immediate mitigation:
- if rule is wrong, silence with time-boxed reason;
- if service is down, restore service first;
- if target disappeared after deploy, roll back or restore scrape config;
- if Alertmanager routing failed, use backup notification path manually.

## 11.2 No alerts, but customers report outage

Do:
1. Check Grafana dashboards directly.
2. Query Prometheus for:
   - request rate drop;
   - error spikes;
   - p95 latency growth;
   - unavailable targets.
3. Query Loki for error logs in last 15 minutes.
4. Search Tempo for the affected route, operation, or service.
5. Check Sentry for new issues and release spikes.
6. Verify health endpoints manually.

Interpretation:
- no alert does not mean no incident;
- missing telemetry may itself indicate an incident;
- investigate both product path and telemetry path.

## 11.3 Logs missing in Loki

Loki exposes APIs for pushing, querying, and tailing logs, and querying is based on log stream selectors and pipelines. :contentReference[oaicite:12]{index=12}

Symptoms:
- empty queries for active services;
- sudden ingestion gap;
- logs visible locally but not in Grafana;
- only some services missing.

Check:
1. Is the service still emitting logs locally.
2. Is the shipper or collector healthy.
3. Are labels still matching expected selectors.
4. Did a label schema change break queries.
5. Is ingestion failing because of auth, network, or storage.
6. Are queries too restrictive.

Mitigation:
- switch to local container logs if available;
- reduce query scope to stable labels only;
- revert recent label schema changes;
- restore shipper credentials or endpoint;
- disable noisy debug flood if Loki is overloaded.

Recovery criteria:
- logs visible again for critical services;
- query latency acceptable;
- incident window searchable end-to-end.

## 11.4 Traces missing in Tempo

Tempo is the trace backend, and TraceQL is its trace query language. Tempo also integrates with Grafana and exemplars. :contentReference[oaicite:13]{index=13}

Symptoms:
- no traces for active requests;
- partial spans only;
- exemplars absent from metrics;
- trace-to-log correlation broken.

Check:
1. Is OpenTelemetry instrumentation still active.
2. Are environment variables or exporter endpoints changed.
3. Are collectors receiving spans.
4. Is sampling set too low.
5. Are traces blocked by network or auth errors.
6. Did the service lose resource attributes such as `service.name`.

Mitigation:
- temporarily raise sampling for critical flows;
- restore exporter endpoint;
- roll back instrumentation/config change;
- use logs and metrics while traces recover.

Recovery criteria:
- new traces searchable;
- parent-child span relationships intact;
- service name and environment attributes present;
- cross-links from metrics/logs operational.

## 11.5 Sentry spike or flood

Sentry supports issue alerts, metric alerts, and uptime alerts. Best-practice guidance focuses on reducing noise and routing effectively. :contentReference[oaicite:14]{index=14}

Symptoms:
- sudden issue explosion after release;
- repeated duplicate issues;
- alert storm from one known regression;
- performance alert flood.

Check:
1. Is there a new release correlation.
2. Are errors coming from one environment only.
3. Are they new issues or frequency spikes of known issues.
4. Are sampling or SDK filters changed.
5. Did one failing dependency cascade across many endpoints.

Mitigation:
- roll back bad release if customer impact is real;
- mute noisy non-actionable rules temporarily;
- create issue filters for known non-actionable signatures;
- keep one canonical alert active for the incident.

Recovery criteria:
- issue rate returns to expected baseline;
- alert rules no longer flood;
- post-release regression understood and tracked.

## 11.6 Prometheus target down

Prometheus relies on scraping targets and exporters. If a target is down, determine whether the monitored service is down or only the scrape path is broken. :contentReference[oaicite:15]{index=15}

Check:
1. service process/container health;
2. `/metrics` endpoint availability;
3. service discovery or static target config;
4. TLS/auth mismatch;
5. network reachability;
6. exporter process state.

Mitigation:
- restart exporter or service;
- restore metrics endpoint path;
- revert discovery/config change;
- temporarily rely on alternative signals while scrape is restored.

## 11.7 Alertmanager routing failure

Alertmanager is responsible for deduplication, grouping, routing, silencing, and inhibition. Routing configuration is controlled through its configuration file. :contentReference[oaicite:16]{index=16}

Symptoms:
- alerts firing in Prometheus but no notifications;
- duplicated notifications;
- wrong receiver;
- silences not applying;
- inhibition not working.

Check:
1. Is Alertmanager reachable.
2. Does Prometheus show successful alert delivery.
3. Is the route tree correct.
4. Are label matchers correct.
5. Is the receiver integration healthy.
6. Are silences or inhibition rules conflicting.

Mitigation:
- use fallback communication path manually;
- fix receiver credentials;
- reload validated configuration;
- remove overly broad silence if it hides critical alerts.

## 12. Standard queries

These are templates. Adapt names to the real metric and label schema.

## 12.1 Prometheus PromQL

### API error ratio
```promql
sum(rate(http_server_requests_total{service="api",status=~"5.."}[5m]))
/
sum(rate(http_server_requests_total{service="api"}[5m]))