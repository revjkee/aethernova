# Observability Core audit — 2026-07-16

## Outcome

Observability Core is now an installable, tested service instead of a collection
of mutually incompatible prototypes. Its maintained boundary is the
`observability_core` package under `src/`; experimental top-level integrations
remain outside the installed package until they have explicit contracts.

## Corrected defects

- Replaced the broken Pydantic 1 settings import with `pydantic-settings`.
- Replaced the generated lifecycle shell, undefined collection methods, and
  misspelled class names with an idempotent runtime and compatibility aliases.
- Added FastAPI health, readiness, status, and Prometheus metrics endpoints.
- Consolidated two incompatible latency event models and repaired the decorator,
  tracker, aggregator, validator, and Pushgateway exporter contract.
- Removed nonexistent `observability.*` imports from SIEM routing and made
  vendor handlers dependency-injected or optional-extra aware.
- Fixed PII history leakage, batching lock scope, cache TTL handling, weighted
  backend ordering, and nested PII redaction.
- Replaced stale tests targeting nonexistent packages with 19 runtime contract
  tests.
- Added a deterministic dashboard lockfile, truthful empty-state values,
  production-safe mock-data gating, realtime metric name mapping, and a
  non-recursive Grafana proxy.
- Moved broken duplicate ELK, Zabbix, Prometheus, and nested workflow files to
  `docs/legacy/`.
- Connected Observability Core, Prometheus rules, Alertmanager, Grafana, and the
  backend through the repository root Compose and monitoring ownership layer.
- Added Observability Core Python, dashboard, and container checks to root CI.

## Validation

- `ruff check src tests`
- `pytest -q`: 19 passed
- import sweep of every installed `observability_core` module: 0 failures
- dashboard clean `npm ci`, `npm run lint`, `npm run typecheck`, and production
  `npm run build`
- `docker compose config --quiet`
- monitoring YAML and Prometheus rule label type validation
- repository audit: 0 errors

The local Docker daemon was not running, so image execution and `promtool` were
left to the added GitHub Actions container job. Compose structure was validated
locally.

## Remaining boundary

Directories such as `ai_monitors/`, `exporters/`, `failover/`,
`incident-replay/`, `logging/`, `otel/`, and `policies/` are retained source
prototypes. They are deliberately excluded from the installable runtime and
should be migrated only after their dependencies, schemas, and ownership are
defined.

The dashboard still uses older major lines of ESLint and Recharts. Their
deprecation notices are documented technical debt; major-version migration was
not mixed into this repair because it requires UI regression testing.
