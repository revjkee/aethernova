# Aethernova Observability Core

Observability Core is the maintained health, metrics, logging, and tracing
service for Aethernova. The installable Python package uses the standard
`src/observability_core` layout.

## Maintained runtime

- FastAPI endpoints: `/health`, `/ready`, `/status`, and `/metrics`.
- Idempotent lifecycle with a background collection loop.
- Optional discovery of sibling core systems without making optional
  integrations a readiness dependency.
- Structured logging helpers, event filters, latency tracking, processors,
  and UEBA utilities under the `observability_core` package.
- A separately buildable React dashboard in `observability-dashboard/`.

## Local development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
uvicorn observability_core.api:app --host 0.0.0.0 --port 8080
```

Dashboard:

```bash
cd observability-dashboard
npm ci
npm run build
```

From the repository root, `docker compose up observability-core prometheus
grafana` starts the service on port `8081` and connects it to the canonical
monitoring stack.

## Repository layout

- `src/observability_core/` — maintained Python runtime and libraries.
- `tests/` — executable contract and unit tests.
- `observability-dashboard/` — separately built React dashboard.
- `dashboards/` — Grafana assets awaiting migration to the root provisioning
  layer.
- Prometheus rules live in the repository-wide
  `monitoring/prometheus/rules/` directory.
- top-level integration prototypes such as `exporters/`, `ai_monitors/`, and
  `incident-replay/` are retained for migration but are not installed as part
  of the runtime package.

Configuration is read from variables prefixed with
`OBSERVABILITY_CORE_`. Nested values use a double underscore, for example
`OBSERVABILITY_CORE_REQUIRED_SYSTEMS='["engine-core"]'`.
