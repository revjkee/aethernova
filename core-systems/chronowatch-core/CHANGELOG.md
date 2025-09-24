# Changelog

## [0.1.0] - 2025-08-28
### Added
- Initial industrial-grade release of chronowatch-core:
  - FastAPI service with async SQLAlchemy (PostgreSQL) and Redis leader election.
  - Distributed scheduler loop with idempotent executions and execution history.
  - Jobs registry with built-in `heartbeat` and `cleanup_executions`.
  - RBAC (role-based access checks) and request tracing IDs.
  - Prometheus metrics and health/readiness probes.
  - Dockerfile, docker-compose.yml, Helm chart, and minimal tests.
