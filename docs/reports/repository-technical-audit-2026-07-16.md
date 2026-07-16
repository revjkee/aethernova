# Repository technical audit

Date: 2026-07-16

## Result

This pass converted the normalized repository into a reproducible active
development contour.

- Active Python syntax errors: **116 → 0**.
- Active Python `SyntaxWarning` findings: **20 → 0**, including exception
  suppression caused by `return`/`break` inside `finally`.
- Tracked paths: **15,789 → 13,220**.
- Removed exact duplicate roadmap snapshots: **2,568 files / 31.2 MB**.
- Permission-mode suffixes embedded in filenames: **28 → 0**.
- Active JSON/TOML parse errors, excluding JSONC and deliberate invalid test
  fixtures: **0**.
- Case-insensitive path collisions: **0**.
- Production frontend TypeScript errors: **7 → 0**.
- Full frontend prototype tree TypeScript errors: **3,133** (tracked
  separately from the production graph).

## Corrected contracts

- Replaced the broken root/backend Docker split with one root backend image.
- Corrected the frontend container port from `80` to its actual `8080`.
- Added a dedicated PostgreSQL service for Zabbix and completed Zabbix web DB
  settings.
- Added Grafana Prometheus provisioning and fixed Elasticsearch/Kibana local
  connectivity.
- Consolidated generated CI/CD definitions into one non-deploying CI workflow.
- Repaired Makefile, tox, pytest, pre-commit, and Dependabot paths.
- Converted malformed JSON/TOML stubs into valid configuration files.
- Normalized Genius Core Python package directories to snake_case.
- Archived roadmap overlays that collided with canonical core systems.
- Repaired the production frontend router contract, removed nested routers,
  and separated production type-checking from unfinished prototype modules.
- Regenerated the inconsistent npm lockfile and corrected the frontend
  container dependency-install stage.
- Replaced zero-byte backend test placeholders with executable application
  contract tests and corrected CI runtime dependency installation.

## Validation

- `python tools/repository_audit.py`: passed with only the empty-license
  warning.
- Active Python source compilation: passed.
- `docker compose config --quiet`: passed.
- Active TOML parsing: passed.
- Active JSON parsing: passed; JSONC files and intentionally invalid fixtures
  were excluded from strict JSON validation.
- `npm ci`, production frontend type-check, and Vite production build: passed.
- Backend application contract tests: passed.
- Local Docker image builds were not executed because the Docker daemon was
  unavailable; Compose rendering passed and CI now builds the backend image.

## Required decision

The root `LICENSE` file is empty. A license cannot be chosen safely by
automation. Select the intended license before publishing releases or packages.

## Remaining debt

- Thousands of zero-byte placeholder files remain in recovered or scaffold
  components. They need owner-by-owner implementation or removal, not bulk
  filling.
- `npm run typecheck:all` reports 3,133 errors in frontend prototypes that are
  outside the production import graph. The dominant classes are missing
  feature modules, stale aliases, and incompatible component contracts.
- Several historical TeslaAI/NeuroCity identifiers remain in compatibility
  contracts and archived documentation.
- Full dependency-backed backend and prototype frontend test suites should be
  enabled incrementally as their owning components become active.
