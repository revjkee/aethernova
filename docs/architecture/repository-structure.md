# Repository structure

## Purpose

This document defines the canonical layout of the Aethernova monorepo. It is
the reference for placing new code and for deciding whether a directory is
active, experimental, historical, or generated.

## Canonical areas

### Platform systems

`core-systems/<system-name>/` contains independently testable platform
components. Service directory names use kebab-case and normally end in
`-core`. Python import packages inside a service use snake_case.

`core-systems/2roadmap/` is an incubation area for components that do not yet
have a canonical counterpart. Components may live there while their contracts
and ownership are still evolving. A component must be moved to the top level
of `core-systems/` when it becomes canonical; name collisions between the two
areas are forbidden.

Recovered roadmap snapshots that collided with canonical components are kept
under `archive/roadmap-overlays/`. They are historical comparison material,
not an overlay mechanism and not an import source.

### Applications

- `backend/` is the main API and AI application backend.
- `frontend/` is the main web client.
- `aethernova-web/` is a separate operations/dashboard client.
- Product workspaces such as `csmarket/`, `reva-studio/`, `telegram_bot/`, and
  `mobile_app/` remain at the repository root because they contain multiple
  deployable parts.

### Agents and operations

- `agent_mash/` and `agents/` contain agent runtimes and role implementations.
- `monitoring/`, `launch/`, `workflows/`, and `tools/` contain shared
  operational assets.
- `lab-os/` is the canonical laboratory workspace. `lab_os/` must not be
  recreated as a second root.

### Documentation and archives

- Current documentation belongs under `docs/`.
- Historical reports belong under `docs/reports/legacy/`.
- Superseded design drafts belong under `docs/legacy/`.
- Emergency source snapshots belong under `archive/recovery-snapshots/` and
  are read-only. Production code must never import from `archive/`.
- Colliding roadmap snapshots belong under `archive/roadmap-overlays/` until
  their unique deltas are reviewed or removed.

## Repository hygiene

The following content must never be tracked:

- `.env` files containing values;
- virtual environments and dependency directories;
- databases, logs, caches, and build output;
- IDE-specific workspace state;
- nested copies of the repository;
- directories named `copy`, `old`, `backup`, or `tmp` used as source control.

Use Git history for rollback. If a snapshot must be retained for forensic or
recovery reasons, place it under `archive/recovery-snapshots/` with a README
explaining its origin and status.

## Required component shape

An independently deployable component should normally contain:

```text
component/
├── README.md
├── pyproject.toml, package.json, or Cargo.toml
├── src/ or an importable package
├── tests/
├── config/ or configs/
└── deployment files when applicable
```

Generated dependencies are restored with the component's package manager and
are not part of this shape.
