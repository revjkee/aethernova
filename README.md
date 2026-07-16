# Aethernova

Aethernova is a research and engineering monorepo for AI orchestration,
governance, security, distributed systems, product applications, and
operational tooling.

The repository contains multiple independently runnable components. The root
project provides shared development conventions and a Docker Compose stack;
individual systems may also define their own dependencies, tests, and
deployment manifests.

## Repository layout

| Path | Purpose |
| --- | --- |
| `core-systems/` | Canonical platform and infrastructure services |
| `backend/` | Main Python API and AI application backend |
| `frontend/` | Main web client |
| `aethernova-web/` | Separate operations/dashboard web application |
| `agent_mash/`, `agents/` | Agent runtime, governance, workforce, and tests |
| `csmarket/`, `reva-studio/`, `telegram_bot/`, `mobile_app/` | Product workspaces |
| `lab-os/` | Laboratory management and security-lab tooling |
| `monitoring/`, `launch/`, `workflows/`, `tools/` | Platform operations |
| `docs/` | Current architecture, policies, reports, and historical documents |
| `archive/recovery-snapshots/` | Read-only recovery snapshots; not active code |

See [Repository structure](docs/architecture/repository-structure.md) for
ownership rules and naming conventions.

## Development setup

Requirements:

- Python 3.11+
- Node.js 20+
- Docker with Docker Compose

Create local configuration:

```bash
cp .env.example .env
```

Install the root Python and frontend development dependencies:

```bash
python -m venv .venv
python -m pip install -r requirements-dev.txt
npm --prefix frontend ci
```

Run the fast repository and Compose checks:

```bash
python tools/repository_audit.py
docker compose config --quiet
```

Useful commands:

```bash
make help
make test
make lint
make docker-up
make docker-down
```

To start only the shared stack:

```bash
docker compose up --build
```

## Working agreements

- Do not commit `.env` files, credentials, databases, logs, virtual
  environments, dependency directories, or generated build output.
- Use kebab-case for service/workspace directories and snake_case for Python
  import packages.
- Active implementations belong in their canonical directory. Copies,
  emergency snapshots, and superseded drafts belong under `archive/` or
  `docs/legacy/`.
- Each independently deployable component should keep its own README,
  dependency manifest, tests, and deployment configuration.

## Security

The repository previously contained local environment configuration in Git.
Treat any credential that has ever been committed as compromised and rotate it.
Use `.env.example` for variable names and secret-management tooling for actual
values.
