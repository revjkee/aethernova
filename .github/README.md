# GitHub automation

The repository has one active workflow:

- `workflows/ci.yml` validates repository contracts, backend unit tests,
  frontend type checking and builds, and the backend container image.

Deployment is intentionally not performed from this repository until
production environments, required secrets, and rollback ownership are
documented. Superseded generated workflows are retained under
`docs/legacy/github-workflows/` for reference only.
