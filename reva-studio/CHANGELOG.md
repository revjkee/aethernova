# Changelog

All notable changes to `reva-studio` will be documented in this file.

The format of this changelog is based on Keep a Changelog:
https://keepachangelog.com/en/1.1.0/

This project follows Semantic Versioning:
https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added
- Initial production-grade changelog structure for release tracking.
- Standardized sections for:
  - Added
  - Changed
  - Deprecated
  - Removed
  - Fixed
  - Security
- Release documentation policy for backend, frontend, infrastructure, CI/CD, database, and Telegram bot changes.
- Rules for recording breaking changes, migrations, and security-impacting updates.

### Changed
- Reserved for backward-compatible functionality changes and internal improvements.

### Deprecated
- Reserved for features and APIs scheduled for removal in future releases.

### Removed
- Reserved for deleted features, endpoints, commands, modules, or configurations.

### Fixed
- Reserved for bug fixes affecting application behavior, tests, deployment, or observability.

### Security
- Reserved for vulnerability fixes, secret handling changes, auth hardening, permission updates, and dependency remediation.

## [0.1.0] - 2026-03-22

### Added
- Bootstrap release of `reva-studio`.
- Base changelog introduced for human-readable release history.
- Initial release governance for documenting notable project changes.
- Release note categories aligned for application, infrastructure, and security workstreams.

---

## Changelog Policy

### What must be recorded
Record only notable changes that matter to developers, operators, QA, product owners, or integrators, including:
- new features and modules
- public API changes
- database schema or migration changes
- Docker, Compose, CI/CD, or deployment changes
- authentication, authorization, or security changes
- performance improvements with visible impact
- deprecations and removals
- fixes for production-facing defects

### What should usually not be recorded
Do not clutter the changelog with low-signal internal noise, for example:
- typo-only fixes without operational impact
- insignificant refactoring with no external effect
- trivial formatting updates
- intermediate WIP commits
- local-only experiments that never shipped

### Release entry rules
For every released version:
- use the heading format: `## [X.Y.Z] - YYYY-MM-DD`
- place newest versions first
- keep wording concise and factual
- group entries by change type
- mention breaking changes explicitly
- mention required migrations explicitly
- mention security fixes explicitly

### Breaking changes rule
If a release contains backward-incompatible behavior:
- describe exactly what changed
- identify affected module, endpoint, command, contract, or schema
- state required migration or rollout action
- increment MAJOR version according to Semantic Versioning

### Database and migration rule
When a release changes persistent data structures, include:
- migration identifier or purpose
- affected tables/entities
- backward compatibility status
- rollback constraints if relevant

### Security rule
Any change related to:
- credentials
- tokens
- authentication
- authorization
- encryption
- dependency vulnerabilities
- rate limits
- audit logging
must be documented in the `Security` section.

### Infrastructure rule
Any notable change to:
- Dockerfile
- docker-compose
- reverse proxy
- CI/CD pipeline
- environment variables
- healthchecks
- observability stack
- backup/restore process
should be recorded when it affects deployment, operability, or runtime behavior.

---

## Versioning Reference

This project uses Semantic Versioning:

- MAJOR version for incompatible or breaking changes
- MINOR version for backward-compatible functionality
- PATCH version for backward-compatible bug fixes

Examples:
- `1.0.0 -> 1.0.1` for bug fixes
- `1.0.0 -> 1.1.0` for new backward-compatible features
- `1.0.0 -> 2.0.0` for breaking changes

---

## Maintenance Notes

When preparing a release:
1. Move completed items from `Unreleased` into the new version section.
2. Add the release date in ISO 8601 format: `YYYY-MM-DD`.
3. Keep entries short, specific, and verifiable.
4. Do not rewrite history for already released versions.
5. Start a fresh `Unreleased` section immediately after release cut.

[Unreleased]: https://github.com/your-org/reva-studio/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/reva-studio/releases/tag/v0.1.0