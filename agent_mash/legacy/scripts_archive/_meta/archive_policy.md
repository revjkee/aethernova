# Legacy Scripts Archive Policy

Status: Active
Scope: agent_mash/legacy/scripts_archive
Owner: Repository maintainers

## 1. Definitions

Archive
A read-mostly repository area containing deprecated scripts preserved for traceability, audit, and historical reference.

Deprecated script
A script that must not be used for new development and must not be invoked from production automation.

Replacement
A maintained implementation that supersedes a deprecated script. It can be a new script, a module, a service, or documentation that eliminates the need.

Registry
The file deprecation_registry.json, which is the authoritative metadata source for all archived items.

## 2. Objectives

- Ensure archived scripts are discoverable, attributable, and non-ambiguous.
- Prevent accidental execution in production.
- Maintain a consistent lifecycle for deprecations and removals.
- Enable CI validations via a stable machine-readable registry.

## 3. Invariants

The following must always be true:

- Every archived item that is a script must have a registry entry.
- Every registry entry must have:
  - a stable id
  - a relative path
  - a status
  - at least one reason
  - owner and reviewer
  - deprecation date
  - risk classification
- Archived scripts must not be referenced by active production pipelines.
- Archived scripts must not be modified except for:
  - adding a deprecation banner/header
  - fixing security-sensitive secrets leakage (removal)
  - adding clarifying comments that do not change behavior
  - adjusting line endings or permissions for archival consistency

If behavior must be changed, the correct approach is to implement a maintained replacement outside the archive.

## 4. Allowed Content

Allowed:
- Deprecated scripts and their supporting non-executable artifacts required for understanding (sample configs, notes).
- Minimal documentation required to interpret the script.
- Checksums or provenance notes (recommended).
- Test vectors only if required for forensic reproducibility, and only with non-sensitive data.

Forbidden:
- Secrets, credentials, tokens, private keys.
- Production configuration containing sensitive endpoints or internal credentials.
- Any automation hooks that execute archived scripts by default.
- Binary artifacts unless explicitly approved and documented with checksum and origin.

## 5. Archival Process

When archiving a script:

1. Classify the reason:
   - replaced: superseded by a maintained replacement
   - obsolete: no longer needed
   - risky: security, compliance, or operational risk
   - duplicated: duplicate of another maintained path
   - unknown: only if no reliable history exists; must include investigation note

2. Move the script into a stable path under scripts_archive
Recommended path patterns:
- by domain: scripts_archive/<domain>/<script>
- by date: scripts_archive/<yyyy>/<mm>/<script>
- by team: scripts_archive/<team>/<domain>/<script>

3. Add a deprecation banner inside the script header where applicable:
   - DEPRECATED
   - date
   - status
   - replacement pointer

4. Register the script in deprecation_registry.json.

5. Validate:
   - no active references remain
   - registry passes schema and constraints

## 6. Lifecycle and Statuses

Statuses:
- deprecated
  Script is archived and must not be used.
- superseded
  Script is deprecated and has a confirmed replacement.
- blocked
  Script is deprecated due to a risk; usage is prohibited. Replacement may be pending.
- exception
  Temporary permitted use under strict conditions. Must include expiry_date and scope.
- removed
  Script removed from repository. Registry entry remains for audit, with final notes.

Status transitions:
- deprecated -> superseded
- deprecated -> blocked
- deprecated -> removed
- superseded -> removed
- exception -> deprecated or superseded or removed

Exception policy:
- Exceptions require an explicit expiry_date.
- Exceptions must define allowed scope (where, who, what pipeline).
- Exceptions must have an approving authority recorded in the registry events.

## 7. Retention

Default retention guidance:
- Keep deprecated and superseded items for at least 12 months after last known use.
- Keep blocked items as long as needed for incident postmortems and compliance.
- Removal should be a deliberate change with a registry event and justification.

This policy intentionally uses guidance rather than hard time rules, because retention depends on your compliance obligations.

## 8. Security and Privacy

- Secrets must be removed immediately if discovered.
- If a script contains sensitive operational details, redact and document the redaction in the registry event log.
- Prefer storing hashes/checksums for integrity.
- Archived scripts must not be distributed outside the repository without review.

## 9. Ownership and Review

- Every entry must have an owner and reviewer.
- Owner: responsible for metadata accuracy and replacement guidance.
- Reviewer: validates the archival decision and risk classification.

## 10. Auditability Requirements

For each archived script, the registry must support:
- who archived it
- when it was deprecated
- why it was deprecated
- what replaced it (if applicable)
- what risks exist
- what events occurred over time (status changes, exceptions, removals)

## 11. Change Control

Changes to:
- archive_policy.md
- deprecation_registry.json structure
must be reviewed by repository maintainers.

Changes to registry entries:
- Allowed only via pull request.
- Must include an event log entry for status changes, exceptions, and removals.

## 12. Enforcement Recommendations

Recommended automated checks:
- JSON schema validation for deprecation_registry.json
- Validate that every file under scripts_archive matching executable patterns is in the registry
- Validate that exception entries have expiry_date in the future
- Validate that removed entries do not reference existing paths

This policy does not prescribe a specific CI tool; it defines what should be enforced.
