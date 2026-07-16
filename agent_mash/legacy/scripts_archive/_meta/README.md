# scripts_archive meta

This directory contains governance metadata for the legacy scripts archive located at:

agent_mash/legacy/scripts_archive

Purpose:
- Preserve deprecated legacy scripts for auditability and forensic reference.
- Prevent accidental use in production.
- Maintain a single source of truth for deprecations, replacements, and ownership.

Files:
- archive_policy.md
  Human-readable archive governance policy. Defines what is allowed, required, and forbidden.

- deprecation_registry.json
  Machine-readable registry of deprecated scripts and their replacements. Intended to be validated in CI.

Core principles:
- Archived scripts are not maintained for feature development.
- Archived scripts must not be executed automatically in production pipelines.
- Every archived script must have traceable provenance and a reason for archival.
- Deprecation metadata must be explicit: owner, dates, risk, replacement, and status.

How to add a new archived script:
1. Move the script into the archive tree, preserving a sensible structure by domain/team/date.
2. Add or update an entry in deprecation_registry.json:
   - Identify the script path relative to agent_mash/legacy/scripts_archive
   - Provide deprecation reason and risk classification
   - Provide replacement path (or state "none" and justify)
   - Assign an owner and reviewer
3. Ensure the script header contains a deprecation banner (recommended):
   - "DEPRECATED"
   - date
   - replacement pointer
4. Ensure no CI or production code references the archived path.
5. Run repository checks that validate the registry JSON schema and constraints.

Non-goals:
- This is not a general documentation folder.
- This does not define runtime behavior; it defines governance and metadata only.

If you need to restore an archived script:
- Prefer re-implementing it under the active codebase with tests.
- If temporary restoration is required, document the exception with a new registry event and clear expiry.
