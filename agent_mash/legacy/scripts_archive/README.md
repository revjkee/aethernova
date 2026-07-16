# Legacy Scripts Archive

## Status

This directory contains archived legacy scripts.

All files located here are **deprecated**, **unsupported**, and **must not be used**
in production, testing pipelines, CI workflows, or any active development.

## Purpose

The scripts in this directory are preserved strictly for the following reasons:

- historical reference and traceability
- audit and compliance review
- incident investigation and root cause analysis
- migration context during major refactoring phases

They are **not** part of the current system architecture.

## Usage Policy

- Execution of any script in this directory is prohibited.
- Importing code from this directory into active modules is prohibited.
- CI, CD, and automated tooling must ignore this directory.
- Any new development must rely exclusively on the current supported codebase.

## Maintenance Policy

- No bug fixes, security patches, or enhancements are applied.
- Files may be removed only through an explicit, documented decision.
- Changes to this directory require architectural approval.

## Risk Notice

Legacy scripts may:
- violate current security requirements
- use outdated dependencies or APIs
- conflict with current data models or contracts

They are intentionally isolated to prevent accidental reuse.

## Ownership

This directory is maintained as part of the project legacy boundary.
Responsibility lies with the core architecture and security maintainers.

## Revision Policy

This document may be updated only to clarify status or governance rules.
It must not be used to justify reactivation of archived scripts.
