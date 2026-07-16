# Repository structure audit

Date: 2026-07-16

## Result

The active Git tree was reduced from 60,367 tracked paths and approximately
515.7 MB of file content to 15,788 tracked paths and approximately 119.4 MB.

Removed from the active tree:

- 30,393 files under `node_modules`;
- 7,208 virtual-environment paths;
- a 6,415-file nested repository copy under
  `core-systems/graph-core/examples/20`;
- tracked `.env` values, databases, logs, IDE state, TypeScript build state,
  and invalid local submodule state;
- 30 generated `*.backup.<id>` files;
- emergency directory copies already preserved by Git history.

Normalized:

- `lab-os/` is the only active Lab OS root;
- `identity-access-core` now uses standard `src/`, `docs/`, and `tests/`
  directories;
- the root `ai-ethics-engine` implementation moved under the canonical
  `core-systems/ai-ethics-engine/legacy-components/`;
- recovery reports and superseded README drafts moved out of the repository
  root;
- root metadata now identifies Aethernova rather than TeslaAI Genesis;
- the development container targets an existing Compose service;
- secret templates use `.example` naming.

## Validation

- JSON and TOML configuration parsing: passed.
- Docker Compose configuration rendering: passed.
- Python bytecode compilation for the normalized identity-access package:
  passed.
- Documentation link check: passed.
- Git whitespace/error check: passed.
- Forbidden tracked-path scan: passed.
- Maximum tracked relative path length: 169 characters.

The focused pytest suite could not run in the available host interpreter
because `pytest` is not installed. Dependencies were intentionally not
installed during this structural cleanup.

## Required follow-up

1. Rotate every credential that was previously stored in the committed root
   `.env`, especially the OpenAI key and service passwords.
2. If the repository is public or broadly shared, coordinate a Git history
   rewrite to purge the old `.env`, virtual environment, dependency tree,
   databases, and other large blobs. A normal cleanup commit does not remove
   them from prior commits.
3. Review components duplicated between `core-systems/` and
   `core-systems/2roadmap/`, then promote or archive them one system at a time.
4. Migrate remaining TeslaAI/NeuroCity product identifiers only with explicit
   compatibility planning; several are embedded in image names, metrics,
   policies, and public contracts.
