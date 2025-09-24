# THIRD_PARTY_NOTICES — `policy-core`

> Status: Template with placeholders. Replace `<...>` with factual data discovered by your license scanner/SBOM.
> This document does not assert project facts until you fill them in.

- Module: `policy-core/`
- Project: `<PROJECT_NAME>`
- Maintainer (optional): `<LEGAL_CONTACT_EMAIL_OR_URL>`
- SPDX package name (optional): `SPDXRef-<PROJECT_NAME>-policy-core`
- SBOM reference (optional): `<PATH/TO/SBOM.spdx.json or CycloneDX>`

## 1) Overview

This document lists third-party components that are bundled with or required by
`policy-core`. For each component we record name, version, license (SPDX ID),
source/origin, and copyright.

If a license requires redistribution of its full text (e.g., Apache-2.0 §4), the
verbatim text is provided in section “Full License Texts”.

## 2) Summary Table

| Component                      | Version | License (SPDX)   | Source / Origin                            | Copyright           |
|-------------------------------|:-------:|------------------|--------------------------------------------|---------------------|
| <COMPONENT_1_NAME>            | <x.y.z> | <Apache-2.0>     | <https://example.com or registry coords>   | <Owner>             |
| <COMPONENT_2_NAME>            | <x.y.z> | <MIT>            | <https://…>                                | <Owner>             |
| <COMPONENT_3_NAME>            | <x.y.z> | <BSD-3-Clause>   | <https://…>                                | <Owner>             |
| <add more rows as needed>     |         |                  |                                            |                     |

Notes:
- Prefer exact sources (VCS URL + commit or artifact coordinates).
- Use canonical SPDX license identifiers (https://spdx.org/licenses/).
- If a component is dual-licensed, indicate the chosen license and rationale in “Notes”.

## 3) Notes and Exceptions (optional)

- `<COMPONENT_X>` — dual-licensed `<LGPL-2.1-or-later>` / `<MIT>`. We distribute under `<MIT>` because only headers are used.
- If a component is used as a dynamic system dependency and not redistributed, consider listing it under “Runtime-only (Not Redistributed)”.

## 4) Runtime-only (Not Redistributed)

These components are required at runtime but are not bundled in the distributed
artifacts of `policy-core`:

| Component            | Version | License (SPDX) | Source / Origin       |
|---------------------|:-------:|----------------|-----------------------|
| <RUNTIME_DEP_1>     | <x.y.z> | <License>      | <system package mgr>  |

## 5) How to Regenerate This File (process guidance)

If you maintain SBOMs and automated license scanning, update this file as follows:

- Generate SBOM (choose one):
  - SPDX JSON: `spdx-sbom-generator` / `syft packages dir:. -o spdx-json`
  - CycloneDX: `cyclonedx-bom -o bom.json`
- Scan licenses:
  - `licensee detect .` (for Git repos)
  - `pip-licenses --format=markdown` (Python) / `cargo license` (Rust) / `yarn licenses list` (JS)
- Reconcile results and update sections 2–6 accordingly.
- Commit alongside NOTICE and LICENSE.

## 6) Full License Texts

> Include the verbatim texts for licenses that require inclusion upon redistribution of binaries or sources. Below are canonical placeholders. Replace with the exact text for the specific version used. Do not alter license wording.

### Apache License 2.0 (Apache-2.0)
