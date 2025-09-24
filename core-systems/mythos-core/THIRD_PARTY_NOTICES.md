<!-- mythos-core/THIRD_PARTY_NOTICES.md -->
SPDX-License-Identifier: NOASSERTION

# THIRD-PARTY NOTICES for mythos-core

This document lists third-party components included in mythos-core, together with
their license identifiers (SPDX), source locations, and attribution requirements.
It is intended to satisfy license notice and attribution obligations for
redistribution of source and/or binary forms.

> IMPORTANT
> 1) This file is generated and maintained by compliance automation where possible.
> 2) Do not remove the GENERATED blocks below; CI tools will update their contents.
> 3) If you manually add entries, place them in the “Manual Addenda” section.

---

## How this file is produced

- SBOM format: SPDX 2.3 (preferred) or CycloneDX 1.5+
- Tooling examples: OSS Review Toolkit (ORT), ScanCode Toolkit, FOSSA, ORT Evaluator
- Source of truth: repository SBOM artifacts (if present), license scanners,
  and component lockfiles.

Automation looks for:
- `sbom/spdx/*.spdx.json`
- `sbom/cyclonedx/*.json`
- scanner outputs at `compliance/reports/*`

---

## Inventory (Machine-Readable Table)

The table below is intended to be updated by CI based on SBOM data.

<!-- BEGIN GENERATED: INVENTORY TABLE -->
| Component Name | Version | License (SPDX) | Source/URL | Copyright | Notes |
|----------------|---------|----------------|------------|-----------|-------|
| (generated)    | (gen)   | (gen)          | (gen)      | (gen)     | (gen) |
<!-- END GENERATED: INVENTORY TABLE -->

### Manual Addenda (Curated)
Add curated entries that are not discoverable automatically (e.g., vendored code
without package metadata):

- Name: <Component>
- Version: <X.Y.Z or commit>
- License: <SPDX-ID>
- Source: <URL>
- Files: `<path/glob>`
- Modifications: <Yes/No + summary>
- Required NOTICE text: <inline or reference>

---

## License Texts

Full license texts for all third-party components follow. Generated block is
populated by scanners; manual texts can be appended after it.

<!-- BEGIN GENERATED: LICENSE TEXTS -->
<!-- Each entry:
### <Component> <version> — <SPDX-ID>
<full license text verbatim>

--- -->
<!-- END GENERATED: LICENSE TEXTS -->

### Manual License Texts (if any)
If a component’s license cannot be auto-retrieved, paste its exact, verbatim
license text here, preserving formatting.

---

## Notices Required by Upstream

Some licenses (e.g., Apache-2.0, BSD-style) require retaining upstream NOTICE
content. Such content is reproduced here verbatim.

<!-- BEGIN GENERATED: UPSTREAM NOTICES -->
<!-- For each component requiring NOTICE retention, insert upstream NOTICE text -->
<!-- END GENERATED: UPSTREAM NOTICES -->

---

## Source Code Availability (for copyleft where required)

If binaries are redistributed and copyleft terms require offering source, provide
the offer or link here. For example:

- “Complete corresponding source code is available at: <URL or process>”
- “For a period of 3 years from distribution, source will be provided upon request
  to <contact>.”

(Adjust text according to the exact license obligations.)

---

## Compliance Footnotes

- “NOASSERTION” in SPDX header means the top-level license of this file is not
  asserting a project license; consult the repository `LICENSE`.
- Dual/multi-license components must identify the selected license for this build.
- If a component’s SPDX identifier is unknown, use `LicenseRef-*` and include a
  verbatim text in “License Texts”.

---

## Contact

Compliance & Legal: <LEGAL CONTACT OR URL>  
Project Home: <PROJECT URL>
