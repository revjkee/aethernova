# THIRD_PARTY_NOTICES

Status: I cannot verify this. The definitive list of third-party components cannot be confirmed from the provided input.

This document summarizes third-party software, data, and assets (“Third-Party Materials”)
that may be included in, or required by, **cybersecurity-core**. The canonical source of
truth for transitive and direct dependencies is the auto-generated SBOM and notice artifacts
attached to releases.

## Canonical Artifacts

When available, each release includes:
- **SBOM** (CycloneDX or SPDX), e.g.:
  - `sbom/cyclonedx.json`
  - `sbom/spdx.json`
- **Auto-generated license inventory**, e.g.:
  - `third_party/THIRD_PARTY_NOTICES.json`
  - `third_party/THIRD_PARTY_NOTICES.md`
- **Provenance/attestations** (e.g., SLSA) and cryptographic checksums/signatures.

If these files exist, they supersede any static lists below.

## Generation (for maintainers)

This section documents standard generation patterns. Use what matches your stack.
It does not assert that these tools are currently in use.

- Python: `pip-licenses` or `pip-licenses -f markdown` and/or `pipdeptree`, SBOM via `cyclonedx-py`.
- Node.js: `license-checker --json` or `--markdown`, SBOM via `cyclonedx-npm`.
- Go: `go-licenses report` and SBOM via `cyclonedx-gomod`.
- Rust: `cargo-license` / `cargo about`, SBOM via `cargo cyclonedx`.
- Java: `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom` or Gradle CycloneDX plugin.
- Container images: generate SBOM via `syft` (CycloneDX/SPDX).
- Consolidation: use `bom -merge` (CycloneDX), or SPDX tools to produce unified artifacts.

All generated artifacts should be committed under `third_party/` and/or `sbom/`
or published with releases.

## Attributions (Static Overlay)

If any Third-Party Materials require explicit attribution notices beyond license headers,
list them here. This section is intended for rare cases where auto-generated inventories
are insufficient (e.g., embedded assets, logos, or datasets with attribution clauses).

