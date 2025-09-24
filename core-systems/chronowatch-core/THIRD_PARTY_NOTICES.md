# ChronoWatch-Core — Third-Party Notices and Licenses
SPDX-License-Identifier: NOASSERTION

This document lists third-party software included in ChronoWatch-Core and provides their licenses, notices, and attribution statements. It is intended to accompany both source and binary distributions.

Important
- Scope: Only components that are distributed as part of ChronoWatch-Core are listed. Optional dev, test, and tooling dependencies may be excluded from runtime packages, as appropriate.
- Source of Truth: The SBOM artifacts (SPDX and CycloneDX) accompanying releases are authoritative for component names, versions, and declared licenses. I cannot verify this.
- Completeness: If this file appears without populated component tables, consult the SBOMs or regenerate this file from the build pipeline. I cannot verify this.

## Aggregated Inventory

When available, use the SBOM files:
- sbom/spdx/chronowatch-core.spdx.json
- sbom/cyclonedx/chronowatch-core.cdx.json

If these files are missing in your copy, obtain them from the corresponding release artifacts. I cannot verify this.

## Attribution Requirements

Some licenses require that specific notices be retained in distributions (e.g., Apache-2.0 NOTICE, BSD-2-Clause/3-Clause, MIT, ISC). Such notices are preserved verbatim below under “Verbatim Notices”.

## Component Tables

Note: Tables below are placeholders and must be populated by the automated build process from the authoritative SBOMs. I cannot verify this.

### JavaScript or TypeScript (npm, pnpm, yarn)
| Package | Version | License | License File | Homepage | Copyright |
|--------|---------|---------|--------------|----------|-----------|
| (auto) | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

### Python (pip, Poetry, PDM)
| Package | Version | License | License File | Homepage | Copyright |
|--------|---------|---------|--------------|----------|-----------|
| (auto) | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

### Go (modules)
| Module | Version | License | License File | Homepage | Copyright |
|--------|---------|---------|--------------|----------|-----------|
| (auto) | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

### Rust (crates)
| Crate | Version | License | License File | Homepage | Copyright |
|-------|---------|---------|--------------|----------|-----------|
| (auto) | (auto) | (auto)  | (auto)       | (auto)   | (auto)    |

### Java and JVM (Maven, Gradle)
| Artifact | Version | License | License File | Homepage | Copyright |
|----------|---------|---------|--------------|----------|-----------|
| (auto)   | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

### C and C++
| Library | Version | License | License File | Homepage | Copyright |
|---------|---------|---------|--------------|----------|-----------|
| (auto)  | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

### Other Ecosystems
| Component | Version | License | License File | Homepage | Copyright |
|-----------|---------|---------|--------------|----------|-----------|
| (auto)    | (auto)  | (auto)  | (auto)       | (auto)   | (auto)    |

## Verbatim Notices

The following notices are reproduced exactly as required by their respective licenses. Each subsection corresponds to a third-party component.

<!--
Example structure to be populated automatically:

### component-name version
License: Apache-2.0
Notice:
This product includes software developed by Example Authors.
Additional attribution per upstream:
"ExampleProject" is a trademark of Example Org.

Full license text is available at: third_party/licenses/component-name-LICENSE.txt
-->

I cannot verify this.

## Full License Texts

Where required, full license texts for third-party components are included under `third_party/licenses/` with filenames following this convention:

- third_party/licenses/<ecosystem>/<component>-<version>-LICENSE.txt
- third_party/licenses/<ecosystem>/<component>-<version>-NOTICE.txt (if applicable)

Examples shown above are naming conventions only. I cannot verify this.

## Methodology

This file is intended to be generated from SBOM data emitted during the build, ensuring consistency with released artifacts and minimizing manual edits. It should be treated as read-only in source control except for template maintenance. I cannot verify this.

End of THIRD_PARTY_NOTICES.md
