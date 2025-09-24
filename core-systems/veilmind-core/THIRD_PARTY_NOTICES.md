# Third‑Party Notices — VeilMind Core

Status: generated for VeilMind Core at <UTC DATE>.  
Project owner/license: <FILL HERE>.  This file only covers third‑party materials used by VeilMind Core.

## Scope

This document lists third‑party software that VeilMind Core references or interacts with in the provided code samples, along with their licenses and upstream sources. It is not exhaustive if your deployment adds or removes dependencies.

## Summary Table

| Component                          | License            | Upstream (Source)                                | Notes / Obligations (non-exhaustive)                   |
|-----------------------------------|--------------------|--------------------------------------------------|--------------------------------------------------------|
| PyYAML                            | MIT                | https://pypi.org/project/PyYAML/                 | Preserve copyright & license notice in copies.         |
| Kubernetes Python Client          | Apache-2.0         | https://github.com/kubernetes-client/python      | Include Apache-2.0 text; retain/upstream NOTICEs.      |
| HTTPX (encode/httpx)              | BSD-3-Clause       | https://github.com/encode/httpx                  | Preserve copyright & license notice in copies.         |
| redis-py                          | MIT                | https://github.com/redis/redis-py                | Preserve copyright & license notice in copies.         |
| psycopg2                          | LGPL-3.0-or-later  | https://www.psycopg.org/license/                 | Provide LGPL text; allow relinking; convey source.     |
| python-dotenv                     | BSD-3-Clause       | https://github.com/theskumar/python-dotenv       | Preserve copyright & license notice in copies.         |
| Cilium CLI (cilium-cli)           | Apache-2.0         | https://github.com/cilium/cilium-cli             | Tool invoked externally; include Apache‑2.0 text if redistributed. |
| Hubble (CLI/daemon)               | Apache-2.0         | https://github.com/cilium/hubble                 | Tool invoked externally; include Apache‑2.0 text if redistributed. |

> Legend: MIT = MIT License; Apache‑2.0 = Apache License, Version 2.0; BSD‑3‑Clause = BSD 3‑Clause License; LGPL‑3.0‑or‑later = GNU Lesser General Public License v3 or later.

## Component‑by‑Component Notices

### PyYAML — MIT
- Upstream: https://pypi.org/project/PyYAML/  
- License obligations: include the MIT license text and attribution in source and binary redistributions.

### Kubernetes Python Client — Apache‑2.0
- Upstream: https://github.com/kubernetes-client/python  
- Obligations: include the full Apache‑2.0 license text; retain any upstream NOTICE files; state significant changes where required by the license.

### HTTPX (encode/httpx) — BSD‑3‑Clause
- Upstream: https://github.com/encode/httpx  
- Obligations: retain BSD‑3 license notice and disclaimer in source/binary redistributions; do not use contributor names to endorse without permission.

### redis‑py — MIT
- Upstream: https://github.com/redis/redis-py  
- Obligations: include MIT license text and attribution.

### psycopg2 — LGPL‑3.0‑or‑later
- Upstream: https://www.psycopg.org/license/  
- Obligations (summary, non‑exhaustive): include LGPL‑3 license text; if you distribute a combined work in a form that requires dynamic or static linking to psycopg2, ensure users can modify/replace psycopg2 (e.g., via dynamic linking) and obtain its source code and build instructions.

### python‑dotenv — BSD‑3‑Clause
- Upstream: https://github.com/theskumar/python-dotenv  
- Obligations: retain BSD‑3 license notice and disclaimer.

### Cilium CLI — Apache‑2.0
- Upstream: https://github.com/cilium/cilium-cli  
- Notes: invoked as an external tool. If you redistribute binaries, include Apache‑2.0 license text; preserve upstream NOTICE if present.

### Hubble — Apache‑2.0
- Upstream: https://github.com/cilium/hubble  
- Notes: invoked as an external tool. If you redistribute binaries, include Apache‑2.0 license text; preserve upstream NOTICE if present.

## Attribution Format (recommended)

When reproducing notices in UIs, logs, or documentation, the following compact form is acceptable (example for MIT/BSD/Apache):

