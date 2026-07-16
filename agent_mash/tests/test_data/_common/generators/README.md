# agent_mash/tests/test_data/_common/generators

## Purpose

This directory contains test-data generators and conventions for producing:
- deterministic valid request payloads
- deterministic invalid payloads (negative cases)
- deterministic edge-case payloads (boundary / tolerance scenarios)

The output of generators must be committed into `agent_mash/tests/test_data/**`
as plain files (JSON/YAML). Generators must not require network access.

## Formats and specifications

- JSON must conform to RFC 8259. 
- YAML meta files must conform to YAML 1.2.2. 

## Directory structure (contract)

- `valid/api/input/json/*.json`
  - must contain only payloads that are accepted by the API as valid
  - names: `request_valid_XX.json` where `XX` is 2-digit ordinal starting from `01`

- `invalid/api/meta/cases.yaml`
  - meta-registry of negative test cases (each case references an input json)
  - referenced inputs located in `invalid/api/input/json/*.json`

- `edge_cases/api/meta/cases.yaml`
  - meta-registry of boundary/tolerance cases
  - referenced inputs located in `edge_cases/api/input/json/*.json`

- `_common/generators/`
  - generator scripts and shared utilities (optional)
  - MUST NOT be required at runtime for tests that only consume committed JSON/YAML

## Determinism requirements

All generators must be deterministic:
- A fixed seed is required.
- Any randomness must be driven by that seed only.
- No system time dependency unless explicitly encoded into output fixtures as a constant.

Recommended env variables (if generators exist):
- `TESTDATA_SEED` (default: `1337`)
- `TESTDATA_OUT_DIR` (default: `agent_mash/tests/test_data`)

## Naming and versioning

### File naming

- Valid:
  - `request_valid_01.json`, `request_valid_02.json`, ...
- Invalid:
  - `request_missing_request_id_01.json`
  - `request_invalid_traceparent_01.json`
  - `request_payload_wrong_type_01.json`
- Edge cases:
  - `request_unicode_01.json`
  - `request_future_timestamp_01.json`
  - `request_with_extra_fields_01.json`

Names must describe the intention and the expected behavior.

### Meta format version

Every `cases.yaml` must contain:
- `schema_version: <int>` at the top-level
- `suite.name` and `suite.description`
- `cases[]` list with stable `id` per case

Changing the `schema_version` is required if:
- field names change
- semantics of `expect` change
- path conventions change

## cases.yaml contract (minimum)

Each entry in `cases:` MUST have:
- `id`: unique string within suite
- `title`: human readable description
- `input_json`: relative path to an input JSON payload

Recommended fields:
- `tags`: list of strings
- `expect.status_code` OR `expect.status_code_any_of`
- `expect.message_contains_any`
- `expect.error_object.required_keys`
- `override.headers` (for header-based negative cases)

### Example skeleton

```yaml
schema_version: 1
suite:
  name: example_suite
  description: Example meta suite
cases:
  - id: example_case
    title: Example
    input_json: ../input/json/request_example_01.json
    expect:
      status_code_any_of: [200, 202]
