nikto/plugins/enumeration/README.md
markdown
Копировать
Редактировать
# Nikto Enumeration Plugins — Industrial Documentation

## Overview

This directory contains **industrial-grade enumeration plugins** for the Nikto web server scanner. These plugins are designed to extend Nikto’s detection capabilities by probing for specific vectors, misconfigurations, and vulnerabilities in HTTP(S) environments.

Each plugin operates **modularly and independently**, leveraging the Nikto core engine and HTTP client to perform targeted analysis of web resources and metadata.

---

## Directory Purpose

- `check_sensitive_files.pl`  
  Detects known exposed files and misconfigured directories (e.g., `.env`, `.git`, `.DS_Store`, backups).

- `check_user_enum.pl`  
  Attempts to enumerate valid usernames or accounts via response behavior (status code, message content, timing).

- `custom_vuln_check.pl`  
  Integrates user-defined vulnerability signatures in JSON or YAML for adaptive scanning strategies.

---

## Plugin Architecture

Every plugin must:
- Be written in **Perl 5.10+**
- Implement an entrypoint function named `run_<plugin_name>`
- Receive standardized input: `(target_url, http_client, logger)`
- Return `1` on success, `undef` on failure
- Emit structured logs via the unified `logger->log_event({ ... })` method

Plugins are executed in **parallelized chains** via the core dispatcher. Error isolation and timeout protection are handled by the plugin runtime manager.

---

## Plugin Development Guidelines

- **Naming**: Use snake_case with clear semantic purpose.
- **Security**: Avoid dangerous payloads unless in strict test mode (`ENV{NIKTO_TEST_MODE}`).
- **Logging**: Always emit structured logs for compatibility with `TeslaAI SIEM`, `Prometheus`, and `Zabbix` exporters.
- **Performance**: Must complete execution under 3 seconds per plugin unless explicitly configured.
- **Extensibility**: Ensure compatibility with config-driven scanning via `plugin_config.yaml`.

---

## Expected Output Fields

| Field         | Description                                     |
|---------------|-------------------------------------------------|
| `type`        | Event type: `vuln`, `info`, `warning`           |
| `path`        | Endpoint or resource path                       |
| `severity`    | `low`, `medium`, `high`, `critical`             |
| `plugin`      | Plugin name                                     |
| `description` | Human-readable description                      |
| `reference`   | CVE, CWE, or internal knowledge base            |

---

## Dynamic Configuration

All plugins support dynamic reloading via:

```bash
nikto --reload-plugins
This triggers a cold reload of enumeration plugins from disk and invalidates old plugin states.

For granular control, use:

bash
Копировать
Редактировать
nikto --enable-plugin=check_sensitive_files
nikto --disable-plugin=check_user_enum
These options can also be set in plugin_registry.yaml.

Testing Strategy
Each plugin is verified through:

Static Analysis: Perl::Critic strict mode, TeslaAI Linter v2

Unit Tests: Found in tests/enumeration/test_<plugin>.t

Functional Scans: Against hardened Docker testbeds with synthetic vulnerabilities

CI/CD integration is done via TeslaAI SecureScan Pipeline.

Meta
Maintainers: TeslaAI Genesis ThreatOps

Plugin schema version: 2.0-industrial

Last update: 2025-07-25

License: TeslaAI Secure License v1.3

Contributing
Use plugin_template.pl as the starting point. Submit merge requests to secure/nitko/enumeration-plugins branch. All contributions are reviewed by the Plugin Consilium (20 agents + 3 meta-generals) before merge.

Future Extensions
AI-assisted plugin writing via LLM agents

Integration with Nikto Web UI (MiniApp)

GraphQL & WebSocket-specific enumeration plugins

Plugin dependency chains & orchestration logic

yaml
Копировать
Редактировать

---

Файл готов для промышленного использования и встраивания в основную ветку проекта. Ж