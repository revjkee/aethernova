# Payments Legacy Scripts Archive

## Status

This directory contains **archived legacy payment-related scripts**.

These scripts are **NOT active**, **NOT maintained**, and **MUST NOT** be used in production, staging, or testing environments.

They are preserved исключительно для:
- исторического контекста,
- аудита прошлых решений,
- анализа эволюции архитектуры,
- контролируемой миграции логики в актуальные модули.

## Purpose of This Archive

The `payments/` archive exists to:

- prevent accidental loss of historically important payment logic,
- allow forensic or security review of old implementations,
- document architectural and design decisions made in earlier stages of the project,
- support regulated environments where traceability of financial logic is required.

## Why These Scripts Are Legacy

Scripts in this directory were archived because one or more of the following conditions apply:

- use of deprecated APIs or protocols,
- lack of compliance with current security standards,
- tight coupling to obsolete infrastructure,
- absence of automated tests or formal contracts,
- replacement by new payment subsystems.

## Usage Restrictions

Strict rules apply:

- DO NOT import these scripts into active code.
- DO NOT execute them in any environment connected to real payment systems.
- DO NOT modify files in this directory.
- DO NOT rely on this code as a reference implementation.

Any violation of these rules can lead to security, compliance, or financial risks.

## How to Work With This Code Safely

If analysis is required:

1. Work only in an isolated, offline environment.
2. Treat all credentials or endpoints as invalid.
3. Do not assume correctness or security of the logic.
4. Use the code only for read-only review purposes.

## Migration Policy

If any logic from this archive must be reintroduced:

- it MUST be fully rewritten,
- it MUST pass current security and compliance reviews,
- it MUST be covered by modern automated tests,
- it MUST NOT reuse legacy patterns blindly.

Direct reuse or copy-paste is strictly forbidden.

## Ownership and Responsibility

This archive is maintained as part of the project’s **technical memory**.

No active team owns this code.
Responsibility lies with the architecture and security review process.

## Final Notice

This directory exists by design.
Its presence does not indicate technical debt, but controlled historical preservation.

