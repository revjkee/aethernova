# Changelog — security-core

## [1.0.0] - 2025-08-19
### Added
- Zero-Trust PDP/PEP: intent validator, access decision engine, device posture checks.
- RBAC (роли/разрешения) и ABAC (атрибутные политики) с безопасным интерпретатором.
- Криптомодуль: AES‑GCM (AEAD), Ed25519 подпись/проверка, локальный Key Vault c шифрованием ключей.
- Защищённый аудит-лог (append-only, hash chain) и проверка целостности цепочки.
- MFA TOTP совместимый с RFC 6238.
- Провайдеры секретов (ENV, файл), строгая конфигурация через pydantic BaseSettings.
