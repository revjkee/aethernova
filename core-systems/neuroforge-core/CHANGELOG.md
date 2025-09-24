# Changelog
Все заметные изменения этого проекта будут документироваться в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/)  
и этот проект использует [Semantic Versioning 2.0.0](https://semver.org/lang/ru/).

## [Unreleased]
### Added
- Поддержка новых KMS-бэкендов (AWS/GCP/Azure) в адаптере (черновик).
- CLI: подкоманда `doctor` для расширенной диагностики окружения.
- Политики хранения доказательств: гибкая настройка retention/TTL.
- Настройки observability (метрики/трейсинг) в `config.yaml`.

### Changed
- Обновлены зависимости инфраструктуры CI/CD.
- Улучшена документация по конфигурации.

### Fixed
- Исправлена обработка UTC времени в `utils/time.py`.
- Мелкие исправления CLI-парсера аргументов.

### Security
- Ужесточены права доступа по умолчанию (umask 077).
- Проверка подписи манифеста в EvidencePackager.

---

## [1.0.0] - 2025-08-01
### Added
- Первый стабильный релиз `neuroforge-core`.
- Модуль `kms_adapter.py` с Envelope Encryption (AES-256-CTR+HMAC-SHA256, RSA-OAEP-SHA256).
- Модуль `packager.py` для детерминированной упаковки цифровых доказательств.
- CLI `oblivionvault-admin` с командами: `info`, `kms`, `envelope`, `evidence`, `doctor`.
- Конфигурация `examples/quickstart/config.yaml` с профилями dev/staging/prod.
- Вспомогательные утилиты `utils/time.py`.

### Changed
- Структура проекта выровнена под промышленный стандарт.
- Логирование переведено на JSON-совместимый формат.

### Security
- Реализована криптографическая очистка ключей (crypto-shred).
- Политики: обязательный UTC, запрет core dump в проде.

---

## [0.5.0] - 2025-06-15
### Added
- Интеграционные тесты для KMS и crypto-shred.
- Генерация RSA-ключей через CLI (`kms gen-keypair`).
- Проверка целостности и подмены конвертов (tamper test).

### Changed
- Улучшен формат сериализации Envelope (детерминированный JSON).

---

## [0.1.0] - 2025-05-01
### Added
- Инициализация репозитория `neuroforge-core`.
- Базовая структура: `adapters/`, `evidence/`, `utils/`, `cli/`, `tests/`.
- Первые версии `KmsAdapter`, `EvidencePackager`.

---

[Unreleased]: https://github.com/neuroforge/neuroforge-core/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/neuroforge/neuroforge-core/releases/tag/v1.0.0
[0.5.0]: https://github.com/neuroforge/neuroforge-core/releases/tag/v0.5.0
[0.1.0]: https://github.com/neuroforge/neuroforge-core/releases/tag/v0.1.0
