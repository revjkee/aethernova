oblivionvault-core/README.md
# OblivionVault Core

**OblivionVault Core** — это промышленное ядро защищенного хранилища для проекта NeuroCity/TeslaAI.  
Оно предназначено для реализации **Zero-Knowledge** и **Zero-Trust** принципов в хранении и обработке данных, а также для обеспечения приватности и устойчивости системы к внешним атакам.

## Основные возможности
- **Шифрование на стороне клиента** (end-to-end, AES-256-GCM + Curve25519).
- **Zero-Knowledge Proofs** для аутентификации и аудита.
- **Immutable Storage**: данные не могут быть изменены без следа (Merkle DAG + контентные хэши).
- **Multi-Backend Support**: поддержка локального FS, S3-совместимых стораджей и IPFS.
- **Промышленный уровень журналирования**: наблюдаемость через OpenTelemetry, Prometheus, Loki.
- **RBAC + ABAC** модели доступа, совместимые с Kubernetes Secrets и Vault API.
- **Анонимные каналы** через PhantomMesh overlay-сеть.
- **Интеграция с DAO**: контроль доступа и ключей через on-chain-голосование.

## Структура директории


oblivionvault-core/
├── README.md # Текущее описание
├── LICENSE # Лицензия
├── src/ # Исходный код ядра
├── api/ # gRPC/REST интерфейсы
├── docs/ # Архитектурная документация
├── tests/ # Автоматические тесты
└── helm/ # Чарты для деплоя


## Сценарии использования
- Хранение приватных ключей, секретов и токенов.
- Обеспечение приватности данных в рамках AI-обработки.
- Защита логов, телеметрии и результатов вычислений.
- Организация **облачного сейфа** с кросс-чейн-аутентификацией.

## Запуск (локально)
```bash
# Сборка контейнера
docker build -t oblivionvault-core .

# Запуск с конфигурацией по умолчанию
docker run -d \
  -e OVC_CONFIG=./config/default.yaml \
  -p 8443:8443 oblivionvault-core

Интеграция

gRPC API: proto/oblivionvault.proto

REST API: /api/v1/vault

SDK: Python, Go, Rust (планируется)

Roadmap

 Базовое ядро шифрования

 gRPC API

 Поддержка zk-SNARKs

 Поддержка квантово-устойчивых алгоритмов (Kyber, Dilithium)

 WebUI-панель администратора

 Поддержка cross-chain storage proof