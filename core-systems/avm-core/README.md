# core-systems/avm-core/README.md

# Aethernova Virtual Machine Core (AVM-core)

AVM — «виртуальная машина‑агент» внутри Aethernova: изолированная среда выполнения с Zero Trust‑контролями, анонимной сетью (PhantomMesh/Tor/WireGuard), Policy-as-Code (OPA/Rego) и полным аудитом. Проект предоставляет API, CLI и рантайм на базе QEMU/KVM.

Статус: Production-Ready  
Версия: см. файл `VERSION`

---

## 1. Цели

- Безопасная изоляция задач (VM‑агенты) в анонимном мире Aethernova.
- Принципы Zero Trust: mTLS, короткоживущие токены, PoP‑привязка к каналу.
- Унифицированная сеть: PhantomMesh, Tor и собственный VPN (WireGuard) с kill‑switch.
- Политики доступа как код (OPA/Rego); deny‑by‑default.
- Полная наблюдаемость: структурированные логи, метрики Prometheus, трассировка.
- Управление жизненным циклом: создание/запуск/стоп/снапшоты/бэкапы/удаление.

---

## 2. Архитектура

Слои:
- **API/CLI**: FastAPI (`/v1/*`) и `avmctl` для управления.
- **Security**: проверка JWT (PS256/EdDSA), PoP (mTLS/DPoP), PEP→PDP (OPA).
- **Identity**: SVID/DID для сервисов, короткий TTL; интеграция с `security-core`.
- **Network**: провайдеры PhantomMesh/Tor/WireGuard (killswitch, multi‑hop).
- **Engine**: QEMU/KVM раннер, планировщик, хранилище дисков.
- **Data**: снапшоты, бэкапы (шифрование), контроль доступа к образам.
- **Observability**: логи (WORM‑совместимые синки), метрики, трассировки.

Директория (сокращенно):
