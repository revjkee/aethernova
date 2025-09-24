# zero-trust-core/README.md

# Zero Trust Core

Zero Trust Core — это производственное ядро доверенной архитектуры: единая точка применения политик (Policy Enforcement Point, PEP), принятия решений (Policy Decision Point, PDP) и управления политиками (Policy Governance, PG) для сервисов, пользователей и машинных агентов.

Статус: Production‑Ready  
Лицензия: см. `LICENSE`

---

## 1. Цели

- Безусловный deny‑by‑default на границах и внутри сервис‑меша.
- Унифицированная аутентификация: mTLS, JWT (PS256/EdDSA), PASETO v4, DPoP.
- Привязка токена к каналу (PoP) и короткие TTL.
- Авторизация Policy‑as‑Code на OPA/Rego с GitOps‑жизненным циклом.
- Интеграция с HSM/KMS, неизменяемый аудит и измеримые SLO.

---

## 2. Архитектура

Слои:
- PEP: sidecar/ingress‑прокси с проверкой TLS, PoP, токенов, аттестации.
- PDP: OPA с бандлами политик и внешними данными (roles, scopes, абонементы).
- PG: управление политиками, ревью и публикация бандлов.
- Identity: SPIFFE/SVID и OIDC; публикация JWKS.
- Secrets: HSM/KMS, провайдер секретов, key rotation.
- Observability: аудит в WORM‑хранилище, метрики Prometheus, трассировка OTLP.

Референсная схема потоков:

