# core-systems/security-core/README.md

# Security Core

Security Core — это центральный модуль платформы, обеспечивающий Zero Trust безопасность, управление идентичностью и доступом, криптографией, политиками и аудитом для всех сервисов Core Systems.

Статус: Production-ready
Версия: 1.0.0
Лицензия: Apache-2.0

## 1. Цели

1. Единая реализация Zero Trust архитектуры для всех сервисов.
2. Централизованная аутентификация и авторизация людей и сервисов.
3. Управление ключами (KMS), PKI и mTLS между сервисами.
4. Управление секретами с динамическими учетными данными и ротацией.
5. Policy-as-Code для доступа, шифрования, токенов, сетевых правил.
6. Полный аудит действий, безопасность цепочки поставок, инцидент-менеджмент.
7. Соответствие требованиям: ISO 27001, SOC 2, GDPR (ориентиры).

## 2. Архитектура (высокий уровень)

Слои:
- Identity Layer: OIDC/OAuth 2.1, сервисная идентичность (SPIFFE/SPIRE или эквивалент).
- Transport Layer: mTLS, TLS 1.3, обязательная проверка клиентских сертификатов.
- Key Management: интеграция с внешним KMS или HSM, собственная PKI.
- Secrets Layer: безопасное хранение секретов, динамические креды, короткие TTL.
- Policy Layer: PDP на OPA/Rego, PEP в гейтвеях и сервисах.
- Observability and IR: аудит, метрики, алерты, плейбуки реагирования.
- Supply Chain Security: SBOM, подписи артефактов, аттестация билда.

Типовые потоки:
1) Человек: Browser → Auth Gateway (OIDC) → Token Issuer → Service API (PEP) → PDP Decision → Audit.
2) Сервис: Service A → mTLS → Service B, SVID или клиентский сертификат, PEP → PDP Decision → Audit.
3) Ключи/Секреты: Service → Secrets Broker → KMS → выдать краткоживущие учетки → Audit.

## 3. Принципы

- Zero Trust: не доверяем сети, идентифицируем и авторизуем каждую сущность.
- Наименьшие привилегии: права выдаются по минимально необходимому уровню.
- Defense in Depth: многослойная защита, независимые контроли.
- Secure by Default: шифрование, mTLS, строгие политики включены по умолчанию.
- Ephemeral Credentials: краткоживущие токены и учетные данные, автоматическая ротация.
- Policy as Code: все правила в коде, версионируемы и тестируемы.
- Observability: все действия логируются, метрики и трассировки доступны в SIEM.

## 4. Структура директории (рекомендуемая)

Папки здесь описаны для ориентира. В текущем репозитории присутствуют README и LICENSE. Реализация может располагаться в соседних модулях.

security-core/
README.md
LICENSE
docs/
threat-models/
standards/
runbooks/
pki/
ca/
intermediate/
policies/
rego/
authz/
data/
dlp/
config/
security-core.yaml
pki.yaml
opa.yaml
examples/
k8s/
networkpolicy.yaml
psps-or-policies.yaml
opa/
sample_policy.rego
oidc/
well-known-openid.md
ci/
attestations/
cosign/
slsa/

yaml
Копировать
Редактировать

## 5. Интеграции

- Identity Provider: OIDC/OAuth 2.1, поддержка SSO.
- Service Identity: SPIFFE/SPIRE или эквивалент для SVID.
- Service Mesh: mTLS между всеми Pod/Service.
- KMS/HSM: облачный KMS или on-prem HSM для генерации и хранения ключей.
- Secrets: брокер секретов с динамическими учетками и TTL.
- PDP/PEP: OPA как PDP, Envoy ext_authz как PEP.
- SIEM/Logs: централизованный сбор логов, WORM хранилище для аудита.
- Artifact Security: Sigstore/cosign подписи, генерация SBOM, аттестации SLSA.

## 6. Конфигурация (пример)

`config/security-core.yaml`
```yaml
version: 1
oidc:
  issuer_url: https://auth.example.com
  audience: core-systems
  required_claims: [sub, aud, exp]
service_identity:
  spiffe_trust_domain: example.internal
  svid_ttl_seconds: 3600
mtls:
  min_version: 1.3
  require_client_cert: true
kms:
  provider: gcp-kms
  keyring: core-systems
  keys:
    - name: jwt-signing
      purpose: asym-sign
    - name: data-at-rest
      purpose: sym-encrypt
secrets:
  broker: vault
  default_ttl: 900
  max_ttl: 3600
opa:
  bundles:
    - name: authz
      url: https://opa-bundles.example.com/authz.tar.gz
logging:
  level: INFO
  audit_sink: tls://audit-sink.example.internal:6514
7. Политики (Policy-as-Code)
Rego пример для авторизации по ролям и атрибутам:

policies/rego/authz/service_access.rego

rego
Копировать
Редактировать
package authz.service_access

default allow = false

allow {
  input.subject.kind == "service"
  input.subject.spiffe_id == "spiffe://example.internal/ns/prod/sa/payments"
  input.action == "write"
  input.resource.namespace == "prod"
  input.resource.name == "ledger"
}

allow {
  input.subject.kind == "user"
  input.subject.roles[_] == "admin"
  input.action == "read"
}
8. Журналирование и аудит
Схема аудита (JSON Lines):

json
Копировать
Редактировать
{
  "ts": "2025-08-19T08:00:00Z",
  "actor": {"type":"service","id":"spiffe://example.internal/ns/prod/sa/web"},
  "action": "token.exchange",
  "resource": {"type":"secrets","id":"db-cred-prod"},
  "decision": "allow",
  "policy": "authz/service_access.rego#L1-L20",
  "correlation_id": "f2b6c4be-1d9e-47df-9d2d-1f5c6b1f2a90"
}
Все audit-логи доставляются в защищенный sink, сохраняются не менее 1 года, доступны только для группы безопасности и compliance.

9. PKI и mTLS
Собственная PKI с корневым и промежуточным CA, офлайн хранение корневого ключа.

Выдача SVID для сервисов с TTL 1 час.

Обязательный mutual TLS со стороны клиента и сервера.

Отзыв сертификатов через CRL или OCSP stapling, короткий TTL предпочтительнее.

Пример NetworkPolicy для Kubernetes:

yaml
Копировать
Редактировать
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
  policyTypes: ["Ingress","Egress"]
10. Управление секретами
Хранение только зашифрованным образом, KMS-обертка.

Динамические креды к БД и брокерам, TTL до 15 минут.

Ротация при каждом деплое и по расписанию.

Запрет статических секретов в переменных окружения.

11. Токены и форматы
Для пользователей: OIDC ID Token + Access Token, короткий срок жизни.

Для сервисов: mTLS и SVID как первичный фактор, опционально токен авторизации.

Рекомендация использовать PASETO v2/v4 для внутренних токенов.

12. Наблюдаемость и детекция
Метрики: число отказов по политике, ошибки mTLS, частота выдачи секретов.

Логи: структурированные, неизменяемые, с корреляцией trace-id.

SIEM: корреляция событий, правила детекции для отклонений и DLP.

13. Supply Chain Security
Обязательный SBOM для каждого артефакта.

Подписи артефактов и контейнеров (cosign), проверка в Admission Controller.

SLSA Level 3 как целевой ориентир для билдов.

Аттестации компилятора, зафиксированные в хранилище аттестаций.

14. Соответствие требованиям
Контроли сопоставляются с ISO 27001 Annex A, SOC 2 CC, GDPR (минимизация, шифрование, журналирование). Подробная матрица в docs/standards/controls-mapping.md (рекомендуется добавить).

15. Угрозы и меры (кратко, STRIDE)
Spoofing: mTLS, SVID, OIDC, защищенный канал.

Tampering: подписи, целостность артефактов, неизменяемые логи.

Repudiation: централизованный аудит и WORM.

Information Disclosure: шифрование в движении и покое, DLP.

Denial of Service: квоты, rate-limit, изоляция сети.

Elevation of Privilege: минимальные привилегии, PDP/PEP, периодический review.

16. Инциденты
Плейбуки:

Утечка токена: немедленная отзывка ключей, ротация, инвентаризация затронутых систем.

Компрометация сервиса: блокировка сети, отзыв SVID, форензика, восстановление из доверенного образа.

Компрометация ключа: отзыв и генерация новых ключей, пересоздание сертификатов.

17. CI/CD требования
Перед сборкой: скан зависимостей, проверка лицензий.

Во время сборки: репродуцируемые сборки, генерация SBOM, подпись.

Перед деплоем: верификация подписи, политик, аттестаций, секретов.

После деплоя: проверка mTLS, валидация OPA бандлов, smoke-тесты безопасности.

18. Примеры
Пример Rego на запрет выдачи секретов без mTLS:

rego
Копировать
Редактировать
package authz.secrets

default allow = false

allow {
  input.transport.mtls_verified == true
  input.action == "secrets.get"
  input.subject.kind == "service"
}
Пример ротации ключа (псевдокод):

python
Копировать
Редактировать
def rotate_key(kms, key_name):
    new_ver = kms.create_key_version(key_name)
    kms.set_primary_version(key_name, new_ver)
    revoke_tokens_dependent_on(key_name)
    reissue_certs()
    audit("kms.rotate", {"key": key_name, "version": new_ver})
19. План внедрения
Включить mTLS и выдать SVID всем сервисам.

Подключить PDP/PEP и зафиксировать базовые политики.

Завести KMS ключи и перевести шифрование на KMS-обертку.

Включить аудит и доставку логов в SIEM.

Включить подписи артефактов и проверку в Admission Controller.

Перейти на динамические секреты и короткие TTL.