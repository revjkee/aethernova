policy-core/README.md

# policy-core

Policy Core — модуль принятия решений доступа (PDP) и управления политиками (PAP) для Zero-Trust архитектуры NeuroCity/TeslaAI. Предоставляет детерминированную, проверяемую и аудируемую оценку политик RBAC/ABAC/ReBAC с обязательствами (obligations), телеметрией и строгим default-deny.

## TL;DR
- Модель: PDP (принятие решения) + PEP (принудительное исполнение) + PAP (администрирование).
- Алгоритм объединения: deny-overrides, по умолчанию deny.
- Формат политик: YAML/JSON с JSON Schema, версионирование и подпись бандлов.
- API: `/v1/decision`, `/v1/policies`, `/v1/validate`, `/health`.
- Инварианты безопасности: идемпотентность оценки, неизменяемость входа, стабильный порядок правил, полный аудит.

## Архитектура


    +-------------+        Decision Request        +--------------+


Client/ | Service | ----------------------------> | PEP |
Caller +-------------+ +------+------+
Enforce | Allow/Deny + Obligations
v
+------+------+
| PDP | policy-core
+------+------+
|
+--------------------+--------------------+
| |
+-----+-----+ +--+-----------------+
| Policy | | Telemetry/Audit |
| Store | | (OTel/JSONL/SIEM)|
+-----------+ +-------------------+


Роли:
- PEP: HTTP middleware, gRPC interceptor, message-bus filter.
- PDP: ядро policy-core, реализует оценку.
- PAP: управление политиками (CRUD, импорт бандлов, подписи).

## Гарантии и инварианты

- Default-deny: при отсутствии подходящих правил — отказ.
- Deny-overrides: любое совпавшее правило с effect=deny блокирует доступ, даже если есть allow.
- Детерминированность: стабильная сортировка политики по (priority desc, created_at asc, id asc).
- Идемпотентность: одинаковый input всегда дает одинаковое решение, при одинаковом наборе политик.
- Трассируемость: каждое решение содержит trace_id, policy_id и причину.
- Политики не могут вызывать произвольный код; только декларативные выражения.

## Модель политики

Минимальный документ политики:

```yaml
version: 1
id: "allow_read_own_profile"
description: "Пользователь читает только свой профиль"
priority: 100            # больше — выше приоритета
effect: "allow"          # allow | deny
subjects:
  roles: ["user"]        # опционально: ids: ["u:*"], attrs: {"dept":"*"}
resources:
  type: "profile"        # логический тип ресурса
  ids: ["{subject.id}"]  # шаблон c подстановкой
actions: ["read"]        # действие или множество
conditions:
  all:
    - eq: ["resource.owner_id", "subject.id"]
    - time_between: ["09:00", "21:00", "Europe/Stockholm"]
obligations:
  - "audit"              # семантика задается PEP
  - redact_fields: ["ssn"]


Поддерживаемые предикаты (ядро):

eq, ne, gt, ge, lt, le

in, not_in, regex_match

any, all, none

time_between(hh:mm, hh:mm, tz)

ip_in_cidr("10.0.0.0/8"), geo_in(["SE","NO"])

device_risk_below(n), mfa_required()

Алгоритм объединения:

Фильтруем политики по subject/resource/action.

Сортируем по priority desc, created_at asc, id asc.

Идем слева направо, накапливая allow; как только встречаем deny — немедленно deny (deny-overrides).

Если нет совпавших allow — deny.

JSON Schema (сокращенная)
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.org/policy.schema.json",
  "type": "object",
  "required": ["version","id","effect","resources","actions"],
  "properties": {
    "version": { "type": "integer", "minimum": 1 },
    "id": { "type": "string", "minLength": 1 },
    "description": { "type": "string" },
    "priority": { "type": "integer", "minimum": 0, "default": 0 },
    "effect": { "enum": ["allow","deny"] },
    "subjects": {
      "type": "object",
      "properties": {
        "ids": { "type": "array", "items": { "type": "string" } },
        "roles": { "type": "array", "items": { "type": "string" } },
        "attrs": { "type": "object", "additionalProperties": true }
      },
      "additionalProperties": false
    },
    "resources": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "type": { "type": "string", "minLength": 1 },
        "ids":  { "type": "array", "items": { "type": "string" } }
      },
      "additionalProperties": false
    },
    "actions": {
      "type": "array",
      "items": { "type": "string", "minLength": 1 },
      "minItems": 1
    },
    "conditions": { "type": "object" },
    "obligations": { "type": "array", "items": {} },
    "created_at": { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}

REST API v1

Базовые эндпоинты:

POST /v1/decision — принять решение.

POST /v1/policies — загрузка или замена набора политик (bundle).

GET /v1/policies — получить активный набор с метаданными.

POST /v1/validate — валидация политики или бандла по JSON Schema.

GET /health — liveness/readiness.

Пример запроса решения:

POST /v1/decision
Content-Type: application/json

{
  "subject": { "id": "u-123", "roles": ["user"], "attrs": {"dept": "sales"} },
  "resource": { "type": "profile", "id": "u-123", "attrs": {"owner_id": "u-123"} },
  "action": "read",
  "context": { "ip": "192.0.2.5", "time": "2025-08-28T09:30:00+02:00", "tz": "Europe/Stockholm" }
}


Ответ:

{
  "decision": "allow",
  "policy_id": "allow_read_own_profile",
  "obligations": ["audit", {"redact_fields":["ssn"]}],
  "trace_id": "2a3f2e7a-0c1e-4b54-b6c5-8b0db1b1a1d1",
  "eval_ms": 0.42
}


Коды ошибок:

400 неверный формат,

422 схема нарушена,

500 внутренняя ошибка. Default-deny не преобразуется в 5xx, а возвращается как 200 с decision=deny.

PEP интеграция (пример FastAPI middleware, псевдокод)
async def pep_enforce(request, call_next):
    input_ = build_decision_input(request)
    decision = await pdp_client.decide(input_)
    if decision["decision"] == "deny":
        return JSONResponse({"detail": "forbidden", "trace_id": decision["trace_id"]}, status_code=403)
    response = await call_next(request)
    apply_obligations(response, decision.get("obligations", []))
    return response

Политики: формат бандла

Директория:

manifest.json:

{ "version": 1, "id": "bundle-2025-08-28", "count": 12, "created_at": "2025-08-28T08:00:00Z", "signature": "..." }


policies/*.yaml

Опционально: подпись signature (Ed25519), публичный ключ в конфигурации PDP.

ETag/If-None-Match для кэширования клиента.

Конфигурация (env)

POLICYCORE_LOG_LEVEL (INFO|DEBUG)

POLICYCORE_CACHE_TTL_SEC (по умолчанию 5)

POLICYCORE_BUNDLE_PATH или POLICYCORE_BUNDLE_URL

POLICYCORE_REQUIRE_SIGNATURE (true|false)

POLICYCORE_DENY_OVERRIDES (true, по умолчанию)

Производительность

Кэш решений на ключе (subject.hash, resource.hash, action, bundle_etag) с TTL.

Предкомпиляция предикатов в AST.

SLO ориентир: P99 < 5 ms на один запрос решения при 5k rps (на типовом CPU). Этот показатель зависит от окружения. I cannot verify this.

Наблюдаемость и аудит

OpenTelemetry трассировка: trace_id в ответе.

Аудит в JSONL: timestamp, subject, resource, action, decision, policy_id, obligations, checksum(bundle).

Счетчики Prometheus: decisions_total{decision,policy_id}, eval_ms_bucket.

Тестирование

Контрактные тесты API v1 (см. tests/contract/test_http_api_v1.py).

Генеративные тесты выражений условий с property-based фреймворком.

Снапшот хэш OpenAPI v1 (sha256) для детекции изменений контракта.

Безопасность

Default-deny, deny-overrides.

Никаких произвольных функций в политике; только whitelisted предикаты.

Ограничения глубины AST и времени выполнения.

Защита от path traversal при загрузке бандла.

Валидация схемы и подписи бандла при REQUIRE_SIGNATURE=true.

Версионирование

Политики: version: 1 (major), несовместимые изменения требуют bump.

API: /v1/*. Изменения контракта — через новое /v2/*.