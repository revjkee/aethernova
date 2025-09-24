package policies.data_access

# Rego >= 0.45: включаем будущие ключевые слова (удобный синтаксис "in")
import future.keywords
import data.globals         # опционально: глобальные константы/переключатели из bundle
import input                # явное указание на вход (подсказка для читателя)
import net

# ------------------------------------------------------------------------------
# ВХОДНОЙ КОНТРАКТ (ожидаемые поля input)
# ------------------------------------------------------------------------------
# input = {
#   "env": "prod" | "staging" | "dev",
#   "zone": "prod" | "staging",
#   "subject": {
#     "id": "sub-123",
#     "roles": ["world","anonymous","partner","service","blocked"],
#     "tenant": "public" | "acme" | "multi",
#     "tags": ["abuse", ...],
#   },
#   "request": {
#     "method": "GET"|"POST"|...,
#     "path": "/api/public/...",
#     "host": "api.example.org",
#     "headers": { "x-idempotency-key": "...", "x-presigned": "true", ... },
#     "auth": { "mode": "none"|"apiKey"|"jwt"|"oidc", "aud": "datafabric-core-partner", "service": "ext-sync" },
#     "ip": "203.0.113.10",
#   },
#   "resource": {
#     "type": "http"|"kafka"|"object"|"db",
#     "sensitivity": "public"|"internal"|"confidential"|"restricted",
#     "tenant": "public"|"acme",
#     # http:
#     "host": "api.example.org",
#     "path": "/api/public/...",
#     # kafka:
#     "bootstrap": "kafka:9092", "topic": "ingest.public.events",
#     # object:
#     "endpoint": "https://s3.example.org", "bucket": "pub-assets", "key": "/public/...",
#     # db:
#     "engine": "postgres", "database": "datafabric", "schema": "public", "table": "events",
#     # общее:
#     "action": "read"|"write"|"admin"|"produce"|"consume"|"select"|"insert"|"update"|"delete"|"ddl"
#   }
# }

# ------------------------------------------------------------------------------
# ОБЩИЕ НАСТРОЙКИ
# ------------------------------------------------------------------------------
default allow := false

# Собираем причины отказа (list) и обязательства (map)
deny_reasons := reasons {
  reasons := array.concat([], [
    reason | reason := r; deny_rule[r]
  ])
}

obligations := obls {
  obls := merge_objects_all([
    o | o := obj; obligation_rule[obj]
  ])
}

# Разрешение только если НЕТ причин отказа и сработало хотя бы одно allow-правило
allow {
  count(deny_reasons) == 0
  some _; allow_rule[_]
}

# ------------------------------------------------------------------------------
# УТИЛИТЫ
# ------------------------------------------------------------------------------
is_world := "world" in input.subject.roles
is_anonymous := "anonymous" in input.subject.roles
is_partner := "partner" in input.subject.roles
is_service := "service" in input.subject.roles
is_blocked := "blocked" in input.subject.roles

is_idempotent(method) := method == "GET" or method == "HEAD" or method == "OPTIONS"

has_header(name) := lower(name) in {lower(k) | some k; k := key; _ := input.request.headers[key]}
header_value(name, def) := v { some k; lower(k) == lower(name); v := input.request.headers[k] } else := def

starts_with(s, prefix) := indexof(s, prefix) == 0

# Слияние списка объектов в один (правые перекрывают левые)
merge_objects_all(list) := out {
  out := fold(list, {}, func(acc, x) { acc | acc := object.union(acc, x) })
}

# Условные флаги
req_is_health := starts_with(input.request.path, "/health") or starts_with(input.request.path, "/ready")
req_is_docs   := input.request.path == "/openapi.json" or input.request.path == "/swagger" or input.request.path == "/docs"

# ------------------------------------------------------------------------------
# ПРИОРИТЕТНЫЕ ОТКАЗЫ (DENY) — применяются первыми
# ------------------------------------------------------------------------------
deny_rule["subject blocked by policy/reputation"] {
  is_blocked
}

deny_rule["non-idempotent method from world is forbidden"] {
  is_world
  not is_idempotent(input.request.method)
  input.resource.type == "http"
}

deny_rule["admin paths are forbidden on public edge"] {
  input.resource.type == "http"
  starts_with(input.request.path, "/admin/")
}

deny_rule["confidential/restricted resources are not accessible from world"] {
  is_world
  input.resource.sensitivity == "confidential" or input.resource.sensitivity == "restricted"
}

deny_rule["db write/DDL from world is forbidden"] {
  is_world
  input.resource.type == "db"
  input.resource.action == "insert" or input.resource.action == "update" or
  input.resource.action == "delete" or input.resource.action == "ddl"
}

deny_rule["object write to non-public buckets is forbidden"] {
  is_world
  input.resource.type == "object"
  not re_match("^pub(-[a-z0-9]+)?$", input.resource.bucket)
  input.resource.action == "put" or input.resource.action == "delete"
}

deny_rule["kafka admin from world is forbidden"] {
  is_world
  input.resource.type == "kafka"
  input.resource.action == "admin"
}

# Ограничение по географии/странам (опционально; если список задан в globals)
deny_rule["geo not allowed"] {
  globals.allowed_countries != null
  count(globals.allowed_countries) > 0
  not input.geo.country in globals.allowed_countries
}

# ------------------------------------------------------------------------------
# РАЗРЕШЕНИЯ (ALLOW) — применяются только если нет DENY
# ------------------------------------------------------------------------------
# 1) Health/Docs — всегда доступны для мира (read)
allow_rule["allow health/docs read"] {
  input.resource.type == "http"
  req_is_health or req_is_docs
  input.resource.action == "read"
}
obligation_rule({"cache": {"control": "public, max-age=60"}}) {
  input.resource.type == "http"
  req_is_health or req_is_docs
}

# 2) Публичные API READ
allow_rule["allow public api read"] {
  input.resource.type == "http"
  input.resource.action == "read"
  input.resource.sensitivity == "public"
  starts_with(input.request.path, "/api/public/")
}
obligation_rule({"cache": {"control": "public, max-age=120"}}) {
  input.resource.type == "http"
  starts_with(input.request.path, "/api/public/")
  input.resource.action == "read"
}

# 3) Партнёрские READ/WRITE (ограниченно)
allow_rule["partner/service limited read/write"] {
  (is_partner or is_service)
  input.resource.type == "http"
  starts_with(input.request.path, "/api/partner/")
  input.resource.action == "read" or input.resource.action == "write"
  # Требуем аутентификацию и скоуп аудитории для партнёров (если указан)
  input.request.auth.mode == "apiKey" or input.request.auth.mode == "jwt" or input.request.auth.mode == "oidc"
  # Идемпотентность обязательна, за исключением POST
  is_idempotent(input.request.method) or input.request.method == "POST"
  # Тенант-изоляция
  resource_tenant_ok
}
resource_tenant_ok {
  # Ресурс принадлежит тому же тенанту, что и субъект
  input.resource.tenant == input.subject.tenant
} else {
  # У субъекта мульти-тенантный доступ
  input.subject.tenant == "multi"
}
obligation_rule({"tier": "partner"}) {
  (is_partner or is_service)
  starts_with(input.request.path, "/api/partner/")
}

# 4) Kafka: produce в публичные ingest-темы партнёрами/сервисами с идемпотентностью
allow_rule["kafka produce to ingest.public.* with idempotency key"] {
  (is_partner or is_service)
  input.resource.type == "kafka"
  input.resource.action == "produce"
  re_match("^ingest\\.public\\.[A-Za-z0-9._-]+$", input.resource.topic)
  # Требуем аутентификацию и идемпотентный ключ
  input.request.auth.mode == "apiKey" or input.request.auth.mode == "jwt" or input.request.auth.mode == "oidc"
  header_value("x-idempotency-key", "") != ""
}
obligation_rule({"qos": "low", "retention": "168h"}) {
  input.resource.type == "kafka"
  input.resource.action == "produce"
  re_match("^ingest\\.public\\.", input.resource.topic)
}

# 5) Kafka: consume broadcast публичной аудиторией
allow_rule["kafka consume broadcast.public.* for world"] {
  is_world
  input.resource.type == "kafka"
  input.resource.action == "consume"
  re_match("^broadcast\\.public\\.[A-Za-z0-9._-]+$", input.resource.topic)
}

# 6) Object Storage: GET/LIST из публичных бакетов/префиксов
allow_rule["object get/list from pub buckets under /public"] {
  input.resource.type == "object"
  (input.resource.action == "get" or input.resource.action == "list")
  re_match("^pub(-[a-z0-9]+)?$", input.resource.bucket)
  starts_with(input.resource.key, "/public/")
}
obligation_rule({"cache": {"control": "public, max-age=300"}}) {
  input.resource.type == "object"
  (input.resource.action == "get" or input.resource.action == "list")
  re_match("^pub(-[a-z0-9]+)?$", input.resource.bucket)
  starts_with(input.resource.key, "/public/")
}

# 7) Object Storage: PUT/DELETE только для presigned + публичные бакеты
allow_rule["object put/delete via presigned to pub buckets"] {
  input.resource.type == "object"
  (input.resource.action == "put" or input.resource.action == "delete")
  header_value("x-presigned", "") == "true"
  re_match("^pub(-[a-z0-9]+)?$", input.resource.bucket)
}
obligation_rule({"integrity": {"hash": "sha256-required"}}) {
  input.resource.type == "object"
  (input.resource.action == "put" or input.resource.action == "delete")
  header_value("x-presigned", "") == "true"
}

# 8) Staging: расширенные чтения (пример)
allow_rule["staging wider read"] {
  input.env == "staging"
  input.resource.type == "http"
  input.resource.action == "read"
  starts_with(input.request.path, "/api/staging/")
}

# ------------------------------------------------------------------------------
# BREAK-GLASS (строго аудируется; разрешение поверх deny, если включён заголовок)
# ------------------------------------------------------------------------------
# ВНИМАНИЕ: используйте осторожно. В типичном пайплайне break-glass реализуют вне OPA,
# либо поднимают приоритет результата ниже operate-политики.
allow_rule["break-glass override"] {
  header_value("x-break-glass", "") == "true"
  input.subject != null
  "platform-oncall" in input.subject.roles
}

obligation_rule({"break_glass": {"ttl_seconds": 900}}) {
  header_value("x-break-glass", "") == "true"
}

# ------------------------------------------------------------------------------
# ДИАГНОСТИКА / ОБЩЕЕ
# ------------------------------------------------------------------------------
# Возврат структурированного ответа может быть настроен на уровне сервиса:
# - allow (bool), deny_reasons (list[string]), obligations (map)

# ------------------------------------------------------------------------------
# ВСТРОЕННЫЕ САНИТИ‑ПРОВЕРКИ (lint-like)
# ------------------------------------------------------------------------------
deny_rule["missing resource.type"] {
  not input.resource.type
}
deny_rule["missing request.method"] {
  not input.request.method
}
deny_rule["missing subject.roles"] {
  not input.subject.roles
}

# Конец файла
