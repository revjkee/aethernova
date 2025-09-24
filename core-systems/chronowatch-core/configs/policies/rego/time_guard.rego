package chronowatch.policies.time_guard

import future.keywords

# =========================
# Метаданные
# =========================
# METADATA
# title: ChronoWatch Time Guard
# description: Политика допуска и валидации для Time/Schedule/Lease сервисов.
# owners: platform-security, chronowatch-core
# schemas:
#   - input: chronowatch.input.v1
#   - output: chronowatch.decision.v1

default allow := false

# Для интеграций удобно возвращать единый документ решения.
decision := {
  "allow": allow,
  "denies": denies_sorted,
  "constraints": constraints,
}

# Упорядочиваем причины отказов для детерминизма.
denies_sorted := sorted(denies)

# Собираем ограничения, релевантные текущей операции/среде.
constraints := {
  "env": env(),
  "min_interval_ms": min_interval_ms(env()),
  "max_payload_bytes": max_payload_bytes(env()),
  "max_lease_ttl_ms": max_lease_ttl_ms(env()),
  "allowed_roles": allowed_roles_for_action(action()),
}

# =========================
# Вспомогательные извлечения
# =========================
# Безопасная среда по умолчанию — "prod"
env() := e {
  e := lower(input.env)
} else := "prod"

now_ms() := n {
  n := input.request.now_unix_ms
} else := 0

method() := upper(input.request.method)
path() := input.request.path
action() := input.request.action # предпочтительно явное действие: "time.now", "schedule.create" и т.д.

# Клеймы, выданные внешней проверкой JWT (подпись проверяется вне политики).
claims := c {
  c := input.auth.jwt.claims
} else := {}

jwt_verified := input.auth.jwt.verified == true
mtls_present := input.auth.mtls.present == true

roles := rs {
  rs := input.auth.principal.roles
} else := rs {
  rs := claims.roles
} else := []

subject() := s {
  s := input.auth.principal.sub
} else := s {
  s := claims.sub
} else := ""

issuer() := claims.iss
audience() := claims.aud

client_ip() := input.request.client_ip

# Запрашиваемые параметры для операций (могут отсутствовать в зависимости от действия).
schedule := input.request.schedule
lease := input.request.lease

# Телеметрия для контроля дрейфа
tele := input.telemetry

# =========================
# Константы и профили по средам
# =========================
allowed_issuers := {
  "prod": {"https://auth.company.com", "https://login.microsoftonline.com/XXXX/v2.0"},
  "staging": {"https://auth.staging.company.com"},
  "dev": {"http://localhost:8081/auth"},
}[env()]

allowed_audiences := {
  "prod": {"chronowatch"},
  "staging": {"chronowatch-stg", "chronowatch"},
  "dev": {"chronowatch-dev", "chronowatch"},
}[env()]

# Минимально допустимые интервалы для RATE/DELAY/ISO в миллисекундах.
min_interval_ms(env) := v {
  v := {
    "prod": 5000,     # >= 5s
    "staging": 1000,  # >= 1s
    "dev": 200,       # >= 200ms
  }[env]
}

# Допустимый дрейф между эталонным (ntp) и стеночным временем.
max_drift_ms(env) := v {
  v := {
    "prod": 20,
    "staging": 50,
    "dev": 100,
  }[env]
}

max_payload_bytes(env) := v {
  v := {
    "prod": 16384,    # 16 KiB
    "staging": 65536, # 64 KiB
    "dev": 262144,    # 256 KiB
  }[env]
}

max_lease_ttl_ms(env) := v {
  v := {
    "prod": 60000,    # 60s
    "staging": 120000,# 120s
    "dev": 300000,    # 300s
  }[env]
}

min_lease_ttl_ms := 1000  # 1s для защиты от флудов

# =========================
# Предикаты и утилиты
# =========================
has_role(r) {
  some i
  roles[i] == r
}

in_set(x, s) {
  some i
  s[i] == x
}

internal_network {
  startswith(client_ip(), "10.")  # упрощенно, при необходимости замените на CIDR-проверку в sidecar
} or {
  startswith(client_ip(), "192.168.")
} or {
  re_match("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*", client_ip())
}

# Проверка базовой аутентификации: допускаем, если есть верифицированный JWT или mTLS.
authenticated {
  jwt_verified
} or {
  mtls_present
}

# Валидация временных клеймов (exp/nbf). exp и nbf в секундах.
jwt_time_valid {
  not claims.exp  # если exp отсутствует — считаем проверенным вне OPA
} or {
  claims.exp * 1000 >= now_ms()
}
jwt_nbf_valid {
  not claims.nbf
} or {
  claims.nbf * 1000 <= now_ms()
}

issuer_allowed {
  count(allowed_issuers) == 0
} or {
  in_set(issuer(), allowed_issuers)
}
audience_allowed {
  count(allowed_audiences) == 0
} or {
  in_set(audience(), allowed_audiences)
}

# Парсинг duration из строк "rate:5s" или "delay:250ms"
is_rate(s) {
  re_match("(?i)^rate:\\d+(ms|s|m|h)$", s)
}
is_delay(s) {
  re_match("(?i)^delay:\\d+(ms|s|m|h)$", s)
}
is_iso8601_duration(s) {
  re_match("(?i)^P(?!$)(\\d+Y)?(\\d+M)?(\\d+D)?(T(\\d+H)?(\\d+M)?(\\d+(\\.\\d+)?S)?)?$", s)
}
is_cron(s) {
  # Разрешаем 5 или 6 полей, исключая невалидные пробелы, без под-секунд.
  re_match("^\\s*([^\\s]+\\s+){4,5}[^\\s]+\\s*$", s)
}

# Извлекаем число и единицу из rate:/delay:
rate_delay_number(s) = n {
  parts := split(lower(s), ":")
  len(parts) == 2
  tail := parts[1]
  unit := rate_delay_unit(s)
  n := to_number(replace(tail, unit, ""))
}
rate_delay_unit(s) = u {
  lower(endswith(s, "ms")); u := "ms"
} else = u {
  lower(endswith(s, "s")); u := "s"
} else = u {
  lower(endswith(s, "m")); u := "m"
} else = u {
  lower(endswith(s, "h")); u := "h"
}

unit_factor("ms") := 1
unit_factor("s") := 1000
unit_factor("m") := 60000
unit_factor("h") := 3600000

duration_ms(s) = ms {
  is_rate(s) or is_delay(s)
  n := rate_delay_number(s)
  u := rate_delay_unit(s)
  f := unit_factor(u)
  ms := n * f
}

# Проверка дрейфа времени, если telemetry предоставлена.
drift_ms() = d {
  tele.ntp_unix_ms
  tele.wall_unix_ms
  d := abs(tele.wall_unix_ms - tele.ntp_unix_ms)
}

# Проверка имени лизы, 3..128 допустимых символов.
lease_name_valid(n) {
  re_match("^[a-z0-9:/._-]{3,128}$", n)
}

# =========================
# Базовые запреты (DENY)
# =========================
deny[{"code": "auth/unauthenticated", "msg": "Authentication required"}] {
  not authenticated
}

deny[{"code": "auth/issuer", "msg": sprintf("Issuer %q is not allowed for env %q", [issuer(), env()])}] {
  authenticated
  issuer() != ""
  not issuer_allowed
}

deny[{"code": "auth/audience", "msg": sprintf("Audience %q is not allowed for env %q", [audience(), env()])}] {
  authenticated
  audience() != ""
  not audience_allowed
}

deny[{"code": "auth/expired", "msg": "JWT is expired"}] {
  authenticated
  not jwt_time_valid
}

deny[{"code": "auth/nbf", "msg": "JWT not yet valid (nbf)"}] {
  authenticated
  not jwt_nbf_valid
}

deny[{"code": "time/drift", "msg": sprintf("Clock drift %dms exceeds max %dms for env %q", [drift_ms(), max_drift_ms(env()), env()])}] {
  drift_ms() > max_drift_ms(env())
}

# =========================
# Правила по действиям
# =========================

# ---- Time.Now ----
# Разрешаем всем аутентифицированным ролям читать время.
deny[{"code": "time/method", "msg": "Only GET is allowed for time.now"}] {
  action() == "time.now"
  method() != "GET"
}

# ---- Schedule.Create ----
deny[{"code": "schedule/role", "msg": "Role scheduler or admin required"}] {
  action() == "schedule.create"
  not (has_role("admin") or has_role("scheduler"))
}

deny[{"code": "schedule/body", "msg": "Missing schedule payload"}] {
  action() == "schedule.create"
  not schedule
}

# Валидация типа и выражения
deny[{"code": "schedule/expr", "msg": sprintf("Unsupported schedule type: %q", [schedule.type])}] {
  action() == "schedule.create"
  not (schedule.type == "CRON" or schedule.type == "RATE" or schedule.type == "DELAY" or schedule.type == "ISO8601")
}

deny[{"code": "schedule/expr", "msg": "Invalid CRON expression"}] {
  action() == "schedule.create"
  schedule.type == "CRON"
  not is_cron(schedule.expr)
}

deny[{"code": "schedule/expr", "msg": sprintf("RATE too small: %dms < %dms", [duration_ms(lower(schedule.expr)), min_interval_ms(env())])}] {
  action() == "schedule.create"
  schedule.type == "RATE"
  not is_cron(schedule.expr)
  duration_ms(lower(schedule.expr)) < min_interval_ms(env())
}

deny[{"code": "schedule/expr", "msg": sprintf("DELAY too small: %dms < %dms", [duration_ms(lower(schedule.expr)), min_interval_ms(env())])}] {
  action() == "schedule.create"
  schedule.type == "DELAY"
  duration_ms(lower(schedule.expr)) < min_interval_ms(env())
}

deny[{"code": "schedule/expr", "msg": "Invalid ISO8601 duration"}] {
  action() == "schedule.create"
  schedule.type == "ISO8601"
  not is_iso8601_duration(schedule.expr)
}

# Ограничение размера полезной нагрузки
deny[{"code": "schedule/payload", "msg": sprintf("Payload too large: %d > %d bytes", [input.request.payload_size_bytes, max_payload_bytes(env())])}] {
  action() == "schedule.create"
  input.request.payload_size_bytes > max_payload_bytes(env())
}

# Владелец должен совпадать с субъектом или быть админом
deny[{"code": "schedule/owner", "msg": "Owner must match subject or role admin required"}] {
  action() == "schedule.create"
  schedule.owner
  not has_role("admin")
  lower(schedule.owner) != lower(subject())
}

# В prod запрещаем создание CRON чаще, чем раз в 5 секунд (задает min_interval_ms)
deny[{"code": "schedule/frequency", "msg": "CRON with sub-5s cadence is not allowed in prod"}] {
  action() == "schedule.create"
  env() == "prod"
  schedule.type == "CRON"
  # строгую проверку реального периода CRON тут не проводим; требование реализуется на admission в сервисе
}

# ---- Schedule.Delete / Pause / Resume ----
deny[{"code": "schedule/delete", "msg": "Only admin may delete schedules in prod"}] {
  action() == "schedule.delete"
  env() == "prod"
  not has_role("admin")
}

deny[{"code": "schedule/modify", "msg": "Role scheduler or admin required"}] {
  action() == "schedule.pause" or action() == "schedule.resume"
  not (has_role("admin") or has_role("scheduler"))
}

# ---- Lease.Acquire ----
deny[{"code": "lease/role", "msg": "Role service or admin required"}] {
  action() == "lease.acquire"
  not (has_role("service") or has_role("admin"))
}

deny[{"code": "lease/name", "msg": "Invalid lease name"}] {
  action() == "lease.acquire"
  not lease_name_valid(lease.name)
}

deny[{"code": "lease/ttl", "msg": sprintf("TTL out of bounds: %dms not in [%d,%d]", [lease.ttl_ms, min_lease_ttl_ms, max_lease_ttl_ms(env())])}] {
  action() == "lease.acquire"
  not (lease.ttl_ms >= min_lease_ttl_ms and lease.ttl_ms <= max_lease_ttl_ms(env()))
}

deny[{"code": "lease/fencing", "msg": "Fencing token must not be provided on acquire"}] {
  action() == "lease.acquire"
  lease.fencing_token
}

# ---- Lease.Renew ----
deny[{"code": "lease/renew/role", "msg": "Role service or admin required"}] {
  action() == "lease.renew"
  not (has_role("service") or has_role("admin"))
}

deny[{"code": "lease/renew/fencing", "msg": "Fencing token required on renew"}] {
  action() == "lease.renew"
  not lease.fencing_token
}

deny[{"code": "lease/renew/ttl", "msg": sprintf("Renew TTL out of bounds: %dms not in [%d,%d]", [lease.ttl_ms, min_lease_ttl_ms, max_lease_ttl_ms(env())])}] {
  action() == "lease.renew"
  not (lease.ttl_ms >= min_lease_ttl_ms and lease.ttl_ms <= max_lease_ttl_ms(env()))
}

# ---- Lease.Release ----
deny[{"code": "lease/release/role", "msg": "Role service or admin required"}] {
  action() == "lease.release"
  not (has_role("service") or has_role("admin"))
}

deny[{"code": "lease/release/fencing", "msg": "Fencing token required on release"}] {
  action() == "lease.release"
  not lease.fencing_token
}

# ---- Observability ----
deny[{"code": "metrics/access", "msg": "Metrics are internal-only"}] {
  action() == "metrics.read"
  not internal_network
  not has_role("admin")
  not has_role("auditor")
}

# =========================
# Итог: allow, если нет deny
# =========================
allow {
  count(denies) == 0
}

# =========================
# Сервисные deny-сборщики
# =========================
denies[msg] {
  some d
  d := deny_entry
  msg := d
}

# Каждое конкретное правило deny добавляет запись через коллекцию deny_entry.
# Для Rego мы используем синтетический агрегатор ниже.
deny_entry := d { some d = data.partial.deny_entries[_] } else := d { some d = data.partial2.deny_entries[_] }
# Заглушки на случай, если модуль импортируется совместно с внешними частями:
data.partial.deny_entries := [] with input as input
data.partial2.deny_entries := [] with input as input
