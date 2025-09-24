# =====================================================================
# cybersecurity-core/configs/policies/rego/data_guard.rego
# Пакет промышленной политики OPA (Rego) для защиты данных (DLP/PII/SecOps).
# Вход (пример):
# {
#   "action": "read|write|export|delete",
#   "resource": {
#     "type": "db.table|s3.bucket|kafka.topic|http.endpoint",
#     "name": "orders",
#     "vendor": "internal|aws-eu|aws-us|gcp-eu|third-party",
#     "region": "eu-north-1",
#     "tags": ["pii","payment"]
#   },
#   "data": {
#     "schema": {"email":"string","pan":"string"},
#     "labels": {"pan": ["secret","payment"], "email": ["pii"]},
#     "records_sample": [{"email":"a@b.com","pan":"4111111111111111"}]
#   },
#   "security": {
#     "encryption": {"at_rest": true, "in_transit_tls": "1.3", "kms": true},
#     "mfa": true
#   },
#   "actor": {"id":"u1","role":"data_engineer","clearance":["pii_read"], "network_zone":"prod"},
#   "purpose": "analytics",
#   "legal": {"basis": "consent|contract|legitimate_interest|na"}
# }
#
# Выход:
# {
#   "allow": true|false,
#   "deny": {"...","..."},
#   "redact_fields": {"field1","field2",...},
#   "mask_rules": { {"field":"email","strategy":"hash"}, ... },
#   "required_controls": {"encrypt_at_rest","tokenize","pseudonymize",...},
#   "audit": {"severity":"low|medium|high","must_capture":{"request_id","actor.id",...}},
#   "retention_days": 365
# }
# =====================================================================

package data_guard

default allow := false

# ----------------------------
# Константы/настройки политики
# ----------------------------

# Разрешенные поставщики для хранения/обработки PII
allowed_vendors := {"internal", "onprem", "aws-eu", "gcp-eu", "azure-eu"}

# Разрешенные TLS версии
allowed_tls := {"1.2", "1.3"}

# Роли с правом на "raw" доступ к секретам (ограничить до IR/DPO)
raw_secret_roles := {"secops", "dpo"}

# Роли с доступом к PII (в маскированном/псевдонимном виде)
pii_roles := {"secops", "dpo", "data_engineer", "ml_engineer", "service"}

# Регулярные выражения для детекции PII/секретов
patterns := {
  "email":    "(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
  "phone":    "(?i)\\+?\\d[\\d\\s().-]{9,}\\d",
  "pan":      "(?:(?:^|\\D)(4\\d{12}(\\d{3})?|5[1-5]\\d{14}|3[47]\\d{13}|6(?:011|5\\d{2})\\d{12})(?:\\D|$))",
  "iban":     "(?i)\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b",
  "aws_key":  "\\bAKIA[0-9A-Z]{16}\\b",
  "bearer":   "(?i)\\bBearer\\s+[A-Za-z0-9._\\-]+\\b",
  "privkey":  "-----BEGIN\\s+(?:EC|RSA|DSA|OPENSSH|PGP)?\\s*PRIVATE\\s+KEY-----"
}

# Политически допустимые EU-регионы (эвристика по имени)
eu_region_regex := "(?i)\\b(eu|europe|westeurope|northeurope|uksouth|ukwest|france|germany|swedencentral|sweden|poland|italy|spain|switzerland|norwayeast|europe-west\\d+)\\b"

# Рекомендованные поля для аудита
audit_must := {"timestamp","request_id","actor.id","actor.role","purpose","resource.name","resource.type","resource.region","record_count"}

# Рекомендованная ретенция (в днях) по категориям политики
retention_map := {
  "secret": 0,          # хранить сырые секреты — запрещено (0 дней -> немедленно удалить/не сохранять)
  "payment": 90,        # платежные токены/транзакции
  "pii": 365,           # общая PII
  "log": 30             # технические логи без PII
}

# ----------------------------
# Утилиты
# ----------------------------

is_string_val(v) { type_name(v) == "string" }

re_match_safe(p, v) {
  is_string_val(v)
  re_match(p, v)
}

lower_safe(s) := x {
  is_string_val(s)
  x := lower(s)
} else := s

# EU регион по имени
is_eu_region := re_match(eu_region_regex, lower_safe(input.resource.region))

# Есть ли тег категории у ресурса
resource_has_tag(tag) {
  some i
  lower(input.resource.tags[i]) == lower(tag)
}

# ----------------------------
# Детекция PII и секретов
# ----------------------------

# Поля, отмеченные метками как PII/secret/payment
labeled_pii_fields[f] {
  input.data.labels[f][i] == "pii"
}

labeled_secret_fields[f] {
  input.data.labels[f][i] == "secret"
}

labeled_payment_fields[f] {
  input.data.labels[f][i] == "payment"
}

# Поля, детектированные по regex в sample данных
sample_pii_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["email"], v)  # email
}

sample_pii_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["phone"], v)  # phone
}

sample_pii_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["iban"], v)   # iban
}

sample_secret_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["aws_key"], v)  # AWS key
} 

sample_secret_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["bearer"], v)   # Bearer token
}

sample_secret_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["privkey"], v)  # Private key block
}

sample_payment_fields[f] {
  some i
  rec := input.data.records_sample[i]
  some f
  v := rec[f]
  is_string_val(v)
  re_match_safe(patterns["pan"], v)      # Payment PAN
}

# Объединенные множества
pii_fields[f] {
  labeled_pii_fields[f]
} else {
  sample_pii_fields[f]
}

secret_fields[f] {
  labeled_secret_fields[f]
} else {
  sample_secret_fields[f]
}

payment_fields[f] {
  labeled_payment_fields[f]
} else {
  sample_payment_fields[f]
}

contains_pii := count(pii_fields) > 0
contains_secret := count(secret_fields) > 0
contains_payment := count(payment_fields) > 0

# ----------------------------
# Контроль доступа/шифрования
# ----------------------------

# Требования к шифрованию
deny["Encryption at-rest is required for sensitive data"] {
  (contains_pii or contains_secret or contains_payment)
  not input.security.encryption.at_rest
}

deny["KMS is required for at-rest encryption of sensitive data"] {
  (contains_pii or contains_secret or contains_payment)
  not input.security.encryption.kms
}

deny["TLS 1.2+ is required in transit"] {
  (contains_pii or contains_secret or contains_payment)
  not allowed_tls[input.security.encryption.in_transit_tls]
}

# MFA требование для операций с чувствительными данными
deny["MFA is required for sensitive data operations"] {
  (contains_pii or contains_secret or contains_payment)
  not input.security.mfa
}

# Ограничение по ролям: сырые секреты — только для secops/dpo и только для IR
deny["Raw secrets access is restricted to SecOps/DPO with purpose=incident_response"] {
  contains_secret
  not raw_secret_roles[input.actor.role]
} {
  contains_secret
  input.purpose != "incident_response"
}

# PII доступ: только утвержденные роли
deny["PII access requires approved role"] {
  contains_pii
  not pii_roles[input.actor.role]
}

# Экспорт за пределы ЕС запрещен для PII/платежей
deny["PII/payment export outside EU is not allowed"] {
  (contains_pii or contains_payment)
  input.action == "export"
  not is_eu_region
}

# Вендор должен быть разрешен при работе с PII/секретами/платежами
deny["Vendor is not approved for sensitive data"] {
  (contains_pii or contains_secret or contains_payment)
  not allowed_vendors[input.resource.vendor]
}

# Юридическое основание требуется для обработки PII
deny["Legal basis is required for PII processing"] {
  contains_pii
  not legal_has_basis
}

legal_has_basis {
  some b
  b := lower_safe(input.legal.basis)
  b == "consent"  # примерные основания, расширяйте по политике организации
} {
  lower_safe(input.legal.basis) == "contract"
} {
  lower_safe(input.legal.basis) == "legitimate_interest"
}

# ----------------------------
# Маскирование/редакция и контроли
# ----------------------------

# Поля, подлежащие редактированию (жесткая редакция в журналах/экспортах)
redact_fields[f] {
  secret_fields[f]
} 
redact_fields[f] {
  payment_fields[f]
}

# Стратегии маскирования (набор объектов {field, strategy})
mask_rules[x] {
  some f
  pii_fields[f]
  x := {"field": f, "strategy": "hash"}  # для PII — хеширование/псевдонимизация
}
mask_rules[x] {
  some f
  payment_fields[f]
  x := {"field": f, "strategy": "redact"}  # платежные — полная редакция или токенизация
}
mask_rules[x] {
  some f
  secret_fields[f]
  x := {"field": f, "strategy": "drop"}   # сырые секреты — удалять из потока
}

# Требуемые дополнительные контроли
required_controls[c] {
  contains_pii
  c := "pseudonymize"
}
required_controls[c] {
  contains_payment
  c := "tokenize"
}
required_controls[c] {
  contains_secret
  c := "secrets_manager_only"
}
required_controls[c] {
  (contains_pii or contains_payment or contains_secret)
  c := "encrypt_at_rest"
}
required_controls[c] {
  (contains_pii or contains_payment or contains_secret)
  c := "tls12_plus"
}

# ----------------------------
# Аудит и ретенция
# ----------------------------

audit.severity := s {
  contains_secret
  s := "high"
} else := s {
  (contains_pii or contains_payment) 
  (input.action == "export" or not is_eu_region)
  s := "medium"
} else := "low"

audit.must_capture := audit_must

# Рекомендованная ретенция выбирается по максимальному риску
retention_days := d {
  contains_secret
  d := retention_map["secret"]
} else := d {
  contains_payment
  d := retention_map["payment"]
} else := d {
  contains_pii
  d := retention_map["pii"]
} else := retention_map["log"]

# ----------------------------
# Итоговое решение
# ----------------------------

# Разрешаем, если нет нарушений
allow {
  not deny[_]
}

# Итоговый объект результата (для удобства интеграции)
result := {
  "allow": allow,
  "deny": deny,
  "redact_fields": redact_fields,
  "mask_rules": mask_rules,
  "required_controls": required_controls,
  "audit": audit,
  "retention_days": retention_days
}
