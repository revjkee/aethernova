# zero-trust-core/configs/policies/rego/access_policy.rego
package zero_trust.access

import future.keywords
import input
import data
import regex
import glob

# ============================
# Версия/метаданные
# ============================

policy_version := "1.0.0"
policy_name := "zero-trust-access"

# ============================
# Безопасные дефолты и настройки (переопределяемы через data.settings.*)
# ============================

# Разрешённые издатели и аудитории JWT
default allowed_issuers := {"https://auth.aethernova.example"}
allowed_issuers := s { s := data.settings.allowed_issuers } else { allowed_issuers }

default accepted_audiences := {"api://core", "api://admin"}
accepted_audiences := s { s := data.settings.accepted_audiences } else { accepted_audiences }

# Требования к JWT/идентичности
default require_verified_identity := true
require_verified_identity := b { b := data.settings.require_verified_identity } else { require_verified_identity }

# Порог риска (0..1)
default high_risk_threshold := 0.8
high_risk_threshold := x { x := data.settings.high_risk_threshold } else { high_risk_threshold }

default medium_risk_threshold := 0.5
medium_risk_threshold := x { x := data.settings.medium_risk_threshold } else { medium_risk_threshold }

# Step-up MFA
default mfa_required_actions := {"write", "delete", "admin"}
mfa_required_actions := s { s := data.settings.mfa_required_actions } else { mfa_required_actions }

default mfa_max_age_seconds := 900   # 15 минут
mfa_max_age_seconds := n { n := data.settings.mfa_max_age_seconds } else { mfa_max_age_seconds }

# Требование mTLS для чувствительных ресурсов
default mtls_required_resource_globs := {"arn:prod:*", "project:*/secrets/*", "repo:*/protected/*"}
mtls_required_resource_globs := g { g := data.settings.mtls_required_resource_globs } else { mtls_required_resource_globs }

default allowed_spiffe_domains := {"prod.example.com", "stage.example.com"}
allowed_spiffe_domains := s { s := data.settings.allowed_spiffe_domains } else { allowed_spiffe_domains }

# Поза устройства
default require_device_compliance_in := {"prod"}
require_device_compliance_in := s { s := data.settings.require_device_compliance_in } else { require_device_compliance_in }

# Маппинг ролей в разрешения (можно вынести в data.roles.*)
default role_permissions := {
  "role:admin": {
    "actions": {"read","write","delete","admin"},
    "resources": {"*"}
  },
  "role:read": {
    "actions": {"read"},
    "resources": {"*"}
  },
  "role:dev": {
    "actions": {"read","write"},
    "resources": {"project:*","repo:*"}
  },
  "role:sre": {
    "actions": {"read","write","admin"},
    "resources": {"infra:*","monitoring:*"}
  }
}
role_permissions := rp { rp := data.roles.permissions } else { role_permissions }

# Карта HTTP-метод -> действие
method_action_map := {
  "GET": "read",
  "HEAD": "read",
  "OPTIONS": "read",
  "POST": "write",
  "PUT": "write",
  "PATCH": "write",
  "DELETE": "delete"
}

# ============================
# Точка принятия решения
# ============================

# Булево решение (для Envoy ext_authz bool)
default allow := false
allow {
  base_permit
  not step_up_required
  not mtls_required_unmet
  not device_required_unmet
  not high_risk_denied
}

# Полный объект решения
decision := {
  "policy": policy_name,
  "version": policy_version,
  "allow": allow,
  "reasons": reasons_array,
  "obligations": obligations_object,
  "risk_level": risk_level,
  "effective_roles": sorted(effective_roles),
  "input_digest": digest   # для трассировки/кеширования (best-effort)
}

# ============================
# Базовые проверки допуска (RBAC + JWT базовые политики)
# ============================

base_permit {
  jwt_ok
  rbac_ok
  # ABAC-фильтры по чувствительности/тегам ресурса можно добавить здесь при необходимости
}

jwt_ok {
  require_verified_identity
  input.identity.verified == true
}

jwt_ok {
  not require_verified_identity
}

jwt_ok {
  allowed_issuers[input.identity.iss]
}

jwt_ok {
  some aud
  aud := input.identity.aud
  accepted_audiences[aud]
}

# Разрешение согласно RBAC: хотя бы одна роль даёт нужное действие на ресурс
rbac_ok {
  needed_action := action
  needed_resource := resource
  some r
  r := input.identity.roles[_]
  role_permissions[r].actions[needed_action]
  resource_match(role_permissions[r].resources, needed_resource)
}

# ============================
# Обязательства и причины отказа
# ============================

# Требуется step-up MFA?
step_up_required {
  mfa_required_for_action
  not mfa_recent_and_strong
}

mfa_required_for_action {
  mfa_required_actions[action]
}

# Сильная и свежая MFA: amr содержит достаточный метод и возраст <= max
mfa_recent_and_strong {
  some amr
  amr := input.identity.amr[_]   # например: "otp", "webauthn", "hwk"
  strong_mfa_methods[amr]
  mfa_age_seconds := input.identity.mfa_age_seconds
  mfa_age_seconds <= mfa_max_age_seconds
}

strong_mfa_methods := {"otp","webauthn","hwk","swk"}

# Требуется mTLS для ресурса, но не выполнено?
mtls_required_unmet {
  resource_match(mtls_required_resource_globs, resource)
  not mtls_bound_and_trusted
}

mtls_bound_and_trusted {
  input.mtls.bound == true
  some id
  id := input.mtls.spiffe_ids[_]
  startswith(id, concat("", ["spiffe://", domain_prefix]))
  allowed_spiffe_domains[domain_prefix]
}

# В prod требуем compliant устройство, иначе обязательство
device_required_unmet {
  env_in := input.environment.env
  require_device_compliance_in[env_in]
  not device_compliant
}

device_compliant {
  input.device.posture.compliant == true
}

# Высокий риск => автоматический отказ для опасных действий/ресурсов
high_risk_denied {
  risk_level == "high"
  sensitive_action_or_resource
  # если предпочтительно — можно требовать step-up вместо отказа;
  # здесь демонстрация жёсткой политики на high-risk
}

sensitive_action_or_resource {
  action == "delete"
} else {
  action == "admin"
} else {
  resource_match({"arn:prod:*","secrets:*","payments:*"}, resource)
}

# Уровень риска
risk_level := "high" {
  input.risk.score >= high_risk_threshold
} else := "medium" {
  input.risk.score >= medium_risk_threshold
} else := "low"

# ============================
# Причины/обязательства/диагностика
# ============================

# Накопление причин отказа (set)
reasons_set[r] {
  step_up_required
  r := "step_up_required"
}
reasons_set[r] {
  mtls_required_unmet
  r := "mtls_required"
}
reasons_set[r] {
  device_required_unmet
  r := "device_noncompliant"
}
reasons_set[r] {
  high_risk_denied
  r := "high_risk"
}
reasons_set[r] {
  not rbac_ok
  r := "rbac_denied"
}
reasons_set[r] {
  not jwt_ok
  r := "jwt_policy_failed"
}

reasons_array := sorted([r | r := reasons_set[_]])

# Обязательства для приложения/прокси
obligations_object := {
  "require_step_up_mfa": step_up_required,
  "require_mtls": mtls_required_unmet,
  "require_device_remediation": device_required_unmet
}

# Эффективные роли (пересечение известных ролей с предъявленными)
effective_roles[r] {
  r := input.identity.roles[_]
  role_permissions[r]
}

# Псевдо-дайджест (best-effort) — компактная идентификация входа
digest := {
  "iss": input.identity.iss,
  "sub": input.identity.sub,
  "aud": input.identity.aud,
  "env": input.environment.env,
  "act": action,
  "res": resource
}

# ============================
# Помощники/утилиты
# ============================

# Действие из input.request
action := a {
  some m
  m := upper(input.request.method)
  a := method_action_map[m]
} else := a {
  a := input.request.action
}

# Ресурсный идентификатор (лучше отдавать нормализованный из шлюза)
resource := r {
  r := input.request.resource
} else := r {
  # как fallback, трансформируем путь в паттерн вида "path:/a/b"
  r := concat("", ["path:", input.request.path])
}

# Проверка соответствия ресурса наборам glob-паттернов
resource_match(patterns, res) {
  some p
  p := patterns[_]
  glob.match(p, ["/", ":"], res)
}

# ============ Валидация минимального входа (не ломаемся, а отказываем) ============

# Если каких-то полей нет, гарантируем безопасный отказ через дефолты ниже.
default input.identity.verified := false
default input.identity.roles := []
default input.identity.amr := []
default input.identity.mfa_age_seconds := 10e9
default input.identity.iss := ""
default input.identity.aud := ""
default input.identity.sub := ""
default input.request.method := "GET"
default input.request.path := "/"
default input.environment.env := "prod"
default input.risk.score := 1.0
default input.mtls.bound := false
default input.mtls.spiffe_ids := []
default input.device.posture.compliant := false
