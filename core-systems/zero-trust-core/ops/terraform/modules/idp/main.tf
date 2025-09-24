terraform {
  required_version = ">= 1.5.0"

  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = ">= 4.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

################################################################################
# ВХОДНЫЕ ДАННЫЕ
################################################################################

# Базовый URL Keycloak, напр. https://sso.example.com
variable "keycloak_base_url" {
  type        = string
  description = "Базовый URL Keycloak (без хвоста /auth и т.п.)."
}

# Создавать realm внутри модуля или использовать существующий
variable "create_realm" {
  type        = bool
  description = "Если true — модуль создаёт realm; иначе используется существующий."
  default     = false
}

variable "realm_name" {
  type        = string
  description = "Имя realm (существующий или создаваемый)."
}

variable "realm_display_name" {
  type        = string
  default     = "Zero Trust Core"
  description = "Display name для realm при create_realm=true."
}

# Список ролей realm
variable "realm_roles" {
  type        = list(string)
  description = "Роли realm (RBAC)."
  default     = ["owner", "admin", "custodian", "analyst", "service"]
}

# Группы и назначение ролей на группу (для удобства on‑prem)
variable "groups" {
  type = map(object({
    path        = string,             # например "teams/security-core"
    realm_roles = optional(list(string), [])
  }))
  description = "Группы Keycloak и роли, назначаемые на группы."
  default     = {}
}

# Единый client scope для выдачи требований Zero‑Trust (roles/tenant/groups/audience)
variable "ztc_scope_name" {
  type        = string
  default     = "zero-trust"
  description = "Имя кастомного OIDC client scope."
}

# Карта клиентов (OIDC RP)
variable "clients" {
  description = "Клиенты OIDC: конфиденциальные или публичные."
  type = map(object({
    client_id                       = string
    description                     = optional(string, "")
    access_type                     = optional(string, "CONFIDENTIAL") # CONFIDENTIAL|PUBLIC|BEARER-ONLY
    standard_flow_enabled           = optional(bool, true)
    implicit_flow_enabled           = optional(bool, false)
    direct_access_grants_enabled    = optional(bool, false)
    service_accounts_enabled        = optional(bool, false)
    pkce_code_challenge_method      = optional(string, "S256")
    root_url                        = optional(string, null)
    valid_redirect_uris             = list(string)
    web_origins                     = optional(list(string), [])
    consent_required                = optional(bool, false)
    frontchannel_logout_enabled     = optional(bool, true)
    access_token_lifespan_seconds   = optional(number, 900)   # 15m
    refresh_token_lifespan_seconds  = optional(number, 3600)  # 60m
    client_secret                   = optional(string, null)  # только для CONFIDENTIAL, подставляется через CI/TFVARS
    default_scopes                  = optional(list(string), ["email","profile"])
    optional_scopes                 = optional(list(string), [])
    audience_include_client_id      = optional(bool, true)
    additional_claims               = optional(map(string), {}) # { claim_name = static_value } (hardcoded)
  }))
  default = {
    zero-trust-core = {
      client_id                      = "zero-trust-core"
      access_type                    = "CONFIDENTIAL"
      valid_redirect_uris            = ["https://zero-trust-core.example.com/*"]
      web_origins                    = ["+"]
      service_accounts_enabled       = true
      standard_flow_enabled          = true
      direct_access_grants_enabled   = false
      pkce_code_challenge_method     = "S256"
      access_token_lifespan_seconds  = 900
      refresh_token_lifespan_seconds = 3600
      default_scopes                 = ["email","profile"]
      optional_scopes                = []
      audience_include_client_id     = true
      additional_claims              = {}
    }
  }
}

# Включать аудит событий (логины/админ‑события)
variable "enable_realm_events" {
  type        = bool
  default     = true
  description = "Включить login/admin events в realm."
}

variable "events_expiration" {
  type        = number
  default     = 1209600 # 14d
  description = "Время жизни событий в секундах."
}

# Мэппинг атрибутов пользователя -> claims
variable "claims" {
  description = "Мэппинг пользовательских атрибутов в OIDC claims."
  type = object({
    roles_claim      = optional(string, "roles")
    tenant_attr      = optional(string, "tenant_id")   # user attribute name
    tenant_claim     = optional(string, "tenant_id")   # claim name
    groups_claim     = optional(string, "groups")
  })
  default = {}
}

################################################################################
# ПРОВАЙДЕР (конфигурация ожидается на верхнем уровне)
################################################################################

# provider "keycloak" должен быть сконфигурирован в root‑модуле
# пример:
# provider "keycloak" {
#   client_id     = "admin-cli"
#   url           = var.keycloak_base_url
#   username      = var.keycloak_username
#   password      = var.keycloak_password
#   realm         = "master"
# }

################################################################################
# REALM (опционально)
################################################################################

resource "keycloak_realm" "this" {
  count                     = var.create_realm ? 1 : 0
  realm                     = var.realm_name
  display_name              = var.realm_display_name
  enabled                   = true

  # Безопасные TTL по токенам
  access_token_lifespan               = "15m"
  sso_session_idle_timeout            = "30m"
  sso_session_max_lifespan            = "8h"
  offline_session_idle_timeout        = "720h"
  refresh_token_max_reuse             = 0

  # Строгие пароли по умолчанию — можно усилить политикой
  login_with_email_allowed            = true
  verify_email                        = true
  registration_allowed                = false
  remember_me                         = false
}

locals {
  realm_id   = var.create_realm ? keycloak_realm.this[0].id : var.realm_name
  realm_name = var.realm_name

  claims = {
    roles_claim  = coalesce(try(var.claims.roles_claim, null), "roles")
    tenant_attr  = coalesce(try(var.claims.tenant_attr, null), "tenant_id")
    tenant_claim = coalesce(try(var.claims.tenant_claim, null), "tenant_id")
    groups_claim = coalesce(try(var.claims.groups_claim, null), "groups")
  }

  issuer = "${trim(var.keycloak_base_url, "/")}/realms/${local.realm_name}"
}

################################################################################
# АУДИТ СОБЫТИЙ
################################################################################

resource "keycloak_realm_events" "this" {
  count                = var.enable_realm_events ? 1 : 0
  realm_id             = local.realm_id
  events_enabled       = true
  admin_events_enabled = true
  events_expiration    = var.events_expiration
  enabled_event_types  = ["LOGIN","LOGIN_ERROR","LOGOUT","LOGOUT_ERROR","UPDATE_PASSWORD","UPDATE_PROFILE"]
  admin_enabled_event_operations = ["CREATE","UPDATE","DELETE"]
}

################################################################################
# РОЛИ REALM
################################################################################

resource "keycloak_realm_role" "roles" {
  for_each = toset(var.realm_roles)
  realm_id = local.realm_id
  name     = each.value
}

################################################################################
# ГРУППЫ И РОЛИ НА ГРУППЫ
################################################################################

resource "keycloak_group" "groups" {
  for_each = var.groups
  realm_id = local.realm_id
  name     = each.value.path
  # provider ожидает иерархию через parent_id, для простоты создаём плоско (path как имя)
}

resource "keycloak_group_roles" "group_roles" {
  for_each = { for k, v in var.groups : k => v if length(try(v.realm_roles, [])) > 0 }
  realm_id = local.realm_id
  group_id = keycloak_group.groups[each.key].id
  role_ids = [
    for r in each.value.realm_roles : keycloak_realm_role.roles[r].id
  ]
}

################################################################################
# КЛИЕНТСКИЙ SCOPE С МЭППЕРАМИ (roles, tenant_id, groups, audience)
################################################################################

resource "keycloak_openid_client_scope" "ztc" {
  realm_id    = local.realm_id
  name        = var.ztc_scope_name
  description = "Zero-Trust aggregate scope for roles/tenant/groups/audience"
  consent_screen_text = "Zero-Trust policy"
}

# roles -> claim (array)
resource "keycloak_openid_user_realm_role_protocol_mapper" "roles_mapper" {
  realm_id           = local.realm_id
  client_scope_id    = keycloak_openid_client_scope.ztc.id
  name               = "roles"
  claim_name         = local.claims.roles_claim
  claim_value_type   = "String"
  multivalued        = true
  add_to_id_token    = true
  add_to_access_token= true
}

# user attribute tenant_id -> claim
resource "keycloak_openid_user_attribute_protocol_mapper" "tenant_mapper" {
  realm_id           = local.realm_id
  client_scope_id    = keycloak_openid_client_scope.ztc.id
  name               = "tenant_id"
  user_attribute     = local.claims.tenant_attr
  claim_name         = local.claims.tenant_claim
  claim_value_type   = "String"
  add_to_id_token    = true
  add_to_access_token= true
}

# groups -> claim (array)
resource "keycloak_openid_group_membership_protocol_mapper" "groups_mapper" {
  realm_id           = local.realm_id
  client_scope_id    = keycloak_openid_client_scope.ztc.id
  name               = "groups"
  claim_name         = local.claims.groups_claim
  full_path          = false
  add_to_id_token    = true
  add_to_access_token= true
}

################################################################################
# КЛИЕНТЫ OIDC
################################################################################

# Генерим секрет по умолчанию, если не передан явно
resource "random_password" "client_secret" {
  for_each = { for k, v in var.clients : k => v if try(v.access_type, "CONFIDENTIAL") == "CONFIDENTIAL" && try(v.client_secret, null) == null }
  length   = 40
  special  = false
}

resource "keycloak_openid_client" "clients" {
  for_each                           = var.clients

  realm_id                           = local.realm_id
  client_id                          = each.value.client_id
  name                               = coalesce(try(each.value.description, null), each.value.client_id)
  description                        = try(each.value.description, "")

  access_type                        = upper(try(each.value.access_type, "CONFIDENTIAL")) # CONFIDENTIAL|PUBLIC|BEARER-ONLY
  service_accounts_enabled           = try(each.value.service_accounts_enabled, false)
  standard_flow_enabled              = try(each.value.standard_flow_enabled, true)
  implicit_flow_enabled              = try(each.value.implicit_flow_enabled, false)
  direct_access_grants_enabled       = try(each.value.direct_access_grants_enabled, false)

  pkce_code_challenge_method         = try(each.value.pkce_code_challenge_method, "S256")
  root_url                           = try(each.value.root_url, null)
  valid_redirect_uris                = each.value.valid_redirect_uris
  web_origins                        = try(each.value.web_origins, [])

  consent_required                   = try(each.value.consent_required, false)
  frontchannel_logout_enabled        = try(each.value.frontchannel_logout_enabled, true)

  # TTL токенов на уровне клиента (усиливаем дефолты realm)
  access_token_lifespan              = format("%ds", try(each.value.access_token_lifespan_seconds, 900))
  client_session_idle_timeout        = "30m"
  client_session_max_lifespan        = "8h"

  # Секрет только для CONFIDENTIAL
  client_secret                      = (
    upper(try(each.value.access_type, "CONFIDENTIAL")) == "CONFIDENTIAL"
    ? coalesce(try(each.value.client_secret, null), random_password.client_secret[each.key].result)
    : null
  )
}

# Audience мэппер: добавляем client_id как audience при необходимости
resource "keycloak_openid_audience_protocol_mapper" "audience" {
  for_each         = { for k, v in var.clients : k => v if try(v.audience_include_client_id, true) }
  realm_id         = local.realm_id
  client_id        = keycloak_openid_client.clients[each.key].id
  name             = "audience-client"
  included_custom_audience = keycloak_openid_client.clients[each.key].client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# Жёстко заданные дополнительные claims на клиентах (при необходимости)
resource "keycloak_openid_hardcoded_claim_protocol_mapper" "extra_claims" {
  for_each       = { for k, v in var.clients : k => v if length(try(v.additional_claims, {})) > 0 }

  realm_id       = local.realm_id
  client_id      = keycloak_openid_client.clients[each.key].id
  name           = "hardcoded-claims"
  claim_name     = "ztc"               # корневой объект; измените при желании
  claim_value    = jsonencode(each.value.additional_claims)
  claim_value_type = "JSON"
  add_to_access_token = true
  add_to_id_token     = true
}

# Подключаем zero-trust scope как default scope на клиентах
resource "keycloak_openid_client_default_scopes" "clients_defaults" {
  for_each       = var.clients
  realm_id       = local.realm_id
  client_id      = keycloak_openid_client.clients[each.key].id

  default_scopes = concat(
    try(each.value.default_scopes, ["email","profile"]),
    [keycloak_openid_client_scope.ztc.name]
  )
  optional_scopes = try(each.value.optional_scopes, [])
}

################################################################################
# ВЫХОДЫ
################################################################################

output "realm_id" {
  description = "ID/имя realm."
  value       = local.realm_id
}

output "issuer" {
  description = "OIDC Issuer URL."
  value       = local.issuer
}

output "authorize_endpoint" {
  description = "OIDC Authorization Endpoint."
  value       = "${local.issuer}/protocol/openid-connect/auth"
}

output "token_endpoint" {
  description = "OIDC Token Endpoint."
  value       = "${local.issuer}/protocol/openid-connect/token"
}

output "jwks_uri" {
  description = "OIDC JWKS URI."
  value       = "${local.issuer}/protocol/openid-connect/certs"
}

output "clients" {
  description = "Сводная информация по клиентам (без секретов)."
  value = {
    for k, v in keycloak_openid_client.clients :
    k => {
      client_id  = v.client_id
      access_type= v.access_type
      id         = v.id
    }
  }
}

# Секреты не раскрываем по умолчанию; при необходимости — включайте осознанно
output "client_secrets" {
  description = "Секреты клиентов (используйте осторожно)."
  value = {
    for k, v in keycloak_openid_client.clients :
    k => (v.access_type == "CONFIDENTIAL" ? v.client_secret : null)
  }
  sensitive = true
}
