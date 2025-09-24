terraform {
  required_version = ">= 1.5.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 3.0.0"
    }
  }
}

###############################################################################
# ВХОДНЫЕ ДАННЫЕ (СТРОГИЕ ТИПЫ, БЕЗ СЕКРЕТОВ В STATE)
###############################################################################

# Префикс имён сущностей, чтобы изолировать security-core в общем Vault
variable "name_prefix" {
  type        = string
  description = "Имя/префикс для монтируемых путей и политик (например, security-core)."
  default     = "security-core"
}

# Монтирования KV v2: map[path] = description
variable "kv_v2_mounts" {
  type        = map(string)
  description = "Список KV v2 секрет‑энджинов: ключ=путь, значение=описание."
  default     = {
    "secret" = "KV v2 for general application secrets"
  }
}

# Transit engine включение и путь
variable "transit" {
  type = object({
    enabled     = bool
    path        = string
    description = string
  })
  default = {
    enabled     = true
    path        = "transit"
    description = "Transit engine for crypto operations and envelope encryption"
  }
}

# Набор политик: map[policy_name] = HCL policy body
variable "policies" {
  type        = map(string)
  description = "Политики Vault в виде HCL (строка). Не храните секреты внутри."
  default     = {}
}

# Kubernetes auth backend (безопасные роли; JWT/CA/host передаются извне)
variable "kubernetes_auth" {
  type = object({
    enabled              = bool
    path                 = string
    host                 = string
    token_reviewer_jwt   = string
    kubernetes_ca_cert   = string
    issuer               = optional(string)
    roles                = map(object({
      token_policies   = list(string)
      token_ttl        = string
      namespaces       = list(string)
      service_accounts = list(string)
      audience         = optional(string)
    }))
  })
  default = {
    enabled            = false
    path               = "kubernetes"
    host               = ""
    token_reviewer_jwt = ""
    kubernetes_ca_cert = ""
    issuer             = null
    roles              = {}
  }
  sensitive = false
}

# JWT / OIDC auth backend
variable "oidc_auth" {
  type = object({
    enabled             = bool
    path                = string
    bound_issuer        = string
    oidc_discovery_url  = string
    default_role        = string
    roles               = map(object({
      role_name        = string
      user_claim       = string
      bound_audiences  = list(string)
      claim_mappings   = optional(map(string))
      groups_claim     = optional(string)
      token_policies   = list(string)
      token_ttl        = string
      allowed_redirect_uris = list(string)
      bound_subject    = optional(string)
    }))
  })
  default = {
    enabled            = false
    path               = "oidc"
    bound_issuer       = ""
    oidc_discovery_url = ""
    default_role       = "default"
    roles              = {}
  }
}

# AppRole auth backend
variable "approle_auth" {
  type = object({
    enabled = bool
    path    = string
    roles   = map(object({
      token_policies = list(string)
      token_ttl      = string
      secret_id_ttl  = optional(string)
      secret_id_num_uses = optional(number)
      bind_secret_id = optional(bool)
    }))
  })
  default = {
    enabled = false
    path    = "approle"
    roles   = {}
  }
}

# Аудит (по умолчанию выключен; осторожно с файловым аудитором)
variable "audit" {
  type = object({
    enabled   = bool
    type      = string # например "file" или "socket"
    path      = string # логическое имя устройства аудита, например "file"
    options   = map(string) # для file: { file_path = "/vault/logs/audit.log" }
    description = optional(string)
  })
  default = {
    enabled     = false
    type        = "file"
    path        = "file"
    options     = {}
    description = null
  }
}

###############################################################################
# ЛОКАЛЫ
###############################################################################

locals {
  # Полное имя для политик, чтобы избежать коллизий
  policy_name = "${var.name_prefix}"

  # Набор монтирований KV v2 как объект {path, description}
  kv_mounts = {
    for p, desc in var.kv_v2_mounts :
    p => {
      path        = p
      description = desc
    }
  }
}

###############################################################################
# МОНТИРОВАНИЕ ДВИЖКОВ СЕКРЕТОВ
###############################################################################

# KV v2 (несколько путей)
resource "vault_mount" "kv_v2" {
  for_each    = local.kv_mounts
  path        = each.value.path
  type        = "kv"                   # KV v2 через опцию version=2
  description = each.value.description

  options = {
    version = "2"
  }
}

# Transit (опционально)
resource "vault_mount" "transit" {
  count       = var.transit.enabled ? 1 : 0
  path        = var.transit.path
  type        = "transit"
  description = var.transit.description
}

###############################################################################
# ПОЛИТИКИ
###############################################################################

resource "vault_policy" "this" {
  for_each = var.policies
  name     = "${local.policy_name}-${each.key}"
  policy   = each.value
}

###############################################################################
# KUBERNETES AUTH
###############################################################################

# Backend (если включен)
resource "vault_auth_backend" "kubernetes" {
  count = var.kubernetes_auth.enabled ? 1 : 0
  type  = "kubernetes"
  path  = var.kubernetes_auth.path
  tune {
    default_lease_ttl  = "0s"
    max_lease_ttl      = "0s"
    listing_visibility = "unauth"
    description        = "Kubernetes auth for ${var.name_prefix}"
  }
}

# Конфигурация backend
resource "vault_kubernetes_auth_backend_config" "kube" {
  count                 = var.kubernetes_auth.enabled ? 1 : 0
  backend               = vault_auth_backend.kubernetes[0].path
  kubernetes_host       = var.kubernetes_auth.host
  kubernetes_ca_cert    = var.kubernetes_auth.kubernetes_ca_cert
  token_reviewer_jwt    = var.kubernetes_auth.token_reviewer_jwt
  issuer                = coalesce(var.kubernetes_auth.issuer, "")
  disable_iss_validation = var.kubernetes_auth.issuer == null

  depends_on = [vault_auth_backend.kubernetes]
}

# Роли для service accounts
resource "vault_kubernetes_auth_backend_role" "roles" {
  for_each   = var.kubernetes_auth.enabled ? var.kubernetes_auth.roles : {}
  backend    = vault_auth_backend.kubernetes[0].path
  role_name  = each.key

  bound_service_account_names      = each.value.service_accounts
  bound_service_account_namespaces = each.value.namespaces

  token_policies = [
    for p in each.value.token_policies : (
      try(vault_policy.this[p].name, p)
    )
  ]

  token_ttl = each.value.token_ttl

  # audience (опционально)
  audience = try(each.value.audience, null)

  depends_on = [vault_kubernetes_auth_backend_config.kube]
}

###############################################################################
# JWT / OIDC AUTH
###############################################################################

resource "vault_jwt_auth_backend" "oidc" {
  count               = var.oidc_auth.enabled ? 1 : 0
  path                = var.oidc_auth.path
  bound_issuer        = var.oidc_auth.bound_issuer
  oidc_discovery_url  = var.oidc_auth.oidc_discovery_url
  default_role        = var.oidc_auth.default_role

  tune {
    default_lease_ttl  = "0s"
    max_lease_ttl      = "0s"
    listing_visibility = "unauth"
    description        = "OIDC/JWT auth for ${var.name_prefix}"
  }
}

resource "vault_jwt_auth_backend_role" "oidc_roles" {
  for_each     = var.oidc_auth.enabled ? var.oidc_auth.roles : {}
  backend      = vault_jwt_auth_backend.oidc[0].path
  role_name    = each.value.role_name

  user_claim      = each.value.user_claim
  bound_audiences = each.value.bound_audiences
  token_ttl       = each.value.token_ttl
  token_policies  = [
    for p in each.value.token_policies : (
      try(vault_policy.this[p].name, p)
    )
  ]
  allowed_redirect_uris = each.value.allowed_redirect_uris

  claim_mappings = try(each.value.claim_mappings, null)
  groups_claim   = try(each.value.groups_claim, null)
  bound_subject  = try(each.value.bound_subject, null)

  depends_on = [vault_jwt_auth_backend.oidc]
}

###############################################################################
# APPROLE AUTH
###############################################################################

resource "vault_auth_backend" "approle" {
  count = var.approle_auth.enabled ? 1 : 0
  type  = "approle"
  path  = var.approle_auth.path

  tune {
    default_lease_ttl  = "0s"
    max_lease_ttl      = "0s"
    listing_visibility = "unauth"
    description        = "AppRole auth for ${var.name_prefix}"
  }
}

resource "vault_approle_auth_backend_role" "approle_roles" {
  for_each = var.approle_auth.enabled ? var.approle_auth.roles : {}
  backend  = vault_auth_backend.approle[0].path
  role_name = each.key

  token_policies = [
    for p in each.value.token_policies : (
      try(vault_policy.this[p].name, p)
    )
  ]
  token_ttl = each.value.token_ttl

  bind_secret_id      = try(each.value.bind_secret_id, true)
  secret_id_ttl       = try(each.value.secret_id_ttl, null)
  secret_id_num_uses  = try(each.value.secret_id_num_uses, null)

  depends_on = [vault_auth_backend.approle]
}

# role_id можно безопасно выводить; secret_id — нет.
data "vault_approle_auth_backend_role_id" "approle_role_ids" {
  for_each = var.approle_auth.enabled ? var.approle_auth.roles : {}
  backend  = vault_auth_backend.approle[0].path
  role_name = each.key

  depends_on = [vault_approle_auth_backend_role.approle_roles]
}

###############################################################################
# АУДИТ (ОПЦИОНАЛЬНО, ВКЛЮЧАЙТЕ ТОЛЬКО ЕСЛИ ПОНИМАЕТЕ РИСКИ)
###############################################################################

resource "vault_audit" "this" {
  count       = var.audit.enabled ? 1 : 0
  type        = var.audit.type
  path        = var.audit.path
  description = try(var.audit.description, null)

  options = var.audit.options
}

###############################################################################
# ВЫХОДЫ (НЕ ВОЗВРАЩАЮТ СЕКРЕТЫ)
###############################################################################

output "kv_v2_paths" {
  description = "Смонтированные KV v2 пути."
  value       = [for m in vault_mount.kv_v2 : m.path]
}

output "transit_path" {
  description = "Путь Transit (если включен), иначе null."
  value       = try(vault_mount.transit[0].path, null)
}

output "policies_created" {
  description = "Список созданных политик."
  value       = [for p in vault_policy.this : p.name]
}

output "kubernetes_backend_path" {
  description = "Путь Kubernetes‑аутентификации или null."
  value       = var.kubernetes_auth.enabled ? vault_auth_backend.kubernetes[0].path : null
}

output "oidc_backend_path" {
  description = "Путь OIDC/JWT‑аутентификации или null."
  value       = var.oidc_auth.enabled ? vault_jwt_auth_backend.oidc[0].path : null
}

output "approle_backend_path" {
  description = "Путь AppRole‑аутентификации или null."
  value       = var.approle_auth.enabled ? vault_auth_backend.approle[0].path : null
}

output "approle_role_ids" {
  description = "role_id для AppRole‑ролей (не секрет)."
  value = var.approle_auth.enabled ? {
    for k, v in data.vault_approle_auth_backend_role_id.approle_role_ids : k => v.role_id
  } : {}
  sensitive = false
}
