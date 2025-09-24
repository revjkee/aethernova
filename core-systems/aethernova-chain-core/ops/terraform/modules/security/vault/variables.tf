#############################################
# aethernova-chain-core/ops/terraform/modules/security/vault/variables.tf
#############################################

############################
# Базовые параметры
############################
variable "enabled" {
  description = "Включить создание и/или конфигурацию Vault в данном модуле."
  type        = bool
  default     = true
}

variable "name" {
  description = "Имя (префикс) кластера/инсталляции Vault, используется в именовании ресурсов."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{3,64}$", var.name))
    error_message = "name должен соответствовать ^[a-z0-9-]{3,64}$."
  }
}

variable "environment" {
  description = "Среда (dev|stage|prod)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "environment должен быть одним из: dev, stage, prod."
  }
}

variable "tags" {
  description = "Произвольные теги для ресурсов (если применимо)."
  type        = map(string)
  default     = {}
}

############################
# Режим интеграции / деплоя
############################
variable "deployment_mode" {
  description = "Способ использования Vault: external (уже развернут), kubernetes (через Helm/оператор), vm (ВМ/бинарь)."
  type        = string
  default     = "external"

  validation {
    condition     = contains(["external", "kubernetes", "vm"], var.deployment_mode)
    error_message = "deployment_mode должен быть external|kubernetes|vm."
  }
}

############################
# Подключение к уже работающему Vault (deployment_mode=external)
############################
variable "vault_address" {
  description = "Базовый адрес Vault (например, https://vault.example.com:8200) для управления через провайдер."
  type        = string
  default     = null

  validation {
    condition     = var.vault_address == null || can(regex("^https?://", var.vault_address))
    error_message = "vault_address должен начинаться с http:// или https://."
  }
}

variable "vault_namespace" {
  description = "Enterprise Namespace (если используется Vault Enterprise)."
  type        = string
  default     = null
}

variable "vault_token" {
  description = "Токен администратора/оператора для управления (использовать строго секретное хранилище)."
  type        = string
  sensitive   = true
  default     = null
}

############################
# TLS/MTLS (для собственного деплоя или внешнего подключения)
############################
variable "tls" {
  description = "TLS/MTLS параметры для Vault. Не храните приватные ключи в состоянии без необходимости."
  type = object({
    enabled           = optional(bool, true)
    cert_pem          = optional(string)          # Публичный сертификат (PEM)
    key_pem           = optional(string)          # Приватный ключ (PEM)
    ca_chain_pem      = optional(list(string))    # Цепочка CA (PEM)
    require_client_mt = optional(bool, false)     # Требовать mTLS от клиентов
  })
  sensitive = true
  default   = {}
}

############################
# Авто-ансил / unseal
############################
variable "unseal_method" {
  description = "Метод unseal: shamir | awskms | azurekeyvault | gcpckms | transit."
  type        = string
  default     = "shamir"

  validation {
    condition     = contains(["shamir", "awskms", "azurekeyvault", "gcpckms", "transit"], var.unseal_method)
    error_message = "unseal_method должен быть одним из: shamir, awskms, azurekeyvault, gcpckms, transit."
  }
}

variable "awskms_unseal" {
  description = "Параметры авто-ансила через AWS KMS."
  type = object({
    region                = optional(string)
    kms_key_id            = optional(string)
    endpoint              = optional(string)
    access_key_id         = optional(string)
    secret_access_key     = optional(string)
    role_arn              = optional(string)
    sts_region            = optional(string)
    assume_role_external  = optional(bool, false)
  })
  sensitive = true
  default   = {}
}

variable "azurekeyvault_unseal" {
  description = "Параметры авто-ансила через Azure Key Vault."
  type = object({
    key_vault_uri     = optional(string) # https://<vault-name>.vault.azure.net/
    key_name          = optional(string)
    key_version       = optional(string)
    tenant_id         = optional(string)
    client_id         = optional(string)
    client_secret     = optional(string)
  })
  sensitive = true
  default   = {}
}

variable "gcpckms_unseal" {
  description = "Параметры авто-ансила через Google Cloud KMS."
  type = object({
    project      = optional(string)
    location     = optional(string)
    key_ring     = optional(string)
    crypto_key   = optional(string)
    credentials  = optional(string) # JSON содержимое сервис-аккаунта
  })
  sensitive = true
  default   = {}
}

variable "transit_unseal" {
  description = "Параметры авто-ансила через удалённый Vault Transit (bring-your-own KMS)."
  type = object({
    address     = optional(string) # https://vault-kms.example.com:8200
    token       = optional(string)
    mount_path  = optional(string, "transit")
    key_name    = optional(string)
    namespace   = optional(string)
  })
  sensitive = true
  default   = {}
}

############################
# Аутентификация: включение и параметры
############################
variable "auth_methods" {
  description = "Список включаемых методов аутентификации: approle, kubernetes, oidc."
  type        = set(string)
  default     = ["approle"]

  validation {
    condition     = length(setsubtract(var.auth_methods, toset(["approle", "kubernetes", "oidc"]))) == 0
    error_message = "auth_methods допускает только approle, kubernetes, oidc."
  }
}

variable "auth_approle" {
  description = "Параметры для AppRole auth."
  type = object({
    path              = optional(string, "approle")
    token_policies    = optional(set(string), [])
    secret_id_ttl     = optional(string, "24h")
    token_ttl         = optional(string, "1h")
    token_max_ttl     = optional(string, "24h")
    bind_secret_id    = optional(bool, true)
  })
  default = {}
}

variable "auth_kubernetes" {
  description = "Параметры для Kubernetes auth."
  type = object({
    path                 = optional(string, "kubernetes")
    kubernetes_host      = optional(string)
    kubernetes_ca_cert   = optional(string)
    token_reviewer_jwt   = optional(string)
    issuer               = optional(string)
    disable_iss_validation = optional(bool, false)
    default_role         = optional(string, "default")
  })
  sensitive = true
  default   = {}
}

variable "auth_oidc" {
  description = "Параметры для OIDC/OAuth2 auth."
  type = object({
    path                = optional(string, "oidc")
    default_role        = optional(string, "default")
    discovery_url       = optional(string)
    client_id           = optional(string)
    client_secret       = optional(string)
    bound_audiences     = optional(list(string))
    allowed_redirect_uris = optional(list(string))
    claim_mappings      = optional(map(string))
  })
  sensitive = true
  default   = {}
}

############################
# Секрет-энджины и политики
############################
variable "kv_v2_mounts" {
  description = "Монтирования KV v2: карта { path => { description, max_versions, cas_required } }."
  type = map(object({
    description  = optional(string, "")
    max_versions = optional(number, 10)
    cas_required = optional(bool, false)
  }))
  default = {}
}

variable "transit_keys" {
  description = "Ключи Transit: карта { name => { type, convergent, derived, exportable, allow_plaintext_backup } }."
  type = map(object({
    type                     = optional(string, "aes256-gcm96")
    convergent_encryption    = optional(bool, false)
    derived                  = optional(bool, false)
    exportable               = optional(bool, false)
    allow_plaintext_backup   = optional(bool, false)
  }))
  default = {}
}

variable "policies_hcl" {
  description = "Политики Vault в HCL: карта { policy_name => hcl }."
  type        = map(string)
  default     = {}
}

############################
# Аудит
############################
variable "audit" {
  description = "Конфигурация аудита Vault."
  type = object({
    enabled = optional(bool, true)
    sinks   = optional(list(object({
      type    = string              # файл|syslog|socket|stdout|stderr|file|gcs|s3 (конкретный набор зависит от бэкендов/плагинов)
      path    = string              # путь/endpoint/URI
      options = optional(map(string), {}) # произвольные опции sink-а
    })), [])
  })
  default = {}
}

############################
# Сетевая безопасность (пример: ограничения доступа)
############################
variable "allowed_cidrs" {
  description = "Список CIDR, которым разрешён доступ к Vault (если регулируется внешним firewall/SG)."
  type        = list(string)
  default     = []
}

############################
# Тайминги/ретраи (для провайдера/инициализации)
############################
variable "timeouts" {
  description = "Таймауты/ретраи для операций конфигурации (секунды)."
  type = object({
    create = optional(number, 600)
    update = optional(number, 600)
    read   = optional(number, 120)
    delete = optional(number, 600)
    retries = optional(number, 3)
  })
  default = {}
}
