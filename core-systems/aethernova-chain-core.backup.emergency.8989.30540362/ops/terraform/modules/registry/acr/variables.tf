// aethernova-chain-core/ops/terraform/modules/registry/acr/variables.tf
// Переменные модуля Azure Container Registry (ACR).
// Консервативные дефолты: приватность, отсутствие публичного доступа,
// строгие валидации и расширяемые объекты для сети/шифрования/аудита.

// ----------------------------------------------------------------------------
// БАЗОВЫЕ ПАРАМЕТРЫ РЕСУРСА
// ----------------------------------------------------------------------------

variable "name" {
  type        = string
  description = "Имя ACR (уникально в пределах Azure; допустимы строчные буквы и цифры, 5–50 символов)."
}

variable "resource_group_name" {
  type        = string
  description = "Имя Resource Group, где будет создан реестр."
}

variable "location" {
  type        = string
  description = "Регион Azure, в котором создаётся ACR (напр., westeurope)."
}

variable "sku" {
  type        = string
  description = "SKU реестра: Basic | Standard | Premium."
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.sku)
    error_message = "sku должен быть одним из: Basic, Standard, Premium."
  }
}

variable "tags" {
  type        = map(string)
  description = "Теги для ACR и сопутствующих ресурсов."
  default     = {}
}

// ----------------------------------------------------------------------------
// ДОСТУП И АДМИНИСТРИРОВАНИЕ
// ----------------------------------------------------------------------------

variable "admin_enabled" {
  type        = bool
  description = "Включить админ-пользователя реестра (логин/пароль). По умолчанию выключено."
  default     = false
}

variable "public_network_access_enabled" {
  type        = bool
  description = "Разрешить публичный сетевой доступ к ACR. Для максимально закрытой конфигурации оставить false."
  default     = false
}

variable "data_endpoint_enabled" {
  type        = bool
  description = "Включить отдельную data-plane конечную точку (обычно для Premium)."
  default     = false
}

variable "zone_redundancy_enabled" {
  type        = bool
  description = "Зональная отказоустойчивость (доступно не во всех регионах; обычно Premium)."
  default     = false
}

// ----------------------------------------------------------------------------
// СЕТЬ И ДОСТУП (Firewall / VNet rules / Private Link)
// ----------------------------------------------------------------------------

variable "network_rule_set" {
  description = <<EOT
Правила сетевого доступа к ACR.
- default_action: Allow | Deny (рекомендуется: Deny)
- ip_rules: список IP/CIDR, которым явно разрешён доступ
- subnet_ids: список ID подсетей (VNet), которым разрешён доступ
EOT
  type = object({
    default_action = string
    ip_rules       = optional(list(string), [])
    subnet_ids     = optional(list(string), [])
  })
  default = {
    default_action = "Deny"
    ip_rules       = []
    subnet_ids     = []
  }
  validation {
    condition     = contains(["Allow", "Deny"], var.network_rule_set.default_action)
    error_message = "network_rule_set.default_action должен быть Allow или Deny."
  }
}

variable "private_endpoints" {
  description = <<EOT
Список Private Endpoint для приватного доступа к ACR.
Каждый объект:
- name: имя приватной конечной точки
- subnet_id: ID подсети для размещения Private Endpoint
- private_dns_zone_ids: список Private DNS Zone для автоматической регистрации A records
EOT
  type = list(object({
    name                 = string
    subnet_id            = string
    private_dns_zone_ids = optional(list(string), [])
  }))
  default = []
}

// ----------------------------------------------------------------------------
// ШИФРОВАНИЕ И ИДЕНТИЧНОСТЬ
// ----------------------------------------------------------------------------

variable "encryption" {
  description = <<EOT
Настройки шифрования.
- enabled: включить использование customer-managed key (CMK)
- key_vault_key_id: ID ключа в Azure Key Vault (формат: https://{kv}.vault.azure.net/keys/{name}/{version})
- user_assigned_identity_client_id: client_id управляемой идентичности (если требуется для доступа к KV)
EOT
  type = object({
    enabled                           = bool
    key_vault_key_id                  = optional(string)
    user_assigned_identity_client_id  = optional(string)
  })
  default = {
    enabled = false
  }
  validation {
    condition = (
      var.encryption.enabled == false
      || (var.encryption.enabled == true && try(length(var.encryption.key_vault_key_id) > 0, false))
    )
    error_message = "Если encryption.enabled = true, необходимо указать encryption.key_vault_key_id."
  }
}

variable "identity" {
  description = <<EOT
Управляемые идентичности для ACR.
- type: SystemAssigned | UserAssigned | SystemAssigned,UserAssigned
- user_assigned_identity_ids: список ID UAMI (Identity Resource ID)
EOT
  type = object({
    type                         = string
    user_assigned_identity_ids   = optional(list(string), [])
  })
  default = {
    type = "SystemAssigned"
    user_assigned_identity_ids = []
  }
  validation {
    condition     = contains(["SystemAssigned","UserAssigned","SystemAssigned,UserAssigned"], var.identity.type)
    error_message = "identity.type должен быть одним из: SystemAssigned | UserAssigned | SystemAssigned,UserAssigned."
  }
}

// ----------------------------------------------------------------------------
// ГЕОРЕПЛИКАЦИИ
// ----------------------------------------------------------------------------

variable "georeplications" {
  description = <<EOT
Список регионов для георепликации (доступно для Premium).
Каждый объект:
- location: регион (напр., northeurope)
- regional_endpoint_enabled: включать региональную data-plane конечную точку
- zone_redundancy_enabled: включать зонирование в данном регионе
- tags: теги для реплик (опционально)
EOT
  type = list(object({
    location                  = string
    regional_endpoint_enabled = optional(bool, false)
    zone_redundancy_enabled   = optional(bool, false)
    tags                      = optional(map(string), {})
  }))
  default = []
}

// ----------------------------------------------------------------------------
// ПОЛИТИКИ, ЧИСТКА И ПРЕОБРАЗОВАНИЕ СТАРЫХ ОБЪЕКТОВ
// ----------------------------------------------------------------------------

variable "retention_policies" {
  description = <<EOT
Политики ретенции на уровне репозиториев (используются вспомогательными ресурсами/скриптами).
Список объектов:
- repository_regex: регулярное выражение для выбора репозиториев
- days: количество дней хранения
- untagged_only: применять только к untagged артефактам
EOT
  type = list(object({
    repository_regex = string
    days             = number
    untagged_only    = optional(bool, true)
  }))
  default = []
}

variable "task_purge" {
  description = <<EOT
Параметры регулярной очистки (если используется отдельной автоматизацией).
- enabled: включить генерацию job/скриптов purge
- schedule_cron: cron-расписание (если используется в orchestration слое)
EOT
  type = object({
    enabled       = bool
    schedule_cron = optional(string)
  })
  default = {
    enabled = false
  }
}

// ----------------------------------------------------------------------------
// DIAGNOSTICS (ЛОГИ И МЕТРИКИ)
// ----------------------------------------------------------------------------

variable "diagnostic_settings" {
  description = <<EOT
Отправка диагностических логов/метрик ACR.
- enabled: включить diagnostic settings
- destination_type: log_analytics | storage | eventhub
- destination_id: ID назначения (Workspace ID / Storage Account ID / Event Hub Auth Rule ID)
- logs: список категорий логов (напр., ["ContainerRegistryRepositoryEvents","ContainerRegistryLoginEvents"])
- metrics: список категорий метрик (обычно ["AllMetrics"])
EOT
  type = object({
    enabled          = bool
    destination_type = optional(string)
    destination_id   = optional(string)
    logs             = optional(list(string), [])
    metrics          = optional(list(string), [])
  })
  default = {
    enabled = false
    logs    = []
    metrics = []
  }
  validation {
    condition = (
      var.diagnostic_settings.enabled == false
      || (
        var.diagnostic_settings.enabled == true
        && try(length(var.diagnostic_settings.destination_type) > 0 && length(var.diagnostic_settings.destination_id) > 0, false)
      )
    )
    error_message = "Если diagnostic_settings.enabled = true, необходимо указать destination_type и destination_id."
  }
}

// ----------------------------------------------------------------------------
// RBAC (дополнительные назначения ролей на реестр)
// ----------------------------------------------------------------------------

variable "rbac_assignments" {
  description = <<EOT
Список RBAC назначений для ACR (используется вспомогательными ресурсами).
Каждый объект:
- principal_id: объектная ID пользователя/группы/сервис-принципала/Managed Identity
- role_definition_id_or_name: полная ID роли или имя (напр., AcrPull, AcrPush, Owner и т.п.)
- condition, condition_version: опциональные поля для условных назначений (Azure RBAC Conditions)
EOT
  type = list(object({
    principal_id                  = string
    role_definition_id_or_name    = string
    condition                     = optional(string)
    condition_version             = optional(string)
  }))
  default = []
}

// ----------------------------------------------------------------------------
// ФЛАГИ БЕЗОПАСНОГО УДАЛЕНИЯ
// ----------------------------------------------------------------------------

variable "lock_level" {
  type        = string
  description = "Уровень management lock: None | CanNotDelete | ReadOnly (применяется к ACR и, опционально, к Private Endpoint)."
  default     = "None"
  validation {
    condition     = contains(["None", "CanNotDelete", "ReadOnly"], var.lock_level)
    error_message = "lock_level должен быть одним из: None, CanNotDelete, ReadOnly."
  }
}

variable "force_destroy" {
  type        = bool
  description = "Принудительное удаление артефактов/связанных ресурсов при уничтожении (использовать с осторожностью, реализуется на уровне orchestration)."
  default     = false
}

// ----------------------------------------------------------------------------
// ВСПОМОГАТЕЛЬНЫЕ / ТЕХНИЧЕСКИЕ
// ----------------------------------------------------------------------------

variable "name_prefix" {
  type        = string
  description = "Необязательный префикс для связанных ресурсов (PE, Diagnostics и т.д.)."
  default     = ""
}

variable "extra_labels" {
  type        = map(string)
  description = "Дополнительные метки/лейблы для вспомогательных ресурсов (например, Diagnostics)."
  default     = {}
}

variable "timeouts" {
  description = <<EOT
Таймауты операций создания/обновления/удаления (используются в ресурсах модуля).
Задаются в формате Terraform duration (напр., '60m').
EOT
  type = object({
    create = optional(string, "60m")
    update = optional(string, "60m")
    delete = optional(string, "60m")
  })
  default = {
    create = "60m"
    update = "60m"
    delete = "60m"
  }
}
