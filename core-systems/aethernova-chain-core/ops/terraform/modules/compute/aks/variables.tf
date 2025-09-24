############################################################
# AKS — VARIABLES (industrial-grade)
# Terraform >= 1.3+ (используются optional() в object)
############################################################

variable "resource_group_name" {
  description = "Имя ресурcной группы Azure, где создаётся AKS."
  type        = string
}

variable "location" {
  description = "Регион Azure (например, westeurope)."
  type        = string
}

variable "cluster_name" {
  description = "Имя AKS-кластера."
  type        = string
}

variable "kubernetes_version" {
  description = "Версия Kubernetes для control plane (например, 1.29.x)."
  type        = string
  default     = null
}

variable "dns_prefix" {
  description = "DNS prefix для API сервера (публичный сценарий)."
  type        = string
  default     = null
}

variable "node_resource_group" {
  description = "Имя отдельной RG для узлов/инфраструктуры AKS; если null — создаётся автоматически."
  type        = string
  default     = null
}

variable "tags" {
  description = "Набор тегов для всех создаваемых ресурсов."
  type        = map(string)
  default     = {}
}

# ---- SKU Tier (см. актуальные уровни AKS cluster management) ----
variable "sku_tier" {
  description = "Уровень кластера AKS: Free | Standard | Premium."
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Free", "Standard", "Premium"], var.sku_tier)
    error_message = "sku_tier должен быть одним из: Free, Standard, Premium."
  }
}

# ---- RBAC и Entra ID (AAD) ----
variable "role_based_access_control_enabled" {
  description = "Включить Kubernetes RBAC."
  type        = bool
  default     = true
}

variable "azure_rbac_enabled" {
  description = "Включить Azure RBAC для Kubernetes (Entra ID RBAC поверх K8s RBAC)."
  type        = bool
  default     = false
}

variable "admin_group_object_ids" {
  description = "Список Object ID групп Entra ID, которым выдать админ-доступ к кластеру."
  type        = set(string)
  default     = []
}

variable "local_account_disabled" {
  description = "Отключить локальные учётные записи администратора кластера (рекомендуется для прод)."
  type        = bool
  default     = true
}

# ---- Идентичность кластера ----
variable "identity" {
  description = <<EOT
Идентичность кластера:
  type: "SystemAssigned" | "UserAssigned"
  user_assigned_identity_id: ID user-assigned identity (для типа UserAssigned)
EOT
  type = object({
    type                        = string
    user_assigned_identity_id   = optional(string, null)
  })
  default = {
    type = "SystemAssigned"
  }
  validation {
    condition     = contains(["SystemAssigned", "UserAssigned"], var.identity.type)
    error_message = "identity.type должен быть: SystemAssigned или UserAssigned."
  }
}

# ---- Workload Identity / OIDC ----
variable "oidc_issuer_enabled" {
  description = "Включить OIDC issuer у кластера (требуется для Azure AD Workload Identity)."
  type        = bool
  default     = true
}

variable "workload_identity_enabled" {
  description = "Включить Azure AD Workload Identity (замена AAD Pod Identity)."
  type        = bool
  default     = true
}

# ---- Приватность API и авторизованные IP ----
variable "private_cluster_enabled" {
  description = "Сделать кластер приватным (API только по приватному адресу)."
  type        = bool
  default     = true
}

variable "private_dns_zone_id" {
  description = "ID частной DNS-зоны для приватного кластера (BYO Private DNS Zone)."
  type        = string
  default     = null
}

variable "api_server_access_profile" {
  description = <<EOT
Профиль доступа к API серверу:
  authorized_ip_ranges   — набор CIDR для доступа к API (для публичного эндпойнта);
  vnet_integration_enabled — публикация API в делегированной подсети (API Server VNet Integration);
  subnet_id              — подсеть для интеграции API (если используется Integration).
EOT
  type = object({
    authorized_ip_ranges    = optional(set(string), null)
    vnet_integration_enabled = optional(bool, false)
    subnet_id               = optional(string, null)
  })
  default = {}
}

# ---- Сетевой профиль ----
variable "network_profile" {
  description = <<EOT
Сетевой профиль AKS:
  network_plugin       — "azure" (Azure CNI) или "kubenet";
  network_plugin_mode  — "overlay" только с Azure CNI (Azure CNI Overlay);
  network_policy       — "azure" или "calico" (если поддерживается выбранным плагином);
  service_cidr         — CIDR для ClusterIP сервисов;
  dns_service_ip       — IP DNS-сервиса внутри service_cidr;
  docker_bridge_cidr   — CIDR для docker bridge;
  outbound_type        — "loadBalancer" | "userDefinedRouting";
  load_balancer_sku    — "standard";
  pod_cidr             — CIDR для Pod (обычно для kubenet; при overlay — отдельный приватный CIDR).
EOT
  type = object({
    network_plugin       = string
    network_plugin_mode  = optional(string, null)
    network_policy       = optional(string, null)
    service_cidr         = optional(string, null)
    dns_service_ip       = optional(string, null)
    docker_bridge_cidr   = optional(string, null)
    outbound_type        = optional(string, null)
    load_balancer_sku    = optional(string, "standard")
    pod_cidr             = optional(string, null)
  })
  default = {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
  }
  validation {
    condition = contains(["azure", "kubenet"], var.network_profile.network_plugin)
    error_message = "network_profile.network_plugin должен быть azure или kubenet."
  }
}

# ---- Канал авто-обновлений control plane (смотрите заметки провайдера) ----
variable "automatic_channel_upgrade" {
  description = "Канал авто-обновлений: stable | rapid | patch | node-image (имя может отличаться в провайдере v4+)."
  type        = string
  default     = null
  validation {
    condition     = var.automatic_channel_upgrade == null || contains(["stable", "rapid", "patch", "node-image"], var.automatic_channel_upgrade)
    error_message = "automatic_channel_upgrade: допустимы stable, rapid, patch, node-image или null."
  }
}

# ---- Аддоны ----
variable "azure_policy_enabled" {
  description = "Включить интеграцию с Azure Policy (addon_profile.azure_policy)."
  type        = bool
  default     = false
}

variable "oms_agent" {
  description = "Логирование в Log Analytics (OMS agent)."
  type = object({
    enabled                     = bool
    log_analytics_workspace_id  = optional(string, null)
  })
  default = {
    enabled = false
  }
}

variable "key_vault_secrets_provider" {
  description = "Secrets Store CSI Driver — Azure Key Vault provider (ротация секретов)."
  type = object({
    secret_rotation_enabled  = optional(bool, false)
    secret_rotation_interval = optional(string, null) # например, \"2m\", \"24h\"
  })
  default = {}
}

# ---- СИСТЕМНЫЙ (DEFAULT) NODE POOL ----
variable "default_node_pool" {
  description = <<EOT
Системный пул узлов:
  name                 — имя пула (3–12 строчных букв/цифр);
  vm_size              — SKU ВМ для узлов;
  node_count           — фиксированное число узлов (если autoscaling выключен);
  enable_auto_scaling  — включить авто-масштабирование;
  min_count/max_count  — пределы для авто-масштабирования;
  vnet_subnet_id       — подсеть для узлов;
  max_pods             — лимит Pod на узел;
  os_disk_size_gb      — размер OS-диска (ГБ);
  os_disk_type         — Managed | Ephemeral;
  orchestrator_version — версия k8s для пула (обычно совпадает с версией кластера);
  availability_zones   — список зон для зоны-резервирования (например, [\"1\",\"2\",\"3\"]);
  node_labels          — метки узлов;
  node_taints          — таинты узлов.
EOT
  type = object({
    name                 = string
    vm_size              = string
    node_count           = optional(number, null)
    enable_auto_scaling  = optional(bool, true)
    min_count            = optional(number, 1)
    max_count            = optional(number, 3)
    vnet_subnet_id       = string
    max_pods             = optional(number, null)
    os_disk_size_gb      = optional(number, 128)
    os_disk_type         = optional(string, "Managed")
    orchestrator_version = optional(string, null)
    availability_zones   = optional(list(string), null)
    node_labels          = optional(map(string), {})
    node_taints          = optional(list(string), [])
  })
}

# ---- ДОПОЛНИТЕЛЬНЫЕ NODE POOLS (User) ----
variable "node_pools" {
  description = <<EOT
Карта дополнительных пулов (User):
  ключ                 — логическое имя пула;
  value:
    name, vm_size, mode ("System"|"User"), node_count/auto-scaling,
    vnet_subnet_id/pod_subnet_id (при overlay),
    max_pods, os_disk_size_gb, os_disk_type (Managed|Ephemeral),
    orchestrator_version, availability_zones, node_labels, node_taints,
    enable_host_encryption, ultra_ssd_enabled, fips_enabled, spot_max_price.
EOT
  type = map(object({
    name                 = string
    vm_size              = string
    mode                 = optional(string, "User")
    node_count           = optional(number, null)
    enable_auto_scaling  = optional(bool, true)
    min_count            = optional(number, 1)
    max_count            = optional(number, 3)
    vnet_subnet_id       = optional(string, null)
    pod_subnet_id        = optional(string, null) # для Azure CNI Overlay
    max_pods             = optional(number, null)
    os_disk_size_gb      = optional(number, 128)
    os_disk_type         = optional(string, "Managed")
    orchestrator_version = optional(string, null)
    availability_zones   = optional(list(string), null)
    node_labels          = optional(map(string), {})
    node_taints          = optional(list(string), [])
    enable_host_encryption = optional(bool, false)
    ultra_ssd_enabled      = optional(bool, false)
    fips_enabled           = optional(bool, false)
    spot_max_price         = optional(number, null) # для Spot-пулов
  }))
  default = {}
}

# ---- Диагностика/метаданные вывода из модуля ----
variable "enable_outputs_diagnostics" {
  description = "Включить расширенные вычисления сводных output-значений (если реализовано в модуле)."
  type        = bool
  default     = true
}
