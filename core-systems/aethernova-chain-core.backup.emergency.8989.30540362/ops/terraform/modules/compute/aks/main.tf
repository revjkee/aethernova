############################################################
# aethernova-chain-core/ops/terraform/modules/compute/aks/main.tf
#
# Источники (проверяемые, см. комментарии по блокам):
# - Ресурс AKS (azurerm_kubernetes_cluster), поля OIDC/Workload Identity,
#   приватный кластер, сеть, auto-upgrade канал и т.д.:
#   Terraform Registry (актуальная спецификация ресурса)
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster  # :contentReference[oaicite:0]{index=0}
# - Azure CNI Overlay и экономия IP / dataplane Cilium (концепции):
#   https://learn.microsoft.com/en-us/azure/aks/concepts-network-azure-cni-overlay  # :contentReference[oaicite:1]{index=1}
# - Workload Identity / OIDC в AKS (пример и пояснения):
#   https://github.com/Azure-Samples/aks-workload-identity-terraform  # :contentReference[oaicite:2]{index=2}
#   https://support.hashicorp.com/hc/en-us/articles/34843116127891  # :contentReference[oaicite:3]{index=3}
# - Автоапгрейд AKS (каналы обновлений):
#   https://learn.microsoft.com/en-us/azure/aks/auto-upgrade-cluster  # :contentReference[oaicite:4]{index=4}
# - Log Analytics/Container insights и включение мониторинга:
#   https://learn.microsoft.com/en-us/azure/azure-monitor/containers/kubernetes-monitoring-enable  # :contentReference[oaicite:5]{index=5}
# - Диагностические логи/метрики AKS и категории:
#   https://learn.microsoft.com/en-us/azure/aks/monitor-aks  # :contentReference[oaicite:6]{index=6}
#   https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference  # :contentReference[oaicite:7]{index=7}
#   https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings  # :contentReference[oaicite:8]{index=8}
# - Azure Policy для AKS (вкл. через аргумент azure_policy_enabled):
#   https://www.kristhecodingunicorn.com/post/aks-azure-policy/  # :contentReference[oaicite:9]{index=9}
# - Key Vault Secrets Store CSI Driver rotation (интервалы ротации):
#   https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-configuration-options  # :contentReference[oaicite:10]{index=10}
# - Частный DNS для приватного AKS (System/ID/None — историческая справка):
#   https://registry.terraform.io/providers/hashicorp/azurerm/2.57.0/docs/resources/kubernetes_cluster  # :contentReference[oaicite:11]{index=11}
############################################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      # Закрепляемся на стабильной 4.x ветке провайдера AzureRM.
      # История/изменения 4.x: https://learn.microsoft.com/en-us/azure/developer/terraform/provider-version-history-azurerm-4-0-0-to-current  # :contentReference[oaicite:12]{index=12}
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
}

############################################################
# Входы модуля (production-friendly)
############################################################
variable "name" {
  type        = string
  description = "Базовый префикс ресурсов AKS."
}

variable "location" {
  type        = string
  description = "Регион Azure."
}

variable "resource_group_name" {
  type        = string
  description = "Имя существующей Resource Group. Если не задано и create_rg=true — будет создана."
  default     = null
}

variable "create_rg" {
  type        = bool
  description = "Создавать ли Resource Group."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Глобальные теги."
  default     = {}
}

# Сеть
variable "vnet_subnet_id" {
  type        = string
  description = "ID подсети, где будут узлы AKS. Для Azure CNI / overlay требуется валидная подсеть."
}

variable "network_plugin_mode" {
  type        = string
  description = "Режим плагина сети: null или \"overlay\" для Azure CNI Overlay (экономит IP). См. docs." # :contentReference[oaicite:13]{index=13}
  default     = "overlay"
  validation {
    condition     = var.network_plugin_mode == null || var.network_plugin_mode == "overlay"
    error_message = "network_plugin_mode должен быть null или \"overlay\"."
  }
}

variable "outbound_type" {
  type        = string
  description = "Тип исходящего трафика: loadBalancer или userDefinedRouting."
  default     = "loadBalancer"
  validation {
    condition     = contains(["loadBalancer", "userDefinedRouting"], var.outbound_type)
    error_message = "outbound_type: допустимы loadBalancer или userDefinedRouting."
  }
}

# Приватность API и DNS
variable "private_cluster_enabled" {
  type        = bool
  description = "Включить приватный API-сервер AKS."
  default     = true
}

variable "private_dns_zone_id" {
  type        = string
  description = "ID приватной DNS-зоны для приватного кластера. Если null — используется \"System\" (AKS управляет зоной). См. docs." # :contentReference[oaicite:14]{index=14}
  default     = null
}

# RBAC/Entra ID и Workload Identity
variable "enable_azure_policy" {
  type        = bool
  description = "Включить Azure Policy add-on (рекомендуется)."
  default     = true
}

variable "enable_oidc" {
  type        = bool
  description = "Включить OIDC issuer для кластера (требуется для Workload Identity)."
  default     = true
}

variable "enable_workload_identity" {
  type        = bool
  description = "Включить Azure AD Workload Identity."
  default     = true
}

# Версии/апгрейды
variable "kubernetes_version" {
  type        = string
  description = "Версия Kubernetes (GA). Если пусто — пусть Azure выберет по умолчанию."
  default     = null
}

variable "automatic_channel_upgrade" {
  type        = string
  description = "Канал автоапгрейда: patch | rapid | stable | node-image."
  default     = "patch"
  validation {
    condition     = contains(["patch", "rapid", "stable", "node-image"], var.automatic_channel_upgrade)
    error_message = "automatic_channel_upgrade должен быть одним из: patch, rapid, stable, node-image."
  }
  # Каналы автоапгрейда AKS: см. официальную документацию. :contentReference[oaicite:15]{index=15}
}

# Профиль мониторинга
variable "enable_monitoring" {
  type        = bool
  description = "Разворачивать интеграцию с Log Analytics (Container insights) и Diagnostic Settings."
  default     = true
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Существующий Log Analytics Workspace ID. Если null и enable_monitoring=true — будет создан workspace."
  default     = null
}

# Профиль ключей/секретов
variable "enable_kv_secrets_provider" {
  type        = bool
  description = "Включить Key Vault Secrets Store CSI Driver rotation-поддержку."
  default     = true
}

variable "kv_rotation_interval" {
  type        = string
  description = "Интервал опроса ротации секретов (например, \"5m\", \"2h\"). См. docs."
  default     = "2m"
  # См. rotation polling interval по умолчанию 2 минуты. :contentReference[oaicite:16]{index=16}
}

# Сеть сервиса/подсети кластера
variable "service_cidr" {
  type        = string
  description = "Сервисная CIDR (например, 10.2.0.0/16)."
  default     = "10.2.0.0/16"
}

variable "dns_service_ip" {
  type        = string
  description = "IP kube-dns из service_cidr (например, 10.2.0.10)."
  default     = "10.2.0.10"
}

variable "docker_bridge_cidr" {
  type        = string
  description = "Docker bridge CIDR (например, 172.17.0.1/16)."
  default     = "172.17.0.1/16"
}

# API server authorized ranges
variable "api_server_authorized_ip_ranges" {
  type        = list(string)
  description = "Список разрешённых внешних IP для доступа к API (если кластер не приватный или используется LB outbound)."
  default     = []
}

# SKU, зоны, системный пул узлов
variable "sku_tier" {
  type        = string
  description = "SKU кластера: Free или Paid (SLA)."
  default     = "Paid"
  validation {
    condition     = contains(["Free", "Paid"], var.sku_tier)
    error_message = "sku_tier должен быть Free или Paid."
  }
}

variable "zones" {
  type        = list(string)
  description = "Зоны доступности для системного пула (например, [\"1\",\"2\",\"3\"])."
  default     = ["1", "2", "3"]
}

variable "system_vm_size" {
  type        = string
  description = "Тип VM для системного пула."
  default     = "Standard_D4s_v5"
}

variable "system_min_count" {
  type        = number
  description = "Мин. узлов в системном пуле."
  default     = 3
}

variable "system_max_count" {
  type        = number
  description = "Макс. узлов в системном пуле."
  default     = 10
}

variable "system_max_pods" {
  type        = number
  description = "Максимум подов на узел."
  default     = 110
}

# Linux профиль/SSH
variable "linux_admin_username" {
  type        = string
  description = "Имя администратора для Linux-профиля."
  default     = "aksadmin"
}

variable "ssh_public_key" {
  type        = string
  description = "SSH публичный ключ (RFC4716/OpenSSH) для узлов."
}

############################################################
# Локальные вычисления
############################################################
locals {
  rg_name = var.create_rg ? azurerm_resource_group.this[0].name : var.resource_group_name

  # При BYO private DNS zone Azure требует управляемую идентичность с нужными правами; в этом примере по умолчанию используем System-управление зоной.  # :contentReference[oaicite:17]{index=17}
  effective_private_dns_zone_id = var.private_cluster_enabled ? coalesce(var.private_dns_zone_id, "System") : null

  common_tags = merge({
    Module      = "compute/aks"
    ManagedBy   = "Terraform"
  }, var.tags)
}

############################################################
# Инфраструктура-окружение: Resource Group / Log Analytics
############################################################
resource "azurerm_resource_group" "this" {
  count    = var.create_rg ? 1 : 0
  name     = "${var.name}-rg"
  location = var.location
  tags     = local.common_tags
}

resource "random_id" "dns" {
  byte_length = 4
}

# Создаём Log Analytics Workspace при необходимости
resource "azurerm_log_analytics_workspace" "this" {
  count               = var.enable_monitoring && var.log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.name}-law"
  location            = var.location
  resource_group_name = local.rg_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.common_tags
  # Включение мониторинга/Container insights: см. Azure Monitor docs.  # :contentReference[oaicite:18]{index=18}
}

############################################################
# Кластер AKS
############################################################
resource "azurerm_kubernetes_cluster" "this" {
  name                = "${var.name}-aks"
  location            = var.location
  resource_group_name = local.rg_name
  dns_prefix          = "${var.name}-${random_id.dns.hex}"

  sku_tier                   = var.sku_tier
  kubernetes_version         = var.kubernetes_version
  automatic_channel_upgrade  = var.automatic_channel_upgrade  # каналы: patch/rapid/stable/node-image.  # :contentReference[oaicite:19]{index=19}

  # Приватный API-сервер и приватный DNS
  private_cluster_enabled = var.private_cluster_enabled
  private_dns_zone_id     = local.effective_private_dns_zone_id  # "System" или ID зоны.  # :contentReference[oaicite:20]{index=20}

  # RBAC и Azure Policy
  role_based_access_control_enabled = true
  azure_policy_enabled              = var.enable_azure_policy  # :contentReference[oaicite:21]{index=21}

  # OIDC + Workload Identity
  oidc_issuer_enabled      = var.enable_oidc                  # :contentReference[oaicite:22]{index=22}
  workload_identity_enabled = var.enable_workload_identity    # :contentReference[oaicite:23]{index=23}

  # Сетевой профиль: Azure CNI, dataplane Cilium, overlay при необходимости.
  network_profile {
    network_plugin       = "azure"
    network_plugin_mode  = var.network_plugin_mode            # "overlay" экономит IP.  # :contentReference[oaicite:24]{index=24}
    network_policy       = "azure"
    network_data_plane   = "cilium"                           # dataplane Cilium.  # :contentReference[oaicite:25]{index=25}
    dns_service_ip       = var.dns_service_ip
    service_cidr         = var.service_cidr
    docker_bridge_cidr   = var.docker_bridge_cidr
    outbound_type        = var.outbound_type
    load_balancer_profile {
      managed_outbound_ip_count = 2
    }
  }

  # Системный пул (обязателен)
  default_node_pool {
    name                         = "sysnp"
    vm_size                      = var.system_vm_size
    zones                        = var.zones
    type                         = "VirtualMachineScaleSets"
    enable_auto_scaling          = true
    min_count                    = var.system_min_count
    max_count                    = var.system_max_count
    max_pods                     = var.system_max_pods
    vnet_subnet_id               = var.vnet_subnet_id
    only_critical_addons_enabled = true
    node_labels = {
      "kubernetes.azure.com/mode" = "system"
    }
  }

  # Linux профиль и SSH ключ (для доступа на ноды; требования к ssh_key отражены в Registry)
  # См. ssh_key в linux_profile.  # :contentReference[oaicite:26]{index=26}
  linux_profile {
    admin_username = var.linux_admin_username
    ssh_key {
      key_data = var.ssh_public_key
    }
  }

  # Интеграция с Log Analytics через OMS агент (Container insights)
  # Подробности включения мониторинга — Azure Monitor docs.  # :contentReference[oaicite:27]{index=27}
  dynamic "oms_agent" {
    for_each = var.enable_monitoring ? [1] : []
    content {
      log_analytics_workspace_id = coalesce(var.log_analytics_workspace_id, azurerm_log_analytics_workspace.this[0].id)
    }
  }

  # Key Vault Secrets Store CSI Driver rotation (интервалы) — см. docs.  # :contentReference[oaicite:28]{index=28}
  dynamic "key_vault_secrets_provider" {
    for_each = var.enable_kv_secrets_provider ? [1] : []
    content {
      secret_rotation_enabled  = true
      secret_rotation_interval = var.kv_rotation_interval
    }
  }

  # Авторизованные IP для API, если заданы
  api_server_access_profile {
    authorized_ip_ranges = var.api_server_authorized_ip_ranges
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

############################################################
# User-пул (пример; можно отключить, передав count = 0 через переменную)
############################################################
variable "create_user_pool" {
  type        = bool
  description = "Создавать ли user-пул."
  default     = true
}

variable "user_pool_vm_size" {
  type        = string
  description = "Тип VM для user-пула."
  default     = "Standard_D8s_v5"
}

variable "user_pool_min" { type = number, default = 3 }
variable "user_pool_max" { type = number, default = 30 }
variable "user_pool_max_pods" { type = number, default = 110 }

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  count                = var.create_user_pool ? 1 : 0
  name                 = "usernp"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size              = var.user_pool_vm_size
  zones                = var.zones
  node_labels = {
    "workload" = "user"
  }
  enable_auto_scaling = true
  min_count           = var.user_pool_min
  max_count           = var.user_pool_max
  max_pods            = var.user_pool_max_pods
  mode                = "User"
  vnet_subnet_id      = var.vnet_subnet_id
  orchestrator_version = var.kubernetes_version
  tags                = local.common_tags
}

############################################################
# Diagnostic Settings: контрольные логи control plane и метрики
# Категории лога/метрик и рекомендации — см. AKS monitoring docs.
#   - Мониторинг AKS: https://learn.microsoft.com/en-us/azure/aks/monitor-aks             # :contentReference[oaicite:29]{index=29}
#   - Справочник данных мониторинга AKS: https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference  # :contentReference[oaicite:30]{index=30}
#   - Общие сведения о Diagnostic Settings: https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings  # :contentReference[oaicite:31]{index=31}
############################################################
resource "azurerm_monitor_diagnostic_setting" "aks" {
  count                      = var.enable_monitoring ? 1 : 0
  name                       = "${var.name}-diag"
  target_resource_id         = azurerm_kubernetes_cluster.this.id
  log_analytics_workspace_id = coalesce(var.log_analytics_workspace_id, azurerm_log_analytics_workspace.this[0].id)

  # Примеры важных категорий control-plane (доступность зависит от региона/версии API):
  enabled_log { category = "kube-apiserver" }
  enabled_log { category = "kube-controller-manager" }
  enabled_log { category = "kube-scheduler" }
  enabled_log { category = "cluster-autoscaler" }
  enabled_log { category = "kube-audit" }

  metric { category = "AllMetrics" }
}

############################################################
# Валидации
############################################################
locals {
  _monitor_ws_needed = var.enable_monitoring && var.log_analytics_workspace_id == null
}

# Если включён мониторинг и не задан существующий Workspace — должен быть создан ресурсная группа (или передано существующее имя)
validation {
  condition     = !(var.enable_monitoring && var.log_analytics_workspace_id == null && local.rg_name == null)
  error_message = "Для enable_monitoring=true нужен существующий log_analytics_workspace_id или create_rg=true/существующая RG."
}

############################################################
# Выходы
############################################################
output "resource_group_name" {
  value       = local.rg_name
  description = "Имя RG с кластером."
}

output "aks_id" {
  value       = azurerm_kubernetes_cluster.this.id
  description = "ID кластера AKS."
}

output "aks_name" {
  value       = azurerm_kubernetes_cluster.this.name
  description = "Имя кластера AKS."
}

output "oidc_issuer_url" {
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
  description = "OIDC Issuer URL (для Workload Identity)."
}

output "kube_config" {
  value = {
    host     = azurerm_kubernetes_cluster.this.kube_config[0].host
    username = azurerm_kubernetes_cluster.this.kube_config[0].username
    password = azurerm_kubernetes_cluster.this.kube_config[0].password
    client_certificate     = azurerm_kubernetes_cluster.this.kube_config[0].client_certificate
    client_key             = azurerm_kubernetes_cluster.this.kube_config[0].client_key
    cluster_ca_certificate = azurerm_kubernetes_cluster.this.kube_config[0].cluster_ca_certificate
  }
  sensitive   = true
  description = "Kubeconfig параметры (секретные)."
}
