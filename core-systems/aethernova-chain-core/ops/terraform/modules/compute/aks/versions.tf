##############################################
# modules/compute/aks/versions.tf
##############################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0" # Рекомендуется задавать нижнюю и верхнюю границы для предсказуемости. 
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0, < 4.0.0"       # Фиксация мейджора согласно best practices.
    }
  }
}

provider "azurerm" {
  features {}
}

########################################################
# Variables
########################################################

variable "location" {
  description = "Локация Azure (например, westeurope)."
  type        = string
}

variable "include_preview_versions" {
  description = "Включать ли preview-версии Kubernetes из AKS каталога."
  type        = bool
  default     = false
}

# Стратегия выбора версии AKS:
# - pin:   использовать var.kubernetes_version (должна быть в списке доступных)
# - latest:последняя доступная версия по данным Azure
# - default:версия по умолчанию AKS (N-1 минор, последний патч) либо свойство default_version провайдера
variable "version_strategy" {
  description = "Стратегия выбора версии Kubernetes (pin | latest | default)."
  type        = string
  default     = "default"
  validation {
    condition     = contains(["pin", "latest", "default"], var.version_strategy)
    error_message = "version_strategy должен быть одним из: pin, latest, default."
  }
}

variable "kubernetes_version" {
  description = "Фиксированная версия Kubernetes для стратегии 'pin' (формат X.Y.Z)."
  type        = string
  default     = null
}

########################################################
# Data source: AKS supported versions for the location
########################################################

data "azurerm_kubernetes_service_versions" "this" {
  location        = var.location
  include_preview = var.include_preview_versions
}

########################################################
# Locals: вычисление эффективной версии
########################################################

# Полный список доступных версий (строки вида X.Y.Z)
locals {
  available_versions = data.azurerm_kubernetes_service_versions.this.versions
  latest_version     = try(data.azurerm_kubernetes_service_versions.this.latest_version, null)
  # default_version свойство появилось в провайдере позднее — безопасно читаем через try()
  provider_default_version = try(data.azurerm_kubernetes_service_versions.this.default_version, null)
}

# Надёжный fallback на случай отсутствия default_version:
# Правило AKS: версия по умолчанию — N-1 минор и последний патч (если доступно несколько миноров).
# Если доступен только один минор, берём в нём максимальный патч.
locals {
  parsed_versions = [
    for v in local.available_versions : {
      v     = v
      major = tonumber(split(".", v)[0])
      minor = tonumber(split(".", v)[1])
      patch = tonumber(split(".", v)[2])
    }
  ]

  minors         = distinct([for p in local.parsed_versions : p.minor])
  highest_minor  = max(local.minors...)
  target_minor   = length(local.minors) > 1 ? (local.highest_minor - 1) : local.highest_minor
  candidates     = [for p in local.parsed_versions : p if p.minor == local.target_minor]
  max_patch      = max([for p in local.candidates : p.patch]...)
  # Предполагаем major=1 для AKS, но берём фактический major из кандидатов
  fallback_default_version = length(local.candidates) > 0 ?
    format("%d.%d.%d", local.candidates[0].major, local.target_minor, local.max_patch) :
    local.latest_version

  effective_default_version = try(local.provider_default_version, local.fallback_default_version)
}

# Итоговая версия по стратегии
locals {
  kubernetes_version_resolved = (
    var.version_strategy == "pin"    && var.kubernetes_version != null ? var.kubernetes_version :
    var.version_strategy == "latest"                          ? local.latest_version :
                                                                local.effective_default_version
  )
}

########################################################
# (Опционально) Валидационные "подсказки" как выходы
# Применяйте в пайплайнах/проверках перед созданием AKS.
########################################################

output "available_versions" {
  description = "Список версий Kubernetes, доступных для AKS в заданной локации."
  value       = local.available_versions
}

output "latest_version" {
  description = "Последняя доступная версия Kubernetes в локации."
  value       = local.latest_version
}

output "default_version_effective" {
  description = "Эффективная default-версия (из провайдера либо fallback по правилу AKS N-1 минор)."
  value       = local.effective_default_version
}

output "kubernetes_version_resolved" {
  description = "Выбранная версия Kubernetes с учётом стратегии."
  value       = local.kubernetes_version_resolved
}

# Подсказка о валидности пинованной версии (true если версия допустима)
output "pin_version_is_valid" {
  description = "Истина, если var.kubernetes_version (при strategy=pin) входит в список доступных."
  value       = var.version_strategy != "pin" || var.kubernetes_version == null
    ? true
    : contains(local.available_versions, var.kubernetes_version)
}
