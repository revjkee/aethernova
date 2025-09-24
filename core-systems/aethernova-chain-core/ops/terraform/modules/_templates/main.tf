###############################################################################
# Aethernova Terraform Module Template (industrial-grade)
# Purpose: стартовая точка для новых модулей согласно практикам HashiCorp.
#
# Docs (обоснование):
# - Standard module structure (main.tf / variables.tf / outputs.tf): 
#   https://developer.hashicorp.com/terraform/language/modules/develop/structure
# - terraform block (required_version / required_providers):
#   https://developer.hashicorp.com/terraform/language/terraform
# - Providers within modules (не конфигурировать provider в child-модулях):
#   https://developer.hashicorp.com/terraform/language/modules/develop/providers
# - Version constraints (синтаксис и best practices):
#   https://developer.hashicorp.com/terraform/language/expressions/version-constraints
# - Locals: https://developer.hashicorp.com/terraform/language/block/locals
# - merge(): https://developer.hashicorp.com/terraform/language/functions/merge
# - variable validation: https://developer.hashicorp.com/terraform/language/block/variable
###############################################################################

terraform {
  # Модуль должен объявлять минимум допустимую версию Terraform (best practice для reusable modules):
  # https://developer.hashicorp.com/terraform/language/expressions/version-constraints#best-practices
  required_version = ">= 1.6.0"

  # Каждый модуль обязан объявить требуемые провайдеры (источник и минимальную версию).
  # ВАЖНО: не конфигурировать provider-блоки внутри модуля; они должны быть в root module.
  # https://developer.hashicorp.com/terraform/language/modules/develop/providers
  required_providers {
    # Пример (раскомментировать и заменить при необходимости):
    # aws = {
    #   source  = "hashicorp/aws"
    #   version = ">= 5.0.0"
    # }
  }

  # Backend/cloud конфигурируются на уровне root-модуля/окружения (style guide).
  # https://developer.hashicorp.com/terraform/language/style#file-names
}

###############################################################################
# ВХОДНЫЕ ПЕРЕМЕННЫЕ (минимальный набор для шаблона)
# Примечание: в реальных модулях обычно выносятся в variables.tf (style guide),
# но допускается объявлять и здесь, так как это стартовый шаблон.
# https://developer.hashicorp.com/terraform/language/style#file-names
###############################################################################

variable "name" {
  type        = string
  description = "Логическое имя экземпляра модуля (используется в именах/тегах)."

  validation {
    condition     = length(var.name) > 0 && length(var.name) <= 63
    error_message = "name должен быть непустым и не длиннее 63 символов."
  }
}

variable "environment" {
  type        = string
  description = "Окружение развёртывания (например: prod, staging, dev)."

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "environment должен быть одним из: prod, staging, dev."
  }
}

variable "labels" {
  type        = map(string)
  description = "Пользовательские метки/теги (key -> value), будут смержены с базовыми."
  default     = {}
}

###############################################################################
# LOCALS
# - basename(path.module) даёт имя каталога модуля (удобно для тегов/префиксов).
#   https://developer.hashicorp.com/terraform/language/functions/basename
#   https://developer.hashicorp.com/terraform/language/expressions/references (path.module)
# - merge() — слияние карт с приоритетом последних аргументов.
#   https://developer.hashicorp.com/terraform/language/functions/merge
###############################################################################
locals {
  module_name = basename(path.module)

  # Базовые теги/метки, которые можно переопределить через var.labels.
  # Придерживаемся нейтрального набора, пригодного для большинства провайдеров.
  base_labels = {
    "module"      = local.module_name
    "name"        = var.name
    "environment" = var.environment
    "managed_by"  = "terraform"
  }

  # Итоговые метки: пользовательские имеют приоритет (последний merge).
  # Пример использования: передавайте local.effective_labels в теги/метаданные ресурсов.
  effective_labels = merge(local.base_labels, var.labels)
}

###############################################################################
# РЕСУРСЫ
# Этот шаблон умышленно пуст (без ресурсов) — дополняйте при создании модуля.
# ПРИМЕЧАНИЕ О ПРОВАЙДЕРАХ:
# - child-модули НЕ должны содержать provider-блоки (см. docs ниже).
# - Провайдеры настраиваются в root-модуле и при необходимости передаются в module {}.
# https://developer.hashicorp.com/terraform/language/modules/develop/providers
###############################################################################

# resource "<PROVIDER>_<TYPE>" "example" {
#   # name        = var.name
#   # tags/labels = local.effective_labels
# }

###############################################################################
# ВЫВОДЫ
# Обычно выносятся в outputs.tf (style guide), но для шаблона укажем базовые.
# https://developer.hashicorp.com/terraform/language/style#file-names
###############################################################################

output "module_name" {
  description = "Имя каталога модуля (basename(path.module))."
  value       = local.module_name
}

output "effective_labels" {
  description = "Сконсолидированные метки (base + пользовательские)."
  value       = local.effective_labels
  sensitive   = false
}
