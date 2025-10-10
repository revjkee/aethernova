#############################################
# registry/acr/versions.tf  (industrial)
# Terraform >= 1.5 | azurerm >= 3.x
#############################################

terraform {
  # Требования к версии Terraform CLI
  required_version = ">= 1.5.0, < 2.0.0"

  # Пины провайдеров (консервативные границы для безопасных апгрейдов)
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0, < 5.0.0"
    }

    # Для возможных назначений ролей AAD к ACR (pull/push) вне рамок RBAC Azure RBAC on ACR
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.0.0, < 3.0.0"
    }

    # Утилитарные провайдеры: суффиксы имён, тайминги ротаций/валидаций и т.п.
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0, < 2.0.0"
    }
  }
}
