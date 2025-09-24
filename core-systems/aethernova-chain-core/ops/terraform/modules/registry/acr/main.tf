/**
 * SPDX-License-Identifier: Apache-2.0
 *
 * Module: registry/acr
 * File:   main.tf
 *
 * Описание:
 *   Промышленная реализация Azure Container Registry (ACR) с
 *   - управляемым шифрованием CMK (Key Vault + Managed Identity),
 *   - сетевыми ACL (deny-by-default + IP allow-list),
 *   - Private Endpoint'ами для subresources "registry" и "registry_data",
 *   - георепликациями (Premium),
 *   - диагностическими логами (Azure Monitor Diagnostic Settings),
 *   - строгими зависимостями и тегами.
 *
 * Ссылки:
 *   - Terraform azurerm_container_registry: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry
 *   - ACR Private Link/Endpoint (subresources registry/registry_data): https://learn.microsoft.com/azure/container-registry/container-registry-private-link
 *   - ACR CMK (Key Vault + managed identity): https://learn.microsoft.com/azure/container-registry/tutorial-enable-customer-managed-keys
 *   - ACR SKU возможности/ограничения: https://learn.microsoft.com/azure/container-registry/container-registry-skus
 *   - Terraform Diagnostic Settings: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting
 */

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.115.0" # зафиксировать мажор 3.x для стабильности
    }
  }
}

# Провайдер конфигурируется во внешнем (корневом) модуле:
# provider "azurerm" { features {} }

############################
# Локали и входные параметры
############################

locals {
  # Безопасное deny-by-default, если явно не разрешено обратное
  default_acr_firewall_action = var.default_firewall_action != null ? var.default_firewall_action : "Deny"

  # Флаги Private Endpoint'ов в зависимости от SKU/фич
  pe_enable_registry = var.private_endpoint.enable && var.private_endpoint.for_registry
  pe_enable_data     = var.private_endpoint.enable && var.private_endpoint.for_data && var.data_endpoint_enabled

  # Диагностика
  diag_enabled = var.diagnostic.enable && (
    var.diagnostic.log_analytics_workspace_id != null ||
    var.diagnostic.eventhub_authorization_rule_id != null ||
    var.diagnostic.storage_account_id != null
  )
}

############################
# ACR реестр
############################

resource "azurerm_container_registry" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location

  # SKU: Basic | Standard | Premium (часть возможностей доступна только в Premium)
  sku = var.sku

  # Выключение публичного доступа при использовании Private Endpoint'ов
  public_network_access_enabled = var.public_network_access_enabled

  # Админ-аккаунт ACR (по умолчанию выключен в проде)
  admin_enabled = var.admin_enabled

  # Выделенный data endpoint (требует Premium)
  data_endpoint_enabled = var.data_endpoint_enabled

  # Сетевые правила для публичной поверхности (не применяются к Private Endpoint)
  dynamic "network_rule_set" {
    for_each = [true]
    content {
      default_action = local.default_acr_firewall_action

      # Разрешенные подсети по IP/CIDR
      dynamic "ip_rule" {
        for_each = var.allowed_cidrs
        content {
          action   = "Allow"
          ip_range = ip_rule.value
        }
      }
    }
  }

  # Шифрование CMK через Key Vault (Premium), требует управляемую идентичность
  dynamic "encryption" {
    for_each = var.cmk.enabled ? [1] : []
    content {
      key_vault_key_id   = var.cmk.key_vault_key_id
      identity_client_id = var.cmk.user_assigned_identity_client_id
    }
  }

  # Managed Identity (нужна для доступа к Key Vault при CMK)
  dynamic "identity" {
    for_each = var.identity.type != null ? [1] : []
    content {
      type         = var.identity.type                                    # "SystemAssigned" | "UserAssigned" | "SystemAssigned, UserAssigned"
      identity_ids = var.identity.user_assigned_identity_ids              # список ID user-assigned identities
    }
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = contains(["Basic", "Standard", "Premium"], var.sku)
      error_message = "sku должен быть одним из: Basic, Standard, Premium."
    }
    precondition {
      condition     = !(var.cmk.enabled) || (var.cmk.key_vault_key_id != null && var.cmk.user_assigned_identity_client_id != null && var.sku == "Premium")
      error_message = "CMK требует Premium SKU, key_vault_key_id и user-assigned identity client_id (см. официальную документацию ACR CMK)."
    }
    precondition {
      condition     = !(var.data_endpoint_enabled) || var.sku == "Premium"
      error_message = "data_endpoint_enabled поддерживается только в Premium SKU."
    }
  }
}

#########################################
# Георепликации (Premium) — опционально
#########################################

resource "azurerm_container_registry_replication" "this" {
  for_each = var.replications.enabled && var.sku == "Premium" ? toset(var.replications.locations) : []
  name                   = "rep-${each.value}"
  location               = each.value
  registry_name          = azurerm_container_registry.this.name
  resource_group_name    = var.resource_group_name
  zone_redundancy_enabled = var.replications.zone_redundancy_enabled

  tags = var.tags
}

#########################################
# Private Endpoints (registry, data) — опционально
#########################################

# Private Endpoint для subresource "registry"
resource "azurerm_private_endpoint" "acr_registry" {
  count               = local.pe_enable_registry ? 1 : 0
  name                = "${var.name}-pe-registry"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint.subnet_id

  private_service_connection {
    name                           = "${var.name}-psc-registry"
    is_manual_connection           = false
    private_connection_resource_id = azurerm_container_registry.this.id
    subresource_names              = ["registry"] # см. ACR Private Link subresources
  }

  dynamic "private_dns_zone_group" {
    for_each = var.private_endpoint.private_dns_zone_ids != null && length(var.private_endpoint.private_dns_zone_ids) > 0 ? [1] : []
    content {
      name                 = "acr-registry-dns"
      private_dns_zone_ids = var.private_endpoint.private_dns_zone_ids
    }
  }

  tags = var.tags
}

# Private Endpoint для subresource "registry_data" (требует data_endpoint_enabled=true)
resource "azurerm_private_endpoint" "acr_data" {
  count               = local.pe_enable_data ? 1 : 0
  name                = "${var.name}-pe-data"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint.subnet_id

  private_service_connection {
    name                           = "${var.name}-psc-data"
    is_manual_connection           = false
    private_connection_resource_id = azurerm_container_registry.this.id
    subresource_names              = ["registry_data"] # см. ACR Private Link subresources
  }

  dynamic "private_dns_zone_group" {
    for_each = var.private_endpoint.private_dns_zone_ids != null && length(var.private_endpoint.private_dns_zone_ids) > 0 ? [1] : []
    content {
      name                 = "acr-data-dns"
      private_dns_zone_ids = var.private_endpoint.private_dns_zone_ids
    }
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.data_endpoint_enabled
      error_message = "PE для 'registry_data' может быть создан только при включенном data_endpoint_enabled."
    }
  }
}

#########################################
# Диагностические логи/метрики (Azure Monitor)
#########################################

resource "azurerm_monitor_diagnostic_setting" "this" {
  count = local.diag_enabled ? 1 : 0

  name                       = "${var.name}-diag"
  target_resource_id         = azurerm_container_registry.this.id
  log_analytics_workspace_id = var.diagnostic.log_analytics_workspace_id
  eventhub_authorization_rule_id = var.diagnostic.eventhub_authorization_rule_id
  eventhub_name                  = var.diagnostic.eventhub_name
  storage_account_id             = var.diagnostic.storage_account_id

  dynamic "enabled_log" {
    for_each = toset(var.diagnostic.log_categories)
    content {
      category = enabled_log.value
    }
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

############################
# Вспомогательные выходы
############################

output "acr_id" {
  value       = azurerm_container_registry.this.id
  description = "ID созданного Azure Container Registry."
}

output "acr_login_server" {
  value       = azurerm_container_registry.this.login_server
  description = "FQDN реестра для docker login/pull/push."
}

output "private_endpoint_registry_id" {
  value       = one(azurerm_private_endpoint.acr_registry[*].id)
  description = "ID Private Endpoint для subresource 'registry' (если создан)."
}

output "private_endpoint_data_id" {
  value       = one(azurerm_private_endpoint.acr_data[*].id)
  description = "ID Private Endpoint для subresource 'registry_data' (если создан)."
}
