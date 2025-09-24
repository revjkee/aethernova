##############################################
# Module: registry/acr
# File  : outputs.tf
# NOTE  : Ожидается ресурс с именем azurerm_container_registry.acr
##############################################

# Базовые идентификаторы
output "acr_id" {
  description = "Resource ID реестра контейнеров (ACR)."
  value       = azurerm_container_registry.acr.id
}

output "acr_name" {
  description = "Имя реестра контейнеров."
  value       = azurerm_container_registry.acr.name
}

output "acr_resource_group_name" {
  description = "Имя resource group, в которой создан ACR."
  value       = azurerm_container_registry.acr.resource_group_name
}

output "acr_location" {
  description = "Регион ACR."
  value       = azurerm_container_registry.acr.location
}

output "acr_sku" {
  description = "SKU ACR (Basic/Standard/Premium)."
  value       = azurerm_container_registry.acr.sku
}

# Данные для docker login / образов
output "acr_login_server" {
  description = "FQDN реестра (host), используемый для docker login и pull/push."
  value       = azurerm_container_registry.acr.login_server
}

# Административные креденшалы (если admin_enabled = true)
# Значения доступны из ресурса только при включённом админ-аккаунте.
output "acr_admin_username" {
  description = "Имя администратора ACR (если admin_enabled=true), иначе null."
  value       = try(azurerm_container_registry.acr.admin_username, null)
}

output "acr_admin_password" {
  description = "Пароль администратора ACR (если admin_enabled=true), иначе null."
  value       = try(azurerm_container_registry.acr.admin_password, null)
  sensitive   = true
}

# Выделенные data endpoints (Premium)
output "acr_data_endpoint_enabled" {
  description = "Флаг включения выделенных data endpoints (доступно в Premium)."
  value       = try(azurerm_container_registry.acr.data_endpoint_enabled, false)
}

output "acr_data_endpoint_host_names" {
  description = "Набор выделенных data endpoint хостов (когда включены), иначе пустой список."
  value       = try(azurerm_container_registry.acr.data_endpoint_host_names, [])
}

# Managed Identity (MSI)
output "acr_identity_type" {
  description = "Тип управляемой идентичности (SystemAssigned/UserAssigned/None)."
  value       = try(azurerm_container_registry.acr.identity[0].type, "None")
}

output "acr_identity_principal_id" {
  description = "Principal ID управляемой идентичности реестра (если задана), иначе null."
  value       = try(azurerm_container_registry.acr.identity[0].principal_id, null)
}

output "acr_identity_tenant_id" {
  description = "Tenant ID управляемой идентичности реестра (если задана), иначе null."
  value       = try(azurerm_container_registry.acr.identity[0].tenant_id, null)
}

# Удобный объект для дальнейшей привязки
output "acr_summary" {
  description = "Сводный объект с ключевыми свойствами ACR."
  value = {
    id                         = azurerm_container_registry.acr.id
    name                       = azurerm_container_registry.acr.name
    resource_group_name        = azurerm_container_registry.acr.resource_group_name
    location                   = azurerm_container_registry.acr.location
    sku                        = azurerm_container_registry.acr.sku
    login_server               = azurerm_container_registry.acr.login_server
    admin_enabled              = try(azurerm_container_registry.acr.admin_enabled, null)
    admin_username             = try(azurerm_container_registry.acr.admin_username, null)
    # Пароль намеренно опущен из summary по соображениям минимизации распространения секретов.
    data_endpoint_enabled      = try(azurerm_container_registry.acr.data_endpoint_enabled, false)
    data_endpoint_host_names   = try(azurerm_container_registry.acr.data_endpoint_host_names, [])
    identity = {
      type         = try(azurerm_container_registry.acr.identity[0].type, null)
      principal_id = try(azurerm_container_registry.acr.identity[0].principal_id, null)
      tenant_id    = try(azurerm_container_registry.acr.identity[0].tenant_id, null)
    }
  }
}
