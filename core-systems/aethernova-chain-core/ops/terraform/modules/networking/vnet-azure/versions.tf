#############################################
# aethernova-chain-core/ops/terraform/modules/networking/vnet-azure/versions.tf
#############################################

terraform {
  # Совместимость с линейкой Terraform 1.x (проверено с >=1.9):
  # Разрешаем обновления, но блокируем переход на 2.x до явного апгрейда.
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    # AzureRM v4.x (актуальная мажорная ветка с 2024-08; фиксируем <5.0.0)
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0, < 5.0.0"
    }
  }
}

# Примечание:
# Конфигурацию провайдера (provider "azurerm" { features {} ... }) держите в providers.tf,
# так как для azurerm блок features {} обязателен в конфигурации провайдера.
# Данный файл фиксирует только версии и источник провайдера.
