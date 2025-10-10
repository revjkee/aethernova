/**
 * SPDX-License-Identifier: Apache-2.0
 *
 * Module: backups/snapshots
 * File:   versions.tf
 *
 * Назначение:
 *   Жёстко задаёт поддерживаемые версии Terraform и провайдеров для модулей,
 *   выполняющих бэкапы/снимки (EBS/EFS/RDS, Azure Managed Disks/Backup,
 *   GCP Compute/Filestore и т.п.). Провайдеры НЕ конфигурируются здесь —
 *   только объявляются как требования и настраиваются в корневом модуле.
 */

terraform {
  # Стабильный коридор Terraform Core для продакшена.
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # AWS provider v5 (актуальная мажорная линия для продакшена).
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }

    # AzureRM: поддерживаем ветки 3.x и 4.x (реалистичный продакшен-коридор).
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0, < 5.0.0"
    }

    # Google provider v6 (текущая мажорная линия).
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }

    # Вспомогательные провайдеры
    time = {
      source  = "hashicorp/time"
      version = ">= 0.13.0, < 1.0.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0, < 3.0.0"
    }

    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0, < 4.0.0"
    }
  }
}

# Примечания по эксплуатации:
# - Этот модуль не содержит provider-блоков — конфигурация провайдеров
#   (учётные данные, регионы, алиасы) должна задаваться в корневом модуле,
#   после чего провайдеры «унаследуются» дочерними модулями.
# - Верхние границы (< next major) защищают от внезапных breaking changes.
# - Если ваш ландшафт ограничен одним облаком, ненужные провайдеры можно удалить.
