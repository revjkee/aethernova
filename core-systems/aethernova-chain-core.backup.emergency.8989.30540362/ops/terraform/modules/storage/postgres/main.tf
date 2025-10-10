###############################################################################
# modules/storage/postgres/main.tf
# Multi-cloud managed PostgreSQL (AWS RDS / GCP Cloud SQL / Azure Flexible)
###############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.70"
    }
  }
}

############################
# Common inputs (expected) #
############################
# Эти переменные предполагаются в variables.tf модуля:
#   cloud                      = "aws" | "gcp" | "azure"
#   name                       = идентификатор БД/сервера (без пробелов)
#   db_name                    = имя создаваемой БД
#   db_username                = мастер-пользователь (RDS/Cloud SQL)/admin login (Azure)
#   db_password                = пароль (sensitive) — не используется, если задан manage_master_user_password (AWS)
#   deletion_protection        = bool
#   tags/labels                = map(string)
#
# AWS-специфичные:
#   aws_subnet_ids             = list(string)
#   aws_security_group_ids     = list(string)
#   aws_engine_version         = string (например, "15.5")
#   aws_instance_class         = string (например, "db.r6g.large")
#   aws_allocated_storage      = number (GiB)
#   aws_max_allocated_storage  = number (GiB) | null
#   aws_multi_az               = bool
#   aws_kms_key_id             = string | null
#   aws_backup_retention_days  = number
#   aws_backup_window          = string | null (UTC hh24:mi-hh24:mi)
#   aws_maintenance_window     = string | null (ddd:hh24:mi-ddd:hh24:mi)
#   aws_parameter_family       = string (например, "postgres15")
#   aws_parameters             = list(object({ name=string, value=string, apply_method=optional(string) }))
#   aws_publicly_accessible    = bool
#   aws_monitoring_interval    = number (в секундах) | 0
#   aws_performance_insights_enabled = bool
#   aws_performance_insights_kms_key_id = string | null
#   aws_manage_master_user_password = bool
#
# GCP-специфичные:
#   gcp_region                 = string
#   gcp_database_version       = string ("POSTGRES_15" и т.п.)
#   gcp_tier                   = string ("db-custom-2-7680" и т.п.)
#   gcp_availability_type      = string ("REGIONAL" | "ZONAL")
#   gcp_disk_type              = string ("PD_SSD" | "PD_HDD")
#   gcp_disk_size_gb           = number
#   gcp_backup_enabled         = bool
#   gcp_backup_start_time      = string | null ("HH:MM")
#   gcp_ipv4_enabled           = bool
#   gcp_private_network        = string | null (SelfLink/ID VPC)
#   gcp_authorized_networks    = list(object({ name=string, value=string })) # для public IP
#   gcp_maintenance_day        = number | null (1..7)
#   gcp_maintenance_hour       = number | null (0..23)
#
# Azure-специфичные:
#   azure_resource_group       = string
#   azure_location             = string
#   azure_version              = string ("15", "16" и т.п.)
#   azure_sku_name             = string (например, "Standard_B2ms" или "GP_Standard_D2s_v5")
#   azure_storage_mb           = number
#   azure_backup_retention_days= number
#   azure_network_delegated_subnet_id = string | null
#   azure_private_dns_zone_id  = string | null
#   azure_ha_enabled           = bool
#   azure_ha_mode              = string ("ZoneRedundant") # см. доки ресурса
#   azure_standby_az           = string | null            # например, "2"
#   azure_public_network_access_enabled = bool

locals {
  is_aws   = lower(var.cloud) == "aws"
  is_gcp   = lower(var.cloud) == "gcp"
  is_azure = lower(var.cloud) == "azure"
}

########################
# AWS RDS for Postgres #
########################
# Официальные ресурсы: aws_db_instance, aws_db_subnet_group, aws_db_parameter_group. :contentReference[oaicite:3]{index=3}

resource "aws_db_subnet_group" "this" {
  count      = local.is_aws ? 1 : 0
  name       = "${var.name}-db-subnets"
  subnet_ids = var.aws_subnet_ids
  tags       = var.tags
}

resource "aws_db_parameter_group" "this" {
  count  = local.is_aws ? 1 : 0
  name   = "${var.name}-pg"
  family = var.aws_parameter_family
  dynamic "parameter" {
    for_each = var.aws_parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = try(parameter.value.apply_method, null)
    }
  }
  tags = var.tags
}

resource "aws_db_instance" "this" {
  count                              = local.is_aws ? 1 : 0
  identifier                         = var.name
  engine                             = "postgres"
  engine_version                     = var.aws_engine_version
  instance_class                     = var.aws_instance_class
  db_subnet_group_name               = aws_db_subnet_group.this[0].name
  parameter_group_name               = aws_db_parameter_group.this[0].name
  vpc_security_group_ids             = var.aws_security_group_ids

  username                           = var.aws_manage_master_user_password ? null : var.db_username
  password                           = var.aws_manage_master_user_password ? null : var.db_password
  manage_master_user_password        = var.aws_manage_master_user_password # Secrets Manager интеграция
  # Подтверждено AWS/Terraform: manage_master_user_password включает управление паролем RDS в Secrets Manager. :contentReference[oaicite:4]{index=4}

  db_name                            = var.db_name
  port                               = 5432

  allocated_storage                  = var.aws_allocated_storage
  max_allocated_storage              = try(var.aws_max_allocated_storage, null)

  multi_az                           = var.aws_multi_az
  # Multi-AZ повышает доступность, создавая синхронный standby в другой AZ. :contentReference[oaicite:5]{index=5}

  storage_encrypted                  = true
  kms_key_id                         = try(var.aws_kms_key_id, null)
  # Шифрование RDS на диске с KMS описано в документации AWS. :contentReference[oaicite:6]{index=6}

  backup_retention_period            = var.aws_backup_retention_days
  backup_window                      = try(var.aws_backup_window, null)
  maintenance_window                 = try(var.aws_maintenance_window, null)
  auto_minor_version_upgrade         = true
  deletion_protection                = var.deletion_protection
  publicly_accessible                = var.aws_publicly_accessible

  monitoring_interval                = try(var.aws_monitoring_interval, 0)
  performance_insights_enabled       = try(var.aws_performance_insights_enabled, false)
  performance_insights_kms_key_id    = try(var.aws_performance_insights_kms_key_id, null)

  enabled_cloudwatch_logs_exports    = ["postgresql", "upgrade"]

  tags = var.tags
}

########################
# GCP Cloud SQL (PG)   #
########################
# Официальный ресурс: google_sql_database_instance (+ user/database). :contentReference[oaicite:7]{index=7}

resource "google_sql_database_instance" "this" {
  count            = local.is_gcp ? 1 : 0
  name             = var.name
  region           = var.gcp_region
  database_version = var.gcp_database_version
  deletion_protection = var.deletion_protection

  settings {
    tier             = var.gcp_tier
    availability_type= var.gcp_availability_type  # REGIONAL = HA, ZONAL = single-zone. :contentReference[oaicite:8]{index=8}
    disk_type        = var.gcp_disk_type
    disk_size        = var.gcp_disk_size_gb

    backup_configuration {
      enabled    = var.gcp_backup_enabled
      start_time = try(var.gcp_backup_start_time, null)
    }

    ip_configuration {
      ipv4_enabled    = var.gcp_ipv4_enabled
      private_network = try(var.gcp_private_network, null) # Private IP. :contentReference[oaicite:9]{index=9}
      require_ssl     = true

      dynamic "authorized_networks" {
        for_each = var.gcp_ipv4_enabled ? var.gcp_authorized_networks : []
        content {
          name  = authorized_networks.value.name
          value = authorized_networks.value.value
        }
      }
    }

    dynamic "maintenance_window" {
      for_each = (var.gcp_maintenance_day != null && var.gcp_maintenance_hour != null) ? [1] : []
      content {
        day  = var.gcp_maintenance_day
        hour = var.gcp_maintenance_hour
      }
    }

    user_labels = try(var.labels, {})
  }
}

resource "google_sql_user" "this" {
  count    = local.is_gcp ? 1 : 0
  instance = google_sql_database_instance.this[0].name
  name     = var.db_username
  password = var.db_password
}

resource "google_sql_database" "this" {
  count    = local.is_gcp ? 1 : 0
  instance = google_sql_database_instance.this[0].name
  name     = var.db_name
}

##############################################
# Azure Database for PostgreSQL Flexible     #
##############################################
# Официальный ресурс: azurerm_postgresql_flexible_server (+ database). :contentReference[oaicite:10]{index=10}
# Концепция и HA Flexible Server — официальные материалы Microsoft. :contentReference[oaicite:11]{index=11}

resource "azurerm_postgresql_flexible_server" "this" {
  count               = local.is_azure ? 1 : 0
  name                = var.name
  resource_group_name = var.azure_resource_group
  location            = var.azure_location
  version             = var.azure_version
  administrator_login = var.db_username
  administrator_password = var.db_password
  sku_name            = var.azure_sku_name
  storage_mb          = var.azure_storage_mb

  backup {
    retention_days = var.azure_backup_retention_days
  }

  dynamic "high_availability" {
    for_each = var.azure_ha_enabled ? [1] : []
    content {
      mode                      = var.azure_ha_mode # например, "ZoneRedundant" согласно докам. :contentReference[oaicite:12]{index=12}
      standby_availability_zone = try(var.azure_standby_az, null)
    }
  }

  dynamic "network" {
    for_each = (var.azure_network_delegated_subnet_id != null || var.azure_private_dns_zone_id != null) ? [1] : []
    content {
      delegated_subnet_id = try(var.azure_network_delegated_subnet_id, null)
      private_dns_zone_id = try(var.azure_private_dns_zone_id, null)
    }
  }

  public_network_access_enabled = var.azure_public_network_access_enabled
  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  count     = local.is_azure ? 1 : 0
  name      = var.db_name
  server_id = azurerm_postgresql_flexible_server.this[0].id
  collation = "en_US.utf8"
  charset   = "UTF8"
}

################
# Unified outs #
################

output "postgres_connection" {
  description = "Унифицированные данные подключения (эндпойнт/порт/провайдер)."
  value = local.is_aws ? {
    provider = "aws"
    host     = aws_db_instance.this[0].address
    port     = aws_db_instance.this[0].port
    db_name  = var.db_name
    user     = var.db_username
  } : local.is_gcp ? {
    provider = "gcp"
    host     = google_sql_database_instance.this[0].public_ip_address != null ?
               google_sql_database_instance.this[0].public_ip_address :
               google_sql_database_instance.this[0].private_ip_address
    port     = 5432
    db_name  = var.db_name
    user     = var.db_username
  } : {
    provider = "azure"
    host     = azurerm_postgresql_flexible_server.this[0].fqdn
    port     = 5432
    db_name  = var.db_name
    user     = var.db_username
  }
}

output "rds_master_user_secret_arn" {
  description = "ARN секрета мастер-пользователя (если manage_master_user_password=true)."
  value       = local.is_aws ? try(aws_db_instance.this[0].master_user_secret[0].secret_arn, null) : null
}
