##############################################
# modules/storage/redis/main.tf
##############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws     = { source = "hashicorp/aws" }
    google  = { source = "hashicorp/google" }
    azurerm = { source = "hashicorp/azurerm" }
  }
}

##############################################
# Variables (общие и провайдер-специфичные)
##############################################

variable "cloud" {
  description = "Целевая облачная платформа: aws | gcp | azure."
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud должен быть одним из: aws, gcp, azure."
  }
}

variable "name" {
  description = "Базовое имя инстанса/группы Redis."
  type        = string
}

variable "tags" {
  description = "Теги/метки для ресурсов (где поддерживается)."
  type        = map(string)
  default     = {}
}

########################
# AWS ElastiCache (Redis)
########################

variable "aws_replication_group_id" {
  description = "ID replication group (требование ElastiCache)."
  type        = string
  default     = null
}

variable "aws_description" {
  description = "Описание replication group."
  type        = string
  default     = "Managed by Terraform"
}

variable "aws_engine_version" {
  description = "Версия Redis (например, 7.1)."
  type        = string
  default     = null
}

variable "aws_node_type" {
  description = "Тип ноды (например, cache.t3.small)."
  type        = string
  default     = null
}

variable "aws_parameter_group_name" {
  description = "Имя параметр-группы ElastiCache (например, default.redis7)."
  type        = string
  default     = null
}

variable "aws_port" {
  description = "Порт Redis."
  type        = number
  default     = 6379
}

variable "aws_transit_encryption_enabled" {
  description = "Включить шифрование трафика (in-transit/TLS)."
  type        = bool
  default     = true
}

variable "aws_at_rest_encryption_enabled" {
  description = "Включить шифрование данных в покое."
  type        = bool
  default     = true
}

variable "aws_kms_key_id" {
  description = "KMS ключ для шифрования в покое (опционально)."
  type        = string
  default     = null
}

variable "aws_auth_token" {
  description = "AUTH-пароль (требует включённый TLS)."
  type        = string
  default     = null
  sensitive   = true
}

variable "aws_security_group_ids" {
  description = "Список Security Group IDs для доступа к Redis."
  type        = list(string)
  default     = []
}

variable "aws_subnet_ids" {
  description = "Список Subnet IDs для subnet group."
  type        = list(string)
  default     = []
}

variable "aws_maintenance_window" {
  description = "Окно обслуживания (например, sun:23:00-mon:01:30)."
  type        = string
  default     = null
}

variable "aws_snapshot_window" {
  description = "Окно снапшотов (например, 03:00-05:00)."
  type        = string
  default     = null
}

variable "aws_snapshot_retention_limit" {
  description = "Хранение снапшотов (в днях)."
  type        = number
  default     = 0
}

variable "aws_apply_immediately" {
  description = "Применять изменения сразу (true) либо в окно (false)."
  type        = bool
  default     = false
}

# Кластерный режим (Cluster Mode)
variable "aws_cluster_mode_enabled" {
  description = "Включить Redis Cluster Mode (шардинг)."
  type        = bool
  default     = false
}

variable "aws_num_node_groups" {
  description = "Число шардов (Cluster Mode Enabled)."
  type        = number
  default     = null
}

variable "aws_replicas_per_node_group" {
  description = "Число реплик на шарде (Cluster Mode Enabled)."
  type        = number
  default     = null
}

variable "aws_number_cache_clusters" {
  description = "Число нод при Cluster Mode Disabled (>=1)."
  type        = number
  default     = 1
}

########################
# GCP Memorystore (Redis)
########################

variable "gcp_region" {
  description = "Регион GCP (например, europe-west1)."
  type        = string
  default     = null
}

variable "gcp_tier" {
  description = "BASIC или STANDARD_HA."
  type        = string
  default     = "STANDARD_HA"
  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.gcp_tier)
    error_message = "gcp_tier должен быть BASIC или STANDARD_HA."
  }
}

variable "gcp_memory_size_gb" {
  description = "Размер памяти (GB)."
  type        = number
  default     = 5
}

variable "gcp_redis_version" {
  description = "Версия Redis Memorystore (например, REDIS_7_2)."
  type        = string
  default     = null
}

variable "gcp_authorized_network" {
  description = "Полное имя VPC: projects/PROJECT/global/networks/NAME."
  type        = string
  default     = null
}

variable "gcp_connect_mode" {
  description = "DIRECT_PEERING или PRIVATE_SERVICE_ACCESS."
  type        = string
  default     = null
}

variable "gcp_transit_encryption_mode" {
  description = "DISABLED или SERVER_AUTHENTICATION (TLS)."
  type        = string
  default     = null
}

variable "gcp_reserved_ip_range" {
  description = "Имя выделенного диапазона для PSA (если используется)."
  type        = string
  default     = null
}

variable "gcp_labels" {
  description = "Метки ресурса GCP."
  type        = map(string)
  default     = {}
}

########################
# Azure Cache for Redis
########################

variable "az_resource_group_name" {
  description = "Resource Group для Azure Cache."
  type        = string
  default     = null
}

variable "az_location" {
  description = "Локация Azure (например, westeurope)."
  type        = string
  default     = null
}

variable "az_sku_name" {
  description = "SKU: Basic | Standard | Premium."
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.az_sku_name)
    error_message = "az_sku_name должен быть Basic, Standard или Premium."
  }
}

variable "az_family" {
  description = "Семейство: C (Basic/Standard) или P (Premium)."
  type        = string
  default     = "C"
  validation {
    condition     = contains(["C", "P"], var.az_family)
    error_message = "az_family должен быть C (Basic/Standard) или P (Premium)."
  }
}

variable "az_capacity" {
  description = "Размер кэша (емкость SKU)."
  type        = number
  default     = 1
}

variable "az_enable_non_ssl_port" {
  description = "Разрешить не-SSL порт 6379."
  type        = bool
  default     = false
}

variable "az_minimum_tls_version" {
  description = "Минимальная версия TLS (например, 1.2)."
  type        = string
  default     = "1.2"
}

variable "az_subnet_id" {
  description = "Subnet ID для VNet-интеграции (только Premium)."
  type        = string
  default     = null
}

##############################################
# Locals
##############################################

locals {
  is_aws   = var.cloud == "aws"
  is_gcp   = var.cloud == "gcp"
  is_azure = var.cloud == "azure"

  # Устойчивое имя, пригодное везде
  base_name = var.name
}

##############################################
# AWS: сеть (subnet group) — опционально
##############################################

resource "aws_elasticache_subnet_group" "this" {
  count       = local.is_aws && length(var.aws_subnet_ids) > 0 ? 1 : 0
  name        = "${local.base_name}-subnets"
  description = "Subnet group for ${local.base_name}"
  subnet_ids  = var.aws_subnet_ids

  tags = var.tags
}

##############################################
# AWS: Redis (Cluster Mode Disabled)
##############################################

resource "aws_elasticache_replication_group" "aws_nonc" {
  count = local.is_aws && var.aws_cluster_mode_enabled == false ? 1 : 0

  replication_group_id          = coalesce(var.aws_replication_group_id, replace(lower(local.base_name), "/[^a-z0-9-]/", "-"))
  description                   = var.aws_description
  engine                        = "redis"
  engine_version                = var.aws_engine_version
  node_type                     = var.aws_node_type
  number_cache_clusters         = var.aws_number_cache_clusters
  parameter_group_name          = var.aws_parameter_group_name
  port                          = var.aws_port
  maintenance_window            = var.aws_maintenance_window
  snapshot_window               = var.aws_snapshot_window
  snapshot_retention_limit      = var.aws_snapshot_retention_limit
  apply_immediately             = var.aws_apply_immediately
  at_rest_encryption_enabled    = var.aws_at_rest_encryption_enabled
  transit_encryption_enabled    = var.aws_transit_encryption_enabled
  kms_key_id                    = var.aws_kms_key_id
  auth_token                    = var.aws_auth_token
  security_group_ids            = var.aws_security_group_ids
  subnet_group_name             = try(aws_elasticache_subnet_group.this[0].name, null)
  automatic_failover_enabled    = true

  tags = var.tags

  lifecycle {
    prevent_destroy = false
  }
}

##############################################
# AWS: Redis (Cluster Mode Enabled)
##############################################

resource "aws_elasticache_replication_group" "aws_clustered" {
  count = local.is_aws && var.aws_cluster_mode_enabled == true ? 1 : 0

  replication_group_id          = coalesce(var.aws_replication_group_id, replace(lower(local.base_name), "/[^a-z0-9-]/", "-"))
  description                   = var.aws_description
  engine                        = "redis"
  engine_version                = var.aws_engine_version
  node_type                     = var.aws_node_type
  num_node_groups               = var.aws_num_node_groups
  replicas_per_node_group       = var.aws_replicas_per_node_group
  parameter_group_name          = var.aws_parameter_group_name
  port                          = var.aws_port
  maintenance_window            = var.aws_maintenance_window
  snapshot_window               = var.aws_snapshot_window
  snapshot_retention_limit      = var.aws_snapshot_retention_limit
  apply_immediately             = var.aws_apply_immediately
  at_rest_encryption_enabled    = var.aws_at_rest_encryption_enabled
  transit_encryption_enabled    = var.aws_transit_encryption_enabled
  kms_key_id                    = var.aws_kms_key_id
  auth_token                    = var.aws_auth_token
  security_group_ids            = var.aws_security_group_ids
  subnet_group_name             = try(aws_elasticache_subnet_group.this[0].name, null)
  automatic_failover_enabled    = true

  tags = var.tags

  lifecycle {
    prevent_destroy = false
  }
}

##############################################
# GCP: Memorystore (Redis)
##############################################

resource "google_redis_instance" "gcp" {
  count = local.is_gcp ? 1 : 0

  name           = local.base_name
  region         = var.gcp_region
  tier           = var.gcp_tier
  memory_size_gb = var.gcp_memory_size_gb

  redis_version            = var.gcp_redis_version
  authorized_network       = var.gcp_authorized_network
  connect_mode             = var.gcp_connect_mode
  reserved_ip_range        = var.gcp_reserved_ip_range
  transit_encryption_mode  = var.gcp_transit_encryption_mode

  labels = var.gcp_labels
}

##############################################
# Azure: Cache for Redis
##############################################

provider "azurerm" {
  features {}
}

resource "azurerm_redis_cache" "az" {
  count               = local.is_azure ? 1 : 0
  name                = local.base_name
  location            = var.az_location
  resource_group_name = var.az_resource_group_name

  sku_name = var.az_sku_name
  family   = var.az_family
  capacity = var.az_capacity

  enable_non_ssl_port   = var.az_enable_non_ssl_port
  minimum_tls_version   = var.az_minimum_tls_version

  # Доступно только для Premium SKU (VNet интеграция)
  subnet_id             = var.az_sku_name == "Premium" ? var.az_subnet_id : null

  tags = var.tags
}

##############################################
# Outputs (унифицированные)
##############################################

output "aws_primary_endpoint" {
  description = "AWS: primary endpoint (Cluster Mode Disabled)."
  value       = local.is_aws && var.aws_cluster_mode_enabled == false ? aws_elasticache_replication_group.aws_nonc[0].primary_endpoint_address : null
}

output "aws_reader_endpoint" {
  description = "AWS: reader endpoint (Cluster Mode Disabled)."
  value       = local.is_aws && var.aws_cluster_mode_enabled == false ? aws_elasticache_replication_group.aws_nonc[0].reader_endpoint_address : null
}

output "aws_configuration_endpoint" {
  description = "AWS: configuration endpoint (Cluster Mode Enabled)."
  value       = local.is_aws && var.aws_cluster_mode_enabled == true ? aws_elasticache_replication_group.aws_clustered[0].configuration_endpoint_address : null
}

output "gcp_host_port" {
  description = "GCP: хост и порт Memorystore (host:port)."
  value       = local.is_gcp ? "${google_redis_instance.gcp[0].host}:${google_redis_instance.gcp[0].port}" : null
}

output "azure_hostname_port" {
  description = "Azure: хост и порт Cache for Redis (hostname:port)."
  value       = local.is_azure ? "${azurerm_redis_cache.az[0].hostname}:${azurerm_redis_cache.az[0].ssl_port}" : null
}
