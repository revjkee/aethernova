// physical-integration-core/ops/terraform/modules/compute/main.tf

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.60"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = ">= 2.3"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

############################
# Common variables & locals
############################

variable "platform" {
  description = "Целевая платформа: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.platform)
    error_message = "platform должен быть одним из: aws, gcp, azure."
  }
}

variable "name" {
  description = "Базовое имя ресурса/группы"
  type        = string
}

variable "environment" {
  description = "Окружение (prod|staging|dev и т.д.)"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Дополнительные теги/метки"
  type        = map(string)
  default     = {}
}

variable "min_replicas" {
  description = "Минимальное число экземпляров"
  type        = number
  default     = 1
  validation {
    condition     = var.min_replicas >= 0
    error_message = "min_replicas должен быть >= 0."
  }
}

variable "desired_replicas" {
  description = "Желаемое число экземпляров"
  type        = number
  default     = 1
}

variable "max_replicas" {
  description = "Максимальное число экземпляров"
  type        = number
  default     = 3
}

variable "user_data" {
  description = "cloud-init/user-data скрипт (опционально). Для Windows используйте подходящий формат."
  type        = string
  default     = null
}

locals {
  common_tags = merge(
    {
      "Name"        = var.name
      "Environment" = var.environment
      "Module"      = "physical-integration-core/compute"
      "ManagedBy"   = "Terraform"
    },
    var.tags
  )

  # Унифицированная проверка размеров
  size_ok = var.min_replicas <= var.desired_replicas && var.desired_replicas <= var.max_replicas
}

############################
# Global Preconditions
############################

resource "null_resource" "preconditions" {
  triggers = {
    size_ok = tostring(local.size_ok)
  }

  lifecycle {
    precondition {
      condition     = local.size_ok
      error_message = "Требование min_replicas <= desired_replicas <= max_replicas нарушено."
    }
  }
}

############################
# AWS (ASG + Launch Template)
############################

# -------- AWS Variables --------
variable "aws_vpc_subnet_ids" {
  description = "Список приватных Subnet IDs для размещения ASG"
  type        = list(string)
  default     = []
}

variable "aws_security_group_ids" {
  description = "Список Security Group IDs"
  type        = list(string)
  default     = []
}

variable "aws_instance_profile_name" {
  description = "Имя IAM Instance Profile (если требуется)"
  type        = string
  default     = null
}

variable "aws_ami_id" {
  description = "AMI ID для инстансов"
  type        = string
  default     = null
}

variable "aws_instance_type" {
  description = "Тип инстанса (например, m6i.large)"
  type        = string
  default     = "m6i.large"
}

variable "aws_root_device_name" {
  description = "Имя корневого устройства"
  type        = string
  default     = "/dev/xvda"
}

variable "aws_root_volume" {
  description = "Параметры корневого диска"
  type = object({
    size           = number
    type           = string
    encrypted      = bool
    kms_key_id     = optional(string)
    delete_on_termination = optional(bool, true)
  })
  default = {
    size      = 50
    type      = "gp3"
    encrypted = true
  }
}

variable "aws_target_group_arns" {
  description = "Список Target Group ARNs для регистрации инстансов"
  type        = list(string)
  default     = []
}

variable "aws_health_check_type" {
  description = "Тип health-check (EC2 или ELB)"
  type        = string
  default     = "EC2"
}

variable "health_check_grace_period" {
  description = "Grace период перед health-check (сек.)"
  type        = number
  default     = 300
}

variable "aws_capacity_rebalance" {
  description = "Включить Capacity Rebalance для ASG"
  type        = bool
  default     = true
}

variable "aws_termination_policies" {
  description = "Политики завершения для ASG"
  type        = list(string)
  default     = ["OldestLaunchTemplate", "OldestInstance", "Default"]
}

# -------- AWS Resources --------

resource "aws_launch_template" "this" {
  count = var.platform == "aws" ? 1 : 0

  name_prefix   = "${var.name}-lt-"
  image_id      = var.aws_ami_id
  instance_type = var.aws_instance_type

  update_default_version = true

  vpc_security_group_ids = var.aws_security_group_ids

  iam_instance_profile {
    name = var.aws_instance_profile_name
  }

  block_device_mappings {
    device_name = var.aws_root_device_name
    ebs {
      volume_size           = var.aws_root_volume.size
      volume_type           = var.aws_root_volume.type
      encrypted             = var.aws_root_volume.encrypted
      delete_on_termination = coalesce(var.aws_root_volume.delete_on_termination, true)
      kms_key_id            = try(var.aws_root_volume.kms_key_id, null)
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # IMDSv2
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }

  user_data = var.user_data == null ? null : base64encode(var.user_data)
}

resource "aws_autoscaling_group" "this" {
  count = var.platform == "aws" ? 1 : 0

  name                      = "${var.name}-asg"
  max_size                  = var.max_replicas
  min_size                  = var.min_replicas
  desired_capacity          = var.desired_replicas
  vpc_zone_identifier       = var.aws_vpc_subnet_ids
  health_check_type         = var.aws_health_check_type
  health_check_grace_period = var.health_check_grace_period
  capacity_rebalance        = var.aws_capacity_rebalance
  target_group_arns         = var.aws_target_group_arns
  default_cooldown          = 60
  wait_for_capacity_timeout = "10m"

  launch_template {
    id      = aws_launch_template.this[0].id
    version = "$Latest"
  }

  dynamic "tag" {
    for_each = [for k, v in local.common_tags : { k = k, v = v }]
    content {
      key                 = tag.value.k
      value               = tag.value.v
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 60
    }
    triggers = ["launch_template"]
  }
}

############################
# GCP (Instance Template + Regional MIG)
############################

# -------- GCP Variables --------
variable "gcp_project" {
  description = "GCP Project ID"
  type        = string
  default     = null
}

variable "gcp_region" {
  description = "GCP Region"
  type        = string
  default     = null
}

variable "gcp_zones" {
  description = "Список зон для распределения MIG (опц.)"
  type        = list(string)
  default     = []
}

variable "gcp_network" {
  description = "Имя/ссылка на сеть"
  type        = string
  default     = null
}

variable "gcp_subnetwork" {
  description = "Имя/ссылка на сабнет"
  type        = string
  default     = null
}

variable "gcp_assign_public_ip" {
  description = "Выдавать Public IP инстансам"
  type        = bool
  default     = false
}

variable "gcp_machine_type" {
  description = "Тип машины (e.g., e2-standard-4)"
  type        = string
  default     = "e2-standard-4"
}

variable "gcp_image" {
  description = "Образ диска (например, projects/debian-cloud/global/images/family/debian-12)"
  type        = string
  default     = null
}

variable "gcp_disk" {
  description = "Параметры диска"
  type = object({
    size_gb    = number
    type       = string           # pd-balanced | pd-ssd | pd-standard
    kms_key    = optional(string) # Self link KMS
  })
  default = {
    size_gb = 50
    type    = "pd-balanced"
  }
}

variable "gcp_service_account_email" {
  description = "Service Account email (опц.)"
  type        = string
  default     = null
}

variable "gcp_service_account_scopes" {
  description = "Scopes для SA"
  type        = list(string)
  default     = ["https://www.googleapis.com/auth/cloud-platform"]
}

variable "gcp_health_check_self_link" {
  description = "Ссылка на Health Check (опц.)"
  type        = string
  default     = null
}

# -------- GCP Resources --------

resource "google_compute_instance_template" "this" {
  count        = var.platform == "gcp" ? 1 : 0
  project      = var.gcp_project
  name_prefix  = "${var.name}-tmpl-"
  machine_type = var.gcp_machine_type

  disk {
    source_image = var.gcp_image
    auto_delete  = true
    boot         = true
    disk_type    = var.gcp_disk.type
    disk_size_gb = var.gcp_disk.size_gb

    dynamic "disk_encryption_key" {
      for_each = var.gcp_disk.kms_key == null ? [] : [var.gcp_disk.kms_key]
      content {
        kms_key_self_link = disk_encryption_key.value
      }
    }
  }

  network_interface {
    network    = var.gcp_network
    subnetwork = var.gcp_subnetwork

    dynamic "access_config" {
      for_each = var.gcp_assign_public_ip ? [1] : []
      content {}
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = length(local.common_tags) > 0 ? {
    "tags" = jsonencode(local.common_tags)
  } : null

  metadata_startup_script = var.user_data

  service_account {
    email  = var.gcp_service_account_email
    scopes = var.gcp_service_account_scopes
  }

  labels = { for k, v in local.common_tags : lower(replace(k, "/[^a-zA-Z0-9_-]/", "_")) => lower(v) }
}

resource "google_compute_region_instance_group_manager" "this" {
  count   = var.platform == "gcp" ? 1 : 0
  project = var.gcp_project
  region  = var.gcp_region
  name    = "${var.name}-mig"

  base_instance_name = var.name
  target_size        = var.desired_replicas

  version {
    name              = "primary"
    instance_template = google_compute_instance_template.this[0].self_link
  }

  update_policy {
    type                    = "PROACTIVE"
    minimal_action          = "REPLACE"
    max_surge_fixed         = 1
    max_unavailable_fixed   = 0
    replacement_method      = "RECREATE"
    most_disruptive_allowed_action = "REPLACE"
  }

  dynamic "auto_healing_policies" {
    for_each = var.gcp_health_check_self_link == null ? [] : [1]
    content {
      health_check      = var.gcp_health_check_self_link
      initial_delay_sec = 300
    }
  }

  dynamic "distribution_policy_zones" {
    for_each = length(var.gcp_zones) == 0 ? [] : var.gcp_zones
    content {
      zone = distribution_policy_zones.value
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

############################
# Azure (Linux VM Scale Set)
############################

# -------- Azure Variables --------
variable "azure_resource_group_name" {
  description = "Имя Resource Group"
  type        = string
  default     = null
}

variable "azure_location" {
  description = "Регион Azure"
  type        = string
  default     = null
}

variable "azure_subnet_id" {
  description = "ID подсети"
  type        = string
  default     = null
}

variable "azure_sku" {
  description = "SKU VMSS (например, Standard_D4s_v5)"
  type        = string
  default     = "Standard_D4s_v5"
}

variable "azure_image_reference" {
  description = "Ссылка на образ (source_image_reference) — publisher/offer/sku/version"
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
  default = {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}

variable "azure_admin_username" {
  description = "Логин администратора"
  type        = string
  default     = "ubuntu"
}

variable "azure_ssh_public_key" {
  description = "Публичный SSH ключ"
  type        = string
  default     = null
}

variable "azure_assign_public_ip" {
  description = "Назначать публичные IP (по умолчанию — нет)"
  type        = bool
  default     = false
}

variable "azure_disk" {
  description = "Параметры OS диска"
  type = object({
    storage_account_type = string          # Premium_LRS / StandardSSD_LRS / Standard_LRS
    disk_size_gb         = number
    disk_encryption_set_id = optional(string)
    caching              = optional(string, "ReadWrite")
  })
  default = {
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 64
  }
}

variable "azure_identity_type" {
  description = "Тип Managed Identity: SystemAssigned | UserAssigned"
  type        = string
  default     = "SystemAssigned"
}

variable "azure_identity_ids" {
  description = "Список IDs User Assigned Identity (если используется)"
  type        = list(string)
  default     = []
}

variable "azure_lb_backend_address_pool_ids" {
  description = "Список Backend Pool IDs для подключения"
  type        = list(string)
  default     = []
}

variable "azure_health_probe_id" {
  description = "ID Health Probe (опц.)"
  type        = string
  default     = null
}

# -------- Azure Resource --------

resource "azurerm_linux_virtual_machine_scale_set" "this" {
  count               = var.platform == "azure" ? 1 : 0
  name                = "${var.name}-vmss"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  sku                 = var.azure_sku
  instances           = var.desired_replicas
  admin_username      = var.azure_admin_username
  disable_password_authentication = true

  source_image_reference {
    publisher = var.azure_image_reference.publisher
    offer     = var.azure_image_reference.offer
    sku       = var.azure_image_reference.sku
    version   = var.azure_image_reference.version
  }

  dynamic "identity" {
    for_each = [1]
    content {
      type         = var.azure_identity_type
      identity_ids = var.azure_identity_type == "UserAssigned" ? var.azure_identity_ids : null
    }
  }

  admin_ssh_key {
    username   = var.azure_admin_username
    public_key = var.azure_ssh_public_key
  }

  os_disk {
    caching              = try(var.azure_disk.caching, "ReadWrite")
    storage_account_type = var.azure_disk.storage_account_type
    disk_size_gb         = var.azure_disk.disk_size_gb
    disk_encryption_set_id = try(var.azure_disk.disk_encryption_set_id, null)
  }

  upgrade_mode = "Rolling"
  automatic_os_upgrade_policy {
    disable_automatic_rollback = false
    enable_automatic_os_upgrade = true
  }

  network_interface {
    name                          = "${var.name}-nic"
    primary                       = true
    enable_ip_forwarding          = false
    enable_accelerated_networking = true

    ip_configuration {
      name                                   = "${var.name}-ipcfg"
      primary                                = true
      subnet_id                               = var.azure_subnet_id
      load_balancer_backend_address_pool_ids  = var.azure_lb_backend_address_pool_ids

      dynamic "public_ip_address_configuration" {
        for_each = var.azure_assign_public_ip ? [1] : []
        content {
          name = "${var.name}-pip"
        }
      }

      dynamic "health_probe" {
        for_each = var.azure_health_probe_id == null ? [] : [1]
        content {
          id = var.azure_health_probe_id
        }
      }
    }
  }

  boot_diagnostics {
    storage_account_uri = null
  }

  custom_data = var.user_data == null ? null : base64encode(var.user_data)

  tags = local.common_tags
}

############################
# Common Outputs (optional)
############################

output "platform_selected" {
  value = var.platform
}

output "group_name" {
  value = var.name
}

output "effective_tags" {
  value = local.common_tags
}

# Платформенные outputs
output "aws_asg_name" {
  value       = var.platform == "aws" ? aws_autoscaling_group.this[0].name : null
  description = "Имя ASG (AWS)"
}

output "gcp_mig_name" {
  value       = var.platform == "gcp" ? google_compute_region_instance_group_manager.this[0].name : null
  description = "Имя Regional MIG (GCP)"
}

output "azure_vmss_id" {
  value       = var.platform == "azure" ? azurerm_linux_virtual_machine_scale_set.this[0].id : null
  description = "ID VMSS (Azure)"
}
