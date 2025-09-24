terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

########################################
# Locals
########################################
locals {
  name_prefix = var.name != "" ? var.name : "security-core-hsm"
  tags = merge(
    {
      "Project"                        = "core-systems"
      "Component"                      = "security-core"
      "IaC"                            = "terraform"
      "Managed-By"                     = "terraform"
      "SecurityCore:Tier"              = "critical"
      "SecurityCore:Module"            = "hsm"
    },
    var.tags
  )
  # Равномерное распределение HSM по подсетям
  subnets_cycled = tolist(var.cluster_subnet_ids)
}

########################################
# Input variables
########################################
variable "vpc_id" {
  type        = string
  description = "ID VPC, где разворачивается CloudHSM."
  validation {
    condition     = can(regex("^vpc-", var.vpc_id))
    error_message = "vpc_id должен быть валидным AWS VPC ID (vpc-xxxxxxxx)."
  }
}

variable "cluster_subnet_ids" {
  type        = set(string)
  description = "Сет подсетей (минимум 2 AZ) для размещения CloudHSM ENI."
  validation {
    condition     = length(var.cluster_subnet_ids) >= 2
    error_message = "Должно быть как минимум 2 подсети в разных AZ для отказоустойчивости."
  }
}

variable "allowed_admin_cidrs" {
  type        = list(string)
  description = "Список CIDR, откуда разрешён доступ админ‑хостов (например, bastion/опер. подсети)."
  default     = []
}

variable "hsm_count" {
  type        = number
  description = "Количество HSM в кластере."
  default     = 2
  validation {
    condition     = var.hsm_count >= 1 && var.hsm_count <= 6
    error_message = "hsm_count должен быть в диапазоне 1..6 (практический предел для пилота — 6)."
  }
}

variable "name" {
  type        = string
  description = "Короткое имя ресурса. Если пусто — используется префикс по умолчанию."
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Дополнительные теги."
  default     = {}
}

variable "enable_kms_custom_key_store" {
  type        = bool
  description = "Создавать ли KMS Custom Key Store, привязанный к CloudHSM."
  default     = false
}

variable "create_test_kms_key" {
  type        = bool
  description = "Создать ли тестовый симметричный KMS ключ в Custom Key Store (только если включён custom keystore)."
  default     = false
}

variable "kms_key_admin_arns" {
  type        = list(string)
  description = "IAM ARN администраторов тестового KMS ключа (если create_test_kms_key=true)."
  default     = []
}

variable "prevent_destroy" {
  type        = bool
  description = "Защитить ли кластер и HSM от уничтожения на уровне Terraform."
  default     = true
}

########################################
# Data sources
########################################
data "aws_vpc" "this" {
  id = var.vpc_id
}

########################################
# Security Group (минимально необходимый)
########################################
resource "aws_security_group" "hsm_admin" {
  name        = "${local.name_prefix}-admin-sg"
  description = "Security group для CloudHSM администрирования и клиентского доступа внутри VPC"
  vpc_id      = var.vpc_id

  # CloudHSM использует защищённые сервисные порты. Открываем только из доверенных CIDR.
  # Базовый набор портов (упрощённо): 2223-2225/TCP для клиента/администрирования кластером.
  dynamic "ingress" {
    for_each = var.allowed_admin_cidrs
    content {
      description = "CloudHSM admin from ${ingress.value}"
      from_port   = 2223
      to_port     = 2225
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  # Внутрикластерное общение по тем же портам — внутри VPC (ограничиваем CIDR VPC)
  ingress {
    description = "Intra-VPC HSM"
    from_port   = 2223
    to_port     = 2225
    protocol    = "tcp"
    cidr_blocks = [data["aws_vpc"].this.cidr_block]
  }

  egress {
    description = "Outbound to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [data["aws_vpc"].this.cidr_block]
  }

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-admin-sg"
  })
}

########################################
# CloudHSM v2 Cluster
########################################
resource "aws_cloudhsm_v2_cluster" "this" {
  hsm_type   = "hsm1.medium"
  subnet_ids = local.subnets_cycled

  # Привязка SG делается на уровне ENI у HSM‑инстансов; сам кластер SG не принимает,
  # но тегируем для трассируемости.
  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-cluster"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }

  timeouts {
    create = "60m"
    delete = "60m"
  }
}

########################################
# HSM Instances (распределение по подсетям)
########################################
resource "aws_cloudhsm_v2_hsm" "this" {
  count             = var.hsm_count
  cluster_id        = aws_cloudhsm_v2_cluster.this.cluster_id
  availability_zone = null
  subnet_id         = local.subnets_cycled[count.index % length(local.subnets_cycled)]

  # Прямого поля `security_group_ids` нет, SG применяется к ENI после инициализации.
  # Рекомендуется обеспечить сетевую изоляцию на уровне подсети/ACL.
  # Тегируем для дальнейшей автоматизации.
  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-hsm-${count.index + 1}"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
    ignore_changes  = [availability_zone] # AWS может изменять при восстановлении
  }

  timeouts {
    create = "60m"
    delete = "60m"
  }
}

########################################
# Optional: AWS KMS Custom Key Store
########################################
resource "aws_kms_custom_key_store" "this" {
  count                     = var.enable_kms_custom_key_store ? 1 : 0
  custom_key_store_name     = "${local.name_prefix}-ckstore"
  cloudhsm_cluster_id       = aws_cloudhsm_v2_cluster.this.cluster_id
  key_store_type            = "AWS_CLOUDHSM"
  trust_anchor_certificate  = aws_cloudhsm_v2_cluster.this.cluster_certificates[0].cluster_certificate

  tags = local.tags

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

########################################
# Optional: Test KMS Key in custom keystore
########################################
resource "aws_kms_key" "test" {
  count                    = var.enable_kms_custom_key_store && var.create_test_kms_key ? 1 : 0
  description              = "Security-core test CMK in CloudHSM-backed custom key store"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 30
  multi_region             = false
  custom_key_store_id      = aws_kms_custom_key_store.this[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnableRootAccount"
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "KeyAdmins"
        Effect = "Allow"
        Principal = {
          AWS = var.kms_key_admin_arns
        }
        Action = [
          "kms:Create*","kms:Describe*","kms:Enable*","kms:List*","kms:Put*",
          "kms:Update*","kms:Revoke*","kms:Disable*","kms:Get*","kms:Delete*",
          "kms:ScheduleKeyDeletion","kms:CancelKeyDeletion","kms:TagResource",
          "kms:UntagResource"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-test-cmk"
  })

  lifecycle {
    prevent_destroy = var.prevent_destroy
  }
}

data "aws_caller_identity" "current" {}

########################################
# Outputs
########################################
output "cluster_id" {
  description = "ID созданного CloudHSM кластера."
  value       = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "cluster_state" {
  description = "Текущее состояние кластера."
  value       = aws_cloudhsm_v2_cluster.this.state
}

output "hsm_ids" {
  description = "Список ID созданных HSM."
  value       = [for h in aws_cloudhsm_v2_hsm.this : h.hsm_id]
}

output "security_group_id" {
  description = "ID SG для администрирования/доступа к HSM."
  value       = aws_security_group.hsm_admin.id
}

output "kms_custom_key_store_id" {
  description = "ID KMS Custom Key Store (если создан)."
  value       = try(aws_kms_custom_key_store.this[0].id, null)
}

output "test_kms_key_id" {
  description = "ID тестового KMS ключа (если создан)."
  value       = try(aws_kms_key.test[0].key_id, null)
}
