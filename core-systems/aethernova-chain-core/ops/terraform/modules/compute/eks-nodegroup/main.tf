#############################################
# compute/eks-nodegroup/main.tf  (industrial)
# Terraform >= 1.5  |  aws >= 5.x
#############################################

terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0, < 2.0.0"
    }
  }
}

#############################################
# Variables (module-scope)
#############################################

variable "cluster_name" {
  description = "Имя существующего EKS-кластера, к которому привязывается Node Group."
  type        = string
}

variable "node_group_name" {
  description = "Имя создаваемой EKS Node Group."
  type        = string
}

variable "subnet_ids" {
  description = "Список subnet IDs для нод."
  type        = list(string)
}

variable "capacity_type" {
  description = "Тип емкости: ON_DEMAND или SPOT."
  type        = string
  default     = "ON_DEMAND"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.capacity_type)
    error_message = "capacity_type должен быть ON_DEMAND или SPOT."
  }
}

variable "instance_types" {
  description = "Список типов инстансов (например, [\"t3.large\"])."
  type        = list(string)
  default     = ["t3.large"]
}

variable "ami_type" {
  description = "Тип AMI для Node Group."
  type        = string
  default     = "AL2_x86_64"
  validation {
    condition = contains([
      "AL2_x86_64",
      "AL2_x86_64_GPU",
      "AL2_ARM_64",
      "BOTTLEROCKET_x86_64",
      "BOTTLEROCKET_ARM_64",
      "AL2023_x86_64_STANDARD",
      "AL2023_x86_64_NVIDIA",
      "AL2023_ARM_64_STANDARD"
    ], var.ami_type)
    error_message = "ami_type имеет недопустимое значение."
  }
}

variable "release_version" {
  description = "Release version (EKS AMI release), опционально."
  type        = string
  default     = ""
}

variable "disk_size" {
  description = "Размер root EBS (ГБ) для нод (используется без Launch Template)."
  type        = number
  default     = 20
  validation {
    condition     = var.disk_size >= 8 && var.disk_size <= 2048
    error_message = "disk_size должен быть 8..2048 ГБ."
  }
}

variable "min_size" {
  description = "Минимальное число нод."
  type        = number
}

variable "desired_size" {
  description = "Желаемое число нод."
  type        = number
}

variable "max_size" {
  description = "Максимальное число нод."
  type        = number
}

variable "labels" {
  description = "Kubernetes labels для нод."
  type        = map(string)
  default     = {}
}

variable "taints" {
  description = "Kubernetes taints для нод."
  type = list(object({
    key    = string
    value  = string
    effect = string # NO_SCHEDULE | NO_EXECUTE | PREFER_NO_SCHEDULE
  }))
  default = []
  validation {
    condition = alltrue([
      for t in var.taints : contains(["NO_SCHEDULE","NO_EXECUTE","PREFER_NO_SCHEDULE"], t.effect)
    ])
    error_message = "effect taint должен быть NO_SCHEDULE | NO_EXECUTE | PREFER_NO_SCHEDULE."
  }
}

variable "update_max_unavailable" {
  description = "Макс. число недоступных нод при обновлении (шт.)."
  type        = number
  default     = null
}

variable "update_max_unavailable_percentage" {
  description = "Макс. недоступных нод при обновлении (%)."
  type        = number
  default     = null
}

variable "force_update_version" {
  description = "Принудительно обновлять версию при несовпадении."
  type        = bool
  default     = false
}

variable "remote_access" {
  description = "Параметры удаленного доступа к нодам (опционально)."
  type = object({
    ec2_ssh_key                = optional(string)
    source_security_group_ids  = optional(list(string))
  })
  default = {}
}

variable "use_launch_template" {
  description = "Использовать ли кастомный Launch Template."
  type        = bool
  default     = false
}

variable "launch_template_id" {
  description = "ID launch template (если use_launch_template=true)."
  type        = string
  default     = ""
}

variable "launch_template_version" {
  description = "Версия launch template (число, спец. '$Latest'/'$Default' не допускается в EKS)."
  type        = string
  default     = ""
}

variable "create_iam_role" {
  description = "Создать IAM роль для нод (true) или использовать существующую (false)."
  type        = bool
  default     = false
}

variable "node_role_name" {
  description = "Имя IAM роли (используется при create_iam_role=true)."
  type        = string
  default     = ""
}

variable "node_role_arn" {
  description = "ARN существующей IAM роли (если create_iam_role=false)."
  type        = string
  default     = ""
}

variable "iam_policy_arns" {
  description = "Список ARNs managed-политик для роли нод (например, EKSWorkerNodePolicy/ECRReadOnly/CNI)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "AWS теги для Node Group и связанных ресурсов."
  type        = map(string)
  default     = {}
}

variable "timeouts" {
  description = "Тайм-ауты операций Node Group."
  type = object({
    create = optional(string, "30m")
    update = optional(string, "60m")
    delete = optional(string, "30m")
  })
  default = {}
}

#############################################
# Locals
#############################################

locals {
  effective_node_role_arn = var.create_iam_role ? aws_iam_role.ng[0].arn : var.node_role_arn

  enable_remote_access = try(length(lookup(var.remote_access, "ec2_ssh_key", "")) > 0, false) || try(length(lookup(var.remote_access, "source_security_group_ids", [])) > 0, false)

  use_lt = var.use_launch_template && var.launch_template_id != "" && var.launch_template_version != ""
}

#############################################
# Optional IAM role for nodes (least-privilege attach is up to caller)
#############################################

resource "aws_iam_role" "ng" {
  count = var.create_iam_role ? 1 : 0

  name               = var.node_role_name != "" ? var.node_role_name : "${var.cluster_name}-${var.node_group_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, {
    "Name"        = var.node_group_name
    "k8s_cluster" = var.cluster_name
    "component"   = "eks-nodegroup"
  })
}

resource "aws_iam_role_policy_attachment" "ng_attach" {
  for_each = var.create_iam_role ? toset(var.iam_policy_arns) : []
  role     = aws_iam_role.ng[0].name
  policy_arn = each.value
}

#############################################
# EKS Managed Node Group
#############################################

resource "aws_eks_node_group" "this" {
  cluster_name    = var.cluster_name
  node_group_name = var.node_group_name

  node_role_arn   = local.effective_node_role_arn
  subnet_ids      = var.subnet_ids
  capacity_type   = var.capacity_type
  ami_type        = var.ami_type

  instance_types  = var.instance_types

  # disk_size применяется только без Launch Template
  dynamic "scaling_config" {
    for_each = [1]
    content {
      min_size     = var.min_size
      desired_size = var.desired_size
      max_size     = var.max_size
    }
  }

  # Только если не используем Launch Template — можно указать disk_size
  dynamic "launch_template" {
    for_each = local.use_lt ? [1] : []
    content {
      id      = var.launch_template_id
      version = var.launch_template_version
    }
  }

  disk_size = local.use_lt ? null : var.disk_size

  # Labels
  labels = var.labels

  # Taints
  dynamic "taint" {
    for_each = var.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  # Update strategy
  dynamic "update_config" {
    for_each = (var.update_max_unavailable != null || var.update_max_unavailable_percentage != null) ? [1] : []
    content {
      max_unavailable            = var.update_max_unavailable
      max_unavailable_percentage = var.update_max_unavailable_percentage
    }
  }

  force_update_version = var.force_update_version
  release_version      = var.release_version != "" ? var.release_version : null

  # Remote access (опционально)
  dynamic "remote_access" {
    for_each = local.enable_remote_access ? [1] : []
    content {
      ec2_ssh_key               = try(var.remote_access.ec2_ssh_key, null)
      source_security_group_ids = try(var.remote_access.source_security_group_ids, null)
    }
  }

  tags = merge(var.tags, {
    "Name"        = var.node_group_name
    "k8s_cluster" = var.cluster_name
    "component"   = "eks-nodegroup"
  })

  timeouts {
    create = try(var.timeouts.create, "30m")
    update = try(var.timeouts.update, "60m")
    delete = try(var.timeouts.delete, "30m")
  }

  lifecycle {
    ignore_changes = [
      labels,                 # допускаем ручное добавление k8s-меток системой
      taint,                  # допускаем управляемые системой taints
      scaling_config[0].desired_size  # чтобы не дрожало при авто-скейлинге
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.ng_attach
  ]
}

#############################################
# Outputs
#############################################

output "node_group_name" {
  description = "Имя созданной EKS Node Group."
  value       = aws_eks_node_group.this.node_group_name
}

output "node_group_arn" {
  description = "ARN созданной EKS Node Group."
  value       = aws_eks_node_group.this.arn
}

output "node_role_arn" {
  description = "Использованная IAM роль нод."
  value       = local.effective_node_role_arn
}
