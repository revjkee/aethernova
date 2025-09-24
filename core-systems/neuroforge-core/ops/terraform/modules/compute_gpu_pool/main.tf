terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

# ------------------------
# ВХОДНЫЕ ПАРАМЕТРЫ
# ------------------------
variable "cluster_name" {
  description = "Имя существующего EKS-кластера"
  type        = string
}

variable "cluster_version" {
  description = "Версия кластера EKS (для привязки Node Group). По умолчанию берется у самого кластера."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Список подсетей для узлов (обычно приватные Subnet IDs)"
  type        = list(string)
}

variable "instance_types" {
  description = "Список типов инстансов для GPU-пула (например: g5.xlarge, p4d.24xlarge)"
  type        = list(string)
  default     = ["g5.xlarge"]
  validation {
    condition = length([
      for t in var.instance_types :
      t if can(regex("^(g[4-6][a-z0-9.]*|p[2-5][a-z0-9.]*)$", t))
    ]) == length(var.instance_types)
    error_message = "instance_types должны быть из GPU семейств AWS: g4/g5/g6/p2/p3/p4/p5."
  }
}

variable "capacity_type" {
  description = "Тип емкости для Node Group: ON_DEMAND или SPOT"
  type        = string
  default     = "ON_DEMAND"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.capacity_type)
    error_message = "capacity_type должен быть ON_DEMAND или SPOT."
  }
}

variable "scaling" {
  description = "Параметры масштабирования: min/max/desired"
  type = object({
    min_size     = number
    max_size     = number
    desired_size = optional(number)
  })
  default = {
    min_size     = 0
    max_size     = 4
    desired_size = 0
  }
}

variable "disk_size_gib" {
  description = "Размер корневого диска каждого узла, GiB"
  type        = number
  default     = 200
  validation {
    condition     = var.disk_size_gib >= 80
    error_message = "disk_size_gib должен быть не меньше 80 GiB для GPU-образов."
  }
}

variable "node_labels" {
  description = "Дополнительные labels для kubelet (добавятся к стандартным)"
  type        = map(string)
  default     = {}
}

variable "node_taints" {
  description = "Список taints узлов. По умолчанию пул таинтится под GPU-нагрузки."
  type = list(object({
    key    = string
    value  = string
    effect = string # NO_SCHEDULE | PREFER_NO_SCHEDULE | NO_EXECUTE
  }))
  default = [
    {
      key    = "nvidia.com/gpu"
      value  = "true"
      effect = "NO_SCHEDULE"
    }
  ]
}

variable "update_config" {
  description = "Параметры RollingUpdate для Node Group"
  type = object({
    max_unavailable = optional(number)
    max_unavailable_percentage = optional(number)
  })
  default = {
    max_unavailable_percentage = 25
  }
}

variable "ami_type" {
  description = "Тип AMI для Managed Node Group"
  type        = string
  default     = "AL2_x86_64_GPU"
}

variable "force_update_version" {
  description = "Принудительное обновление версии при изменении параметров"
  type        = bool
  default     = false
}

variable "enable_remote_access" {
  description = "Разрешить SSH доступ (через key_name и SG). По умолчанию выключено."
  type        = bool
  default     = false
}

variable "ssh_key_name" {
  description = "Имя SSH ключа EC2 (если enable_remote_access=true)"
  type        = string
  default     = null
}

variable "remote_access_security_group_id" {
  description = "ID Security Group для SSH (если enable_remote_access=true)"
  type        = string
  default     = null
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default     = {}
}

# ------------------------
# ДАННЫЕ КЛАСТЕРА
# ------------------------
data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.cluster_name
}

# ------------------------
# IAM РОЛЬ ДЛЯ УЗЛОВ
# ------------------------
resource "aws_iam_role" "nodes" {
  name               = "eks-node-role-gpu-${var.cluster_name}"
  assume_role_policy = data.aws_iam_policy_document.eks_nodes_trust.json

  tags = merge(local.common_tags, {
    "Name" = "eks-node-role-gpu-${var.cluster_name}"
  })
}

data "aws_iam_policy_document" "eks_nodes_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Обязательные управляемые политики для узлов
locals {
  node_managed_policies = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ]

  standard_labels = {
    "workload"           = "gpu"
    "accelerator"        = "nvidia"
    "neuroforge.io/pool" = "gpu"
  }

  common_tags = merge(
    {
      "Project"             = "neuroforge-core"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    },
    var.tags
  )
}

resource "aws_iam_role_policy_attachment" "nodes" {
  for_each   = toset(local.node_managed_policies)
  role       = aws_iam_role["nodes"].name
  policy_arn = each.key
}

# ------------------------
# EKS MANAGED NODE GROUP (GPU)
# ------------------------
resource "aws_eks_node_group" "gpu" {
  cluster_name    = var.cluster_name
  node_group_name = "gpu"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.subnet_ids
  ami_type        = var.ami_type
  capacity_type   = var.capacity_type
  disk_size       = var.disk_size_gib
  instance_types  = var.instance_types

  # Стабильный апгрейд
  update_config {
    max_unavailable            = try(var.update_config.max_unavailable, null)
    max_unavailable_percentage = try(var.update_config.max_unavailable_percentage, null)
  }

  scaling_config {
    min_size     = var.scaling.min_size
    max_size     = var.scaling.max_size
    desired_size = try(var.scaling.desired_size, null)
  }

  labels = merge(local.standard_labels, var.node_labels)

  dynamic "taint" {
    for_each = var.node_taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  # Опциональный доступ по SSH
  dynamic "remote_access" {
    for_each = var.enable_remote_access ? [1] : []
    content {
      ec2_ssh_key               = var.ssh_key_name
      source_security_group_ids = var.remote_access_security_group_id == null ? null : [var.remote_access_security_group_id]
    }
  }

  # Принудительная смена версии, если требуется
  force_update_version = var.force_update_version

  # Обеспечить порядок: сначала роли → потом узлы
  depends_on = [aws_iam_role_policy_attachment.nodes]

  tags = merge(local.common_tags, {
    "Name" = "${var.cluster_name}-gpu"
  })

  lifecycle {
    # Позволяет Cluster Autoscaler управлять desired_size без дрожания плана
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# ------------------------
# ВЫХОДЫ
# ------------------------
output "node_group_name" {
  description = "Имя GPU node group"
  value       = aws_eks_node_group.gpu.node_group_name
}

output "node_role_arn" {
  description = "ARN роли узлов"
  value       = aws_iam_role.nodes.arn
}

output "labels" {
  description = "Итоговые labels узлов"
  value       = aws_eks_node_group.gpu.labels
}

output "taints" {
  description = "Итоговые taints узлов"
  value = [
    for t in aws_eks_node_group.gpu.taint : {
      key    = t.key
      value  = t.value
      effect = t.effect
    }
  ]
}
