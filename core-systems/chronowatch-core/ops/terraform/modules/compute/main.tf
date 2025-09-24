terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

############################
# ВХОДНЫЕ ПАРАМЕТРЫ МОДУЛЯ #
############################

variable "name" {
  description = "Базовое имя ресурсов (узлы EKS)."
  type        = string
}

variable "cluster_name" {
  description = "Имя существующего EKS-кластера."
  type        = string
}

variable "cluster_version" {
  description = "Версия EKS кластера (используется для совместимости nodegroup)."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Список приватных подсетей для узлов."
  type        = list(string)
}

variable "instance_types" {
  description = "Приоритетный список типов инстансов для Node Group."
  type        = list(string)
  default     = ["m6i.large", "m5.large"]
}

variable "capacity_type" {
  description = "Тип емкости: ON_DEMAND или SPOT."
  type        = string
  default     = "SPOT"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.capacity_type)
    error_message = "capacity_type должен быть ON_DEMAND или SPOT."
  }
}

variable "ami_type" {
  description = "Тип AMI для EKS Node Group (без явного AMI в LT)."
  type        = string
  default     = "AL2_x86_64"
  # Примеры допустимых значений: AL2_x86_64, AL2_x86_64_GPU, BOTTLEROCKET_x86_64
}

variable "desired_size" {
  description = "Желаемое количество узлов."
  type        = number
  default     = 3
}

variable "min_size" {
  description = "Минимальное количество узлов."
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Максимальное количество узлов."
  type        = number
  default     = 10
}

variable "root_volume_size_gb" {
  description = "Размер корневого диска, ГБ."
  type        = number
  default     = 60
}

variable "root_volume_type" {
  description = "Тип корневого диска."
  type        = string
  default     = "gp3"
}

variable "root_volume_iops" {
  description = "IOPS для gp3/io1/io2."
  type        = number
  default     = 3000
}

variable "root_volume_throughput" {
  description = "Пропускная способность (MiB/s) для gp3."
  type        = number
  default     = 125
}

variable "kms_key_id" {
  description = "KMS Key ID/ARN для шифрования EBS (опционально)."
  type        = string
  default     = null
}

variable "additional_security_group_ids" {
  description = "Дополнительные SG для сетевых интерфейсов узлов."
  type        = list(string)
  default     = []
}

variable "cluster_security_group_id" {
  description = "Security Group кластера EKS (для inbound от кластера)."
  type        = string
}

variable "labels" {
  description = "Kubernetes labels для Node Group."
  type        = map(string)
  default     = {}
}

variable "taints" {
  description = "Kubernetes taints для Node Group."
  type = list(object({
    key    = string
    value  = string
    effect = string # NO_SCHEDULE | NO_EXECUTE | PREFER_NO_SCHEDULE
  }))
  default = []
}

variable "update_max_unavailable_percentage" {
  description = "Доля недоступных узлов при обновлении Node Group, %."
  type        = number
  default     = 25
}

variable "protect_from_scale_in" {
  description = "Защита узлов от масштабирования вниз (Managed Node Group)."
  type        = bool
  default     = false
}

variable "common_tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

#################
# ЛОКАЛЫ/ТЕГИ   #
#################

locals {
  name_prefix = var.name
  tags = merge({
    "Project"                               = "chronowatch-core"
    "Environment"                           = "prod"
    "ManagedBy"                             = "Terraform"
    "k8s.io/cluster-autoscaler/enabled"     = "true"
    "k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
  }, var.common_tags)
}

###########################
# IAM РОЛЬ ДЛЯ NODE GROUP #
###########################

resource "aws_iam_role" "this" {
  name               = "${local.name_prefix}-node-role"
  assume_role_policy = data.aws_iam_policy_document.nodes_trust.json
  tags               = local.tags
}

data "aws_iam_policy_document" "nodes_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Базовые политики рабочих узлов EKS
resource "aws_iam_role_policy_attachment" "eks_worker" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ecr_ro" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

##############################
# SECURITY GROUP ДЛЯ УЗЛОВ   #
##############################

resource "aws_security_group" "nodes" {
  name        = "${local.name_prefix}-nodes-sg"
  description = "SecurityGroup для воркеров EKS"
  vpc_id      = data.aws_subnet.selected.vpc_id
  tags        = merge(local.tags, { "Name" = "${local.name_prefix}-nodes-sg" })
}

# Разрешаем node-to-node трафик (внутри SG)
resource "aws_security_group_rule" "nodes_ingress_self" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.nodes.id
  self              = true
  description       = "Node-to-node"
}

# Разрешаем трафик от SG кластера (API/контрольная плоскость/аддоны)
resource "aws_security_group_rule" "nodes_ingress_cluster_sg" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.nodes.id
  source_security_group_id = var.cluster_security_group_id
  description              = "Inbound от SG кластера EKS"
}

# Egress наружу
resource "aws_security_group_rule" "nodes_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.nodes.id
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Outbound Internet"
}

# Берём любой сабнет для vpc_id (подсети приватные, но нам нужен только VPC ID)
data "aws_subnet" "selected" {
  id = var.subnet_ids[0]
}

##############################
# LAUNCH TEMPLATE ДЛЯ УЗЛОВ #
##############################

resource "aws_launch_template" "this" {
  name_prefix   = "${local.name_prefix}-lt-"
  update_default_version = true

  # НЕ указываем image_id, чтобы совместно использовать с ami_type в aws_eks_node_group
  # Управляем дисками через block_device_mappings
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted             = true
      kms_key_id            = var.kms_key_id
      volume_size           = var.root_volume_size_gb
      volume_type           = var.root_volume_type
      iops                  = var.root_volume_type == "gp3" ? var.root_volume_iops : null
      throughput            = var.root_volume_type == "gp3" ? var.root_volume_throughput : null
      delete_on_termination = true
    }
  }

  # Жесткая политика IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  # Сетевые интерфейсы: добавляем наш SG и опциональные SG
  network_interfaces {
    delete_on_termination = true
    security_groups       = concat([aws_security_group.nodes.id], var.additional_security_group_ids)
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { "Name" = "${local.name_prefix}-node" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }

  tags = local.tags
}

###########################
# EKS MANAGED NODE GROUP  #
###########################

resource "aws_eks_node_group" "this" {
  cluster_name    = var.cluster_name
  node_group_name = "${local.name_prefix}-ng"
  node_role_arn   = aws_iam_role.this.arn
  subnet_ids      = var.subnet_ids

  # Поддержка нескольких типов инстансов для лучшего подбора емкости
  instance_types = var.instance_types
  capacity_type  = var.capacity_type
  ami_type       = var.ami_type

  scaling_config {
    desired_size = var.desired_size
    min_size     = var.min_size
    max_size     = var.max_size
  }

  # Обновления с контролем недоступности
  update_config {
    max_unavailable_percentage = var.update_max_unavailable_percentage
  }

  # Защита от scale-in (на уровне Managed Node Group)
  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  # Labels
  dynamic "labels" {
    for_each = length(var.labels) > 0 ? [1] : []
    content {
      for k, v in var.labels : k => v
    }
  }

  # Taints
  dynamic "taint" {
    for_each = var.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  # Запираем часть параметров через Launch Template
  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }

  # Совместимость по версии, если задана (обновления API EKS)
  version = var.cluster_version

  # Помечаем теги на ресурсе Node Group
  tags = local.tags

  # Доп. устойчивость планирования обновлений
  force_update_version = true

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker,
    aws_iam_role_policy_attachment.eks_cni,
    aws_iam_role_policy_attachment.ecr_ro,
    aws_iam_role_policy_attachment.ssm_core
  ]
}

#####################
# ВЫХОДНЫЕ ДАННЫЕ   #
#####################

output "node_group_name" {
  description = "Имя Managed Node Group."
  value       = aws_eks_node_group.this.node_group_name
}

output "node_group_arn" {
  description = "ARN Managed Node Group."
  value       = aws_eks_node_group.this.arn
}

output "node_role_arn" {
  description = "ARN IAM роли узлов."
  value       = aws_iam_role.this.arn
}

output "nodes_security_group_id" {
  description = "ID Security Group узлов."
  value       = aws_security_group.nodes.id
}

output "launch_template_id" {
  description = "ID Launch Template."
  value       = aws_launch_template.this.id
}

output "effective_labels" {
  description = "Labels, применённые к Node Group."
  value       = var.labels
}
