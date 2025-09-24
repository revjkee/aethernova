terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

########################################
# ВХОДНЫЕ ДАННЫЕ
########################################

variable "cluster_name" {
  description = "Имя уже существующего EKS‑кластера, куда добавляем compute."
  type        = string

  validation {
    condition     = length(var.cluster_name) > 0
    error_message = "cluster_name обязателен."
  }
}

variable "vpc_id" {
  description = "ID VPC (для SG)."
  type        = string
}

variable "private_subnet_ids" {
  description = "Список приватных подсетей, в которых создаются узлы."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) > 0
    error_message = "Нужно указать хотя бы одну приватную подсеть."
  }
}

variable "cluster_security_group_id" {
  description = "Primary/cluster security group ID EKS‑кластера (для ingress на узлы)."
  type        = string
}

variable "create_node_role" {
  description = "Создавать IAM роль для узлов EC2 (если false — используйте node_role_arn)."
  type        = bool
  default     = true
}

variable "node_role_arn" {
  description = "Готовая IAM роль узлов (если create_node_role = false)."
  type        = string
  default     = null
}

variable "enable_fargate" {
  description = "Создать Fargate pod execution role и профили."
  type        = bool
  default     = false
}

variable "fargate_profiles" {
  description = <<EOF
Опциональные профили Fargate. Ключ — имя профиля.
Пример:
{
  "fp-default" = {
    subnets   = ["subnet-xxx","subnet-yyy"]
    selectors = [
      { namespace = "kube-system", labels = {} },
      { namespace = "jobs",        labels = { "run-on" = "fargate" } }
    ]
    tags = {}
  }
}
EOF
  type = map(object({
    subnets   = list(string)
    selectors = list(object({
      namespace = string
      labels    = optional(map(string), {})
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "node_groups" {
  description = <<EOF
Описание управляемых node group'ов. Ключ — имя ng.
Пример:
{
  "api" = {
    min_size        = 2
    max_size        = 10
    desired_size    = 3
    instance_types  = ["m6i.large"]
    capacity_type   = "ON_DEMAND" # или "SPOT"
    ami_type        = "AL2_x86_64" # AL2_x86_64 | AL2_x86_64_GPU | BOTTLEROCKET_x86_64 | AL2023_x86_64
    version         = null         # или "1.29"
    disk_size       = 50
    labels          = { "workload" = "api" }
    taints          = []
    subnets         = null         # если null — будут var.private_subnet_ids
    tags            = { "k8s.io/cluster-autoscaler/enabled" = "true" }
    enable_launch_template = true
    kubelet_extra_args     = "--max-pods=110" # применимо для AL2/AL2023 с LT+user_data (по умолчанию не задается)
    kms_key_id             = null             # KMS ключ для шифрования EBS (если null — account default)
    ebs_iops               = null             # для gp3
    ebs_throughput         = null             # для gp3
  }
}
EOF
  type = map(object({
    min_size               = number
    max_size               = number
    desired_size           = number
    instance_types         = list(string)
    capacity_type          = string
    ami_type               = string
    version                = optional(string)
    disk_size              = number
    labels                 = optional(map(string), {})
    taints                 = optional(list(object({
      key    = string
      value  = string
      effect = string # NO_SCHEDULE | NO_EXECUTE | PREFER_NO_SCHEDULE
    })), [])
    subnets                = optional(list(string))
    tags                   = optional(map(string), {})
    enable_launch_template = optional(bool, true)
    kubelet_extra_args     = optional(string, null)
    kms_key_id             = optional(string, null)
    ebs_iops               = optional(number)    # gp3 only
    ebs_throughput         = optional(number)    # gp3 only
  }))
  default = {}
}

variable "create_node_security_group" {
  description = "Создавать отдельную SG для узлов (рекомендуется)."
  type        = bool
  default     = true
}

variable "additional_node_sg_ids" {
  description = "Дополнительные SG, которые следует присоединить к узлам."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

########################################
# ЛОКАЛЬНЫЕ ПЕРЕМЕННЫЕ
########################################

locals {
  common_tags = merge(
    {
      "terraform.module" = "zero-trust-core/compute"
      "service"          = "zero-trust-core"
      "managed-by"       = "terraform"
    },
    var.tags
  )

  # Пробег по ng для удобства
  ngs = var.node_groups

  # Проверки
  _ng_nonempty = length(local.ngs) > 0
}

########################################
# IAM ДЛЯ УЗЛОВ (EC2)
########################################

data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}

# IAM роль для узлов (если требуется)
resource "aws_iam_role" "node" {
  count              = var.create_node_role ? 1 : 0
  name               = "${var.cluster_name}-node-role"
  assume_role_policy = data.aws_iam_policy_document.node_trust.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "node_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.${data.aws_partition.this.dns_suffix}"]
    }
  }
}

# Базовые управляемые политики AWS для узлов EKS
resource "aws_iam_role_policy_attachment" "worker_node" {
  count      = var.create_node_role ? 1 : 0
  role       = aws_iam_role.node[0].name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}
resource "aws_iam_role_policy_attachment" "cni" {
  count      = var.create_node_role ? 1 : 0
  role       = aws_iam_role.node[0].name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}
resource "aws_iam_role_policy_attachment" "ecr_ro" {
  count      = var.create_node_role ? 1 : 0
  role       = aws_iam_role.node[0].name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

locals {
  node_role_arn = var.create_node_role ? aws_iam_role.node[0].arn : var.node_role_arn
}

# Предусловие на наличие роли
resource "null_resource" "assert_node_role" {
  lifecycle {
    precondition {
      condition     = local.node_role_arn != null && length(local.node_role_arn) > 0
      error_message = "Не задана IAM роль для узлов (node_role_arn). Либо включите create_node_role, либо укажите node_role_arn."
    }
  }
}

########################################
# SECURITY GROUP ДЛЯ УЗЛОВ
########################################

resource "aws_security_group" "nodes" {
  count       = var.create_node_security_group ? 1 : 0
  name        = "${var.cluster_name}-node-sg"
  description = "Node security group for ${var.cluster_name}"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { "kubernetes.io/cluster/${var.cluster_name}" = "owned" })
}

# Взаимное общение узлов
resource "aws_security_group_rule" "nodes_ingress_self" {
  count                    = var.create_node_security_group ? 1 : 0
  description              = "Node to node"
  type                     = "ingress"
  protocol                 = "-1"
  from_port                = 0
  to_port                  = 0
  security_group_id        = aws_security_group.nodes[0].id
  source_security_group_id = aws_security_group.nodes[0].id
}

# Доступ с control‑plane/cluster SG к kubelet/HTTPS
resource "aws_security_group_rule" "nodes_ingress_from_cluster" {
  count                    = var.create_node_security_group ? 1 : 0
  description              = "From cluster SG to nodes (kubelet/https)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 10250
  to_port                  = 10250
  security_group_id        = aws_security_group.nodes[0].id
  source_security_group_id = var.cluster_security_group_id
}

resource "aws_security_group_rule" "nodes_ingress_from_cluster_https" {
  count                    = var.create_node_security_group ? 1 : 0
  description              = "From cluster SG to nodes (https)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 443
  to_port                  = 443
  security_group_id        = aws_security_group.nodes[0].id
  source_security_group_id = var.cluster_security_group_id
}

# Egress из узлов наружу (можно ужесточить по необходимости)
resource "aws_security_group_rule" "nodes_egress_all" {
  count             = var.create_node_security_group ? 1 : 0
  description       = "Node egress"
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  security_group_id = aws_security_group.nodes[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

locals {
  node_sg_id = var.create_node_security_group ? aws_security_group.nodes[0].id : null
}

########################################
# LAUNCH TEMPLATES ДЛЯ NODE GROUPS
########################################

# Создаем LT только для тех NG, где enable_launch_template = true
resource "aws_launch_template" "ng" {
  for_each = { for k, ng in local.ngs : k => ng if try(ng.enable_launch_template, true) }

  name_prefix = "${var.cluster_name}-${each.key}-"
  # Метаданные — IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Диски (gp3, по умолчанию шифрование)
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = each.value.disk_size
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = try(each.value.kms_key_id, null)
      iops        = try(each.value.ebs_iops, null)
      throughput  = try(each.value.ebs_throughput, null)
    }
  }

  # Сетевые интерфейсы — запрещаем публичный IPv4
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = compact([
      local.node_sg_id,
      var.cluster_security_group_id
    ] ++ var.additional_node_sg_ids)
  }

  # User data (опционально для kubelet_extra_args в AL2/AL2023)
  user_data = try(
    base64encode(
      trimspace(
        <<-BASH
        #!/bin/bash
        /etc/eks/bootstrap.sh ${var.cluster_name} ${each.value.kubelet_extra_args != null ? "--kubelet-extra-args '${each.value.kubelet_extra_args}'" : ""}
        BASH
      )
    ),
    null
  )

  # Теги для инстансов и томов
  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { "Name" = "${var.cluster_name}-${each.key}-node" })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }

  tags = local.common_tags
}

########################################
# УПРАВЛЯЕМЫЕ NODE GROUPS
########################################

resource "aws_eks_node_group" "this" {
  for_each = local.ngs

  cluster_name    = var.cluster_name
  node_group_name = each.key
  node_role_arn   = local.node_role_arn
  subnet_ids      = coalesce(each.value.subnets, var.private_subnet_ids)

  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  capacity_type  = upper(each.value.capacity_type) # SPOT/ON_DEMAND
  ami_type       = each.value.ami_type
  instance_types = each.value.instance_types
  disk_size      = each.value.disk_size

  labels = try(each.value.labels, {})

  dynamic "taints" {
    for_each = try(each.value.taints, [])
    content {
      key    = taints.value.key
      value  = taints.value.value
      effect = taints.value.effect
    }
  }

  # Привязка Launch Template при необходимости
  dynamic "launch_template" {
    for_each = contains(keys(aws_launch_template.ng), each.key) ? [1] : []
    content {
      id      = aws_launch_template.ng[each.key].id
      version = "$Latest"
    }
  }

  # Идентификатор версии Kubernetes для совместимости (необязательно)
  version = try(each.value.version, null)

  # Теги на уровне Node Group
  tags = merge(local.common_tags, try(each.value.tags, {}))

  # Разрешаем Cluster Autoscaler менять desired_size
  lifecycle {
    ignore_changes = [
      scaling_config[0].desired_size,
      tags["k8s.io/cluster-autoscaler/enabled"],
      tags["k8s.io/cluster-autoscaler/${var.cluster_name}"],
    ]
    precondition {
      condition     = each.value.min_size <= each.value.desired_size && each.value.desired_size <= each.value.max_size
      error_message = "Для node group '${each.key}' нарушено условие min <= desired <= max."
    }
  }

  depends_on = [
    null_resource.assert_node_role
  ]
}

########################################
# FARGATE POD EXECUTION ROLE И ПРОФИЛИ (ОПЦИОНАЛЬНО)
########################################

data "aws_iam_policy_document" "fargate_trust" {
  statement {
    sid     = "EKSFargateTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks-fargate-pods.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fargate_pod_exec" {
  count              = var.enable_fargate ? 1 : 0
  name               = "${var.cluster_name}-fargate-pod-exec"
  assume_role_policy = data.aws_iam_policy_document.fargate_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "fargate_pod_exec" {
  count      = var.enable_fargate ? 1 : 0
  role       = aws_iam_role.fargate_pod_exec[0].name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_eks_fargate_profile" "this" {
  for_each = var.enable_fargate ? var.fargate_profiles : {}

  cluster_name           = var.cluster_name
  fargate_profile_name   = each.key
  pod_execution_role_arn = aws_iam_role.fargate_pod_exec[0].arn
  subnet_ids             = each.value.subnets

  dynamic "selector" {
    for_each = each.value.selectors
    content {
      namespace = selector.value.namespace
      labels    = try(selector.value.labels, null)
    }
  }

  tags = merge(local.common_tags, try(each.value.tags, {}))
}

########################################
# ВЫХОДНЫЕ ДАННЫЕ
########################################

output "node_group_names" {
  description = "Имена созданных node group’ов."
  value       = [for k, v in aws_eks_node_group.this : v.node_group_name]
}

output "node_security_group_id" {
  description = "ID SG узлов (если создавалась)."
  value       = local.node_sg_id
}

output "node_role_arn" {
  description = "ARN IAM роли узлов."
  value       = local.node_role_arn
}

output "fargate_profile_names" {
  description = "Имена Fargate профилей (если включено)."
  value       = try([for k, v in aws_eks_fargate_profile.this : v.fargate_profile_name], [])
}
