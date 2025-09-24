###############################################################################
# File: ops/terraform/modules/compute/eks-nodegroup/variables.tf
###############################################################################

terraform {
  required_version = ">= 1.6.0"
}

###############################################################################
# Core identifiers
###############################################################################

variable "name" {
  description = "Имя управляемой группы узлов EKS."
  type        = string
}

variable "cluster_name" {
  description = "Имя кластера EKS, к которому относится группа узлов."
  type        = string
}

variable "subnet_ids" {
  description = "Список подсетей для Auto Scaling группы узлов."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "subnet_ids не может быть пустым."
  }
}

variable "node_role_arn" {
  description = "ARN IAM-роли EC2 узлов (используется в instance profile)."
  type        = string
}

###############################################################################
# Capacity / instances / storage
###############################################################################

variable "capacity_type" {
  description = "Тип емкости для узлов: ON_DEMAND | SPOT | CAPACITY_BLOCK."
  type        = string
  default     = "ON_DEMAND"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT", "CAPACITY_BLOCK"], var.capacity_type)
    error_message = "capacity_type должен быть одним из: ON_DEMAND, SPOT, CAPACITY_BLOCK."
  }
}

variable "instance_types" {
  description = "Список типов инстансов EC2 (при использовании без кастомного Launch Template)."
  type        = list(string)
  default     = []
}

variable "disk_size" {
  description = "Размер EBS диска в ГБ для узлов (применимо, если не используется кастомный Launch Template)."
  type        = number
  default     = null
  validation {
    condition     = var.disk_size == null || var.disk_size >= 20
    error_message = "disk_size должен быть не меньше 20 ГБ."
  }
}

###############################################################################
# AMI / Kubernetes versioning
###############################################################################

variable "ami_type" {
  description = "Тип AMI для узлов. Полный перечень допустимых значений соответствует API EKS Nodegroup."
  type        = string
  default     = "AL2023_x86_64_STANDARD"
  validation {
    condition = contains([
      "AL2_x86_64",
      "AL2_x86_64_GPU",
      "AL2_ARM_64",
      "CUSTOM",
      "BOTTLEROCKET_ARM_64",
      "BOTTLEROCKET_x86_64",
      "BOTTLEROCKET_ARM_64_FIPS",
      "BOTTLEROCKET_x86_64_FIPS",
      "BOTTLEROCKET_ARM_64_NVIDIA",
      "BOTTLEROCKET_x86_64_NVIDIA",
      "WINDOWS_CORE_2019_x86_64",
      "WINDOWS_FULL_2019_x86_64",
      "WINDOWS_CORE_2022_x86_64",
      "WINDOWS_FULL_2022_x86_64",
      "AL2023_x86_64_STANDARD",
      "AL2023_ARM_64_STANDARD",
      "AL2023_x86_64_NEURON",
      "AL2023_x86_64_NVIDIA",
      "AL2023_ARM_64_NVIDIA"
    ], var.ami_type)
    error_message = "Неверный ami_type: используйте одно из значений, указанных в документации EKS."
  }
}

variable "version" {
  description = "Минорная версия Kubernetes для группы узлов (например, \"1.31\"). Не задавайте при кастомном AMI в Launch Template."
  type        = string
  default     = null
  validation {
    condition     = var.version == null || can(regex("^\\d+\\.\\d+$", var.version))
    error_message = "version должен иметь формат вида 1.31."
  }
}

variable "release_version" {
  description = "Версия EKS-оптимизированного AMI (например, \"1.32.3-20250715\"). Не указывать при кастомном AMI в Launch Template."
  type        = string
  default     = null
}

###############################################################################
# Scaling / updates
###############################################################################

variable "scaling_config" {
  description = "Конфигурация масштабирования Auto Scaling группы для узлов."
  type = object({
    desired_size = number
    min_size     = number
    max_size     = number
  })
  default = {
    desired_size = 2
    min_size     = 1
    max_size     = 3
  }
  validation {
    condition     = var.scaling_config.min_size <= var.scaling_config.desired_size && var.scaling_config.desired_size <= var.scaling_config.max_size
    error_message = "Должно выполняться min_size <= desired_size <= max_size."
  }
}

variable "update_config" {
  description = "Параметры параллельного обновления узлов. Укажите ровно один из max_unavailable или max_unavailable_percentage."
  type = object({
    max_unavailable             = optional(number)
    max_unavailable_percentage  = optional(number)
  })
  default = null
  validation {
    condition = var.update_config == null || (
      (
        try(var.update_config.max_unavailable, null) != null &&
        try(var.update_config.max_unavailable_percentage, null) == null &&
        try(var.update_config.max_unavailable, 0) >= 1
      ) ||
      (
        try(var.update_config.max_unavailable, null) == null &&
        try(var.update_config.max_unavailable_percentage, null) != null &&
        try(var.update_config.max_unavailable_percentage, 0) >= 1 &&
        try(var.update_config.max_unavailable_percentage, 101) <= 100
      )
    )
    error_message = "Укажите либо max_unavailable (>=1), либо max_unavailable_percentage (1..100). Оба сразу или ни один — недопустимо."
  }
}

variable "force_update_version" {
  description = "Принудительно продолжать обновление, даже если сливы Pod нарушают PDB."
  type        = bool
  default     = false
}

###############################################################################
# Labels / taints
###############################################################################

variable "labels" {
  description = "Kubernetes-лейблы для узлов (key=value)."
  type        = map(string)
  default     = {}
}

variable "taints" {
  description = "Список таинтов для узлов (key/value/effect)."
  type = list(object({
    key    = string
    value  = string
    effect = string # NO_SCHEDULE | PREFER_NO_SCHEDULE | NO_EXECUTE
  }))
  default = []
  validation {
    condition = alltrue([
      for t in var.taints :
      contains(["NO_SCHEDULE", "PREFER_NO_SCHEDULE", "NO_EXECUTE"], t.effect)
    ])
    error_message = "taints[*].effect должен быть одним из: NO_SCHEDULE, PREFER_NO_SCHEDULE, NO_EXECUTE."
  }
}

###############################################################################
# Remote access (SSH/RDP)
###############################################################################

variable "remote_access" {
  description = "Удаленный доступ к узлам (SSH/RDP). Нельзя использовать совместно с кастомным Launch Template."
  type = object({
    ec2_ssh_key               = optional(string)
    source_security_group_ids = optional(list(string), [])
  })
  default = null
}

###############################################################################
# Launch template
###############################################################################

variable "launch_template" {
  description = "Кастомный Launch Template для узлов. При использовании большинство параметров (instance_types, disk_size, remote_access и т.п.) следует настраивать в самом шаблоне."
  type = object({
    id      = optional(string)
    name    = optional(string)
    version = string
  })
  default = null
  validation {
    condition     = var.launch_template == null || (try(var.launch_template.id, null) != null || try(var.launch_template.name, null) != null)
    error_message = "launch_template: требуется указать id или name вместе с version."
  }
}

###############################################################################
# Node auto repair (provider >= v5.83)
###############################################################################

variable "node_repair_enabled" {
  description = "Включить автоматический ремонт узлов (EKS Node Auto Repair). Требуется поддержка в aws_eks_node_group."
  type        = bool
  default     = null
}

###############################################################################
# Tags / timeouts
###############################################################################

variable "tags" {
  description = "Теги для узлов/ресурса группы узлов."
  type        = map(string)
  default     = {}
}

variable "timeouts" {
  description = "Таймауты операций создания/обновления/удаления."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = null
}
