variable "region" {
  description = "AWS регион для создания ресурсов"
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Имя для ресурсов, создаваемых в этом модуле"
  type        = string
  default     = "default-vpc"
}

variable "cidr_block" {
  description = "CIDR блок для VPC"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.cidr_block))
    error_message = "cidr_block должен быть корректным CIDR (например, 10.0.0.0/16)"
  }
}

variable "instance_tenancy" {
  description = "Тип тенантности инстансов (default, dedicated, host)"
  type        = string
  default     = "default"
  validation {
    condition     = contains(["default", "dedicated", "host"], var.instance_tenancy)
    error_message = "instance_tenancy должен быть одним из: default, dedicated, host"
  }
}

variable "tags" {
  description = "Дополнительные теги, применяемые ко всем ресурсам"
  type        = map(string)
  default     = {}
}
