variable "ami_id" {
  description = "AMI ID для запуска EC2 инстанса"
  type        = string
}

variable "instance_type" {
  description = "Тип EC2 инстанса"
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "ID подсети для размещения инстанса"
  type        = string
}

variable "key_name" {
  description = "Имя SSH ключа для доступа к инстансу"
  type        = string
  default     = null
}

variable "associate_public_ip" {
  description = "Назначать ли публичный IP инстансу"
  type        = bool
  default     = false
}

variable "enable_monitoring" {
  description = "Включить детальный мониторинг CloudWatch"
  type        = bool
  default     = true
}

variable "security_group_id" {
  description = "ID группы безопасности, применяемой к инстансу"
  type        = string
}

variable "iam_instance_profile" {
  description = "IAM профиль, назначаемый инстансу"
  type        = string
  default     = null
}

variable "root_volume_size" {
  description = "Размер корневого тома в гигабайтах"
  type        = number
  default     = 30
}

variable "ebs_device_name" {
  description = "Имя дополнительного EBS устройства"
  type        = string
  default     = "/dev/sdb"
}

variable "ebs_volume_size" {
  description = "Размер дополнительного EBS тома в гигабайтах"
  type        = number
  default     = 50
}

variable "instance_name" {
  description = "Тег Name для инстанса"
  type        = string
}

variable "environment" {
  description = "Окружение (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "additional_tags" {
  description = "Дополнительные теги для инстанса"
  type        = map(string)
  default     = {}
}

variable "cpu_credits" {
  description = "Параметр cpu_credits для burstable инстансов"
  type        = string
  default     = "standard"
}
