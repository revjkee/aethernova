variable "region" {
  description = "AWS регион"
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Имя проекта/модуля"
  type        = string
}

variable "db_identifier" {
  description = "Идентификатор базы данных"
  type        = string
}

variable "engine" {
  description = "Тип движка базы данных"
  type        = string
  default     = "mysql"
  validation {
    condition     = contains(["mysql", "postgres", "mariadb", "oracle-se2", "sqlserver-ex"], var.engine)
    error_message = "engine должен быть mysql, postgres, mariadb, oracle-se2 или sqlserver-ex"
  }
}

variable "engine_version" {
  description = "Версия движка базы данных"
  type        = string
  default     = "8.0"
}

variable "instance_class" {
  description = "Класс инстанса"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Объем хранилища в ГБ"
  type        = number
  default     = 20
  validation {
    condition     = var.allocated_storage >= 20
    error_message = "allocated_storage должен быть не меньше 20 ГБ"
  }
}

variable "storage_type" {
  description = "Тип хранилища"
  type        = string
  default     = "gp2"
  validation {
    condition     = contains(["gp2", "io1", "standard"], var.storage_type)
    error_message = "storage_type должен быть gp2, io1 или standard"
  }
}

variable "subnet_ids" {
  description = "Список ID подсетей для DB subnet group"
  type        = list(string)
}

variable "security_group_ids" {
  description = "Список ID групп безопасности"
  type        = list(string)
}

variable "multi_az" {
  description = "Включить мультизональный режим"
  type        = bool
  default     = false
}

variable "backup_retention_period" {
  description = "Количество дней для хранения резервных копий"
  type        = number
  default     = 7
  validation {
    condition     = var.backup_retention_period >= 0 && var.backup_retention_period <= 35
    error_message = "backup_retention_period должен быть от 0 до 35"
  }
}

variable "apply_immediately" {
  description = "Применять изменения немедленно"
  type        = bool
  default     = false
}

variable "username" {
  description = "Имя пользователя базы данных"
  type        = string
}

variable "password" {
  description = "Пароль пользователя базы данных"
  type        = string
  sensitive   = true
}

variable "parameter_group_name" {
  description = "Имя параметрической группы базы данных"
  type        = string
  default     = null
}

variable "option_group_name" {
  description = "Имя опционной группы базы данных"
  type        = string
  default     = null
}

variable "parameter_group_family" {
  description = "Семейство параметров для группы"
  type        = string
  default     = "mysql8.0"
}

variable "tags" {
  description = "Теги для ресурсов"
  type        = map(string)
  default     = {}
}
