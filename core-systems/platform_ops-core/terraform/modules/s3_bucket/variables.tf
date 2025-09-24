variable "bucket_name" {
  description = "Имя S3 бакета"
  type        = string
}

variable "acl" {
  description = "Политика доступа к бакету"
  type        = string
  default     = "private"
}

variable "versioning_enabled" {
  description = "Включить версионность для бакета"
  type        = bool
  default     = true
}

variable "noncurrent_version_expiration_days" {
  description = "Количество дней для удаления старых версий объектов"
  type        = number
  default     = 30
}

variable "abort_incomplete_multipart_upload_days" {
  description = "Количество дней для отмены незавершённых multipart-загрузок"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Теги для ресурса"
  type        = map(string)
  default     = {}
}
