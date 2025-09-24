terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 6.0.0"
    }
  }
}

############################################
# Core
############################################

variable "name" {
  description = "Базовое имя S3 бакета (уникально в глобальном масштабе)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]{3,63}$", var.name)) && !can(regex("[A-Z_]", var.name))
    error_message = "Имя бакета должно соответствовать правилам S3: 3-63 символа, только a-z, 0-9, точка и дефис."
  }
}

variable "force_destroy" {
  description = "Удалять бакет даже при наличии объектов (использовать осторожно)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Глобальные тэги для ресурсов."
  type        = map(string)
  default     = {}
}

############################################
# Ownership / ACL / Public access
############################################

variable "object_ownership" {
  description = "Политика владения объектами: BucketOwnerEnforced | BucketOwnerPreferred | ObjectWriter."
  type        = string
  default     = "BucketOwnerEnforced"

  validation {
    condition     = contains(["BucketOwnerEnforced", "BucketOwnerPreferred", "ObjectWriter"], var.object_ownership)
    error_message = "object_ownership должен быть одним из: BucketOwnerEnforced, BucketOwnerPreferred, ObjectWriter."
  }
}

variable "acl" {
  description = "ACL бакета. При BucketOwnerEnforced ACL будет игнорироваться AWS."
  type        = string
  default     = "private"

  validation {
    condition     = contains(["private", "public-read", "public-read-write", "authenticated-read", "log-delivery-write"], var.acl)
    error_message = "Недопустимое значение acl."
  }
}

variable "block_public_acls" {
  description = "Включить блокировку публичных ACL."
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "Запретить публичные политики бакета."
  type        = bool
  default     = true
}

variable "ignore_public_acls" {
  description = "Игнорировать выставленные публичные ACL."
  type        = bool
  default     = true
}

variable "restrict_public_buckets" {
  description = "Запретить публичный доступ к бакету."
  type        = bool
  default     = true
}

############################################
# Versioning / Object Lock
############################################

variable "versioning_enabled" {
  description = "Включить версионирование бакета."
  type        = bool
  default     = true
}

variable "object_lock_enabled" {
  description = "Включить Object Lock (требует включения при создании бакета, несовместимо с некоторыми опциями)."
  type        = bool
  default     = false
}

variable "object_lock_default_mode" {
  description = "Режим по умолчанию для Object Lock: GOVERNANCE | COMPLIANCE."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_default_mode)
    error_message = "object_lock_default_mode должен быть GOVERNANCE или COMPLIANCE."
  }
}

variable "object_lock_default_days" {
  description = "Срок удержания (дней) по умолчанию для Object Lock."
  type        = number
  default     = 0

  validation {
    condition     = var.object_lock_default_days >= 0
    error_message = "object_lock_default_days должен быть >= 0."
  }
}

############################################
# Encryption
############################################

variable "encryption" {
  description = <<-EOT
Настройки шифрования:
  - sse_algorithm: AES256 | aws:kms
  - kms_key_arn: ARN KMS-ключа при aws:kms
  - bucket_key_enabled: включить Bucket Keys (экономия запросов к KMS)
EOT
  type = object({
    sse_algorithm     = optional(string, "aws:kms")
    kms_key_arn       = optional(string, null)
    bucket_key_enabled = optional(bool, true)
  })
  default = {}

  validation {
    condition     = contains(["AES256", "aws:kms"], coalesce(var.encryption.sse_algorithm, "aws:kms"))
    error_message = "sse_algorithm должен быть AES256 или aws:kms."
  }
}

############################################
# Access logging
############################################

variable "access_logging" {
  description = <<-EOT
Логирование доступа:
  - enabled: вкл/выкл
  - target_bucket: имя S3 бакета для логов
  - target_prefix: префикс
EOT
  type = object({
    enabled       = optional(bool, false)
    target_bucket = optional(string)
    target_prefix = optional(string, "s3-access-logs/")
  })
  default = {}
}

############################################
# Server-side settings
############################################

variable "request_payer" {
  description = "RequesterPays для бакета (Requester или BucketOwner)."
  type        = string
  default     = "BucketOwner"

  validation {
    condition     = contains(["Requester", "BucketOwner"], var.request_payer)
    error_message = "request_payer должен быть Requester или BucketOwner."
  }
}

variable "cors_rules" {
  description = <<-EOT
Список CORS правил:
  - allowed_methods: ["GET","PUT",...]
  - allowed_origins: ["*","https://example.com"]
  - allowed_headers
  - expose_headers
  - max_age_seconds
EOT
  type = list(object({
    allowed_methods = list(string)
    allowed_origins = list(string)
    allowed_headers = optional(list(string), [])
    expose_headers  = optional(list(string), [])
    max_age_seconds = optional(number, 300)
  }))
  default = []
}

variable "lifecycle_rules" {
  description = <<-EOT
Список Lifecycle правил:
  - id
  - enabled
  - prefix | filter (object)
  - abort_incomplete_multipart_upload_days
  - transition/current_version_transition(s):
      - days | storage_class
  - noncurrent_version_transition(s):
      - noncurrent_days | storage_class
  - expiration:
      - days | expired_object_delete_marker
  - noncurrent_version_expiration:
      - noncurrent_days
EOT
  type = list(object({
    id                                     = string
    enabled                                = bool
    prefix                                 = optional(string)
    filter                                 = optional(any)
    abort_incomplete_multipart_upload_days = optional(number)
    transitions = optional(list(object({
      days          = number
      storage_class = string
    })), [])
    noncurrent_version_transitions = optional(list(object({
      noncurrent_days = number
      storage_class   = string
    })), [])
    expiration = optional(object({
      days                         = optional(number)
      expired_object_delete_marker = optional(bool)
    }))
    noncurrent_version_expiration = optional(object({
      noncurrent_days = number
    }))
  }))
  default = []
}

variable "intelligent_tiering" {
  description = "Включить Intelligent-Tiering для новых объектов (используется вместе с lifecycle правилами)."
  type        = bool
  default     = false
}

############################################
# Replication (CRR/SRR)
############################################

variable "replication" {
  description = <<-EOT
Репликация бакета:
  - enabled
  - role_arn: IAM роль для репликации
  - rules: список правил (id, prefix/filter, storage_class, destination_bucket_arn, metrics/eventual consistency пр.)
  - replica_kms_key_arn: KMS ключ в целевом регионе для SSE-KMS
EOT
  type = object({
    enabled             = optional(bool, false)
    role_arn            = optional(string)
    replica_kms_key_arn = optional(string)
    rules = optional(list(object({
      id                       = string
      status                   = string                      # Enabled | Disabled
      prefix                   = optional(string)
      filter                   = optional(any)
      delete_marker_replication = optional(string)           # Enabled | Disabled
      destination_bucket_arn   = string
      storage_class            = optional(string, "STANDARD")
      priority                 = optional(number, 1)
      metrics = optional(object({
        event_threshold_minutes = optional(number, 15)
        status                  = optional(string, "Enabled")
      }))
      replication_time = optional(object({
        minutes = optional(number, 15)
        status  = optional(string, "Enabled")
      }))
      existing_object_replication = optional(string, "Disabled")
      delete_replication           = optional(string, "Disabled")
    })), [])
  })
  default = {}
}

############################################
# Policy attachments
############################################

variable "bucket_policy_json" {
  description = "Необязательная JSON-политика бакета (string). Если null, не назначается."
  type        = string
  default     = null
}

variable "deny_insecure_transport" {
  description = "Добавить в политику запрет на нешифрованный транспорт (aws:SecureTransport == false)."
  type        = bool
  default     = true
}

variable "allow_list_of_principals" {
  description = "Явный allow для списка principals (например, сервисных аккаунтов или ролей)."
  type        = list(object({
    principal_arn = string
    actions       = list(string)
    resources     = optional(list(string))
    condition     = optional(any)
  }))
  default = []
}

############################################
# Website hosting (optional)
############################################

variable "website" {
  description = <<-EOT
Статический хостинг:
  - enabled
  - index_document
  - error_document
  - redirect_all_requests_to = { host_name, protocol }
  - routing_rules (JSON string)
EOT
  type = object({
    enabled                   = optional(bool, false)
    index_document            = optional(string, "index.html")
    error_document            = optional(string, "error.html")
    redirect_all_requests_to  = optional(object({
      host_name = string
      protocol  = optional(string)
    }))
    routing_rules             = optional(string)
  })
  default = {}
}

############################################
# Access points (optional)
############################################

variable "access_points" {
  description = <<-EOT
Список Access Point’ов:
  - name
  - vpc_id (для VPC-only)
  - policy_json (string)
  - block_public_acls/policy (overrides)
EOT
  type = list(object({
    name                 = string
    vpc_id               = optional(string)
    policy_json          = optional(string)
    block_public_acls    = optional(bool)
    block_public_policy  = optional(bool)
    ignore_public_acls   = optional(bool)
    restrict_public_buckets = optional(bool)
    tags                 = optional(map(string), {})
  }))
  default = []
}

############################################
# Inventory (optional)
############################################

variable "inventory" {
  description = <<-EOT
S3 Inventory отчёты:
  - enabled
  - destination_bucket_arn
  - destination_prefix
  - included_object_versions: Current | All
  - schedule_frequency: Daily | Weekly
  - optional_fields: список дополнительных полей
EOT
  type = object({
    enabled                  = optional(bool, false)
    destination_bucket_arn   = optional(string)
    destination_prefix       = optional(string, "inventory/")
    included_object_versions = optional(string, "Current")
    schedule_frequency       = optional(string, "Daily")
    optional_fields          = optional(list(string), [])
  })
  default = {}
}

############################################
# Event notifications (optional)
############################################

variable "event_notifications" {
  description = <<-EOT
Событийные уведомления:
  - topics: [{ arn, events, filter_prefix, filter_suffix }]
  - queues: [{ arn, events, filter_prefix, filter_suffix }]
  - lambdas: [{ arn, events, filter_prefix, filter_suffix }]
EOT
  type = object({
    topics  = optional(list(object({
      arn           = string
      events        = list(string)
      filter_prefix = optional(string)
      filter_suffix = optional(string)
    })), [])
    queues  = optional(list(object({
      arn           = string
      events        = list(string)
      filter_prefix = optional(string)
      filter_suffix = optional(string)
    })), [])
    lambdas = optional(list(object({
      arn           = string
      events        = list(string)
      filter_prefix = optional(string)
      filter_suffix = optional(string)
    })), [])
  })
  default = {}
}

############################################
# KMS / SSE helpers (optional)
############################################

variable "create_kms_key" {
  description = "Создавать управляемый модулем KMS ключ для SSE-KMS (если kms_key_arn не задан)."
  type        = bool
  default     = false
}

variable "kms_key_deletion_window_in_days" {
  description = "Окно удаления KMS ключа (7-30)."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window_in_days >= 7 && var.kms_key_deletion_window_in_days <= 30
    error_message = "kms_key_deletion_window_in_days должен быть в диапазоне 7..30."
  }
}

############################################
# Validations / Guards
############################################

variable "require_private" {
  description = "Строгая проверка, что бакет не станет публичным."
  type        = bool
  default     = true
}

variable "allowed_storage_classes" {
  description = "Белый список допустимых storage class для lifecycle/replication."
  type        = list(string)
  default     = [
    "STANDARD",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "DEEP_ARCHIVE",
    "GLACIER_IR"
  ]
}
