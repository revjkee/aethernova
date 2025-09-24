// aethernova-chain-core/ops/terraform/modules/security/kms-keys/variables.tf
// Промышленный набор входных переменных для управления KMS Key Ring и Crypto Keys.
// Опирается на официальные ресурсы: google_kms_key_ring, google_kms_crypto_key,
// google_kms_crypto_key_iam_* и правила ротации (rotation_period в секундах).

variable "project_id" {
  description = "ID проекта GCP, в котором создаются KMS ресурсы."
  type        = string
}

variable "location" {
  description = "Регион/локация KMS (например, us-central1, europe-west1)."
  type        = string
}

variable "key_ring_name" {
  description = "Имя KMS Key Ring. KeyRing не удаляется из GCP даже после уничтожения в Terraform."
  type        = string
}

variable "labels" {
  description = "Глобальные метки, которые применяются по умолчанию ко всем ключам, если не переопределены локально."
  type        = map(string)
  default     = {}
}

variable "default_rotation_period_seconds" {
  description = "Период авто-ротации по умолчанию в секундах (минимум > 86400). Пример: 90 дней = 7776000."
  type        = number
  default     = 7776000
  validation {
    condition     = var.default_rotation_period_seconds > 86400
    error_message = "rotation_period должен быть больше 86400 секунд (более суток)."
  }
}

variable "default_protection_level" {
  description = "Уровень защиты ключей по умолчанию (SOFTWARE, HSM, EXTERNAL)."
  type        = string
  default     = "SOFTWARE"
  validation {
    condition = contains(["SOFTWARE", "HSM", "EXTERNAL"], var.default_protection_level)
    error_message = "Допустимые значения: SOFTWARE, HSM, EXTERNAL."
  }
}

variable "default_purpose" {
  description = "Назначение ключа по умолчанию: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC."
  type        = string
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition = contains(["ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC"], var.default_purpose)
    error_message = "Допустимые значения: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC."
  }
}

variable "default_algorithm" {
  description = <<-EOT
  Алгоритм версии ключа по умолчанию для version_template.algorithm.
  Для симметричных ключей используйте GOOGLE_SYMMETRIC_ENCRYPTION.
  Для асимметричных выберите поддерживаемый алгоритм (например, RSA_SIGN_PSS_2048_SHA256, EC_SIGN_P256_SHA256, RSA_DECRYPT_OAEP_2048_SHA256 и т.д.).
  EOT
  type    = string
  default = "GOOGLE_SYMMETRIC_ENCRYPTION"
}

variable "prevent_destroy" {
  description = "Глобальный флаг: добавлять ли lifecycle.prevent_destroy ключам как защиту от случайного удаления."
  type        = bool
  default     = true
}

variable "create_key_ring" {
  description = "Создавать ли Key Ring внутри модуля. Если false — предполагается, что кейринг уже существует."
  type        = bool
  default     = true
}

variable "keys" {
  description = <<-EOT
  Декларативное описание KMS-ключей.
  Ключ карты — логическое имя; будет использоваться для генерации terraform-ресурсов и имени ключа, если name не указан.
  Поля:
    name                — (опц.) Явное имя ключа; по умолчанию = ключ карты.
    purpose             — (опц.) Назначение; по умолчанию var.default_purpose.
    protection_level    — (опц.) SOFTWARE|HSM|EXTERNAL; по умолчанию var.default_protection_level.
    rotation_period_s   — (опц.) Период авто-ротации в секундах; по умолчанию var.default_rotation_period_seconds.
    labels              — (опц.) Метки уровня ключа; мерджатся с var.labels.
    import_only         — (опц.) true, если ключ только для импорта версий (EXTERNAL/импортируемые кейсы).
    purpose_notes       — (опц.) Комментарий для потребителей (избегайте секретов).
    version_template    — (опц.) Объект:
         algorithm         — строка, например GOOGLE_SYMMETRIC_ENCRYPTION (для симметричных) либо RSA_*/EC_* и др.
         protection_level  — (опц.) Может переопределить protection_level на уровне версии.
    iam_bindings        — (опц.) Список IAM-биндингов вида:
         [{ role = "roles/cloudkms.cryptoKeyEncrypterDecrypter", members = ["serviceAccount:..."] }, ...]
    prevent_destroy     — (опц.) Локальное переопределение глобального prevent_destroy.
  EOT
  type = map(object({
    name             = optional(string)
    purpose          = optional(string)
    protection_level = optional(string)
    rotation_period_s = optional(number)
    labels           = optional(map(string), {})
    import_only      = optional(bool, false)
    purpose_notes    = optional(string)
    version_template = optional(object({
      algorithm        = string
      protection_level = optional(string)
    }))
    iam_bindings = optional(list(object({
      role    = string
      members = list(string)
    })), [])
    prevent_destroy = optional(bool)
  }))
  default = {}
  validation {
    condition = alltrue([
      for k, v in var.keys :
      (
        // Проверка purpose (если задан)
        (v.purpose == null || contains(["ENCRYPT_DECRYPT","ASYMMETRIC_SIGN","ASYMMETRIC_DECRYPT","MAC"], v.purpose))
        &&
        // Проверка protection_level (если задан)
        (v.protection_level == null || contains(["SOFTWARE","HSM","EXTERNAL"], v.protection_level))
        &&
        // Проверка rotation_period_s (если задан)
        (v.rotation_period_s == null || v.rotation_period_s > 86400)
      )
    ])
    error_message = "Поля purpose/protection_level/rotation_period_s имеют недопустимые значения."
  }
}

variable "iam_bindings_global" {
  description = "Глобальные IAM-биндинги для всех ключей (мердж с локальными iam_bindings ключей)."
  type = list(object({
    role    = string
    members = list(string)
  }))
  default = []
}

variable "enable_iam_avoid_public" {
  description = "Безопасность: дополнительно валидировать отсутствие allUsers/allAuthenticatedUsers в IAM."
  type        = bool
  default     = true
}

variable "kms_admins" {
  description = "Список субъектов (members) с ролью администрирования ключей (например, roles/cloudkms.admin) на уровне проекта/кейринга (используется, если вы это реализуете в корневом модуле)."
  type        = list(string)
  default     = []
}

// Вспомогательные вычисляемые ограничения/настройки — оставлены переменными
// для удобства переопределения из корневого модуля/окружения.

variable "deny_public_principals" {
  description = "Список запрещенных членов IAM для проверки (защита от публичного доступа)."
  type        = set(string)
  default     = [
    "allUsers",
    "allAuthenticatedUsers",
  ]
}
