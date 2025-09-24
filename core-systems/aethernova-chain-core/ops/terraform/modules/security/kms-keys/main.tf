##############################################
# modules/security/kms-keys/main.tf
##############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0"
    }
  }
}

########################################################
# Variables
########################################################

variable "project_id" {
  description = "ID проекта GCP."
  type        = string
}

variable "location" {
  description = "Регион/локация KMS (например, europe-west1, global)."
  type        = string
}

variable "key_ring_name" {
  description = "Имя создаваемого KMS KeyRing."
  type        = string
}

# Карта ключей: каждый элемент описывает один CryptoKey
variable "keys" {
  description = <<-EOT
    Карта определений KMS-ключей:
    {
      key_name = {
        purpose            = "ENCRYPT_DECRYPT" | "ASYMMETRIC_SIGN" | "ASYMMETRIC_DECRYPT"
        algorithm          = "GOOGLE_SYMMETRIC_ENCRYPTION" | "RSA_SIGN_PSS_2048_SHA256" | ... (см. KMS docs)
        protection_level   = "SOFTWARE" | "HSM"
        rotation_period    = "7776000s"        # >= 86400s; 90 дней = 7776000s
        next_rotation_time = "2025-10-01T00:00:00Z"  # RFC3339; опционально
        labels             = { env = "prod", system = "aethernova" }
        iam = {
          "roles/cloudkms.cryptoKeyEncrypterDecrypter" = [
            "serviceAccount:app-sa@project.iam.gserviceaccount.com"
          ]
          "roles/cloudkms.viewer" = [
            "group:kms-observers@company.com"
          ]
          # Для админов ключа используйте отдельные идентичности:
          # "roles/cloudkms.admin" = ["group:kms-admins@company.com"]
        }
        # Опциональные флаги управления версиями:
        destroy_scheduled_duration = null        # например "2592000s" (30 дней), если потребуется (для версий)
        # Включение ключа по умолчанию:
        is_enabled = true
      }
    }
  EOT
  type = map(object({
    purpose                  = string
    algorithm                = string
    protection_level         = string
    rotation_period          = string
    next_rotation_time       = optional(string)
    labels                   = optional(map(string), {})
    iam                      = optional(map(list(string)), {})
    destroy_scheduled_duration = optional(string)
    is_enabled               = optional(bool, true)
  }))
}

########################################################
# Locals
########################################################

locals {
  project  = var.project_id
  location = var.location

  # Разворачиваем IAM: (key_name, role) => members[]
  key_iam_bindings = merge([
    for kname, kdef in var.keys : {
      for role, members in coalesce(kdef.iam, {}) :
      "${kname}|${role}" => {
        key_name = kname
        role     = role
        members  = members
      }
    }
  ]...)
}

########################################################
# KMS KeyRing
########################################################

resource "google_kms_key_ring" "this" {
  project  = local.project
  name     = var.key_ring_name
  location = local.location

  lifecycle {
    prevent_destroy = true # KeyRing нельзя удалить в GCP; защищаем состояние
  }
}

########################################################
# CryptoKeys (for_each)
########################################################

resource "google_kms_crypto_key" "this" {
  for_each = var.keys

  name            = each.key
  key_ring        = google_kms_key_ring.this.id
  purpose         = each.value.purpose
  rotation_period = each.value.rotation_period

  # Старт ротации можно задать RFC3339 — опционально
  dynamic "next_rotation_time" {
    for_each = each.value.next_rotation_time == null ? [] : [each.value.next_rotation_time]
    content  = next_rotation_time.value
  }

  labels = each.value.labels

  # Управление основными свойствами версии
  version_template {
    algorithm        = each.value.algorithm
    protection_level = each.value.protection_level
  }

  # Управление состоянием ключа
  # (ключ включен/выключен; выключение может блокировать операции шифрования)
  # Если нужен более тонкий контроль, используйте google_kms_crypto_key_version для конкретных версий.
  lifecycle {
    prevent_destroy = true # CryptoKey в GCP не удаляется; меняйте имя при необходимости
  }

  # Не все поля поддерживаются для каждого типа ключа; используем selective ignore
  # чтобы избежать лишних рекреаций из-за меток или будущих несовместимых изменений провайдера.
  # Перечень можно сузить/расширить под вашу политику дрейфа.
  # ignore_changes = [labels]
}

########################################################
# IAM на CryptoKeys (role binding — авторитативно на роль)
########################################################

resource "google_kms_crypto_key_iam_binding" "this" {
  for_each = local.key_iam_bindings

  crypto_key_id = google_kms_crypto_key.this[each.value.key_name].id
  role          = each.value.role
  members       = each.value.members
}

########################################################
# (Опционально) Управление версиями ключей — пример заготовки
########################################################
# Если вам нужно планово создавать новую версию вручную (вне авто-ротации) и делать её primary,
# можно добавить отдельный ресурс версии, однако учтите порядок операций и гонки.
# resource "google_kms_crypto_key_version" "manual" {
#   for_each     = { for k, v in var.keys : k => v if v.is_enabled }
#   crypto_key   = google_kms_crypto_key.this[each.key].id
#   # state = "ENABLED" | "DISABLED" | "DESTROY_SCHEDULED"
#   # destroy_scheduled_duration = each.value.destroy_scheduled_duration
# }

########################################################
# Outputs (минимально необходимые для интеграций)
########################################################

output "key_ring_id" {
  description = "Полный ID KeyRing."
  value       = google_kms_key_ring.this.id
}

output "crypto_keys" {
  description = "Карта созданных ключей: имя => {id, name, purpose, algorithm, protection_level, self_link}."
  value = {
    for k, r in google_kms_crypto_key.this : k => {
      id                = r.id
      name              = r.name
      purpose           = r.purpose
      protection_level  = r.version_template[0].protection_level
      algorithm         = r.version_template[0].algorithm
      self_link         = r.self_link
      rotation_period   = r.rotation_period
      next_rotation_time = try(r.next_rotation_time, null)
      labels            = r.labels
    }
  }
  sensitive = false
}
