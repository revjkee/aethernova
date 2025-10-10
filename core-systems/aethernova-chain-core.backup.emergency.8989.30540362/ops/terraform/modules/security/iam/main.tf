terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0"
    }
  }
}

########################################
# ВХОДНЫЕ ДАННЫЕ МОДУЛЯ
########################################

variable "project_id" {
  description = "ID GCP проекта, в котором применяются IAM-привязки и создаются ресурсы."
  type        = string
}

# Создаваемые сервис-аккаунты (SA)
variable "service_accounts" {
  description = <<EOT
Карта сервис-аккаунтов: ключ — id/account_id, значения — атрибуты.
Если account_id не задан, используется ключ карты.
EOT
  type = map(object({
    display_name = optional(string, null)
    description  = optional(string, null)
    disabled     = optional(bool, false)

    # Проектные роли для этого SA (на сам проект): список ролей (вкл. кастомные).
    project_roles = optional(list(string), [])

    # IAM на сам сервис-аккаунт — кто может impersonate/use/admin этот SA.
    # member в формате principal (например, "user:alice@example.com", "serviceAccount:…").
    sa_iam = optional(list(object({
      role   = string
      member = string
      # Условие (опционально)
      condition = optional(object({
        title       = string
        description = optional(string, null)
        expression  = string
      }))
    })), [])
  }))
  default = {}
}

# Кастомные роли проекта (Least-Privilege — перечисляйте только необходимые permissions)
variable "custom_roles" {
  description = <<EOT
Карта кастомных ролей проекта. Ключ — role_id.
permissions — конкретные разрешения вида "service.resource.verb", НЕ предопределённые роли.
EOT
  type = map(object({
    title       = string
    description = optional(string, null)
    stage       = optional(string, "GA") # ALPHA | BETA | GA | DEPRECATED
    permissions = list(string)
  }))
  default = {}
}

# Проектные привязки ролей (на ресурсы проекта)
variable "project_bindings" {
  description = <<EOT
Карта привязок вида:
  {
    "roles/storage.objectViewer" = {
      members = ["serviceAccount:sa1@proj.iam.gserviceaccount.com", "group:devs@example.com"]
      condition = { title="only-prod", expression="resource.name.startsWith('projects/_/buckets/prod-')" }
    }
  }
EOT
  type = map(object({
    members = list(string)
    condition = optional(object({
      title       = string
      description = optional(string, null)
      expression  = string
    }))
  }))
  default = {}
}

# Проектный Audit Logging (Data Access) через google-beta
variable "audit_logging" {
  description = <<EOT
Включение и настройка audit logging на уровне проекта.
Пример:
{
  enabled = true
  services = {
    "allServices" = {
      log_types        = ["ADMIN_READ","DATA_READ","DATA_WRITE"]
      exempted_members = ["serviceAccount:ci@proj.iam.gserviceaccount.com"]
    }
  }
}
EOT
  type = object({
    enabled  = bool
    services = optional(map(object({
      log_types        = list(string)    # ADMIN_READ | DATA_READ | DATA_WRITE
      exempted_members = optional(list(string), [])
    })), {})
  })
  default = {
    enabled = false
  }
}

########################################
# ЛОКАЛЫ
########################################

locals {
  project_id = var.project_id

  # Нормализованные SA с вычислением account_id
  sa_map = {
    for k, v in var.service_accounts :
    (try(v["account_id"], null) == null ? k : v["account_id"]) => merge(v, { account_id = try(v["account_id"], k) })
  }
}

########################################
# СЕРВИС-АККАУНТЫ
########################################

resource "google_service_account" "sa" {
  for_each     = local.sa_map
  project      = local.project_id
  account_id   = each.value.account_id
  display_name = try(each.value.display_name, null)
  description  = try(each.value.description, null)
  disabled     = try(each.value.disabled, false)
}

########################################
# КАСТОМНЫЕ РОЛИ ПРОЕКТА
########################################

resource "google_project_iam_custom_role" "custom" {
  for_each    = var.custom_roles
  project     = local.project_id
  role_id     = each.key
  title       = each.value.title
  description = try(each.value.description, null)
  stage       = try(each.value.stage, "GA")
  permissions = each.value.permissions
}

########################################
# ПРОЕКТНЫЕ ПРИВЯЗКИ РОЛЕЙ (Least-Privilege)
# Используем точечные google_project_iam_member, чтобы не перетирать чужие биндинги.
########################################

resource "google_project_iam_member" "project_bindings" {
  for_each = {
    for role, cfg in var.project_bindings :
    # «расплющиваем» по каждому member, чтобы управлять парами role↔member
    for member in cfg.members :
    "${role}:::${member}" => {
      role      = role
      member    = member
      condition = try(cfg.condition, null)
    }
  }

  project = local.project_id
  role    = each.value.role
  member  = each.value.member

  dynamic "condition" {
    for_each = each.value.condition == null ? [] : [each.value.condition]
    content {
      title       = condition.value.title
      description = try(condition.value.description, null)
      expression  = condition.value.expression
    }
  }
}

########################################
# ПРИВЯЗКИ РОЛЕЙ К СЕРВИС-АККАУНТАМ (кто может impersonate/use/admin SA)
########################################

resource "google_service_account_iam_member" "sa_iam" {
  for_each = {
    for sa_key, sa in local.sa_map :
    for b in try(sa.sa_iam, []) :
    "${sa_key}:::${b.role}:::${b.member}" => {
      sa_email  = google_service_account.sa[sa_key].email
      role      = b.role
      member    = b.member
      condition = try(b.condition, null)
    }
  }

  service_account_id = "projects/${local.project_id}/serviceAccounts/${each.value.sa_email}"
  role               = each.value.role
  member             = each.value.member

  dynamic "condition" {
    for_each = each.value.condition == null ? [] : [each.value.condition]
    content {
      title       = condition.value.title
      description = try(condition.value.description, null)
      expression  = condition.value.expression
    }
  }
}

########################################
# AUDIT LOGGING НА УРОВНЕ ПРОЕКТА (google-beta)
########################################

resource "google_project_iam_audit_config" "audit" {
  provider = google-beta

  for_each = var.audit_logging.enabled
    ? (length(var.audit_logging.services) > 0
        ? var.audit_logging.services
        : tomap({ "allServices" = { log_types = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"], exempted_members = [] } }))
    : {}

  project = local.project_id
  service = each.key # "allServices" или конкретный сервис

  dynamic "audit_log_config" {
    for_each = toset(each.value.log_types)
    content {
      log_type = audit_log_config.value
      exempted_members = try(each.value.exempted_members, [])
    }
  }
}

########################################
# ВЫХОДЫ (минимум для отладки)
########################################

output "service_accounts_emails" {
  description = "Emails созданных сервис-аккаунтов."
  value       = { for k, v in google_service_account.sa : k => v.email }
}

output "custom_roles_names" {
  description = "Полные имена созданных кастомных ролей проекта."
  value       = { for k, v in google_project_iam_custom_role.custom : k => v.name }
}

output "audit_config_services" {
  description = "Сервисы, для которых включён audit logging (если включён)."
  value       = try(keys(google_project_iam_audit_config.audit), [])
}
