##############################
# modules/security/iam/outputs.tf
##############################
# Предпосылки:
#  - Ресурсы внутри модуля названы:
#      google_service_account.sa          (for_each по карте сервис-аккаунтов)
#      google_project_iam_binding.bindings (for_each по карте {role => [members]})
#      google_project_iam_member.members   (for_each по карте пар {key => {role, member}})
#  - При иных именах скорректируйте ссылки ниже.

################################
# Service Accounts: сводные выводы
################################

# Карта: account_id => объект с ключевыми атрибутами SA
output "service_accounts_by_id" {
  description = "Сервис-аккаунты, индекс — account_id."
  value = {
    for k, sa in google_service_account.sa :
    k => {
      id          = sa.id
      name        = sa.name
      email       = sa.email
      unique_id   = sa.unique_id
      display_name= sa.display_name
      disabled    = try(sa.disabled, null)
    }
  }
  sensitive = false
}

# Список e-mail всех SA
output "service_account_emails" {
  description = "Список email всех сервис-аккаунтов."
  value       = [for sa in values(google_service_account.sa) : sa.email]
}

# Карта: account_id => email (удобно для ссылок в других модулях)
output "service_account_email_by_id" {
  description = "Отображение account_id → email."
  value       = { for k, sa in google_service_account.sa : k => sa.email }
}

################################
# IAM Bindings (авторитативно на роль)
################################

# Карта: role => список members по ресурсу google_project_iam_binding
output "project_bindings_by_role" {
  description = "Назначения IAM на уровне проекта по ролям (authoritative binding)."
  value = {
    for role, b in google_project_iam_binding.bindings :
    role => {
      role    = b.role
      members = b.members
      etag    = try(b.etag, null)
    }
  }
}

# Плоский список всех членов, фигурирующих в binding-ах (уникальный)
output "project_binding_members_flat" {
  description = "Уникальный плоский список principals из всех binding-ов."
  value = distinct(flatten([
    for b in values(google_project_iam_binding.bindings) : b.members
  ]))
}

################################
# IAM Members (точечные назначения)
################################

# Карта: произвольный ключ => {role, member}
output "project_members" {
  description = "Точечные назначения IAM на уровне проекта (per-member)."
  value = {
    for k, m in google_project_iam_member.members :
    k => {
      role   = m.role
      member = m.member
      etag   = try(m.etag, null)
    }
  }
}

# Агрегация per-member по ролям: role => [members]
output "project_members_grouped_by_role" {
  description = "Перегруппировка per-member назначений по ролям."
  value = {
    for role in distinct([for m in values(google_project_iam_member.members) : m.role]) :
    role => [for m in values(google_project_iam_member.members) : m.member if m.role == role]
  }
}

################################
# Сводная панель по IAM на проекте
################################

# Удобный агрегат для экспорта в другие модули/выводы CI
output "project_iam_overview" {
  description = "Сводка по IAM (bindings + members) на уровне проекта."
  value = {
    bindings = {
      for role, b in google_project_iam_binding.bindings :
      role => b.members
    }
    members = [
      for k, m in google_project_iam_member.members : {
        key    = k
        role   = m.role
        member = m.member
      }
    ]
    principals_total = length(distinct(concat(
      flatten([for b in values(google_project_iam_binding.bindings) : b.members]),
      [for m in values(google_project_iam_member.members) : m.member]
    )))
    roles_total = length(distinct(concat(
      keys(google_project_iam_binding.bindings),
      [for m in values(google_project_iam_member.members) : m.role]
    )))
  }
  sensitive = false
}

################################
# Часто нужные “атомарные” выводы
################################

output "roles_in_bindings" {
  description = "Все роли, управляемые через project_iam_binding."
  value       = sort(keys(google_project_iam_binding.bindings))
}

output "all_principals" {
  description = "Все уникальные principals из bindings и per-member назначений."
  value = sort(distinct(concat(
    flatten([for b in values(google_project_iam_binding.bindings) : b.members]),
    [for m in values(google_project_iam_member.members) : m.member]
  )))
}
