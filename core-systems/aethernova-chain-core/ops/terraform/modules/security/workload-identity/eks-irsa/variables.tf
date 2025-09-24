/**
 * Aethernova — Security / Workload Identity (EKS IRSA)
 * File: ops/terraform/modules/security/workload-identity/eks-irsa/variables.tf
 *
 * Назначение:
 *   Промышленная схема переменных для выпуска IAM Roles for Service Accounts (IRSA)
 *   под EKS с гибкой настройкой trust policy, политик доступа, тегирования и K8s SA.
 *
 * Примечания:
 *   - Реализация ресурсов (IAM Role/Policy, aws_iam_openid_connect_provider, kubernetes_service_account и т.д.)
 *     находится в остальных файлах модуля. Здесь — только входные параметры и валидация.
 */

############################################
# Идентификация и теги
############################################

variable "name" {
  description = "Логическое имя модуля/домена (используется в тегах и префиксах)."
  type        = string
}

variable "environment" {
  description = "Среда (dev|staging|prod и т.п.)."
  type        = string
}

variable "region" {
  description = "AWS регион (должен соответствовать конфигурации провайдера)."
  type        = string
}

variable "partition" {
  description = "AWS partition (aws|aws-us-gov|aws-cn). Влияет на ARN-формирование."
  type        = string
  default     = "aws"
  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.partition)
    error_message = "partition must be one of: aws, aws-us-gov, aws-cn."
  }
}

variable "tags" {
  description = "Глобальные теги для всех создаваемых ресурсов."
  type        = map(string)
  default     = {}
}

variable "resource_tags" {
  description = <<EOT
Теги по классам ресурсов. Сливаются поверх 'tags'.
Ключи (необязательно): iam_role, iam_policy, iam_policy_attachment, ksa, oidc_provider
EOT
  type = object({
    iam_role               = optional(map(string), {})
    iam_policy             = optional(map(string), {})
    iam_policy_attachment  = optional(map(string), {})
    ksa                    = optional(map(string), {})
    oidc_provider          = optional(map(string), {})
  })
  default = {}
}

############################################
# Управление OIDC провайдером и EKS
############################################

variable "enable_irsa" {
  description = "Глобальный флаг включения IRSA (создание ролей/политик/привязок)."
  type        = bool
  default     = true
}

variable "cluster_name" {
  description = "Имя EKS кластера для автообнаружения OIDC (если auto_discover_oidc = true)."
  type        = string
  default     = ""
}

variable "auto_discover_oidc" {
  description = "Автообнаружение OIDC провайдера по имени кластера (cluster_name)."
  type        = bool
  default     = true
}

variable "oidc_provider" {
  description = <<EOT
Ручная спецификация OIDC провайдера для IRSA, если автообнаружение отключено или недоступно.
issuer_url: URL-issuer OpenID (например, https://oidc.eks.<region>.amazonaws.com/id/<id>)
arn: ARN IAM OIDC провайдера (если уже создан)
audiences: список допустимых аудиторий (обычно включает 'sts.amazonaws.com')
EOT
  type = object({
    issuer_url = optional(string, "")
    arn        = optional(string, "")
    audiences  = optional(list(string), ["sts.amazonaws.com"])
  })
  default = {}
}

############################################
# Параметры по умолчанию для выпускаемых ролей
############################################

variable "role_defaults" {
  description = <<EOT
Значения по умолчанию для всех создаваемых IAM ролей, если не переопределено на уровне service_account.
path: IAM путь, например '/service-role/'
permissions_boundary_arn: ARN permissions boundary (опционально)
max_session_duration: длительность сессии STS (сек), 3600..43200
role_name_prefix: префикс имени роли
policy_name_prefix: префикс имен inline/managed связок, создаваемых модулем
trust_mode: 'strict' (строгое соответствие subject) или 'wildcard' (маски по subject)
additional_trust_conditions: дополнительные условия в trust policy (map строк или произвольная структура, трактуется реализацией)
EOT
  type = object({
    path                      = optional(string, "/service-role/")
    permissions_boundary_arn  = optional(string)
    max_session_duration      = optional(number, 3600)
    role_name_prefix          = optional(string, "irsa-")
    policy_name_prefix        = optional(string, "irsa-")
    trust_mode                = optional(string, "strict")
    additional_trust_conditions = optional(any)
  })
  default = {}
  validation {
    condition     = contains(["strict", "wildcard"], coalesce(var.role_defaults.trust_mode, "strict"))
    error_message = "role_defaults.trust_mode must be 'strict' or 'wildcard'."
  }
}

############################################
# Массовое объявление IRSA для сервис-аккаунтов
############################################

variable "service_accounts" {
  description = <<EOT
Карта сервис-аккаунтов (ключ — логическое имя), для каждого создаётся IAM роль (если enabled) и, опционально, сам K8s ServiceAccount.

Поля:
  namespace  (string)  — пространство имён K8s
  name       (string)  — имя ServiceAccount в K8s
  enabled    (bool)    — включает выпуск роли/привязок для записи
  create_k8s_service_account (bool) — создавать ли ServiceAccount в кластере
  ksa_annotations (map[string]) — аннотации SA (например, для вывода iamRoleArn)
  ksa_labels      (map[string]) — метки SA
  automount_service_account_token (bool) — автомонтирование токена (по умолчанию true)

  role:
    name_override           (string)  — явное имя IAM роли (иначе сгенерируется)
    description             (string)
    path                    (string)  — IAM путь
    permissions_boundary_arn(string)  — ARN границы разрешений
    max_session_duration    (number)  — 3600..43200

  policies:
    managed_policy_arns     (list[string]) — список присоединяемых AWS Managed/Customer Managed ARNs
    inline_policies         (map(string))  — имя -> JSON (политика в формате JSON строкой)
    statements              (list[object]) — декларативные statements для синтеза inline политики:
      - sid        (string, optional)
      - effect     (string: Allow|Deny)
      - actions    (list[string])
      - resources  (list[string])
      - condition  (any, optional) — структура условий JSON

  trust:
    audiences               (list[string]) — аудитории, по умолчанию из oidc_provider.audiences
    subjects                (list[string]) — допустимые subjects вида 'system:serviceaccount:<ns>:<name>'
    subject_mode            (string)       — 'strict' или 'wildcard' (маски в subjects разрешены при wildcard)
    additional_conditions   (any)          — дополнительные условия к trust policy

  tags (map[string]) — дополнительные теги для ролей/политик/SA конкретной записи
EOT
  type = map(object({
    namespace   = string
    name        = string
    enabled     = optional(bool, true)

    create_k8s_service_account        = optional(bool, false)
    ksa_annotations                   = optional(map(string), {})
    ksa_labels                        = optional(map(string), {})
    automount_service_account_token   = optional(bool, true)

    role = optional(object({
      name_override            = optional(string)
      description              = optional(string, "")
      path                     = optional(string)
      permissions_boundary_arn = optional(string)
      max_session_duration     = optional(number)
    }), {})

    policies = optional(object({
      managed_policy_arns = optional(list(string), [])
      inline_policies     = optional(map(string), {})
      statements = optional(list(object({
        sid       = optional(string)
        effect    = string
        actions   = list(string)
        resources = list(string)
        condition = optional(any)
      })), [])
    }), {})

    trust = optional(object({
      audiences             = optional(list(string))
      subjects              = optional(list(string), [])
      subject_mode          = optional(string, "strict")
      additional_conditions = optional(any)
    }), {})

    tags = optional(map(string), {})
  }))
  default = {}

  # Базовые проверки корректности
  validation {
    condition = alltrue([
      for sa_key, sa in var.service_accounts :
      length(sa.namespace) > 0 && length(sa.name) > 0
    ])
    error_message = "Каждая запись service_accounts должна содержать ненулевые 'namespace' и 'name'."
  }
  validation {
    condition = alltrue([
      for sa_key, sa in var.service_accounts :
      contains(["strict","wildcard"], coalesce(sa.trust.subject_mode, "strict"))
    ])
    error_message = "trust.subject_mode поддерживает только 'strict' или 'wildcard'."
  }
  validation {
    condition = alltrue([
      for sa_key, sa in var.service_accounts :
      (length(coalesce(sa.policies.managed_policy_arns, [])) > 0)
      || (length(coalesce(sa.policies.inline_policies, {})) > 0)
      || (length(coalesce(sa.policies.statements, [])) > 0)
    ])
    error_message = "Для каждой записи service_accounts требуется задать хотя бы одну политику: managed_policy_arns, inline_policies или statements."
  }
}

############################################
# Контроль и расширенные настройки
############################################

variable "strict_validation" {
  description = "Включить дополнительные проверки согласованности входов."
  type        = bool
  default     = true
}

variable "expose_debug_outputs" {
  description = "Публиковать дополнительные отладочные outputs (например, вычисленные ARNs и subjects)."
  type        = bool
  default     = false
}

############################################
# Доп. валидации верхнего уровня
############################################

variable "role_name_global_suffix" {
  description = "Глобальный суффикс для имён IAM ролей (опционально; полезно при мульти-аккаунтах)."
  type        = string
  default     = ""
}

variable "policy_name_global_suffix" {
  description = "Глобальный суффикс для имён IAM политик (опционально)."
  type        = string
  default     = ""
}

# Необязательная защита от пустого кластера при auto_discover_oidc
variable "fail_if_cluster_missing_for_autodiscovery" {
  description = "Падать с ошибкой, если auto_discover_oidc = true, но cluster_name пустой."
  type        = bool
  default     = true
}
