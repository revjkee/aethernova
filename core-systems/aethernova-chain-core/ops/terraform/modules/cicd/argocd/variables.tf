##############################################
# Argo CD via Helm – variables.tf (industrial)
##############################################

variable "enabled" {
  description = "Включает/выключает установку Argo CD через Helm."
  type        = bool
  default     = true
}

variable "name" {
  description = "Имя релиза/логического компонента Argo CD (DNS-1123 label)."
  type        = string
  default     = "argocd"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 63
    error_message = "name должен соответствовать DNS-1123 label: [a-z0-9]([-a-z0-9]*[a-z0-9])?, длина <= 63."
  }
}

variable "namespace" {
  description = "Namespace для установки Argo CD (по умолчанию 'argocd' согласно официальной документации)."
  type        = string
  default     = "argocd"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace)) && length(var.namespace) <= 63
    error_message = "namespace должен соответствовать DNS-1123 label и иметь длину <= 63."
  }
}

variable "create_namespace" {
  description = "Создавать namespace при установке Helm."
  type        = bool
  default     = true
}

variable "helm_repository" {
  description = "Helm-репозиторий чарта Argo CD."
  type        = string
  default     = "https://argoproj.github.io/argo-helm"
  validation {
    condition     = can(regex("^https?://", var.helm_repository))
    error_message = "helm_repository должен быть валидным HTTP(S) URL."
  }
}

variable "helm_chart" {
  description = "Имя Helm-чарта Argo CD."
  type        = string
  default     = "argo-cd"
}

variable "helm_version" {
  description = "Версия Helm-чарта Argo CD (например, 6.7.18). Если null — использовать фиксированную версию в окружении."
  type        = string
  default     = null
  validation {
    condition     = var.helm_version == null || can(regex("^\\d+\\.\\d+\\.\\d+(-[0-9A-Za-z.-]+)?$", var.helm_version))
    error_message = "helm_version должен быть семвером вида MAJOR.MINOR.PATCH (допустимы суффиксы)."
  }
}

variable "helm_wait" {
  description = "Ждать завершения установки/обновления Helm."
  type        = bool
  default     = true
}

variable "helm_atomic" {
  description = "Atomic-установка: откат при ошибке."
  type        = bool
  default     = true
}

variable "helm_timeout_seconds" {
  description = "Таймаут ожидания операций Helm (сек)."
  type        = number
  default     = 600
  validation {
    condition     = var.helm_timeout_seconds >= 60 && var.helm_timeout_seconds <= 7200
    error_message = "helm_timeout_seconds должен быть в диапазоне 60..7200."
  }
}

variable "crds_install" {
  description = "Устанавливать CRDs из чарта (можно отключить и управлять CRDs отдельно)."
  type        = bool
  default     = true
}

variable "helm_values" {
  description = "Карта значений values для чарта argo-cd (будет смержена)."
  type        = map(any)
  default     = {}
}

variable "extra_values_yaml" {
  description = "Список путей к дополнительным values YAML (порядок важен)."
  type        = list(string)
  default     = []
}

variable "global_labels" {
  description = "Глобальные лейблы, добавляемые к создаваемым объектам."
  type        = map(string)
  default     = {}
}

variable "global_annotations" {
  description = "Глобальные аннотации, добавляемые к создаваемым объектам."
  type        = map(string)
  default     = {}
}

##############################################
# Argo CD bootstrap: Projects (AppProject)
##############################################

variable "projects" {
  description = <<-EOT
    Декларация AppProject (массив). Поля соответствуют спецификации Argo CD AppProject.
    Минимум: name, source_repos, destinations. Остальные поля — опциональны.
  EOT
  type = list(object({
    name        = string
    namespace   = optional(string)                 # По умолчанию var.namespace в реализациях модуля
    description = optional(string)
    source_repos = list(string)                    # spec.sourceRepos
    destinations = list(object({                   # spec.destinations
      server    = optional(string)                 # URL кластера (или)
      name      = optional(string)                 # registered cluster name
      namespace = optional(string)
    }))
    # Ограничения ресурсов проекта:
    cluster_resource_whitelist  = optional(list(object({ group = string, kind = string })))
    cluster_resource_blacklist  = optional(list(object({ group = string, kind = string })))
    namespace_resource_whitelist = optional(list(object({ group = string, kind = string })))
    namespace_resource_blacklist = optional(list(object({ group = string, kind = string })))
    # Роли/доступ:
    roles = optional(list(object({
      name        = string
      description = optional(string)
      policies    = optional(list(string))         # rbac policy strings
      groups      = optional(list(string))
      jwt_tokens  = optional(list(map(any)))       # свободная форма под параметры JWT
    })))
    orphaned_resources = optional(object({
      warn   = optional(bool)
      ignore = optional(list(object({ group = string, kind = string })))
    }))
    labels      = optional(map(string))
    annotations = optional(map(string))
  }))
  default = []
  validation {
    condition = alltrue([
      for p in var.projects :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", p.name)) && length(p.name) <= 63
    ])
    error_message = "projects[*].name должен соответствовать DNS-1123 label (длина <= 63)."
  }
}

##############################################
# Argo CD bootstrap: Applications (Application)
##############################################

variable "applications" {
  description = <<-EOT
    Декларация Application (массив). Поддержаны single source (field `source`) и multiple sources (field `sources`).
    См. спецификацию Application, syncPolicy, ignoreDifferences и Helm/kustomize поля.
  EOT
  type = list(object({
    name      = string
    namespace = optional(string)                   # По умолчанию var.namespace в реализациях модуля
    project   = string

    # Назначение:
    destination = object({
      server    = optional(string)
      name      = optional(string)
      namespace = string
    })

    # ЕДИНСТВЕННЫЙ источник (legacy/простой вариант):
    source = optional(object({
      repo_url        = string
      path            = optional(string)
      chart           = optional(string)
      target_revision = optional(string)
      helm = optional(object({
        values        = optional(map(any))
        values_files  = optional(list(string))
        release_name  = optional(string)
        skip_crds     = optional(bool)
        parameters    = optional(list(object({ name = string, value = string })))
      }))
      kustomize = optional(object({
        images    = optional(list(string))
        patches   = optional(list(map(any)))
        commonLabels = optional(map(string))
        commonAnnotations = optional(map(string))
      }))
      directory = optional(object({
        recurse  = optional(bool)
        include  = optional(list(string))
        exclude  = optional(list(string))
        jsonnet  = optional(map(any))
      }))
      ref = optional(string)
    }))

    # НЕСКОЛЬКО источников (предпочтительно при компоновке):
    sources = optional(list(object({
      repo_url        = string
      path            = optional(string)
      chart           = optional(string)
      target_revision = optional(string)
      helm = optional(object({
        values        = optional(map(any))
        values_files  = optional(list(string))
        release_name  = optional(string)
        skip_crds     = optional(bool)
        parameters    = optional(list(object({ name = string, value = string })))
      }))
      kustomize = optional(object({
        images    = optional(list(string))
        patches   = optional(list(map(any)))
        commonLabels = optional(map(string))
        commonAnnotations = optional(map(string))
      }))
      directory = optional(object({
        recurse  = optional(bool)
        include  = optional(list(string))
        exclude  = optional(list(string))
        jsonnet  = optional(map(any))
      }))
      ref = optional(string)
    })))

    sync_policy = optional(object({
      automated = optional(object({
        prune       = optional(bool)
        self_heal   = optional(bool)
        allow_empty = optional(bool)
      }))
      sync_options = optional(list(string))
      retry = optional(object({
        limit   = optional(number)
        backoff = optional(object({
          duration     = optional(string)
          factor       = optional(number)
          max_duration = optional(string)
        }))
      }))
    }))

    revision_history_limit = optional(number)

    ignore_differences = optional(list(object({
      group                 = optional(string)
      kind                  = string
      name                  = optional(string)
      namespace             = optional(string)
      jq_path_expressions   = optional(list(string))
      jsonPointers          = optional(list(string))
    })))

    labels      = optional(map(string))
    annotations = optional(map(string))
  }))
  default = []
  validation {
    condition = alltrue([
      for a in var.applications :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", a.name)) && length(a.name) <= 63
    ])
    error_message = "applications[*].name должен соответствовать DNS-1123 label (длина <= 63)."
  }
}

##############################################
# Репозитории и креденшелы для Argo CD
##############################################

variable "repositories" {
  description = <<-EOT
    Список репозиториев, добавляемых в Argo CD (repo URL/cred). Используйте переменную С УЧЁТОМ чувствительности.
    Поля соответствуют настройкам репозиториев Argo CD (Git, Helm, OCI).
  EOT
  type = list(object({
    url             = string
    name            = optional(string)
    type            = optional(string)             # git|helm|oci
    username        = optional(string)
    password        = optional(string)
    ssh_private_key = optional(string)
    insecure        = optional(bool)
    enable_lfs      = optional(bool)
    tls_client_cert = optional(string)
    tls_client_key  = optional(string)
  }))
  default   = []
  sensitive = true
}

variable "notifications" {
  description = "Конфигурация argo-notifications (configmap/secret в values)."
  type        = map(any)
  default     = {}
}

variable "rbac" {
  description = "Дополнительные RBAC-настройки (например, policy.csv/policy.default) через values."
  type        = map(any)
  default     = {}
}

##############################################
# Внутренние теги/метки для модульной трассируемости
##############################################

variable "module_tags" {
  description = "Технические теги для трассируемости модульных ресурсов."
  type        = map(string)
  default     = {}
}
