# aethernova-chain-core/ops/terraform/modules/cicd/runners/variables.tf
#
# Требования к фичам типов/валидаций см.:
# - Input variables + validation: https://developer.hashicorp.com/terraform/language/values/variables
# - variable block reference (validation): https://developer.hashicorp.com/terraform/language/block/variable
# - Optional object attributes: https://developer.hashicorp.com/terraform/language/expressions/type-constraints
#
# GitHub Actions runners (метки/группы/область регистрации):
# - Labels & scope (repo/org/enterprise): https://docs.github.com/actions/hosting-your-own-runners/using-labels-with-self-hosted-runners
# - Managing with runner groups: https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
# - Adding runners (token time-limited): https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners
# - REST API (регистрация токена и управление): https://docs.github.com/en/rest/actions
#
# GitLab Runners (регистрация/теги/уровни доступа):
# - Registering runners: https://docs.gitlab.com/runner/register/
# - Configure runners (tags, run_untagged, protected): https://docs.gitlab.com/ci/runners/configure_runners/
# - Runners API (access_level values): https://docs.gitlab.com/api/runners/

############################################
# Общие параметры модуля
############################################

variable "name_prefix" {
  type        = string
  description = "Префикс имени/ресурсов раннеров, используется в именовании инфраструктуры/меток."
  default     = "aethernova-runner"
}

variable "runner_count" {
  type        = number
  description = "Число экземпляров раннеров, которые планируется запускать модулем."
  default     = 1

  validation {
    condition     = floor(var.runner_count) == var.runner_count && var.runner_count >= 1
    error_message = "runner_count должен быть целым числом ≥ 1."
  }
}

############################################
# GitHub Actions self-hosted runners
############################################

variable "github" {
  # Используем optional() для объектных атрибутов (официальная поддержка optional в типах объектов).
  # Документация: Type Constraints → Optional Object Type Attributes.
  type = object({
    enabled       = bool
    # Область регистрации раннера: на репозитории, в организации или enterprise.
    # Официально: runners могут находиться на уровне repository/organization/enterprise.
    # Источник: docs.github.com → using labels with self-hosted runners.
    scope         = string                                    # "repository" | "organization" | "enterprise"
    # Для scope = "repository" нужно owner/repo, для "organization" — org, для "enterprise" — enterprise slug.
    repository    = optional(string)                           # формат owner/repo
    organization  = optional(string)
    enterprise    = optional(string)

    # Runner group в организации/enterprise (если используется).
    runner_group  = optional(string)

    # Список меток раннера (labels), по которым воркфлоу выбирает раннер.
    # Источник: docs.github.com → using labels with self-hosted runners.
    labels        = optional(list(string), [])

    # Платформа раннера (для подбора образов/архитектуры при провижининге).
    os            = optional(string, "linux")                  # "linux" | "windows" | "macos"
    arch          = optional(string, "x64")                    # "x64" | "arm64"
  })

  default = {
    enabled = false
    scope   = "repository"
  }

  validation {
    # Разрешенные значения scope.
    condition     = contains(["repository", "organization", "enterprise"], var.github.scope)
    error_message = "github.scope должен быть одним из: repository, organization, enterprise (см. GitHub docs о размещении self-hosted runners)."
  }

  validation {
    # Если включен и scope=repository, должен быть задан repository формата owner/repo.
    condition = (
      !var.github.enabled
      || var.github.scope != "repository"
      || (
        can(regex("^[^/]+/[^/]+$", try(var.github.repository, "")))
        && length(try(var.github.repository, "")) > 0
      )
    )
    error_message = "Для github.enabled=true и github.scope=repository требуется github.repository в формате owner/repo."
  }

  validation {
    # Если включен и scope=organization, должен быть задан organization.
    condition = (
      !var.github.enabled
      || var.github.scope != "organization"
      || length(try(var.github.organization, "")) > 0
    )
    error_message = "Для github.enabled=true и github.scope=organization требуется github.organization (название организации)."
  }

  validation {
    # Если включен и scope=enterprise, должен быть задан enterprise slug.
    condition = (
      !var.github.enabled
      || var.github.scope != "enterprise"
      || length(try(var.github.enterprise, "")) > 0
    )
    error_message = "Для github.enabled=true и github.scope=enterprise требуется github.enterprise (slug enterprise)."
  }

  validation {
    # Валидация OS/ARCH.
    condition = (
      contains(["linux", "windows", "macos"], try(var.github.os, "linux"))
      && contains(["x64", "arm64"], try(var.github.arch, "x64"))
    )
    error_message = "Недопустимые значения github.os или github.arch. Допустимо os: linux|windows|macos; arch: x64|arm64."
  }
}

# Временный токен регистрации self-hosted runner (короткоживущий, генерируется API/консолю).
# Источник: docs.github.com → Adding self-hosted runners (token expires after one hour) и REST API endpoints for GitHub Actions.
variable "github_registration_token" {
  type        = string
  description = "Time-limited registration token для GitHub self-hosted runner. Если null — модуль может получать токен другим способом (например, через GitHub App/REST API)."
  default     = null
  sensitive   = true
}

############################################
# GitLab Runners
############################################

variable "gitlab" {
  # Регистрация/настройка см. в официальной документации:
  # - Registering runners (CLI): register --access-level, теги и т.д.
  # - Configure runners (UI): tags, run_untagged, protected (access level).
  # - Runners API: поля access_level=not_protected|ref_protected, run_untagged, locked, tag_list.
  type = object({
    enabled       = bool
    url           = string                         # Базовый URL GitLab (например, https://gitlab.com или https://gitlab.example.com)
    executor      = string                         # "shell" | "docker" | "kubernetes"
    tags          = optional(list(string), [])
    run_untagged  = optional(bool, false)
    locked        = optional(bool, false)
    access_level  = optional(string, "not_protected")  # "not_protected" | "ref_protected"
    # Доп.поля для настройки таймаутов/описаний при создании через API/провайдеры — при необходимости расширяются:
    description   = optional(string)
    maintenance_note = optional(string)
    maximum_timeout  = optional(number)
  })

  default = {
    enabled  = false
    url      = ""
    executor = "docker"
  }

  validation {
    # executor допустим только из указанного списка (наиболее распространенные).
    condition     = contains(["shell", "docker", "kubernetes"], var.gitlab.executor)
    error_message = "gitlab.executor должен быть одним из: shell, docker, kubernetes (см. GitLab Runner executors)."
  }

  validation {
    # access_level в соответствии с API: not_protected | ref_protected.
    condition     = contains(["not_protected", "ref_protected"], try(var.gitlab.access_level, "not_protected"))
    error_message = "gitlab.access_level должен быть not_protected или ref_protected (см. GitLab Runners API)."
  }

  validation {
    # Если включено, URL не может быть пустым и должен быть http(s) URL.
    condition = (
      !var.gitlab.enabled
      || (
        length(var.gitlab.url) > 0
        && can(regex("^https?://", var.gitlab.url))
      )
    )
    error_message = "Для gitlab.enabled=true требуется валидный gitlab.url, начинающийся с http:// или https://."
  }
}

# GitLab tokens: в 16.0+ рекомендуется authentication token (glrt-...), registration token устарел.
# Источники: docs.gitlab.com → Runner authentication tokens (registration tokens deprecated), Registering runners.
variable "gitlab_authentication_token" {
  type        = string
  description = "GitLab Runner authentication token (рекомендуется с GitLab 16+, префикс glrt-), используется для config.toml."
  default     = null
  sensitive   = true
}

variable "gitlab_registration_token" {
  type        = string
  description = "GitLab Runner registration token (устаревающий механизм). Если указан, может быть использован для получения authentication token."
  default     = null
  sensitive   = true
}
