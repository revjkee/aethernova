/**
 * Aethernova | ops/terraform/modules/registry/gar/variables.tf
 *
 * Переменные для создания Google Artifact Registry (GAR) репозитория:
 * - стандартного (STANDARD_REPOSITORY),
 * - виртуального (VIRTUAL_REPOSITORY),
 * - удалённого (REMOTE_REPOSITORY).
 *
 * Ссылки на поведение и допустимые значения:
 * - Форматы репозиториев: Docker, Maven, npm, Python, Apt, Yum (Artifact Registry Supported formats).
 * - Multi-region локации: asia, europe, us (Provider schema).
 * - Docker immutable tags (docker_config.immutable_tags).
 * - Maven policy (version_policy, allow_snapshot_overwrites).
 * - Включение/отключение уязвимость-сканирования на уровне репозитория.
 * - Политики очистки (delete/keep), условия и dry-run.
 */

variable "project_id" {
  description = "ID проекта GCP, где создаётся репозиторий Artifact Registry."
  type        = string

  validation {
    condition     = length(trim(var.project_id)) > 0
    error_message = "project_id должен быть непустой строкой."
  }
}

variable "location" {
  description = <<-EOT
    Регион или multi-region для репозитория (напр., us-central1, europe-west1, либо multi-region: us, europe, asia).
    Репозитории создаются в регионах или multi-region, а не в зонах.
  EOT
  type = string

  validation {
    condition     = length(trim(var.location)) > 0
    error_message = "location должен быть непустой строкой (регион или multi-region)."
  }
}

variable "repository_id" {
  description = "Идентификатор репозитория (отображается в путях вида LOCATION-docker.pkg.dev/PROJECT/REPOSITORY)."
  type        = string

  validation {
    # Без агрессивной регэксп-валидации имени, так как официальные ограничения по символам для repository_id варьируются по UI/API.
    condition     = length(var.repository_id) > 0 && length(var.repository_id) <= 128
    error_message = "repository_id должен быть непустым и не длиннее 128 символов."
  }
}

variable "description" {
  description = "Произвольное описание репозитория."
  type        = string
  default     = ""
}

variable "format" {
  description = <<-EOT
    Формат артефактов в репозитории. Допустимы:
    - DOCKER
    - MAVEN
    - NPM
    - PYTHON
    - APT
    - YUM
  EOT
  type = string

  validation {
    condition = contains(
      ["DOCKER", "MAVEN", "NPM", "PYTHON", "APT", "YUM"],
      upper(var.format)
    )
    error_message = "format должен быть одним из: DOCKER, MAVEN, NPM, PYTHON, APT, YUM."
  }
}

variable "mode" {
  description = <<-EOT
    Режим репозитория:
    - STANDARD_REPOSITORY: приватное хранилище артефактов.
    - VIRTUAL_REPOSITORY: единая точка доступа, агрегирующая upstream-репозитории одного формата.
    - REMOTE_REPOSITORY: проксирование внешнего источника (Docker Hub, Maven Central, PyPI и т.д.).
  EOT
  type    = string
  default = "STANDARD_REPOSITORY"

  validation {
    condition = contains(
      ["STANDARD_REPOSITORY", "VIRTUAL_REPOSITORY", "REMOTE_REPOSITORY"],
      upper(var.mode)
    )
    error_message = "mode должен быть одним из: STANDARD_REPOSITORY, VIRTUAL_REPOSITORY, REMOTE_REPOSITORY."
  }
}

variable "labels" {
  description = <<-EOT
    Метки ресурса (labels). Google допускает до 64 меток; ключ 1–63 символа, значение до 63.
    Разрешены строчные буквы, цифры, подчёркивания и дефисы. Ключ должен начинаться с буквы.
    Внимание: провайдер управляет только теми метками, что описаны в конфигурации (non-authoritative).
  EOT
  type    = map(string)
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.labels : (
        can(regex("^[a-z][a-z0-9_-]{0,62}$", k)) &&
        (length(v) == 0 || can(regex("^[a-z0-9_-]{0,63}$", v)))
      )
    ])
    error_message = "labels: ключи/значения должны соответствовать ограничениям по длине и символам."
  }
}

variable "kms_key_name" {
  description = <<-EOT
    Полный путь KMS-ключа для шифрования содержимого (CMEK), формат:
    projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
    Поле неизменно после создания репозитория.
  EOT
  type      = string
  default   = null
  nullable  = true

  validation {
    condition = var.kms_key_name == null || can(regex("^projects\\/[^\\/]+\\/locations\\/[^\\/]+\\/keyRings\\/[^\\/]+\\/cryptoKeys\\/[^\\/]+$", var.kms_key_name))
    error_message = "kms_key_name должен быть в формате projects/.../locations/.../keyRings/.../cryptoKeys/...."
  }
}

variable "docker_config" {
  description = "Настройки Docker-репозитория (актуально при format = DOCKER)."
  type = object({
    immutable_tags = optional(bool) # true блокирует изменение/переназначение/удаление тегов (создание новых разрешено)
  })
  default  = {}
  nullable = false
}

variable "maven_config" {
  description = "Настройки Maven-репозитория (актуально при format = MAVEN)."
  type = object({
    version_policy             = optional(string) # RELEASE | SNAPSHOT
    allow_snapshot_overwrites  = optional(bool)   # true разрешает перезапись SNAPSHOT-версий
  })
  default  = {}
  nullable = false

  validation {
    condition = (
      !contains(keys(var.maven_config), "version_policy")
      || contains(["RELEASE", "SNAPSHOT"], upper(try(var.maven_config.version_policy, "")))
    )
    error_message = "maven_config.version_policy должен быть RELEASE или SNAPSHOT."
  }
}

variable "vulnerability_scanning_enablement_config" {
  description = <<-EOT
    Управление автоматическим сканированием уязвимостей для репозитория:
    - INHERITED: унаследовать глобальную политику проекта (Container Scanning API).
    - DISABLED: отключить автоматическое сканирование для этого репозитория.
  EOT
  type    = string
  default = "INHERITED"

  validation {
    condition     = contains(["INHERITED", "DISABLED"], upper(var.vulnerability_scanning_enablement_config))
    error_message = "vulnerability_scanning_enablement_config должен быть INHERITED или DISABLED."
  }
}

variable "cleanup_policy_dry_run" {
  description = "Если true — политики очистки выполняются в dry-run и не удаляют версии."
  type        = bool
  default     = true
}

variable "cleanup_policies" {
  description = <<-EOT
    Список политик очистки (delete/keep). Каждая политика должна иметь уникальный id,
    action (DELETE|KEEP) и либо condition, либо most_recent_versions.

    Пример delete:
      {
        id     = "delete-older-30d"
        action = "DELETE"
        condition = {
          tag_state               = "ANY"       # ANY|TAGGED|UNTAGGED
          tag_prefixes            = ["test", "staging"]
          version_name_prefixes   = ["v1", "v2"]
          package_name_prefixes   = ["backend-", "frontend-"]
          older_than              = "30d"       # s|m|h|d суффиксы
          newer_than              = null
        }
      }

    Пример keep most recent:
      {
        id     = "keep-latest-5"
        action = "KEEP"
        most_recent_versions = {
          keep_count            = 5
          package_name_prefixes = []           # опционально
        }
      }
  EOT
  type = list(object({
    id     = string
    action = string # DELETE | KEEP

    condition = optional(object({
      tag_state             = optional(string)       # ANY|TAGGED|UNTAGGED
      tag_prefixes          = optional(list(string)) # для TAGGED
      version_name_prefixes = optional(list(string))
      package_name_prefixes = optional(list(string))
      older_than            = optional(string)       # "30d", "12h" и т.п.
      newer_than            = optional(string)       # "7d" и т.п.
    }))

    most_recent_versions = optional(object({
      keep_count            = number                 # минимальное число сохраняемых версий
      package_name_prefixes = optional(list(string))
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.cleanup_policies : (
        contains(["DELETE", "KEEP"], upper(p.action)) &&
        (
          # ровно один из двух блоков указан
          (
            try(p.condition != null, false) ? 1 : 0
          ) + (
            try(p.most_recent_versions != null, false) ? 1 : 0
          ) == 1
        ) &&
        (
          # если указан tag_state — он валиден
          !try(contains(["ANY", "TAGGED", "UNTAGGED"], upper(p.condition.tag_state)) == false, false)
        )
      )
    ])
    error_message = "Каждая политика должна иметь action=DELETE|KEEP и ровно один из блоков: condition или most_recent_versions. tag_state (если задан) — ANY|TAGGED|UNTAGGED."
  }
}

variable "virtual_repository_upstream_policies" {
  description = <<-EOT
    Upstream-политики для VIRTUAL_REPOSITORY: приоритет и ссылка на исходные репозитории.
    Поля:
      - id        — произвольный идентификатор политики.
      - repository — ссылка вида projects/PRJ/locations/LOC/repositories/REPO.
      - priority   — большее число = выше приоритет.
  EOT
  type = list(object({
    id         = string
    repository = string
    priority   = number
  }))
  default = []
}

variable "remote_repository_config" {
  description = <<-EOT
    Конфигурация REMOTE_REPOSITORY (прокси внешних источников). Параметры опциональны; задавайте только относящиеся к выбранному формату.
    - common:
        description                 — описание удалённого источника.
        disable_upstream_validation — не валидировать upstream и креденшелы при создании.
        upstream_credentials:
          username        — имя пользователя для upstream.
          secret_version  — ссылка на Secret Manager версию: projects/PRJ/secrets/NAME/versions/N
    - per-format public_repository:
        docker_public_repository: допустимые публичные источники Docker (например, DOCKER_HUB, GHCR_IO) — зависит от API.
        maven_public_repository: MAVEN_CENTRAL
        npm_public_repository:   NPMJS
        python_public_repository: PYPI
        apt_public_repository:   публичные apt-источники (например Debian).
        yum_public_repository:   публичные yum-источники (например CentOS).
  EOT
  type = object({
    common = optional(object({
      description                 = optional(string)
      disable_upstream_validation = optional(bool)
      upstream_credentials = optional(object({
        username       = string
        secret_version = string
      }))
    }))

    docker_public_repository  = optional(string)
    maven_public_repository   = optional(string)
    npm_public_repository     = optional(string)
    python_public_repository  = optional(string)
    apt_public_repository     = optional(string)
    yum_public_repository     = optional(string)
  })
  default  = {}
  nullable = false
}

variable "timeouts" {
  description = "Таймауты операции над ресурсом (Terraform timeouts). Формат значения: '10m', '30m' и т.д."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default  = {}
  nullable = false
}
