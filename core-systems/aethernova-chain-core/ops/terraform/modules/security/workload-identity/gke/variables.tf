#############################################
# aethernova-chain-core/ops/terraform/modules/security/workload-identity/gke/variables.tf
#############################################

############################
# Базовая идентификация кластера/проекта
############################
variable "project_id" {
  description = "ID GCP-проекта, где работает кластер GKE (например, my-project)."
  type        = string

  validation {
    # Базовая проверка project_id; допускает дефисы, строчные буквы и цифры
    condition     = can(regex("^[a-z][-a-z0-9]{4,61}[a-z0-9]$", var.project_id))
    error_message = "project_id должен соответствовать ^[a-z][-a-z0-9]{4,61}[a-z0-9]$."
  }
}

variable "project_number" {
  description = "Числовой номер GCP-проекта (используется в principal:// идентификаторах)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,}$", var.project_number))
    error_message = "project_number должен состоять из цифр."
  }
}

variable "location" {
  description = "Регион или зона кластера (например, europe-west1 или europe-west1-b)."
  type        = string
}

variable "cluster_name" {
  description = "Имя кластера GKE."
  type        = string

  validation {
    # Стандартные ограничения на имя (k8s/gcloud)
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.cluster_name))
    error_message = "cluster_name должен соответствовать ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$."
  }
}

############################
# Пул Workload Identity
############################
variable "workload_pool" {
  description = "Идентификатор пула Workload Identity для кластера. По умолчанию формат PROJECT_ID.svc.id.goog."
  type        = string
  default     = null

  validation {
    condition     = var.workload_pool == null || can(regex("^[a-z][-a-z0-9]{4,61}[a-z0-9]\\.svc\\.id\\.goog$", var.workload_pool))
    error_message = "workload_pool должен иметь формат PROJECT_ID.svc.id.goog."
  }
}

variable "use_fleet_workload_identity" {
  description = "Включить использование Fleet Workload Identity (общий пул на проект-хост флита)."
  type        = bool
  default     = false
}

variable "fleet_workload_identity_pool_id" {
  description = "Полный ресурс пула WI для Fleet (projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID). Задавайте при use_fleet_workload_identity=true."
  type        = string
  default     = null

  validation {
    condition = var.fleet_workload_identity_pool_id == null || can(
      regex("^projects/[0-9]+/locations/global/workloadIdentityPools/[a-zA-Z0-9._-]+$", var.fleet_workload_identity_pool_id)
    )
    error_message = "Ожидаемый формат: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID."
  }
}

############################
# Моделирование KSA (Kubernetes Service Accounts)
############################
variable "kubernetes_service_accounts" {
  description = <<-EOT
    Карта описаний KSA, которые следует создать/использовать.
    Ключ карты — логическое имя (алиас). Поля объекта:
      - namespace (string) — пространство имён;
      - name (string) — имя KSA;
      - create (bool, optional, default=true) — создавать ли KSA;
      - labels (map(string), optional) — метки;
      - annotations (map(string), optional) — аннотации;
      - automount_service_account_token (bool, optional, default=true);
      - quota_project (string, optional) — для аннотации iam.gke.io/credential-quota-project.
  EOT
  type = map(object({
    namespace                         = string
    name                              = string
    create                            = optional(bool, true)
    labels                            = optional(map(string), {})
    annotations                       = optional(map(string), {})
    automount_service_account_token   = optional(bool, true)
    quota_project                     = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.kubernetes_service_accounts :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", v.namespace)) &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", v.name))
    ])
    error_message = "namespace и name каждого KSA должны соответствовать ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$."
  }
}

############################
# 1) Прямые IAM-биндинги на KSA (рекомендуемый способ)
# principal://.../subject/ns/<NAMESPACE>/sa/<KSA_NAME>
############################
variable "direct_iam_grants_project" {
  description = <<-EOT
    Список биндингов ролей на уровень проекта для KSA-принципалов.
    Поля:
      - project_id (string) — проект, на который выдаются роли;
      - namespace (string), ksa_name (string) — целевой KSA;
      - roles (set(string)) — список ролей (например, roles/storage.objectViewer);
      - condition (object, optional) — IAM условие (CEL): { title, description?, expression }.
  EOT
  type = list(object({
    project_id = string
    namespace  = string
    ksa_name   = string
    roles      = set(string)
    condition = optional(object({
      title       = string
      description = optional(string)
      expression  = string
    }))
  }))
  default = []
}

variable "direct_iam_grants_resources" {
  description = <<-EOT
    Список биндингов ролей на конкретные ресурсы (например, gs://BUCKET, Artifact Registry, и т.д.) для KSA-принципалов.
    Поля:
      - resource (string) — идентификатор ресурса для *add-iam-policy-binding* соответствующего сервиса;
      - namespace (string), ksa_name (string);
      - roles (set(string));
      - condition (object, optional) — IAM условие (CEL).
  EOT
  type = list(object({
    resource  = string
    namespace = string
    ksa_name  = string
    roles     = set(string)
    condition = optional(object({
      title       = string
      description = optional(string)
      expression  = string
    }))
  }))
  default = []
}

############################
# 2) Альтернативный путь: импликация GSA (WorkloadIdentityUser) + аннотация KSA
############################
variable "impersonation_bindings" {
  description = <<-EOT
    Список связок KSA<->GSA для альтернативного пути (аннотация + роль WorkloadIdentityUser).
    Поля:
      - gsa_email (string) — email GSA: <name>@<project>.iam.gserviceaccount.com;
      - ksa_namespace (string), ksa_name (string) — целевой KSA;
      - bind_role_workload_identity_user (bool, optional, default=true) — назначить roles/iam.workloadIdentityUser на GSA для принципала KSA;
      - additional_roles (set(string), optional) — доп. роли на GSA (редко требуется);
      - annotate_ksa (bool, optional, default=true) — добавить аннотацию iam.gke.io/gcp-service-account на KSA;
      - extra_annotations (map(string), optional) — дополнительные аннотации на KSA.
  EOT
  type = list(object({
    gsa_email                         = string
    ksa_namespace                     = string
    ksa_name                          = string
    bind_role_workload_identity_user  = optional(bool, true)
    additional_roles                  = optional(set(string), [])
    annotate_ksa                      = optional(bool, true)
    extra_annotations                 = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for b in var.impersonation_bindings :
      can(regex("^[a-zA-Z0-9][a-zA-Z0-9_-]{2,}@[-a-z0-9]+\\.iam\\.gserviceaccount\\.com$", b.gsa_email)) &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", b.ksa_namespace)) &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", b.ksa_name))
    ])
    error_message = "gsa_email должен оканчиваться на .iam.gserviceaccount.com; ksa_namespace/ksa_name — валидные k8s-идентификаторы."
  }
}

############################
# Дополнительно: метки/теги на создаваемые объекты
############################
variable "labels" {
  description = "Глобальные метки для создаваемых ресурсов (если применимо)."
  type        = map(string)
  default     = {}
}

############################
# Управление выполнением
############################
variable "enabled" {
  description = "Глобальный тумблер включения модуля."
  type        = bool
  default     = true
}
