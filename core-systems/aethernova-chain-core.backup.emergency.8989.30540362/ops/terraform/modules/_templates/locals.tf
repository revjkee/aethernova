##############################################
# _templates/locals.tf (industrial)
# Требования: Terraform >= 1.3 (optional в object-типах допустим в вызывающих модулях)
# Назначение: единые локалы для именования, лейблов/аннотаций, образов, селекторов и путей.
##############################################

locals {
  # ---------------------------------------------------------------------------
  # 0) Базовые безопасные значения и короткий идентификатор модуля
  # ---------------------------------------------------------------------------
  _name_input      = lower(coalesce(try(var.name, null), "app"))               # coalesce/try — безопасное получение значений
  _ns_input        = lower(coalesce(try(var.namespace, null), "default"))
  _component_input = lower(coalesce(try(var.component, null), "app"))
  _partof_input    = lower(coalesce(try(var.part_of, null), "aethernova-chain-core"))
  _env_input       = lower(coalesce(try(var.environment, null), "prod"))
  _version_input   = coalesce(try(var.version, null), "0.0.0")

  short_id         = substr(md5(path.module), 0, 6)                            # короткий хэш для уникализации
  # см. md5(), substr(), path.module
  # merge() внизу: поздние аргументы перекрывают ранние (официальное правило merge).

  # ---------------------------------------------------------------------------
  # 1) Нормализация DNS-1123 label (имя и namespace, длина <= 63, только [a-z0-9-])
  #    replace поддерживает regex-паттерны; два вызова убирают крайние дефисы.
  # ---------------------------------------------------------------------------
  name_sanitized_step1   = replace(local._name_input, "[^a-z0-9-]", "-")
  name_sanitized_trim    = replace(replace(local.name_sanitized_step1, "^-+", ""), "-+$", "")
  name_dns_63            = length(local.name_sanitized_trim) > 63 ? substr(local.name_sanitized_trim, 0, 63) : local.name_sanitized_trim

  namespace_sanitized1   = replace(local._ns_input, "[^a-z0-9-]", "-")
  namespace_sanitized    = replace(replace(local.namespace_sanitized1, "^-+", ""), "-+$", "")
  namespace_dns_63       = length(local.namespace_sanitized) > 63 ? substr(local.namespace_sanitized, 0, 63) : local.namespace_sanitized

  # Полезные производные имена
  release_name           = local.name_dns_63
  fullname               = local.name_dns_63                                       # при необходимости можно добавлять суффиксы/префиксы

  # ---------------------------------------------------------------------------
  # 2) Рекомендованные Kubernetes-лейблы (Kubernetes Recommended Labels)
  #    Итоговые метки/аннотации: merge(defaults, user) — пользователь имеет приоритет.
  # ---------------------------------------------------------------------------
  default_labels = {
    "app.kubernetes.io/name"       = local.name_dns_63
    "app.kubernetes.io/instance"   = local.release_name
    "app.kubernetes.io/version"    = local._version_input
    "app.kubernetes.io/component"  = local._component_input
    "app.kubernetes.io/part-of"    = local._partof_input
    "app.kubernetes.io/managed-by" = "terraform"
    "environment"                  = local._env_input
  }

  default_annotations = {
    "meta.terraform.io/module" = path.module
    "meta.terraform.io/root"   = path.root
  }

  # Пользовательские метки/аннотации могут быть определены в модуле как var.labels / var.annotations
  labels_final = merge(local.default_labels, coalesce(try(var.labels, null), {}))
  ann_final    = merge(local.default_annotations, coalesce(try(var.annotations, null), {}))

  # ---------------------------------------------------------------------------
  # 3) Образ контейнера: repository + tag ИЛИ digest.
  #    Формирование ссылки на образ согласно обычной схеме <repo>:<tag> или <repo>@<digest>.
  # ---------------------------------------------------------------------------
  image_repository = coalesce(try(var.image.repository, null), "")
  image_tag        = try(var.image.tag, null)
  image_digest     = try(var.image.digest, null)
  image_pull_policy= coalesce(try(var.image.pull_policy, null), "IfNotPresent")
  image_pull_secrets = coalesce(try(var.image.pull_secrets, null), [])

  image_ref = image_digest != null && image_digest != "" ?
    "${local.image_repository}@${local.image_digest}" :
    "${local.image_repository}:${coalesce(local.image_tag, "latest")}"

  # ---------------------------------------------------------------------------
  # 4) Сетевые параметры/порты: service.targetPort=0 => использовать container_port
  # ---------------------------------------------------------------------------
  container_port     = coalesce(try(var.pod.container_port, null), 8080)
  service_port       = coalesce(try(var.service.port, null), 80)
  service_target_raw = coalesce(try(var.service.target_port, null), 0)
  service_target_port= service_target_raw == 0 ? local.container_port : service_target_raw

  # ---------------------------------------------------------------------------
  # 5) Селекторы и стандартные matchLabels
  # ---------------------------------------------------------------------------
  selector_match_labels = {
    "app.kubernetes.io/name"     = local.name_dns_63
    "app.kubernetes.io/instance" = local.release_name
  }

  # ---------------------------------------------------------------------------
  # 6) Ingress-хосты (если описаны во входных переменных модуля)
  # ---------------------------------------------------------------------------
  ingress_hosts_raw = coalescelist(try([for h in var.ingress.hosts : h.host], []), [])
  ingress_hosts     = [for h in local.ingress_hosts_raw : lower(h)]
  ingress_primary   = length(local.ingress_hosts) > 0 ? local.ingress_hosts[0] : null

  # ---------------------------------------------------------------------------
  # 7) Служебные пути (часто полезны в аннотациях/шаблонах)
  # ---------------------------------------------------------------------------
  module_path = path.module
  root_path   = path.root

  # ---------------------------------------------------------------------------
  # 8) Общая карта для Helm/рендеринга (опционально используйте в шаблонах)
  # ---------------------------------------------------------------------------
  values_common = {
    nameOverride     = local.release_name
    fullnameOverride = local.fullname
    labels           = local.labels_final
    annotations      = local.ann_final
    image = {
      repository = local.image_repository
      tag        = local.image_tag
      pullPolicy = local.image_pull_policy
      pullSecrets= local.image_pull_secrets
    }
    service = {
      port       = local.service_port
      targetPort = local.service_target_port
    }
    selectorLabels = local.selector_match_labels
  }
}
