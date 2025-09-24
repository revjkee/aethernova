/**
 * Aethernova — k8s-observability/prometheus-stack
 * File: outputs.tf
 *
 * Назначение:
 *   Стандартизированные выходы для kube-prometheus-stack (Grafana/Prometheus/Alertmanager)
 *   без жёсткой привязки к kubernetes_* ресам: парсинг манифеста helm_release.
 *
 * Требования:
 *   - В модуле должен существовать ресурс: helm_release.prometheus_stack
 *   - Terraform >= 1.3 (yamldecode/split/regexall/try используются)
 */

############################################
# Locals: парсинг Helm manifest
############################################

locals {
  # Полный manifest чарт-релиза (включает все документы, разделённые '---')
  _manifest_raw = try(helm_release.prometheus_stack.manifest, "")

  # Список YAML-документов (пустые/некорректные — отфильтруются)
  _docs_all = [
    for d in split("\n---\n", local._manifest_raw) :
    try(yamldecode(d), null)
    if try(yamldecode(d) != null, false)
  ]

  # Индексация по kind
  _docs_services = [for o in local._docs_all : o if try(o.kind, "") == "Service"]
  _docs_ingress  = [for o in local._docs_all : o if try(o.kind, "") == "Ingress" || try(o.kind, "") == "Ingress_v1" || try(o.apiVersion, "") == "networking.k8s.io/v1"]

  # Уточняем namespace и базовое имя релиза
  _ns           = try(helm_release.prometheus_stack.namespace, null)
  _release_name = try(helm_release.prometheus_stack.name, null)

  # Ожидаемые имена сервисов/ингрессов по шаблону kube-prometheus-stack:
  # "<release>-grafana", "<release>-prometheus", "<release>-alertmanager"
  _name_grafana     = local._release_name != null ? "${local._release_name}-grafana" : null
  _name_prometheus  = local._release_name != null ? "${local._release_name}-prometheus" : null
  _name_alertmngr   = local._release_name != null ? "${local._release_name}-alertmanager" : null

  # Поиск Service по имени и namespace
  _svc_by_name = {
    for s in local._docs_services :
    "${try(s.metadata.namespace, "")}/${try(s.metadata.name, "")}" => s
  }

  _svc_grafana    = try(local._svc_by_name["${local._ns}/${local._name_grafana}"], null)
  _svc_prometheus = try(local._svc_by_name["${local._ns}/${local._name_prometheus}"], null)
  _svc_alertmngr  = try(local._svc_by_name["${local._ns}/${local._name_alertmngr}"], null)

  # Поиск Ingress по имени и namespace
  _ing_by_name = {
    for ing in local._docs_ingress :
    "${try(ing.metadata.namespace, "")}/${try(ing.metadata.name, "")}" => ing
  }

  _ing_grafana    = try(local._ing_by_name["${local._ns}/${local._name_grafana}"], null)
  _ing_prometheus = try(local._ing_by_name["${local._ns}/${local._name_prometheus}"], null)
  _ing_alertmngr  = try(local._ing_by_name["${local._ns}/${local._name_alertmngr}"], null)

  # Унифицированное представление сервис-портов
  _ports = {
    grafana = local._svc_grafana != null ? [
      for p in try(local._svc_grafana.spec.ports, []) : {
        name       = try(p.name, null)
        port       = try(p.port, null)
        targetPort = try(p.targetPort, null)
        nodePort   = try(p.nodePort, null)
        protocol   = try(p.protocol, null)
      }
    ] : []

    prometheus = local._svc_prometheus != null ? [
      for p in try(local._svc_prometheus.spec.ports, []) : {
        name       = try(p.name, null)
        port       = try(p.port, null)
        targetPort = try(p.targetPort, null)
        nodePort   = try(p.nodePort, null)
        protocol   = try(p.protocol, null)
      }
    ] : []

    alertmanager = local._svc_alertmngr != null ? [
      for p in try(local._svc_alertmngr.spec.ports, []) : {
        name       = try(p.name, null)
        port       = try(p.port, null)
        targetPort = try(p.targetPort, null)
        nodePort   = try(p.nodePort, null)
        protocol   = try(p.protocol, null)
      }
    ] : []
  }

  # Вытягиваем ingress hosts и определяем схему по наличию TLS секций
  _ing_extract = function(ing) => ing == null ? {
    enabled = false
    hosts   = []
    paths   = []
    urls    = []
  } : {
    enabled = true
    hosts   = flatten([for r in try(ing.spec.rules, []) : try(r.host, null)])
    paths   = flatten([
      for r in try(ing.spec.rules, []) :
      [for p in try(r.http.paths, []) : {
        host = try(r.host, null)
        path = try(p.path, "/")
      }]
    ])
    urls = flatten([
      for r in try(ing.spec.rules, []) : [
        for p in try(r.http.paths, []) : format(
          "%s://%s%s",
          length(try(ing.spec.tls, [])) > 0 ? "https" : "http",
          try(r.host, ""),
          try(p.path, "/")
        )
      ]
    ])
  }

  _ing_grafana_ex    = local._ing_extract(local._ing_grafana)
  _ing_prometheus_ex = local._ing_extract(local._ing_prometheus)
  _ing_alertmngr_ex  = local._ing_extract(local._ing_alertmngr)

  # Унифицированное представление сервисов
  _svc_obj = function(svc) => svc == null ? null : {
    name        = try(svc.metadata.name, null)
    namespace   = try(svc.metadata.namespace, null)
    type        = try(svc.spec.type, "ClusterIP")
    cluster_ip  = try(svc.spec.clusterIP, null)             # может быть null на стадии планирования
    external_ips= try(svc.spec.externalIPs, [])
    ports       = [
      for p in try(svc.spec.ports, []) : {
        name       = try(p.name, null)
        port       = try(p.port, null)
        targetPort = try(p.targetPort, null)
        nodePort   = try(p.nodePort, null)
        protocol   = try(p.protocol, null)
      }
    ]
    selectors   = try(svc.spec.selector, {})
  }
}

############################################
# Release info
############################################

output "release" {
  description = "Сводная информация о Helm релизе kube-prometheus-stack."
  value = {
    name       = try(helm_release.prometheus_stack.name, null)
    namespace  = try(helm_release.prometheus_stack.namespace, null)
    chart      = try(helm_release.prometheus_stack.chart, null)
    version    = try(helm_release.prometheus_stack.version, null)
    repository = try(helm_release.prometheus_stack.repository, null)
    status     = try(helm_release.prometheus_stack.status, null)
  }
}

############################################
# Grafana
############################################

output "grafana_service" {
  description = "K8s Service Grafana (тип, порты, селекторы)."
  value       = local._svc_obj(local._svc_grafana)
}

output "grafana_ingress" {
  description = "Ingress Grafana: включён ли, хосты, пути, вычисленные URL."
  value = {
    enabled = local._ing_grafana_ex.enabled
    hosts   = local._ing_grafana_ex.hosts
    paths   = local._ing_grafana_ex.paths
    urls    = local._ing_grafana_ex.urls
  }
}

############################################
# Prometheus
############################################

output "prometheus_service" {
  description = "K8s Service Prometheus (тип, порты, селекторы)."
  value       = local._svc_obj(local._svc_prometheus)
}

output "prometheus_ingress" {
  description = "Ingress Prometheus: включён ли, хосты, пути, вычисленные URL."
  value = {
    enabled = local._ing_prometheus_ex.enabled
    hosts   = local._ing_prometheus_ex.hosts
    paths   = local._ing_prometheus_ex.paths
    urls    = local._ing_prometheus_ex.urls
  }
}

############################################
# Alertmanager
############################################

output "alertmanager_service" {
  description = "K8s Service Alertmanager (тип, порты, селекторы)."
  value       = local._svc_obj(local._svc_alertmngr)
}

output "alertmanager_ingress" {
  description = "Ingress Alertmanager: включён ли, хосты, пути, вычисленные URL."
  value = {
    enabled = local._ing_alertmngr_ex.enabled
    hosts   = local._ing_alertmngr_ex.hosts
    paths   = local._ing_alertmngr_ex.paths
    urls    = local._ing_alertmngr_ex.urls
  }
}

############################################
# Сводка по эндпоинтам (удобно для вывода после apply)
############################################

output "endpoints_summary" {
  description = "Сводка URL (если включены ingress) и сервисных портов по основным компонентам."
  value = {
    grafana = {
      urls  = local._ing_grafana_ex.urls
      ports = local._ports.grafana
    }
    prometheus = {
      urls  = local._ing_prometheus_ex.urls
      ports = local._ports.prometheus
    }
    alertmanager = {
      urls  = local._ing_alertmngr_ex.urls
      ports = local._ports.alertmanager
    }
  }
}

############################################
# Защита чувствительных данных
############################################
# Секреты аутентификации Grafana умышленно не выводятся.
# Рекомендуется получать их через kubernetes_secret data source вне этого модуля при явном запросе.
