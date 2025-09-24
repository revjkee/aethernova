############################################################
# aethernova-chain-core/ops/terraform/modules/k8s-observability/loki-stack/outputs.tf
#
# Источники:
# - Terraform output block: https://developer.hashicorp.com/terraform/language/block/output         # см. синтаксис output и назначение. :contentReference[oaicite:1]{index=1}
# - Туториал по outputs: https://developer.hashicorp.com/terraform/tutorials/configuration-language/outputs   # экспорт структурированных данных из модулей. :contentReference[oaicite:2]{index=2}
# - Helm provider/helm_release: https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release  # атрибуты ресурса (name, namespace, chart, version, status, manifest*). :contentReference[oaicite:3]{index=3}
# - Руководство по Helm-провайдеру: https://developer.hashicorp.com/terraform/tutorials/kubernetes/helm-provider   # подтверждение практики экспорта атрибутов релиза. :contentReference[oaicite:4]{index=4}
# - Установка Loki через Helm (офиц. Grafana): https://grafana.com/docs/loki/latest/setup/install/helm/            # контекст по Loki Helm-чартам. :contentReference[oaicite:5]{index=5}
#
# Пояснения:
# 1) Этот файл предполагает, что в модуле объявлен ресурс:
#       resource "helm_release" "loki_stack" { ... }
#    Имя ресурса может отличаться в вашей кодовой базе.
#    Если у вас другое имя, переименуйте ссылки в outputs.
#    Не могу подтвердить это: фактическое имя ресурса в вашем модуле.
#
# 2) Поле .manifest у helm_release может быть недоступно/равно null в зависимости
#    от версии провайдера и настроек, поэтому вывод помечен как optional/sensitive.
#    См. обсуждения и доки провайдера. :contentReference[oaicite:6]{index=6}
############################################################

# Компактный агрегированный объект с ключевыми атрибутами релиза Loki.
output "loki_release" {
  description = "Ключевые атрибуты Helm-релиза Loki (для межмодульной интеграции)."
  value = {
    name          = helm_release.loki_stack.name
    namespace     = helm_release.loki_stack.namespace
    chart         = helm_release.loki_stack.chart
    chart_version = helm_release.loki_stack.version
    status        = try(helm_release.loki_stack.status, null)
  }
}

# Имя релиза отдельным полем (удобно для обращений в родительских модулях/оркестрации).
output "loki_release_name" {
  description = "Имя Helm-релиза Loki."
  value       = helm_release.loki_stack.name
}

# Пространство имён установки (часто нужно для построения FQDN сервисов и RBAC).
output "loki_namespace" {
  description = "Kubernetes namespace, куда установлен Loki."
  value       = helm_release.loki_stack.namespace
}

# Полезно для отладки: рендер манифеста релиза (если доступен у провайдера).
# Отмечено как sensitive — чтобы не «светить» возможные секреты из rendered values.
output "loki_rendered_manifest" {
  description = "Полный сгенерированный манифест релиза Loki (может быть null в зависимости от провайдера/настроек)."
  value       = try(helm_release.loki_stack.manifest, null)
  sensitive   = true
}

# Версия чарта отдельным полем — удобно для контроля дрифта и соответствия политикам версий.
output "loki_chart_version" {
  description = "Версия Helm-чарта, развернутого для Loki."
  value       = helm_release.loki_stack.version
}

# Текущий статус релиза по данным Helm-провайдера (deployed/superseded/failed и др.).
output "loki_release_status" {
  description = "Статус Helm-релиза Loki по данным Terraform Helm provider."
  value       = try(helm_release.loki_stack.status, null)
}
