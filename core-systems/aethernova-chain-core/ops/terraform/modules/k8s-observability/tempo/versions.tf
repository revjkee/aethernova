terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      # Диапазон для долгоживущего прод-стека без ломающих апдейтов
      version = ">= 2.30.0, < 3.0.0"

      # Поддержка нескольких kube-контекстов/alias внутри монорепозитория
      configuration_aliases = [
        kubernetes.tempo,          # основной alias для ресурсов Tempo
        kubernetes.observability   # общий alias наблюдаемости (общие CRD/NS)
      ]
    }

    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0, < 3.0.0"

      # Разделяем релизы Tempo от прочих чартов наблюдаемости
      configuration_aliases = [
        helm.tempo,
        helm.observability
      ]
    }

    # Опционально: если модуль настраивает Tempo datasource/папки/дашборды в Grafana
    grafana = {
      source  = "grafana/grafana"
      version = ">= 2.11.0, < 3.0.0"

      # Один alias для observability-инстанса Grafana
      configuration_aliases = [
        grafana.observability
      ]
    }
  }
}
