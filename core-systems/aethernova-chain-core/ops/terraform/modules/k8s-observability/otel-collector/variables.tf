// aethernova-chain-core/ops/terraform/modules/k8s-observability/otel-collector/variables.tf
// Промышленный набор переменных для модульного управления OpenTelemetry Collector в Kubernetes.
// Поддерживает развертывание через Helm/манифесты (логика — в остальных файлах модуля).
// Этот файл определяет только входные переменные с валидацией и описаниями.

// ---------- Базовые параметры развёртывания ----------

variable "name" {
  type        = string
  description = "Базовое имя релиза/ресурса (префикс)."
  validation {
    condition     = length(var.name) > 0
    error_message = "name не может быть пустым."
  }
}

variable "namespace" {
  type        = string
  description = "Namespace для развёртывания OTel Collector."
  default     = "observability"
}

variable "create_namespace" {
  type        = bool
  description = "Создавать namespace (если он ещё не существует)."
  default     = true
}

variable "mode" {
  type        = string
  description = "Режим работы коллектора: deployment (стационарный) или daemonset (на каждом узле)."
  default     = "deployment"
  validation {
    condition     = contains(["deployment", "daemonset"], var.mode)
    error_message = "mode должен быть 'deployment' или 'daemonset'."
  }
}

variable "service_account_name" {
  type        = string
  description = "Имя ServiceAccount для коллектора. Если пусто и create_service_account = true — будет создано var.name."
  default     = ""
}

variable "create_service_account" {
  type        = bool
  description = "Создавать ServiceAccount для коллектора."
  default     = true
}

variable "create_rbac" {
  type        = bool
  description = "Создавать Role/RoleBinding/ClusterRole/ClusterRoleBinding при необходимости."
  default     = true
}

variable "priority_class_name" {
  type        = string
  description = "PriorityClassName для Pod."
  default     = null
}

// ---------- Контейнер / образ / ресурсы / реплики ----------

variable "image" {
  type = object({
    repository = string
    tag        = string
    pullPolicy = optional(string, "IfNotPresent")
  })
  description = "Контейнерный образ OpenTelemetry Collector."
  default = {
    repository = "otel/opentelemetry-collector"
    tag        = "0.102.0"
    pullPolicy = "IfNotPresent"
  }
}

variable "replicas" {
  type        = number
  description = "Количество реплик для режима deployment. Для daemonset игнорируется."
  default     = 2
  validation {
    condition     = var.replicas >= 1
    error_message = "replicas должно быть >= 1."
  }
}

variable "resources" {
  type = object({
    requests = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
  })
  description = "Ресурсы контейнера коллектора."
  default = {
    requests = { cpu = "200m", memory = "256Mi" }
    limits   = { cpu = "1",    memory = "1Gi"   }
  }
}

variable "liveness_probe" {
  type = object({
    enabled             = optional(bool, true)
    httpGet             = optional(object({ path = string, port = number }), { path = "/healthz", port = 13133 })
    initialDelaySeconds = optional(number, 10)
    periodSeconds       = optional(number, 10)
    timeoutSeconds      = optional(number, 2)
    failureThreshold    = optional(number, 3)
    successThreshold    = optional(number, 1)
  })
  description = "Liveness probe параметризация."
  default     = {}
}

variable "readiness_probe" {
  type = object({
    enabled             = optional(bool, true)
    httpGet             = optional(object({ path = string, port = number }), { path = "/ready", port = 13133 })
    initialDelaySeconds = optional(number, 5)
    periodSeconds       = optional(number, 10)
    timeoutSeconds      = optional(number, 2)
    failureThreshold    = optional(number, 3)
    successThreshold    = optional(number, 1)
  })
  description = "Readiness probe параметризация."
  default     = {}
}

variable "startup_probe" {
  type = object({
    enabled             = optional(bool, false)
    httpGet             = optional(object({ path = string, port = number }), { path = "/healthz", port = 13133 })
    initialDelaySeconds = optional(number, 0)
    periodSeconds       = optional(number, 10)
    timeoutSeconds      = optional(number, 2)
    failureThreshold    = optional(number, 30)
    successThreshold    = optional(number, 1)
  })
  description = "Startup probe параметризация."
  default     = {}
}

// ---------- Сеть / сервис / порты ----------

variable "service" {
  type = object({
    type                     = optional(string, "ClusterIP")
    annotations              = optional(map(string), {})
    labels                   = optional(map(string), {})
    otlp_grpc_port           = optional(number, 4317)
    otlp_http_port           = optional(number, 4318)
    metrics_port             = optional(number, 8888)
    health_port              = optional(number, 13133)
    additional_ports         = optional(list(object({ name = string, port = number, targetPort = optional(number) })), [])
    cluster_ip               = optional(string)
    external_traffic_policy  = optional(string)
    load_balancer_source_ranges = optional(list(string))
  })
  description = "Сервис для экспорта OTLP и метрик/хелсчеков."
  default     = {}
}

variable "ingress" {
  type = object({
    enabled     = optional(bool, false)
    class_name  = optional(string)
    host        = optional(string)
    path        = optional(string, "/")
    annotations = optional(map(string), {})
    tls         = optional(list(object({
      hosts      = list(string)
      secretName = optional(string)
    })), [])
  })
  description = "Опциональный Ingress для внешнего доступа к OTLP HTTP/gRPC (используйте осторожно)."
  default     = {}
}

variable "expose_otlp_grpc" {
  type        = bool
  description = "Экспортировать OTLP gRPC порт через сервис."
  default     = true
}

variable "expose_otlp_http" {
  type        = bool
  description = "Экспортировать OTLP HTTP порт через сервис."
  default     = true
}

// ---------- Политики безопасности и комплаенс ----------

variable "pod_security_context" {
  type = object({
    runAsUser                = optional(number)
    runAsGroup               = optional(number)
    fsGroup                  = optional(number)
    runAsNonRoot             = optional(bool, true)
    seccompProfile           = optional(object({ type = string }), { type = "RuntimeDefault" })
    supplementalGroups       = optional(list(number), [])
    fsGroupChangePolicy      = optional(string)
    sysctls                  = optional(list(object({ name = string, value = string })), [])
  })
  description = "PodSecurityContext."
  default     = {}
}

variable "security_context" {
  type = object({
    allowPrivilegeEscalation = optional(bool, false)
    readOnlyRootFilesystem   = optional(bool, true)
    privileged               = optional(bool, false)
    capabilities             = optional(object({
      add  = optional(list(string), [])
      drop = optional(list(string), ["ALL"])
    }), {})
    runAsUser  = optional(number)
    runAsGroup = optional(number)
  })
  description = "SecurityContext контейнера."
  default     = {}
}

variable "pod_annotations" {
  type        = map(string)
  description = "Аннотации Pod."
  default     = {}
}

variable "pod_labels" {
  type        = map(string)
  description = "Дополнительные метки Pod."
  default     = {}
}

variable "node_selector" {
  type        = map(string)
  description = "NodeSelector."
  default     = {}
}

variable "tolerations" {
  type = list(object({
    key      = optional(string)
    operator = optional(string, "Exists")
    value    = optional(string)
    effect   = optional(string)
    tolerationSeconds = optional(number)
  }))
  description = "Tolerations."
  default     = []
}

variable "affinity" {
  type        = any
  description = "Kubernetes Affinity (nodeAffinity/podAffinity/podAntiAffinity)."
  default     = null
}

variable "topology_spread_constraints" {
  type = list(object({
    maxSkew           = number
    topologyKey       = string
    whenUnsatisfiable = string
    labelSelector     = optional(object({
      matchLabels = optional(map(string), {})
      matchExpressions = optional(list(object({
        key      = string
        operator = string
        values   = optional(list(string), [])
      })), [])
    }), null)
  }))
  description = "TopologySpreadConstraints для распределения Pod по зонам/узлам."
  default     = []
}

variable "pod_disruption_budget" {
  type = object({
    enabled        = optional(bool, true)
    min_available  = optional(string)
    max_unavailable = optional(string, "33%")
  })
  description = "PDB для повышения устойчивости."
  default     = {}
}

variable "network_policy" {
  type = object({
    enabled = optional(bool, false)
    // Пример: разрешить вход только с namespace мониторинга/приложений
    ingress = optional(list(object({
      from = optional(list(object({
        podSelector       = optional(object({ matchLabels = optional(map(string), {}) }), null)
        namespaceSelector = optional(object({ matchLabels = optional(map(string), {}) }), null)
        ipBlock           = optional(object({ cidr = string, except = optional(list(string), []) }), null)
      })), [])
      ports = optional(list(object({ port = number, protocol = optional(string, "TCP") })), [])
    })), [])
    egress = optional(list(object({
      to = optional(list(object({
        podSelector       = optional(object({ matchLabels = optional(map(string), {}) }), null)
        namespaceSelector = optional(object({ matchLabels = optional(map(string), {}) }), null)
        ipBlock           = optional(object({ cidr = string, except = optional(list(string), []) }), null)
      })), [])
      ports = optional(list(object({ port = number, protocol = optional(string, "TCP") })), [])
    })), [])
    policy_types = optional(list(string), ["Ingress", "Egress"])
  })
  description = "NetworkPolicy: ограничение сетевых потоков."
  default     = {}
}

// ---------- Включение метрик / логов / трейсов и общая конфигурация OTel ----------

variable "enable_metrics" {
  type        = bool
  description = "Включить обработку метрик."
  default     = true
}

variable "enable_logs" {
  type        = bool
  description = "Включить обработку логов."
  default     = true
}

variable "enable_traces" {
  type        = bool
  description = "Включить обработку трейсов."
  default     = true
}

variable "otel_config_overrides" {
  type        = map(any)
  description = <<EOT
Произвольные оверлеи для конфигурации OpenTelemetry Collector (структура, совместимая с YAML):
- receivers / processors / exporters / extensions / service
- Будут мерджиться поверх базового шаблона.
EOT
  default     = {}
}

variable "receivers" {
  type = object({
    otlp = optional(object({
      protocols = optional(object({
        grpc = optional(object({ endpoint = optional(string, "0.0.0.0:4317") }), {})
        http = optional(object({ endpoint = optional(string, "0.0.0.0:4318") }), {})
      }), {})
    }), {})
    // Дополнительные распространённые ресиверы:
    prometheus = optional(any, null) // структура prometheus.receiver as-is
    filelog    = optional(any, null) // filelog receiver для агентского режима
    jaeger     = optional(any, null)
    zipkin     = optional(any, null)
  })
  description = "Receivers-конфигурации OTel."
  default     = {}
}

variable "processors" {
  type        = any
  description = "Processors-конфигурации OTel (batch, memory_limiter, resource, attributes и т.п.)."
  default     = {
    batch          = {}
    memory_limiter = { check_interval = "1s", limit_mib = 400, spike_limit_mib = 200 }
    resource       = { attributes = [] }
  }
}

variable "exporters" {
  type        = any
  description = <<EOT
Exporters-конфигурации OTel (например, otlp/otlphttp/prometheus/file/jaeger/zipkin).
Примеры:
  - otlp:
      endpoint: "https://otel-collector.your.svc:4317"
      headers: { "x-tenant": "prod" }
  - prometheus:
      endpoint: "0.0.0.0:8889"
EOT
  default     = {}
}

variable "extensions" {
  type        = any
  description = "Extensions-конфигурации OTel (health_check, pprof, zpages и т.п.)."
  default     = {
    health_check = {}
    pprof        = { endpoint = "0.0.0.0:1777" }
    zpages       = { endpoint = "0.0.0.0:55679" }
  }
}

variable "service_pipelines" {
  type = object({
    metrics = optional(object({
      receivers  = list(string)
      processors = optional(list(string), ["memory_limiter", "batch"])
      exporters  = list(string)
    }), null)
    logs = optional(object({
      receivers  = list(string)
      processors = optional(list(string), ["memory_limiter", "batch"])
      exporters  = list(string)
    }), null)
    traces = optional(object({
      receivers  = list(string)
      processors = optional(list(string), ["memory_limiter", "batch"])
      exporters  = list(string)
    }), null)
  })
  description = "Явное определение пайплайнов service.pipelines (если не задано — модуль соберёт по enable_* и defaults)."
  default     = {
    metrics = null
    logs    = null
    traces  = null
  }
}

variable "service_telemetry" {
  type = object({
    logs    = optional(object({ level = optional(string, "info") }), {})
    metrics = optional(object({ level = optional(string, "basic") }), {})
  })
  description = "Настройка внутренней телеметрии самого коллектора."
  default     = {}
}

// ---------- Prometheus Operator интеграции ----------

variable "prometheus_operator" {
  type = object({
    create_service_monitor = optional(bool, true)
    service_monitor = optional(object({
      interval          = optional(string, "30s")
      scrapeTimeout     = optional(string, "10s")
      labels            = optional(map(string), {})
      annotations       = optional(map(string), {})
      scheme            = optional(string, "http")
      tlsConfig         = optional(any)
      relabelings       = optional(list(any), [])
      metricRelabelings = optional(list(any), [])
      namespaceSelector = optional(object({
        matchNames = optional(list(string), [])
      }), null)
      endpoints = optional(list(object({
        port     = optional(string)
        interval = optional(string)
        path     = optional(string, "/metrics")
        scheme   = optional(string, "http")
        honorLabels = optional(bool, false)
      })), [])
    }), {})
    create_pod_monitor = optional(bool, false)
    pod_monitor = optional(object({
      interval          = optional(string, "30s")
      scrapeTimeout     = optional(string, "10s")
      labels            = optional(map(string), {})
      annotations       = optional(map(string), {})
      relabelings       = optional(list(any), [])
      metricRelabelings = optional(list(any), [])
    }), {})
  })
  description = "Интеграция с Prometheus Operator (ServiceMonitor/PodMonitor)."
  default     = {}
}

// ---------- Автомасштабирование / устойчивость ----------

variable "hpa" {
  type = object({
    enabled = optional(bool, false)
    min_replicas = optional(number, 2)
    max_replicas = optional(number, 5)
    metrics = optional(list(object({
      type = string
      resource = optional(object({
        name                     = string
        targetAverageUtilization = optional(number)
        targetAverageValue       = optional(string)
      }), null)
      pods = optional(object({
        metric = object({
          name = string
        })
        target = object({
          type               = string
          averageUtilization = optional(number)
          averageValue       = optional(string)
        })
      }), null)
      object = optional(any, null)
      container_resource = optional(any, null)
      external = optional(any, null)
    })), [])
    behavior = optional(any, null)
  })
  description = "HPA для режима deployment."
  default     = {}
}

// ---------- Переменные окружения, файлы, тома ----------

variable "env" {
  type = list(object({
    name  = string
    value = optional(string)
    valueFrom = optional(object({
      secretKeyRef = optional(object({
        name = string
        key  = string
      }), null)
      configMapKeyRef = optional(object({
        name = string
        key  = string
      }), null)
      fieldRef = optional(object({
        fieldPath = string
      }), null)
      resourceFieldRef = optional(object({
        containerName = optional(string)
        resource      = string
        divisor       = optional(string)
      }), null)
    }), null)
  }))
  description = "Дополнительные переменные окружения для контейнера."
  default     = []
  validation {
    condition     = alltrue([for e in var.env : (try(e.name != null && length(e.name) > 0, false))])
    error_message = "Каждый элемент env должен иметь непустое имя."
  }
}

variable "extra_env_from" {
  type = list(object({
    secretRef    = optional(object({ name = string }), null)
    configMapRef = optional(object({ name = string }), null)
  }))
  description = "Подключение env из Secret/ConfigMap."
  default     = []
}

variable "extra_volume_mounts" {
  type = list(object({
    name       = string
    mountPath  = string
    readOnly   = optional(bool, true)
    subPath    = optional(string)
  }))
  description = "Дополнительные VolumeMounts."
  default     = []
}

variable "extra_volumes" {
  type = list(any)
  description = "Дополнительные Volumes (k8s-спеки как есть)."
  default     = []
}

// ---------- Конфиги/секреты для экспортёров ----------

variable "secrets" {
  type = map(object({
    data = map(string) // base64 уже не требуется; указывайте строковые значения — кодирование выполнит манифест/helm-шаблон
    type = optional(string, "Opaque")
  }))
  description = "Secrets, необходимые коллектора (например, токены/credentials для экспортеров)."
  default     = {}
  sensitive   = true
}

variable "config_maps" {
  type = map(object({
    data = map(string)
  }))
  description = "Дополнительные ConfigMap с конфигурацией (при необходимости монтируются)."
  default     = {}
}

// ---------- Логи контейнера / аннотации для агентских сборщиков ----------

variable "pod_log_annotations" {
  type        = map(string)
  description = "Аннотации Pod для агентских сборщиков логов (например, подсказки для сторонних DaemonSet)."
  default     = {}
}

// ---------- Политика рестартов и стратегия ----------

variable "deployment_strategy" {
  type = object({
    type = optional(string, "RollingUpdate")
    rollingUpdate = optional(object({
      maxUnavailable = optional(string, "25%")
      maxSurge       = optional(string, "25%")
    }), {})
  })
  description = "Стратегия Deployment."
  default     = {}
}

variable "daemonset_update_strategy" {
  type = object({
    type = optional(string, "RollingUpdate")
    rollingUpdate = optional(object({
      maxUnavailable = optional(string, "10%")
    }), {})
  })
  description = "Стратегия DaemonSet."
  default     = {}
}

// ---------- Аннотации/лейблы для Service/Endpoints ----------

variable "service_labels" {
  type        = map(string)
  description = "Дополнительные метки для Service."
  default     = {}
}

variable "service_annotations" {
  type        = map(string)
  description = "Дополнительные аннотации для Service."
  default     = {}
}

// ---------- Управление жизненным циклом / hooks ----------

variable "lifecycle_hooks" {
  type = object({
    postStart = optional(object({
      exec = optional(object({ command = list(string) }), null)
      httpGet = optional(object({
        path = string, port = number, host = optional(string), scheme = optional(string, "HTTP")
        httpHeaders = optional(list(object({ name = string, value = string })), [])
      }), null)
      tcpSocket = optional(object({ port = number, host = optional(string) }), null)
    }), null)
    preStop = optional(object({
      exec = optional(object({ command = list(string) }), null)
      httpGet = optional(object({
        path = string, port = number, host = optional(string), scheme = optional(string, "HTTP")
        httpHeaders = optional(list(object({ name = string, value = string })), [])
      }), null)
      tcpSocket = optional(object({ port = number, host = optional(string) }), null)
    }), null)
  })
  description = "Lifecycle hooks контейнера."
  default     = {}
}

// ---------- Трассировка/метрики самого коллектора ----------

variable "collector_self_metrics" {
  type = object({
    enabled = optional(bool, true)
    port    = optional(number, 8888)
    path    = optional(string, "/metrics")
  })
  description = "Экспонирование собственных метрик коллектора (минимально нужно для мониторинга его состояния)."
  default     = {}
}

// ---------- Диагностика и отладка ----------

variable "debug" {
  type        = bool
  description = "Включить расширенный лог уровня debug для коллектора (внутренняя телеметрия и/или аргументы)."
  default     = false
}

variable "extra_args" {
  type        = list(string)
  description = "Дополнительные аргументы командной строки для otelcol."
  default     = []
}

// ---------- Политика перезапуска и тайм-ауты ----------

variable "termination_grace_period_seconds" {
  type        = number
  description = "Grace period при остановке Pod."
  default     = 30
}

variable "pod_runtime_class_name" {
  type        = string
  description = "RuntimeClassName (например, для gVisor)."
  default     = null
}

// ---------- Совместимость/расширения модуля ----------

variable "labels" {
  type        = map(string)
  description = "Глобальные дополнительные метки для всех создаваемых ресурсов."
  default     = {}
}

variable "annotations" {
  type        = map(string)
  description = "Глобальные дополнительные аннотации для всех создаваемых ресурсов."
  default     = {}
}

variable "name_override" {
  type        = string
  description = "Переопределить имя релиза/ресурса."
  default     = null
}

variable "fullname_override" {
  type        = string
  description = "Полностью переопределить fullname ресурсов (если требуется строгая нотация)."
  default     = null
}
