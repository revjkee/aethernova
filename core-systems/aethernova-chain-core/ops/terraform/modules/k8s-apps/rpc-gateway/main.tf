# File: aethernova-chain-core/ops/terraform/modules/k8s-apps/rpc-gateway/main.tf

########################################
# Inputs
########################################

variable "name" {
  description = "Базовое имя приложения/релиза."
  type        = string
  default     = "rpc-gateway"
}

variable "namespace" {
  description = "Namespace для размещения ресурсов."
  type        = string
  default     = "aethernova"
}

variable "create_namespace" {
  description = "Создавать namespace при его отсутствии."
  type        = bool
  default     = true
}

# JSON-RPC (HTTP) сервис
variable "jsonrpc_service_port" {
  description = "Порт Service для JSON-RPC (HTTP/HTTPS), внешний."
  type        = number
  default     = 8545
}

variable "jsonrpc_target_port" {
  description = "targetPort (порт контейнера) для JSON-RPC."
  type        = number
  default     = 8545
}

# gRPC сервис
variable "grpc_service_port" {
  description = "Порт Service для gRPC (HTTP/2)."
  type        = number
  default     = 9090
}

variable "grpc_target_port" {
  description = "targetPort (порт контейнера) для gRPC."
  type        = number
  default     = 9090
}

# Селекторы (метки) рабочих Pod'ов
variable "selector_labels" {
  description = "Селектор Service (labels) для выбора Pod'ов backend."
  type        = map(string)
  default = {
    "app.kubernetes.io/name" = "rpc-backend"
  }
}

# Ingress
variable "enable_ingress" {
  description = "Включить создание Ingress."
  type        = bool
  default     = true
}

variable "ingress_class_name" {
  description = "IngressClassName (например, nginx)."
  type        = string
  default     = "nginx"
}

variable "jsonrpc_host" {
  description = "FQDN для JSON-RPC (например, rpc.example.com)."
  type        = string
}

variable "grpc_host" {
  description = "FQDN для gRPC (например, grpc.example.com)."
  type        = string
}

variable "tls_secret_name" {
  description = "Имя Secret c TLS-сертификатом. Если пусто — TLS не настраивается."
  type        = string
  default     = ""
}

# Аннотации Ingress для NGINX (лимиты, таймауты и т. п.)
variable "ingress_annotations" {
  description = "Дополнительные аннотации для Ingress."
  type        = map(string)
  default = {
    "nginx.ingress.kubernetes.io/proxy-read-timeout"  = "3600"
    "nginx.ingress.kubernetes.io/proxy-send-timeout"  = "3600"
    # gRPC backend: ключевая аннотация согласно Ingress-NGINX docs
    "nginx.ingress.kubernetes.io/backend-protocol"    = "GRPC"
  }
}

# Istio (опционально)
variable "enable_istio" {
  description = "Создавать Istio VirtualService для маршрутизации gRPC/HTTP2 внутри mesh."
  type        = bool
  default     = false
}

variable "istio_gateway" {
  description = "Имя Istio Gateway (namespace/name)."
  type        = string
  default     = "istio-system/ingressgateway"
}

########################################
# Locals
########################################

locals {
  labels_common = {
    "app.kubernetes.io/part-of"    = "aethernova-chain-core"
    "app.kubernetes.io/component"  = "rpc-gateway"
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/instance"   = var.name
  }

  tls_enabled = length(var.tls_secret_name) > 0
}

########################################
# Namespace (optional)
########################################

resource "kubernetes_namespace_v1" "ns" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name   = var.namespace
    labels = local.labels_common
  }
}

########################################
# Services
########################################

# JSON-RPC (HTTP) Service
resource "kubernetes_service_v1" "jsonrpc" {
  metadata {
    name      = "${var.name}-jsonrpc"
    namespace = var.namespace
    labels    = merge(local.labels_common, { "app.kubernetes.io/name" = "${var.name}-jsonrpc" })
  }

  spec {
    type     = "ClusterIP"
    selector = var.selector_labels

    port {
      name        = "http-jsonrpc"
      port        = var.jsonrpc_service_port
      target_port = var.jsonrpc_target_port
      protocol    = "TCP"
      # appProtocol может использоваться контроллерами/mesh для подсказки протокола
      app_protocol = "http"
    }
    session_affinity = "None"
  }

  depends_on = [kubernetes_namespace_v1.ns]
}

# gRPC Service
resource "kubernetes_service_v1" "grpc" {
  metadata {
    name      = "${var.name}-grpc"
    namespace = var.namespace
    labels    = merge(local.labels_common, { "app.kubernetes.io/name" = "${var.name}-grpc" })
  }

  spec {
    type     = "ClusterIP"
    selector = var.selector_labels

    port {
      name         = "grpc"
      port         = var.grpc_service_port
      target_port  = var.grpc_target_port
      protocol     = "TCP"
      # Указываем gRPC/HTTP2 как подсказку для прокси/mesh
      app_protocol = "grpc"
    }
    session_affinity = "None"
  }

  depends_on = [kubernetes_namespace_v1.ns]
}

########################################
# Ingress (HTTP(S) with gRPC backend)
########################################

resource "kubernetes_ingress_v1" "this" {
  count = var.enable_ingress ? 1 : 0

  metadata {
    name        = var.name
    namespace   = var.namespace
    labels      = local.labels_common
    annotations = var.ingress_annotations
  }

  spec {
    ingress_class_name = var.ingress_class_name

    # TLS: включает HTTPS и редирект на 443 у NGINX Ingress (если включён TLS)
    dynamic "tls" {
      for_each = local.tls_enabled ? [1] : []
      content {
        secret_name = var.tls_secret_name
        hosts       = [var.jsonrpc_host, var.grpc_host]
      }
    }

    # Правило для JSON-RPC (HTTP)
    rule {
      host = var.jsonrpc_host
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.jsonrpc.metadata[0].name
              port {
                number = var.jsonrpc_service_port
              }
            }
          }
        }
      }
    }

    # Правило для gRPC (HTTP/2), backend тот же Service c appProtocol=gRPC
    rule {
      host = var.grpc_host
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.grpc.metadata[0].name
              port {
                number = var.grpc_service_port
              }
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_service_v1.jsonrpc,
    kubernetes_service_v1.grpc
  ]
}

########################################
# Istio VirtualService (optional)
########################################
# Требует установленный провайдер Kubernetes >= 2.16 с ресурсом kubernetes_manifest,
# и наличие в кластере CRD networking.istio.io/v1beta1.
# Внутримешевые маршруты HTTP/2/gRPC на сервисы jsonrpc/grpc.
resource "kubernetes_manifest" "istio_virtualservice" {
  count = var.enable_istio ? 1 : 0

  manifest = {
    apiVersion = "networking.istio.io/v1beta1"
    kind       = "VirtualService"
    metadata = {
      name      = var.name
      namespace = var.namespace
      labels    = local.labels_common
    }
    spec = {
      hosts    = [var.jsonrpc_host, var.grpc_host]
      gateways = [var.istio_gateway] # формат: "<ns>/<name>"
      http = [
        {
          name = "jsonrpc-http"
          match = [{ authority = { exact = var.jsonrpc_host } }]
          route = [{
            destination = {
              host = kubernetes_service_v1.jsonrpc.metadata[0].name
              port = { number = var.jsonrpc_service_port }
            }
          }]
        },
        {
          name = "grpc"
          match = [{ authority = { exact = var.grpc_host } }]
          route = [{
            destination = {
              host = kubernetes_service_v1.grpc.metadata[0].name
              port = { number = var.grpc_service_port }
            }
          }]
        }
      ]
    }
  }

  depends_on = [
    kubernetes_service_v1.jsonrpc,
    kubernetes_service_v1.grpc
  ]
}

########################################
# Outputs
########################################

output "jsonrpc_service" {
  value = kubernetes_service_v1.jsonrpc.metadata[0].name
}

output "grpc_service" {
  value = kubernetes_service_v1.grpc.metadata[0].name
}

output "ingress_name" {
  value       = try(kubernetes_ingress_v1.this[0].metadata[0].name, null)
  description = "Имя Ingress (если включён)."
}
