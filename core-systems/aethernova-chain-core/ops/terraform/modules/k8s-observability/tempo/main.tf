/**
 * Module: k8s-observability/tempo
 * File: main.tf
 * Purpose: Install and operate Grafana Tempo (distributed mode) via Helm with
 *          production-grade defaults: object storage (S3/GCS/Azure), secure secrets,
 *          retention by compactor, OTLP ingestion, ServiceMonitor, PSP/NSP, HA, and
 *          tunable resources/affinity.
 *
 * Notes:
 * - Providers (helm, kubernetes) are expected to be configured by the caller/root.
 * - Secrets for object storage are created here from module inputs and mounted as env.
 * - Chart: grafana/tempo-distributed (official). See Grafana docs and ArtifactHub.
 * - Retention is enforced by compactor.block_retention.
 */

terraform {
  required_version = ">= 1.6.0"
}

############################
# Namespace
############################
resource "kubernetes_namespace" "tempo" {
  metadata {
    name = var.namespace
    labels = merge(
      {
        "app.kubernetes.io/name"       = "tempo"
        "app.kubernetes.io/part-of"    = "observability"
        "app.kubernetes.io/component"  = "traces"
        "pod-security.kubernetes.io/enforce" = "restricted"
      },
      var.namespace_labels
    )
  }
}

############################
# Object storage secrets
############################

# S3 / MinIO
resource "kubernetes_secret" "s3" {
  count = var.storage.backend == "s3" ? 1 : 0
  metadata {
    name      = "${var.release_name}-s3"
    namespace = kubernetes_namespace.tempo.metadata[0].name
  }
  type = "Opaque"
  data = {
    TEMPO_S3_ACCESS_KEY = base64encode(var.storage.s3.access_key)
    TEMPO_S3_SECRET_KEY = base64encode(var.storage.s3.secret_key)
  }
}

# GCS service account JSON
resource "kubernetes_secret" "gcs" {
  count = var.storage.backend == "gcs" ? 1 : 0
  metadata {
    name      = "${var.release_name}-gcs"
    namespace = kubernetes_namespace.tempo.metadata[0].name
  }
  type = "Opaque"
  data = {
    GOOGLE_APPLICATION_CREDENTIALS = base64encode(var.storage.gcs.credentials_json)
  }
}

# Azure access key
resource "kubernetes_secret" "azure" {
  count = var.storage.backend == "azure" ? 1 : 0
  metadata {
    name      = "${var.release_name}-azure"
    namespace = kubernetes_namespace.tempo.metadata[0].name
  }
  type = "Opaque"
  data = {
    STORAGE_ACCOUNT_ACCESS_KEY = base64encode(var.storage.azure.account_key)
  }
}

############################
# NetworkPolicy (deny-by-default with allowed scrape/ingest)
############################
resource "kubernetes_network_policy_v1" "deny_all" {
  count = var.enable_network_policy ? 1 : 0
  metadata {
    name      = "${var.release_name}-deny-all"
    namespace = kubernetes_namespace.tempo.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_ns" {
  count = var.enable_network_policy ? 1 : 0
  metadata {
    name      = "${var.release_name}-allow-ingress"
    namespace = kubernetes_namespace.tempo.metadata[0].name
  }
  spec {
    pod_selector {}
    ingress {
      from {
        namespace_selector {
          match_labels = var.allow_ingress_from_namespace_labels
        }
      }
    }
    egress {
      to {
        namespace_selector {}
      }
    }
    policy_types = ["Ingress", "Egress"]
  }
}

############################
# Helm values (yamlencode)
############################

locals {
  # Base Tempo configuration shared across components
  tempo_structured = {
    reportingEnabled = var.reporting_enabled

    # Core Tempo config
    tempo = {
      server = {
        http_listen_port = 3200
      }

      # Storage selection by backend
      storage = {
        trace = merge(
          { backend = var.storage.backend }, // "s3" | "gcs" | "azure" | "local"
          var.storage.backend == "s3" ? {
            s3 = {
              bucket     = var.storage.s3.bucket
              endpoint   = var.storage.s3.endpoint
              region     = var.storage.s3.region
              insecure   = var.storage.s3.insecure
              access_key = "${env("TEMPO_S3_ACCESS_KEY")}"
              secret_key = "${env("TEMPO_S3_SECRET_KEY")}"
              s3forcepathstyle = var.storage.s3.force_path_style
            }
          } : {},
          var.storage.backend == "gcs" ? {
            gcs = {
              bucket_name = var.storage.gcs.bucket
              # Auth via GOOGLE_APPLICATION_CREDENTIALS env from secret
            }
          } : {},
          var.storage.backend == "azure" ? {
            azure = {
              container_name       = var.storage.azure.container
              storage_account_name = var.storage.azure.account_name
              storage_account_key  = "${env("STORAGE_ACCOUNT_ACCESS_KEY")}"
            }
          } : {},
          var.storage.backend == "local" ? {
            local = {
              path = "/var/tempo"
            }
          } : {}
        )
      }

      # Ingestion limits and overrides are optional; retention handled by compactor below
      overrides = {
        defaults = {
          # Example limits
          max_bytes_per_trace = var.limits.max_bytes_per_trace
          ingestion_rate_limit_bytes = var.limits.ingestion_rate_limit_bytes
          ingestion_burst_size_bytes = var.limits.ingestion_burst_size_bytes
        }
      }
    }

    # Enable ServiceMonitor if Prometheus Operator is present
    serviceMonitor = {
      enabled = var.enable_service_monitor
      labels  = var.service_monitor_labels
    }

    # Metrics generator for exemplars
    metricsGenerator = {
      enabled = var.metrics_generator.enabled
      remoteWriteUrl = var.metrics_generator.remote_write_url
      resources      = var.metrics_generator.resources
    }

    # Component replicas and resources
    distributor = {
      replicas  = var.distributor.replicas
      resources = var.distributor.resources
      # Enable OTLP and Jaeger receivers
      receivers = {
        otlp = {
          protocols = {
            grpc = {}
            http = {}
          }
        }
        jaeger = {
          protocols = {
            grpc = {}
            thrift_http = {}
          }
        }
        zipkin = {}
      }
    }

    ingester = {
      replicas  = var.ingester.replicas
      resources = var.ingester.resources
      persistence = {
        enabled      = true
        storageClass = var.ingester.storage_class
        size         = var.ingester.storage_size
      }
      # WAL tuning
      wal = {
        enabled = true
        dir     = "/var/tempo/wal"
      }
    }

    querier = {
      replicas  = var.querier.replicas
      resources = var.querier.resources
    }

    queryFrontend = {
      replicas  = var.query_frontend.replicas
      resources = var.query_frontend.resources
      queryShards = var.query_frontend.query_shards
    }

    queryScheduler = {
      enabled   = var.query_scheduler.enabled
      replicas  = var.query_scheduler.replicas
      resources = var.query_scheduler.resources
    }

    compactor = {
      replicas = var.compactor.replicas
      resources = var.compactor.resources
      config = {
        compaction = {
          block_retention             = var.retention.block_retention # e.g. "720h"
          compacted_block_retention   = var.retention.compacted_block_retention
        }
      }
      persistence = {
        enabled      = true
        storageClass = var.compactor.storage_class
        size         = var.compactor.storage_size
      }
    }

    # Gateway and ingress for external access if needed
    gateway = {
      enabled = var.gateway.enabled
      resources = var.gateway.resources
      ingress = {
        enabled     = var.gateway.ingress.enabled
        ingressClassName = var.gateway.ingress.class_name
        annotations = var.gateway.ingress.annotations
        hosts = var.gateway.ingress.hosts
        tls   = var.gateway.ingress.tls
      }
    }

    # Pod security contexts applied by chart per component; reinforce here
    tempo = {
      securityContext = {
        runAsUser  = 10001
        runAsGroup = 10001
        fsGroup    = 10001
        runAsNonRoot = true
      }
    }

    # Global tolerations/affinity/topology for HA
    tolerations = var.global_tolerations
    nodeSelector = var.global_node_selector
    affinity     = var.global_affinity
    topologySpreadConstraints = var.global_topology_spread_constraints
  }

  # EnvFrom secrets per backend
  extra_envfrom = (
    var.storage.backend == "s3" ? [{ secretRef = { name = kubernetes_secret.s3[0].metadata[0].name } }] :
    var.storage.backend == "gcs" ? [{ secretRef = { name = kubernetes_secret.gcs[0].metadata[0].name } }] :
    var.storage.backend == "azure" ? [{ secretRef = { name = kubernetes_secret.azure[0].metadata[0].name } }] :
    []
  )

  # Final values map passed to Helm chart
  helm_values = merge(
    local.tempo_structured,
    {
      tempo = merge(
        lookup(local.tempo_structured, "tempo", {}),
        { extraEnvFrom = local.extra_envfrom }
      )
    }
  )
}

############################
# Helm release
############################
resource "helm_release" "tempo" {
  name       = var.release_name
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo-distributed"
  version    = var.chart_version
  namespace  = kubernetes_namespace.tempo.metadata[0].name
  timeout    = var.helm_timeout
  wait       = true
  recreate_pods = false
  max_history = 10

  values = [
    yamlencode(local.helm_values)
  ]

  # Optional PDBs and extra manifests controlled by chart; keep CRDs hook policy conservative
  lint = true

  # Keep upgrades safe
  disable_openapi_validation = false
  cleanup_on_fail            = true

  depends_on = concat(
    var.storage.backend == "s3"   ? [kubernetes_secret.s3]   : [],
    var.storage.backend == "gcs"  ? [kubernetes_secret.gcs]  : [],
    var.storage.backend == "azure"? [kubernetes_secret.azure]: [],
    var.enable_network_policy ? [kubernetes_network_policy_v1.deny_all, kubernetes_network_policy_v1.allow_ns] : []
  )
}
