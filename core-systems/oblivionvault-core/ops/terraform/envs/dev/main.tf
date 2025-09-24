terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }

  # ВНИМАНИЕ: значения backend задаются через -backend-config при terraform init.
  backend "s3" {
    # example:
    # bucket         = "tfstate-oblivionvault"
    # key            = "envs/dev/terraform.tfstate"
    # region         = "eu-north-1"
    # dynamodb_table = "tfstate-locks"
    # encrypt        = true
  }
}

############################
# Базовые параметры/локали #
############################

variable "environment" {
  type        = string
  description = "Имя окружения"
  default     = "dev"
}

variable "aws_region" {
  type        = string
  description = "AWS регион"
  default     = "eu-north-1" # Стокгольм
}

variable "aws_profile" {
  type        = string
  description = "Локальный AWS CLI профиль (опционально)"
  default     = null
}

variable "project" {
  type        = string
  description = "Имя проекта"
  default     = "oblivionvault-core"
}

locals {
  name = "${var.project}-${var.environment}"

  tags = {
    Project         = var.project
    Environment     = var.environment
    ManagedBy       = "terraform"
    Owner           = "platform-ops"
    CostCenter      = "core-infra"
    Compliance      = "prod-grade"
    Observability   = "enabled"
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

####################
# Сеть (VPC/Egress)#
####################

variable "vpc_cidr" {
  type        = string
  description = "CIDR блок для VPC"
  default     = "10.20.0.0/16"
}

variable "az_count" {
  type        = number
  description = "Количество AZ для субсетей"
  default     = 3
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Включить NAT GW"
  default     = true
}

variable "single_nat_gateway" {
  type        = bool
  description = "Один NAT на VPC для экономии в dev"
  default     = true
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = local.name
  cidr = var.vpc_cidr

  azs              = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  private_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets   = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, 16 + i)]

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_nat_gateway   = var.enable_nat_gateway
  single_nat_gateway   = var.single_nat_gateway
  enable_ipv6          = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}

##############################
# EKS кластер + managed NGS  #
##############################

variable "cluster_version" {
  type        = string
  description = "Версия Kubernetes"
  default     = "1.29"
}

variable "node_instance_types" {
  type        = list(string)
  description = "Типы инстансов для узлов"
  default     = ["t3.large"]
}

variable "node_desired_size" {
  type        = number
  description = "Желаемое число узлов"
  default     = 2
}

variable "node_min_size" {
  type        = number
  description = "Минимум узлов"
  default     = 1
}

variable "node_max_size" {
  type        = number
  description = "Максимум узлов"
  default     = 4
}

variable "use_spot" {
  type        = bool
  description = "Использовать SPOT узлы"
  default     = true
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name                    = local.name
  cluster_version                 = var.cluster_version
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true
  enable_irsa                     = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
    eks-pod-identity-agent = { most_recent = true }
    aws-ebs-csi-driver     = { most_recent = true }
  }

  eks_managed_node_groups = {
    general = {
      desired_size   = var.node_desired_size
      min_size       = var.node_min_size
      max_size       = var.node_max_size
      instance_types = var.node_instance_types
      capacity_type  = var.use_spot ? "SPOT" : "ON_DEMAND"

      iam_role_additional_policies = {
        # CloudWatch agent / мониторинг, по необходимости
        # cw = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
      }

      labels = {
        "workload" = "general"
      }

      tags = merge(local.tags, {
        "NodeGroup" = "general"
      })
    }
  }

  tags = local.tags
}

########################################
# Подключение к кластеру (K8s/Helm)    #
########################################

data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

##########################
# Namespaces (K8s)       #
##########################

resource "kubernetes_namespace" "observability" {
  metadata {
    name = "observability"
    labels = {
      "app.kubernetes.io/part-of" = var.project
    }
  }
}

resource "kubernetes_namespace" "oblivionvault" {
  metadata {
    name = "oblivionvault"
    labels = {
      "app.kubernetes.io/part-of" = var.project
    }
  }
}

############################################
# Helm: Observability & Ingress controller #
############################################

# AWS Load Balancer Controller (ingress)
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.9.2"

  values = [
    yamlencode({
      clusterName = module.eks.cluster_name
      region      = var.aws_region
      vpcId       = module.vpc.vpc_id
      createPodDisruptionBudget = true
      serviceAccount = {
        create = true
        name   = "aws-load-balancer-controller"
      }
      defaultTags = local.tags
    })
  ]

  depends_on = [module.eks]
}

# Metrics Server
resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.12.1"

  values = [
    yamlencode({
      args = [
        "--kubelet-insecure-tls"
      ]
    })
  ]

  depends_on = [module.eks]
}

# kube-prometheus-stack (Prometheus Operator + Grafana)
resource "helm_release" "kube_prometheus_stack" {
  name       = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "66.2.2"

  values = [
    yamlencode({
      fullnameOverride = "kps"
      grafana = {
        defaultDashboardsEnabled = true
        adminPassword            = "devadmin" # Замените управляемым секретом в prod
        service = { type = "ClusterIP" }
      }
      prometheus = {
        prometheusSpec = {
          retention         = "15d"
          retentionSize     = "25GB"
          scrapeInterval    = "30s"
          evaluationInterval= "30s"
          WALCompression    = true
        }
      }
      alertmanager = {
        enabled = true
      }
    })
  ]

  depends_on = [module.eks]
}

##############################################
# Helm: oblivionvault-core (локальный чарт) #
##############################################

# Путь к локальному чарту из envs/dev: ../../../helm/oblivionvault-core
resource "helm_release" "oblivionvault_core" {
  name       = "oblivionvault-core"
  namespace  = kubernetes_namespace.oblivionvault.metadata[0].name
  chart      = "../../../helm/oblivionvault-core"

  # Флаги для интеграции с Prometheus Operator (ServiceMonitor)
  values = [
    yamlencode({
      serviceMonitor = {
        enabled    = true
        namespace  = kubernetes_namespace.observability.metadata[0].name
        additionalLabels = {
          release = "kube-prometheus-stack"
        }
        interval       = "30s"
        scrapeTimeout  = "10s"
        honorLabels    = true
        endpoints = [
          {
            portName      = "http-metrics"
            path          = "/metrics"
            scheme        = "http"
            honorLabels   = true
            metricRelabelings = [
              {
                action       = "drop"
                sourceLabels = ["__name__"]
                regex        = "go_gc_duration_seconds.*"
              }
            ]
          }
        ]
      }
      podDisruptionBudget = {
        enabled = true
        minAvailable = "50%"
      }
      resources = {
        requests = { cpu = "100m", memory = "128Mi" }
        limits   = { cpu = "500m", memory = "512Mi" }
      }
    })
  ]

  depends_on = [
    module.eks,
    helm_release.kube_prometheus_stack
  ]
}

############
# Outputs  #
############

output "region" {
  value       = var.aws_region
  description = "AWS регион"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "ID созданной VPC"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "Имя EKS кластера"
}

output "kubeconfig_commands" {
  description = "Команды для kubectl"
  value = [
    "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}" ,
    "kubectl get nodes -o wide"
  ]
}
