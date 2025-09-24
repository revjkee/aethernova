terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Удалённое хранение состояния Terraform (S3) с блокировкой (DynamoDB)
  backend "s3" {
    bucket         = "veilmind-tfstate-prod"                      # заменить на ваш бакет
    key            = "veilmind-core/envs/prod/terraform.tfstate"  # путь к state
    region         = "eu-west-1"                                   # регион бакета
    dynamodb_table = "veilmind-tf-locks"                           # таблица блокировок
    encrypt        = true
  }
}

# -------------------------
# Базовые переменные/локали
# -------------------------
variable "aws_region" {
  description = "Регион AWS для окружения prod"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_cidr" {
  description = "CIDR диапазон VPC"
  type        = string
  default     = "10.60.0.0/16"
}

variable "az_count" {
  description = "Количество AZ для приватных/публичных подсетей"
  type        = number
  default     = 3
}

variable "admin_cidrs" {
  description = "Белые списки CIDR для публичной конечной точки EKS API"
  type        = list(string)
  default     = ["0.0.0.0/0"] # замените на ваши офисные/JumpHost сети
}

variable "eks_version" {
  description = "Версия Kubernetes в EKS"
  type        = string
  default     = "1.29"
}

variable "cluster_name" {
  description = "Имя кластера EKS"
  type        = string
  default     = "veilmind-prod-eks"
}

locals {
  name = "veilmind-prod"

  tags = {
    Project     = "veilmind-core"
    Environment = "prod"
    ManagedBy   = "terraform"
    Owner       = "platform-team"
    CostCenter  = "infra"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Выбираем первые var.az_count AZ
locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  public_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 16)]
}

# -------------------------
# Сеть: отказоустойчивая VPC
# -------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets

  enable_dns_hostnames = true
  enable_dns_support   = true

  # NAT per AZ для продакшна (высокая доступность)
  enable_nat_gateway = true
  single_nat_gateway = false

  # Маркируем подсети для балансировщиков EKS
  public_subnet_tags = merge(local.tags, {
    "kubernetes.io/role/elb" = "1"
  })

  private_subnet_tags = merge(local.tags, {
    "kubernetes.io/role/internal-elb" = "1"
  })

  tags = local.tags
}

# -------------------------
# KMS для шифрования Secret-ов EKS (envelope encryption)
# -------------------------
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS secrets encryption (${local.name})"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = merge(local.tags, {
    Name = "${local.name}-eks-kms"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name}/eks"
  target_key_id = aws_kms_key.eks.key_id
}

# -------------------------
# Кластер EKS с IRSA и логами
# -------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.eks_version

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  enable_irsa                    = true
  cluster_endpoint_public_access = true
  cluster_endpoint_public_access_cidrs = var.admin_cidrs

  cluster_encryption_config = [{
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.eks.arn
  }]

  # Логи контроллера
  cluster_enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  # Аддоны кластера (версии управляются AWS; при конфликте — обновлять)
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent              = true
      service_account_role_arn = null
    }
  }

  # Управляемая группа узлов (пример On‑Demand, можно расширять картой)
  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["m6i.large"]

      desired_size = 3
      min_size     = 3
      max_size     = 10

      labels = {
        "workload.veilmind.io/profile" = "default"
      }

      taints = [] # можно добавить таинты при необходимости

      subnet_ids = module.vpc.private_subnets

      update_config = {
        max_unavailable_percentage = 33
      }

      capacity_type = "ON_DEMAND"

      # Дисковая подсистема
      block_device_mappings = [{
        device_name = "/dev/xvda"
        ebs = {
          volume_size = 50
          volume_type = "gp3"
          encrypted   = true
          kms_key_id  = aws_kms_key.eks.arn
        }
      }]
    }
  }

  tags = local.tags
}

# -------------------------
# Провайдеры Kubernetes/Helm для работы с EKS
# -------------------------
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

# -------------------------
# Метрик‑сервер (Helm) — HPA будет работать «из коробки»
# -------------------------
resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.12.2"

  # Жёсткие значения по умолчанию
  values = [
    yamlencode({
      args = [
        "--kubelet-preferred-address-types=InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP",
        "--kubelet-use-node-status-port",
        "--metric-resolution=15s"
      ]
      tolerations = [{
        key      = "node-role.kubernetes.io/control-plane"
        operator = "Exists"
        effect   = "NoSchedule"
      }]
      podLabels = {
        "app.kubernetes.io/part-of" = "veilmind-core"
      }
    })
  ]

  depends_on = [module.eks]
}

# -------------------------
# Важные выходы
# -------------------------
output "region" {
  value       = var.aws_region
  description = "Регион AWS"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "ID VPC"
}

output "private_subnets" {
  value       = module.vpc.private_subnets
  description = "Список приватных подсетей"
}

output "eks_cluster_name" {
  value       = module.eks.cluster_name
  description = "Имя кластера EKS"
}

output "eks_cluster_endpoint" {
  value       = data.aws_eks_cluster.this.endpoint
  description = "Публичная конечная точка EKS API"
}

output "eks_oidc_provider_arn" {
  value       = module.eks.oidc_provider_arn
  description = "ARN OIDC провайдера для IRSA"
}

output "kms_key_arn" {
  value       = aws_kms_key.eks.arn
  description = "ARN KMS ключа, используемого для шифрования Secret-ов EKS"
}
