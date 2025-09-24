#############################################
# neuroforge-core / ops / terraform / envs / prod / main.tf
# Продакшн-инфраструктура AWS для Kubernetes-развертывания Neuroforge Core
#############################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50" # зафиксировано мажорно
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
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

  backend "s3" {
    bucket         = "CHANGEME-tfstate-prod-bucket"
    key            = "neuroforge-core/prod/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "CHANGEME-tfstate-locks"
    encrypt        = true
  }
}

#############################################
# Входные параметры (минимально необходимое)
#############################################

variable "project"   { type = string  default = "neuroforge-core" }
variable "env"       { type = string  default = "prod" }
variable "region"    { type = string  default = "eu-west-1" }
variable "domain"    { type = string  default = "example.com" } # базовый домен
variable "subdomain" { type = string  default = "neuroforge" }   # префикс: neuroforge.example.com

# Класс узлов и ёмкости кластера
variable "eks_instance_types" { type = list(string) default = ["m6i.large"] }
variable "eks_desired_size"   { type = number      default = 3 }
variable "eks_min_size"       { type = number      default = 3 }
variable "eks_max_size"       { type = number      default = 9 }

# Размеры БД/кэша
variable "rds_instance_class" { type = string default = "db.m6g.large" }
variable "redis_node_type"    { type = string default = "cache.m6g.large" }

# Сетевой диапазон
variable "vpc_cidr" { type = string default = "10.60.0.0/16" }

#############################################
# Локали и теги
#############################################

locals {
  name       = "${var.project}-${var.env}"
  region     = var.region
  fqdn       = "${var.subdomain}.${var.domain}"
  common_tags = {
    Project     = var.project
    Environment = var.env
    ManagedBy   = "Terraform"
    Owner       = "Platform"
  }
}

provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#############################################
# KMS для шифрования данных
#############################################

resource "aws_kms_key" "main" {
  description         = "KMS CMK for ${local.name}"
  enable_key_rotation = true
  tags                = local.common_tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.main.id
}

#############################################
# VPC (3 AZ, приватные/публичные сабсети, NAT, Flow Logs)
#############################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.0.0"

  name = local.name
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = [for i in range(0, 3) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i in range(0, 3) : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_flow_log                      = true
  flow_log_destination_type            = "s3"
  flow_log_destination_arn             = aws_s3_bucket.logs.arn
  flow_log_cloudwatch_iam_role_arn     = null
  flow_log_cloudwatch_log_group_arn    = null

  tags = local.common_tags
}

data "aws_availability_zones" "available" {
  state = "available"
}

#############################################
# Лог-бакет для Flow Logs / общих логов
#############################################

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

#############################################
# S3: модели и артефакты (CMEK, lifecycle)
#############################################

resource "aws_s3_bucket" "models" {
  bucket        = "${local.name}-models-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "models" {
  bucket                  = aws_s3_bucket.models.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "models"   { bucket = aws_s3_bucket.models.id   versioning_configuration { status = "Enabled" } }
resource "aws_s3_bucket_versioning" "artifacts"{ bucket = aws_s3_bucket.artifacts.id versioning_configuration { status = "Enabled" } }

resource "aws_s3_bucket_lifecycle_configuration" "models" {
  bucket = aws_s3_bucket.models.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "glacier-after-30d"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "models" {
  bucket = aws_s3_bucket.models.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

#############################################
# ECR для образов приложения
#############################################

resource "aws_ecr_repository" "app" {
  name                 = "${local.name}/app"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key        = aws_kms_key.main.arn
  }
  tags = local.common_tags
}

#############################################
# RDS PostgreSQL (Multi-AZ) + пароль в Secrets Manager
#############################################

resource "random_password" "rds" {
  length  = 24
  special = true
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = ">= 6.0.0"

  identifier = "${local.name}-pg"

  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.rds_instance_class

  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.main.arn

  multi_az               = true
  db_name                = "neuroforge"
  username               = "neuroforge"
  password               = random_password.rds.result
  port                   = 5432
  manage_master_user_password = false

  vpc_security_group_ids = [aws_security_group.rds.id]
  subnet_ids             = module.vpc.private_subnets

  backup_retention_period = 7
  maintenance_window      = "Mon:00:00-Mon:03:00"
  backup_window           = "03:00-06:00"
  deletion_protection     = true
  skip_final_snapshot     = false

  tags = local.common_tags
}

resource "aws_security_group" "rds" {
  name        = "${local.name}-rds"
  description = "RDS access from EKS nodes"
  vpc_id      = module.vpc.vpc_id
  tags        = local.common_tags
}
resource "aws_security_group_rule" "rds_ingress_from_nodes" {
  type                     = "ingress"
  security_group_id        = aws_security_group.rds.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = module.eks.node_security_group_id
}
resource "aws_security_group_rule" "rds_egress_all" {
  type              = "egress"
  security_group_id = aws_security_group.rds.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_secretsmanager_secret" "rds" {
  name                    = "${local.name}/rds"
  description             = "RDS creds for ${local.name}"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 7
  tags                    = local.common_tags
}
resource "aws_secretsmanager_secret_version" "rds" {
  secret_id     = aws_secretsmanager_secret.rds.id
  secret_string = jsonencode({
    username = "neuroforge",
    password = random_password.rds.result,
    engine   = "postgres",
    host     = module.rds.db_instance_address,
    port     = 5432,
    dbname   = "neuroforge"
  })
}

#############################################
# ElastiCache Redis (Primary + Replica)
#############################################

module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = ">= 6.0.0"

  cluster_id           = "${local.name}-redis"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = 2 # primary + 1 replica (Redis Cluster mode off)
  parameter_group_name = "default.redis7"

  subnet_group_name           = aws_elasticache_subnet_group.redis.name
  security_group_ids          = [aws_security_group.redis.id]
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auto_minor_version_upgrade  = true

  tags = local.common_tags
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name}-redis-subnets"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "redis" {
  name        = "${local.name}-redis"
  description = "Allow Redis from EKS nodes"
  vpc_id      = module.vpc.vpc_id
  tags        = local.common_tags
}
resource "aws_security_group_rule" "redis_ingress_from_nodes" {
  type                     = "ingress"
  security_group_id        = aws_security_group.redis.id
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = module.eks.node_security_group_id
}
resource "aws_security_group_rule" "redis_egress_all" {
  type              = "egress"
  security_group_id = aws_security_group.redis.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

#############################################
# EKS (IRSA, MNG, аддоны)
#############################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = ">= 20.0.0"

  cluster_name    = local.name
  cluster_version = "1.29"
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true
  kms_key_arn = aws_kms_key.main.arn

  eks_managed_node_groups = {
    default = {
      instance_types = var.eks_instance_types
      min_size       = var.eks_min_size
      max_size       = var.eks_max_size
      desired_size   = var.eks_desired_size
      capacity_type  = "ON_DEMAND"
      disk_size      = 100
      labels         = { workload = "general" }
      tags           = local.common_tags
    }
  }

  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        env = { ENABLE_PREFIX_DELEGATION = "true" }
      })
    }
    aws-ebs-csi-driver = { most_recent = true }
  }

  tags = local.common_tags
}

# kubeconfig-данные для провайдеров kubernetes/helm
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

#############################################
# Helm-аддоны: AWS LB Controller, external-dns, cert-manager
#############################################

# IAM roles for service accounts (IRSA) — создаются модулем EKS add-ons IRSA, либо вручную ниже.
module "lb_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = ">= 5.40.0"

  role_name_prefix = "${local.name}-alb"
  role_policy_arns = ["arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess"]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.common_tags
}

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.7.2"

  values = [yamlencode({
    clusterName = module.eks.cluster_name
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
      annotations = {
        "eks.amazonaws.com/role-arn" = module.lb_controller_irsa.iam_role_arn
      }
    }
  })]

  depends_on = [module.eks]
}

# ExternalDNS: управляет Route53 зонами
module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = ">= 5.40.0"

  role_name_prefix = "${local.name}-external-dns"
  # Политика с правами на hosted zone (минимальный пример):
  inline_policies = {
    external-dns = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect = "Allow"
        Action = ["route53:ChangeResourceRecordSets"]
        Resource = "arn:aws:route53:::hostedzone/*"
      },{
        Effect = "Allow"
        Action = ["route53:ListHostedZones","route53:ListResourceRecordSets"]
        Resource = "*"
      }]
    })
  }
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
  tags = local.common_tags
}

resource "helm_release" "external_dns" {
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = "1.15.0"

  values = [yamlencode({
    provider = "aws"
    domainFilters = [var.domain]
    txtOwnerId    = local.name
    policy        = "upsert-only"
    serviceAccount = {
      create = true
      name   = "external-dns"
      annotations = {
        "eks.amazonaws.com/role-arn" = module.external_dns_irsa.iam_role_arn
      }
    }
  })]

  depends_on = [module.eks]
}

# cert-manager для TLS
resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  namespace  = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  version    = "v1.15.1"

  create_namespace = true

  values = [yamlencode({
    installCRDs = true
  })]

  depends_on = [module.eks]
}

#############################################
# Выходные значения
#############################################

output "region"                 { value = local.region }
output "vpc_id"                 { value = module.vpc.vpc_id }
output "private_subnets"        { value = module.vpc.private_subnets }
output "eks_cluster_name"       { value = module.eks.cluster_name }
output "eks_oidc_provider_arn"  { value = module.eks.oidc_provider_arn }
output "rds_endpoint"           { value = module.rds.db_instance_address }
output "redis_primary_endpoint" { value = module.redis.primary_endpoint_address }
output "s3_models_bucket"       { value = aws_s3_bucket.models.bucket }
output "s3_artifacts_bucket"    { value = aws_s3_bucket.artifacts.bucket }
output "ecr_repository_url"     { value = aws_ecr_repository.app.repository_url }
output "kms_key_arn"            { value = aws_kms_key.main.arn }
