#############################################
# Terraform root — staging environment (AWS)
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
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

  # Backend — заполняется при init через -backend-config=...
  backend "s3" {
    # пример параметров (не храните секреты в коде):
    # bucket         = "tfstate-datafabric-core"
    # key            = "staging/terraform.tfstate"
    # region         = "eu-north-1"
    # dynamodb_table = "tf-locks-datafabric-core"
    # encrypt        = true
  }
}

########################
# Входные переменные
########################

variable "project"       { type = string  default = "datafabric-core" }
variable "environment"   { type = string  default = "staging" }
variable "aws_region"    { type = string  default = "eu-north-1" }
variable "vpc_cidr"      { type = string  default = "10.42.0.0/16" }
variable "az_count"      { type = number  default = 3 }
variable "eks_version"   { type = string  default = "1.29" }
variable "node_instance_types" { type = list(string) default = ["m6i.large","m6a.large"] }
variable "node_min_size" { type = number  default = 2 }
variable "node_max_size" { type = number  default = 6 }
variable "node_desired"  { type = number  default = 3 }

# RDS
variable "db_engine_version" { type = string default = "15.6" }
variable "db_instance_class" { type = string default = "db.m6g.large" }
variable "db_name"           { type = string default = "datafabric" }
variable "db_username"       { type = string default = "dfc_app" }
variable "db_password"       { type = string sensitive = true }
variable "db_allocated_storage" { type = number default = 100 }

# ElastiCache
variable "redis_node_type"  { type = string default = "cache.m6g.large" }
variable "redis_engine_ver" { type = string default = "7.1" }

# S3
variable "s3_data_bucket"      { type = string default = null } # если null — будет сгенерировано
variable "s3_artifacts_bucket" { type = string default = null }

# MSK (Kafka) — staging‑минимум
variable "msk_broker_nodes" { type = number default = 3 }
variable "msk_kafka_version" { type = string default = "3.6.0" }
variable "msk_instance_type" { type = string default = "kafka.m7g.large" }

########################
# Локальные значения
########################

locals {
  name_prefix = "${var.project}-${var.environment}"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "platform-team"
    CostCenter  = "staging"
  }

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Генерация имён бакетов, если не заданы
  data_bucket_name      = coalesce(var.s3_data_bucket,      "${var.project}-${var.environment}-data-${random_id.suffix.hex}")
  artifacts_bucket_name = coalesce(var.s3_artifacts_bucket, "${var.project}-${var.environment}-artifacts-${random_id.suffix.hex}")
}

########################
# Провайдеры и данные
########################

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "random_id" "suffix" {
  byte_length = 3
}

########################
# KMS ключи для шифрования
########################

resource "aws_kms_key" "rds" {
  description             = "${local.name_prefix}-rds"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_key" "s3" {
  description             = "${local.name_prefix}-s3"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_key" "msk" {
  description             = "${local.name_prefix}-msk"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

########################
# VPC (terraform-aws-modules)
########################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  intra_subnets   = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 20)] # для интерфейсных/внутренних

  enable_nat_gateway   = true
  single_nat_gateway   = true
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}

########################
# Security Groups
########################

module "sg_rds" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"

  name        = "${local.name_prefix}-rds"
  description = "RDS PostgreSQL"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = []
  egress_with_cidr_blocks = [{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = "0.0.0.0/0"
  }]

  tags = local.tags
}

module "sg_redis" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"

  name        = "${local.name_prefix}-redis"
  description = "ElastiCache Redis"
  vpc_id      = module.vpc.vpc_id

  egress_with_cidr_blocks = [{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = "0.0.0.0/0"
  }]

  tags = local.tags
}

module "sg_msk" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"

  name        = "${local.name_prefix}-msk"
  description = "MSK Kafka"
  vpc_id      = module.vpc.vpc_id

  egress_with_cidr_blocks = [{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = "0.0.0.0/0"
  }]

  tags = local.tags
}

########################
# EKS Cluster (IRSA)
########################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.eks_version

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  enable_irsa = true

  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
  }

  eks_managed_node_groups = {
    default = {
      name                  = "default"
      instance_types        = var.node_instance_types
      min_size              = var.node_min_size
      max_size              = var.node_max_size
      desired_size          = var.node_desired
      subnet_ids            = module.vpc.private_subnets
      capacity_type         = "ON_DEMAND"
      ami_type              = "AL2_x86_64"
      create_security_group = true
      # Теги для автоскейлера
      tags = merge(local.tags, {
        "k8s.io/cluster-autoscaler/enabled" = "true"
        "k8s.io/cluster-autoscaler/${local.name_prefix}-eks" = "owned"
      })
    }
  }

  tags = local.tags
}

# Доступ EKS SG к RDS/Redis/MSK
resource "aws_security_group_rule" "allow_eks_to_rds" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = module.sg_rds.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

resource "aws_security_group_rule" "allow_eks_to_redis" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  security_group_id        = module.sg_redis.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

resource "aws_security_group_rule" "allow_eks_to_msk" {
  type                     = "ingress"
  from_port                = 9092
  to_port                  = 9098
  protocol                 = "tcp"
  security_group_id        = module.sg_msk.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

########################
# RDS PostgreSQL (Multi-AZ)
########################

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.7"

  identifier = "${local.name_prefix}-pg"

  engine               = "postgres"
  engine_version       = var.db_engine_version
  family               = "postgres15"
  instance_class       = var.db_instance_class
  allocated_storage    = var.db_allocated_storage
  max_allocated_storage = 200
  multi_az             = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password
  port     = 5432

  vpc_security_group_ids = [module.sg_rds.security_group_id]
  subnet_ids             = module.vpc.private_subnets

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  publicly_accessible = false
  deletion_protection = true
  backup_window       = "02:00-03:00"
  maintenance_window  = "Mon:03:00-Mon:04:00"
  backup_retention_period = 7
  performance_insights_enabled = true

  tags = local.tags
}

########################
# ElastiCache Redis
########################

module "elasticache" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.3"

  engine               = "redis"
  engine_version       = var.redis_engine_ver
  node_type            = var.redis_node_type
  cluster_id           = "${local.name_prefix}-redis"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_ids           = module.vpc.private_subnets
  vpc_security_group_ids = [module.sg_redis.security_group_id]

  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = null # добавить при необходимости (staging обычно без)

  tags = local.tags
}

########################
# S3 Buckets (data, artifacts)
########################

resource "aws_s3_bucket" "data" {
  bucket = local.data_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" kms_master_key_id = aws_kms_key.s3.arn } }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifacts_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" kms_master_key_id = aws_kms_key.s3.arn } }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

########################
# MSK Kafka (staging)
########################

module "msk" {
  source  = "terraform-aws-modules/msk-kafka/aws"
  version = "~> 4.0"

  name                = "${local.name_prefix}-msk"
  kafka_version       = var.msk_kafka_version
  number_of_broker_nodes = var.msk_broker_nodes
  broker_node_client_subnets = module.vpc.private_subnets
  broker_node_instance_type  = var.msk_instance_type
  encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

  security_groups = [module.sg_msk.security_group_id]

  client_authentication = {
    sasl_scram = true
    unauthenticated = false
  }

  configuration_info = {
    server_properties = {
      "auto.create.topics.enable" = "false"
      "num.partitions"            = "3"
    }
  }

  tags = local.tags
}

########################
# EKS OIDC & IRSA roles (external-dns, autoscaler, ALB)
########################

module "irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name_prefix = "${local.name_prefix}-irsa-"
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = [
        "kube-system:external-dns",
        "kube-system:cluster-autoscaler",
        "kube-system:aws-load-balancer-controller"
      ]
    }
  }

  attach_external_dns_policy             = true
  attach_cluster_autoscaler_policy       = true
  attach_load_balancer_controller_policy = true

  tags = local.tags
}

########################
# Kubernetes & Helm providers (через EKS)
########################

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

########################
# CloudWatch Log Group (app logs)
########################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/${var.environment}/app"
  retention_in_days = 14
  kms_key_id        = null
  tags              = local.tags
}

########################
# Выходы
########################

output "vpc_id"                 { value = module.vpc.vpc_id }
output "private_subnets"        { value = module.vpc.private_subnets }
output "eks_cluster_name"       { value = module.eks.cluster_name }
output "eks_cluster_endpoint"   { value = module.eks.cluster_endpoint }
output "rds_endpoint"           { value = module.rds.db_instance_endpoint }
output "redis_endpoint"         { value = module.elasticache.primary_endpoint_address }
output "msk_bootstrap_brokers"  { value = module.msk.bootstrap_brokers_sasl_scram }
output "s3_data_bucket"         { value = aws_s3_bucket.data.bucket }
output "s3_artifacts_bucket"    { value = aws_s3_bucket.artifacts.bucket }
