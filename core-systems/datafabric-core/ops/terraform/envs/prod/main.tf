#############################################
# Terraform root — production environment
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

  backend "s3" {
    # Пример (реальные значения задаются через -backend-config)
    # bucket         = "tfstate-datafabric-core"
    # key            = "prod/terraform.tfstate"
    # region         = "eu-north-1"
    # dynamodb_table = "tf-locks-datafabric-core"
    # encrypt        = true
  }
}

########################
# Variables
########################

variable "project"       { type = string  default = "datafabric-core" }
variable "environment"   { type = string  default = "prod" }
variable "aws_region"    { type = string  default = "eu-north-1" }
variable "vpc_cidr"      { type = string  default = "10.64.0.0/16" }
variable "az_count"      { type = number  default = 3 }

# EKS
variable "eks_version"   { type = string  default = "1.29" }
variable "ng_system_instance_types" { type = list(string) default = ["m6i.large"] }
variable "ng_app_spot_instance_types" { type = list(string) default = ["m6i.xlarge","m6a.xlarge","c6i.xlarge"] }
variable "ng_system_size" { type = object({ min = number, max = number, desired = number }) default = { min = 3, max = 6, desired = 3 } }
variable "ng_app_size"    { type = object({ min = number, max = number, desired = number }) default = { min = 6, max = 30, desired = 10 } }

# Aurora PostgreSQL
variable "aurora_engine_version" { type = string default = "15.4" }
variable "aurora_instance_class" { type = string default = "db.r6g.large" }
variable "aurora_min_capacity"   { type = number default = 2 }  # кол-во инстансов
variable "aurora_max_capacity"   { type = number default = 4 }

# Redis
variable "redis_node_type"  { type = string default = "cache.r6g.large" }
variable "redis_engine_ver" { type = string default = "7.1" }

# MSK
variable "msk_broker_nodes"  { type = number default = 3 }
variable "msk_kafka_version" { type = string default = "3.6.0" }
variable "msk_instance_type" { type = string default = "kafka.m7g.large" }

# S3
variable "s3_data_bucket"      { type = string default = null }
variable "s3_artifacts_bucket" { type = string default = null }
variable "enable_s3_crr"       { type = bool   default = false }
variable "s3_crr_destination_bucket" { type = string default = null } # при enable_s3_crr=true

# DB credentials (секреты — из CI/SSM/Secrets Manager)
variable "db_master_username" { type = string default = "dfc_admin" }
variable "db_master_password" { type = string sensitive = true }

########################
# Locals
########################

locals {
  name_prefix = "${var.project}-${var.environment}"

  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "platform-team"
    CostCenter  = "production"
    Confidentiality = "internal"
  }

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  data_bucket_name      = coalesce(var.s3_data_bucket,      "${var.project}-${var.environment}-data-${random_id.suffix.hex}")
  artifacts_bucket_name = coalesce(var.s3_artifacts_bucket, "${var.project}-${var.environment}-artifacts-${random_id.suffix.hex}")
}

########################
# Providers & Data
########################

provider "aws" {
  region = var.aws_region
  default_tags { tags = local.tags }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "random_id" "suffix" { byte_length = 3 }

########################
# KMS Keys
########################

resource "aws_kms_key" "log" {
  description             = "${local.name_prefix}-log"
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

resource "aws_kms_key" "aurora" {
  description             = "${local.name_prefix}-aurora"
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
# VPC with Flow Logs
########################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  intra_subnets   = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 20)]

  enable_nat_gateway       = true
  one_nat_gateway_per_az   = true
  single_nat_gateway       = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_security_group = true

  public_subnet_tags = { "kubernetes.io/role/elb" = "1" }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = "1" }

  flow_log_destination_type = "cloud-watch-logs"
  create_flow_log_cloudwatch_log_group = true
  flow_log_cloudwatch_log_group_name   = "/${var.project}/${var.environment}/vpc-flow-logs"
  flow_log_cloudwatch_log_group_kms_key_id = aws_kms_key.log.arn
  flow_log_cloudwatch_iam_role_arn     = null
  flow_log_max_aggregation_interval    = 60

  tags = local.tags
}

########################
# CloudTrail (audit)
########################

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = "${local.name_prefix}-trail-${random_id.suffix.hex}"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.log.arn
  tags                          = local.tags
}

########################
# Security Groups shells
########################

module "sg_aurora" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"
  name        = "${local.name_prefix}-aurora"
  description = "Aurora PostgreSQL"
  vpc_id      = module.vpc.vpc_id
  egress_with_cidr_blocks = [{ from_port=0, to_port=0, protocol="-1", cidr_blocks="0.0.0.0/0" }]
  tags = local.tags
}

module "sg_redis" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"
  name        = "${local.name_prefix}-redis"
  description = "ElastiCache Redis"
  vpc_id      = module.vpc.vpc_id
  egress_with_cidr_blocks = [{ from_port=0, to_port=0, protocol="-1", cidr_blocks="0.0.0.0/0" }]
  tags = local.tags
}

module "sg_msk" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.1"
  name        = "${local.name_prefix}-msk"
  description = "MSK Kafka"
  vpc_id      = module.vpc.vpc_id
  egress_with_cidr_blocks = [{ from_port=0, to_port=0, protocol="-1", cidr_blocks="0.0.0.0/0" }]
  tags = local.tags
}

########################
# EKS (IRSA, addons)
########################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = "${local.name_prefix}-eks"
  cluster_version = var.eks_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true
  enable_irsa = true

  cluster_addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }

  eks_managed_node_groups = {
    system = {
      name           = "system"
      instance_types = var.ng_system_instance_types
      min_size       = var.ng_system_size.min
      max_size       = var.ng_system_size.max
      desired_size   = var.ng_system_size.desired
      capacity_type  = "ON_DEMAND"
      labels         = { role = "system" }
      taints         = [{ key="dedicated", value="system", effect="NO_SCHEDULE" }]
    }

    app_spot = {
      name           = "app-spot"
      instance_types = var.ng_app_spot_instance_types
      min_size       = var.ng_app_size.min
      max_size       = var.ng_app_size.max
      desired_size   = var.ng_app_size.desired
      capacity_type  = "SPOT"
      labels         = { role = "app" }
      tags = {
        "k8s.io/cluster-autoscaler/enabled" = "true"
        "k8s.io/cluster-autoscaler/${local.name_prefix}-eks" = "owned"
      }
    }
  }

  tags = local.tags
}

# Разрешения от EKS к БД/Redis/MSK
resource "aws_security_group_rule" "eks_to_pg" {
  type                     = "ingress"
  from_port = 5432
  to_port   = 5432
  protocol  = "tcp"
  security_group_id        = module.sg_aurora.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

resource "aws_security_group_rule" "eks_to_redis" {
  type                     = "ingress"
  from_port = 6379
  to_port   = 6379
  protocol  = "tcp"
  security_group_id        = module.sg_redis.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

resource "aws_security_group_rule" "eks_to_msk" {
  type                     = "ingress"
  from_port = 9092
  to_port   = 9098
  protocol  = "tcp"
  security_group_id        = module.sg_msk.security_group_id
  source_security_group_id = module.eks.node_security_group_id
}

########################
# Aurora PostgreSQL (Multi-AZ)
########################

module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 8.3"

  name                      = "${local.name_prefix}-aurora"
  engine                    = "aurora-postgresql"
  engine_version            = var.aurora_engine_version
  database_name             = "datafabric"
  master_username           = var.db_master_username
  master_password           = var.db_master_password
  port                      = 5432

  vpc_id                    = module.vpc.vpc_id
  subnets                   = module.vpc.private_subnets
  vpc_security_group_ids    = [module.sg_aurora.security_group_id]

  replica_scale_enabled     = false
  instances = {
    one = { instance_class = var.aurora_instance_class, promotion_tier = 1 }
    two = { instance_class = var.aurora_instance_class, promotion_tier = 2 }
  }

  storage_encrypted         = true
  kms_key_id                = aws_kms_key.aurora.arn

  apply_immediately         = false
  backup_retention_period   = 7
  preferred_backup_window   = "02:00-03:00"
  preferred_maintenance_window = "Mon:03:00-Mon:04:00"

  enable_http_endpoint      = false
  deletion_protection       = true

  tags = local.tags
}

########################
# ElastiCache Redis (replica)
########################

module "elasticache" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.3"

  engine               = "redis"
  engine_version       = var.redis_engine_ver
  node_type            = var.redis_node_type
  cluster_id           = "${local.name_prefix}-redis"
  num_cache_nodes      = 1
  replicas_per_node_group = 1
  automatic_failover_enabled = true
  multi_az_enabled     = true
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_ids              = module.vpc.private_subnets
  vpc_security_group_ids  = [module.sg_redis.security_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = null # для prod при необходимости задать

  tags = local.tags
}

########################
# MSK Kafka
########################

module "msk" {
  source  = "terraform-aws-modules/msk-kafka/aws"
  version = "~> 4.0"

  name                       = "${local.name_prefix}-msk"
  kafka_version              = var.msk_kafka_version
  number_of_broker_nodes     = var.msk_broker_nodes
  broker_node_client_subnets = module.vpc.private_subnets
  broker_node_instance_type  = var.msk_instance_type
  encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

  security_groups = [module.sg_msk.security_group_id]

  client_authentication = {
    tls         = true
    sasl_scram  = true
    unauthenticated = false
  }

  configuration_info = {
    server_properties = {
      "auto.create.topics.enable" = "false"
      "num.partitions"            = "6"
      "default.replication.factor"= "3"
    }
  }

  tags = local.tags
}

########################
# S3 Buckets (data, artifacts) + CRR (optional)
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

# Optional: CRR для data bucket
resource "aws_s3_bucket_replication_configuration" "data_crr" {
  count  = var.enable_s3_crr ? 1 : 0
  role   = aws_iam_role.s3_replication[0].arn
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "crr-all"
    status = "Enabled"

    destination {
      bucket        = "arn:aws:s3:::${var.s3_crr_destination_bucket}"
      storage_class = "STANDARD"
      encryption_configuration { replica_kms_key_id = aws_kms_key.s3.arn }
    }
  }
}

resource "aws_iam_role" "s3_replication" {
  count = var.enable_s3_crr ? 1 : 0
  name  = "${local.name_prefix}-s3-crr"
  assume_role_policy = data.aws_iam_policy_document.s3_replication_assume[0].json
  tags = local.tags
}

data "aws_iam_policy_document" "s3_replication_assume" {
  count = var.enable_s3_crr ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["s3.amazonaws.com"] }
  }
}

########################
# IRSA roles (external-dns, autoscaler, ALB controller)
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
# K8s / Helm providers via EKS
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
# CloudWatch Log Group (app)
########################

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/${var.environment}/app"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.log.arn
  tags              = local.tags
}

########################
# Outputs
########################

output "vpc_id"               { value = module.vpc.vpc_id }
output "private_subnets"      { value = module.vpc.private_subnets }
output "eks_cluster_name"     { value = module.eks.cluster_name }
output "eks_cluster_endpoint" { value = module.eks.cluster_endpoint }
output "aurora_cluster_arn"   { value = module.aurora.arn }
output "aurora_endpoints"     { value = { reader = module.aurora.reader_endpoint, writer = module.aurora.endpoint } }
output "redis_endpoint"       { value = module.elasticache.primary_endpoint_address }
output "msk_bootstrap"        { value = module.msk.bootstrap_brokers_tls }
output "s3_data_bucket"       { value = aws_s3_bucket.data.bucket }
output "s3_artifacts_bucket"  { value = aws_s3_bucket.artifacts.bucket }
