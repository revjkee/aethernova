##############################
# modules/compute/eks/outputs.tf
##############################
# Предполагаемые ресурсы в модуле:
#   - aws_eks_cluster.this
#   - aws_eks_node_group.this           (for_each по карте nodegroup-ов)
#   - aws_iam_openid_connect_provider.this  (опционально, если создаётся в модуле)
#   - aws_eks_addon.addons              (опционально, for_each по карте аддонов)
#
# При иных именах ресурсов скорректируйте ссылки ниже.

##############################
# Блок: Кластер (агрегат)
##############################

output "cluster" {
  description = "Сводная информация об EKS-кластере."
  value = {
    name                 = aws_eks_cluster.this.name
    arn                  = aws_eks_cluster.this.arn
    id                   = aws_eks_cluster.this.id
    version              = aws_eks_cluster.this.version
    platform_version     = try(aws_eks_cluster.this.platform_version, null)
    endpoint             = aws_eks_cluster.this.endpoint
    certificate_authority_data = try(aws_eks_cluster.this.certificate_authority[0].data, null)

    # OIDC-issuer, необходим для IRSA и создания IAM OIDC провайдера
    oidc_issuer          = try(aws_eks_cluster.this.identity[0].oidc[0].issuer, null)

    # Security Group кластера: экспортируется как top-level и/или внутри vpc_config
    cluster_security_group_id = try(aws_eks_cluster.this.cluster_security_group_id, null)
    vpc_config = try({
      security_group_ids          = try(aws_eks_cluster.this.vpc_config[0].security_group_ids, null)
      subnet_ids                  = try(aws_eks_cluster.this.vpc_config[0].subnet_ids, null)
      cluster_security_group_id   = try(aws_eks_cluster.this.vpc_config[0].cluster_security_group_id, null)
      endpoint_private_access     = try(aws_eks_cluster.this.vpc_config[0].endpoint_private_access, null)
      endpoint_public_access      = try(aws_eks_cluster.this.vpc_config[0].endpoint_public_access, null)
      public_access_cidrs         = try(aws_eks_cluster.this.vpc_config[0].public_access_cidrs, null)
    }, null)
  }
  sensitive = false
}

##############################
# Блок: Kubeconfig (готовая строка)
##############################
# Формат по образцу HashiCorp: endpoint + CA-data в kubeconfig.
# Токен не записываем (получайте через aws_eks_cluster_auth в рантайме).
locals {
  kubeconfig = <<-KUBECONFIG
    apiVersion: v1
    clusters:
    - cluster:
        server: ${aws_eks_cluster.this.endpoint}
        certificate-authority-data: ${try(aws_eks_cluster.this.certificate_authority[0].data, "")}
      name: ${aws_eks_cluster.this.name}
    contexts:
    - context:
        cluster: ${aws_eks_cluster.this.name}
        user: ${aws_eks_cluster.this.name}
      name: ${aws_eks_cluster.this.name}
    current-context: ${aws_eks_cluster.this.name}
    kind: Config
    preferences: {}
    users:
    - name: ${aws_eks_cluster.this.name}
      user:
        exec:
          apiVersion: "client.authentication.k8s.io/v1beta1"
          command: "aws"
          args:
            - "eks"
            - "get-token"
            - "--cluster-name"
            - "${aws_eks_cluster.this.name}"
  KUBECONFIG
}

output "kubeconfig" {
  description = "Готовый kubeconfig для подключения к кластеру (без долгоживущих секретов)."
  value       = local.kubeconfig
  sensitive   = true
}

##############################
# Блок: Node groups (детализация)
##############################

# Карта node group => объект с ключевыми атрибутами
output "node_groups" {
  description = "Детализация EKS managed node groups."
  value = {
    for name, ng in aws_eks_node_group.this :
    name => {
      id               = ng.id
      arn              = ng.arn
      status           = try(ng.status, null)
      cluster_name     = ng.cluster_name
      version          = try(ng.version, null)
      release_version  = try(ng.release_version, null)
      capacity_type    = try(ng.capacity_type, null)
      instance_types   = try(ng.instance_types, null)
      disk_size        = try(ng.disk_size, null)
      node_role_arn    = try(ng.node_role_arn, null)
      subnet_ids       = try(ng.subnet_ids, null)
      labels           = try(ng.labels, {})
      taints           = try(ng.taints, [])

      scaling_config = try({
        desired_size = ng.scaling_config[0].desired_size
        min_size     = ng.scaling_config[0].min_size
        max_size     = ng.scaling_config[0].max_size
      }, null)

      # Связанные ресурсы (ASG имена) — удобны для интеграции с autoscaling/alarms
      resources = try({
        autoscaling_group_names = try([for g in ng.resources[0].autoscaling_groups : g.name], [])
        remote_access_sg_id     = try(ng.resources[0].remote_access_security_group_id, null)
      }, null)
    }
  }
  sensitive = false
}

# Плоские удобные выводы
output "node_group_arns" {
  description = "Список ARN всех node group."
  value       = [for ng in values(aws_eks_node_group.this) : ng.arn]
}

output "node_group_asg_names" {
  description = "Список имён Auto Scaling Group, созданных для всех node group."
  value = flatten([
    for ng in values(aws_eks_node_group.this) :
    try([for g in ng.resources[0].autoscaling_groups : g.name], [])
  ])
}

##############################
# Блок: IAM OIDC provider (если создаётся модулем)
##############################

output "oidc_provider" {
  description = "Данные IAM OIDC провайдера для IRSA (если создаётся в модуле)."
  value = try({
    arn              = aws_iam_openid_connect_provider.this.arn
    url              = aws_iam_openid_connect_provider.this.url
    thumbprint_list  = aws_iam_openid_connect_provider.this.thumbprint_list
  }, null)
}

##############################
# Блок: EKS addons (если задаются)
##############################

output "addons" {
  description = "Карта установленных EKS add-ons (по имени)."
  value = try({
    for k, a in aws_eks_addon.addons :
    k => {
      arn           = a.arn
      addon_name    = a.addon_name
      addon_version = try(a.addon_version, null)
      cluster_name  = a.cluster_name
      status        = try(a.status, null)
      service_account_role_arn = try(a.service_account_role_arn, null)
    }
  }, null)
  sensitive = false
}

##############################
# Часто нужные атомарные выводы
##############################

output "cluster_endpoint" {
  description = "API endpoint кластера."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_ca_data" {
  description = "CA (base64) кластера для kubeconfig."
  value       = try(aws_eks_cluster.this.certificate_authority[0].data, null)
  sensitive   = true
}

output "cluster_oidc_issuer" {
  description = "OIDC issuer кластера (для IRSA)."
  value       = try(aws_eks_cluster.this.identity[0].oidc[0].issuer, null)
}

output "cluster_security_group_id" {
  description = "Cluster Security Group (создан AWS EKS для кластера)."
  value       = try(aws_eks_cluster.this.cluster_security_group_id, null)
}

output "cluster_vpc_subnet_ids" {
  description = "Идентификаторы подсетей, подключённых к кластеру."
  value       = try(aws_eks_cluster.this.vpc_config[0].subnet_ids, null)
}
