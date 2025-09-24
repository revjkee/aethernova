#############################################
# aethernova-chain-core/ops/terraform/modules/compute/eks-nodegroup/outputs.tf
#############################################

# Базовая идентификация
output "node_group_id" {
  description = "ID узловой группы EKS (обычно совпадает с её именем)."
  value       = aws_eks_node_group.this.id
  depends_on  = [aws_eks_node_group.this]
}

output "node_group_arn" {
  description = "ARN узловой группы EKS."
  value       = aws_eks_node_group.this.arn
  depends_on  = [aws_eks_node_group.this]
}

output "cluster_name" {
  description = "Имя кластера EKS, к которому принадлежит узловая группа."
  value       = aws_eks_node_group.this.cluster_name
}

# Версии и состояние
output "node_group_status" {
  description = "Текущее состояние узловой группы EKS (CREATING/ACTIVE/UPDATING/DELETING/FAILED)."
  value       = aws_eks_node_group.this.status
  depends_on  = [aws_eks_node_group.this]
}

output "kubernetes_version" {
  description = "Версия Kubernetes, заданная для узловой группы (если указана)."
  value       = try(aws_eks_node_group.this.version, null)
}

output "ami_release_version" {
  description = "Версия AMI (release_version) для узловой группы (если управляется вручную)."
  value       = try(aws_eks_node_group.this.release_version, null)
}

# Конфигурация масштабирования
output "scaling_config" {
  description = "Параметры масштабирования узловой группы (desired, min, max)."
  value = try({
    desired_size = aws_eks_node_group.this.scaling_config[0].desired_size
    min_size     = aws_eks_node_group.this.scaling_config[0].min_size
    max_size     = aws_eks_node_group.this.scaling_config[0].max_size
  }, null)
}

# Тип мощности, типы инстансов, диск/AMI
output "capacity_type" {
  description = "Тип мощности (ON_DEMAND или SPOT)."
  value       = try(aws_eks_node_group.this.capacity_type, null)
}

output "instance_types" {
  description = "Список типов инстансов, используемых узловой группой."
  value       = try(aws_eks_node_group.this.instance_types, [])
}

output "ami_type" {
  description = "Тип AMI (например, AL2_x86_64, BOTTLEROCKET_x86_64)."
  value       = try(aws_eks_node_group.this.ami_type, null)
}

output "disk_size_gib" {
  description = "Размер диска рабочих узлов, ГиБ (если задан)."
  value       = try(aws_eks_node_group.this.disk_size, null)
}

# Подсети/безопасность/роль
output "subnet_ids" {
  description = "Список подсетей, в которых размещена узловая группа."
  value       = try(aws_eks_node_group.this.subnet_ids, [])
}

output "node_role_arn" {
  description = "ARN IAM-ролі, используемой узловой группой."
  value       = aws_eks_node_group.this.node_role_arn
}

output "remote_access_security_group_id" {
  description = "ID Security Group, созданной для удалённого доступа (если применимо)."
  value       = try(aws_eks_node_group.this.resources[0].remote_access_security_group_id, null)
  depends_on  = [aws_eks_node_group.this]
}

# Labels/Taints
output "labels" {
  description = "Набор Kubernetes-меток, назначенных узлам группы."
  value       = try(aws_eks_node_group.this.labels, {})
}

output "taints" {
  description = "Список taints, применённых к узлам группы."
  value       = try(aws_eks_node_group.this.taints, [])
}

# Launch Template (если используется)
output "launch_template_id" {
  description = "ID Launch Template, если узловая группа использует LT."
  value       = try(aws_eks_node_group.this.launch_template[0].id, null)
}

output "launch_template_version" {
  description = "Версия Launch Template, если узловая группа использует LT."
  value       = try(aws_eks_node_group.this.launch_template[0].version, null)
}

# Привязанные ASG
output "autoscaling_group_names" {
  description = "Список имён Auto Scaling Group, созданных/привязанных к узловой группе."
  value       = try(flatten([for r in aws_eks_node_group.this.resources : [for g in r.autoscaling_groups : g.name]]), [])
  depends_on  = [aws_eks_node_group.this]
}

# Диагностический сводный объект (удобно для логов CI/CD)
output "diagnostics" {
  description = "Сводная диагностическая информация по узловой группе."
  value = {
    cluster_name     = aws_eks_node_group.this.cluster_name
    node_group_id    = aws_eks_node_group.this.id
    arn              = aws_eks_node_group.this.arn
    status           = aws_eks_node_group.this.status
    kubernetes       = try(aws_eks_node_group.this.version, null)
    release_version  = try(aws_eks_node_group.this.release_version, null)
    capacity_type    = try(aws_eks_node_group.this.capacity_type, null)
    instance_types   = try(aws_eks_node_group.this.instance_types, [])
    scaling          = try({
      desired = aws_eks_node_group.this.scaling_config[0].desired_size
      min     = aws_eks_node_group.this.scaling_config[0].min_size
      max     = aws_eks_node_group.this.scaling_config[0].max_size
    }, null)
    subnets          = try(aws_eks_node_group.this.subnet_ids, [])
    lt               = try({
      id      = aws_eks_node_group.this.launch_template[0].id
      version = aws_eks_node_group.this.launch_template[0].version
    }, null)
    asg_names        = try(flatten([for r in aws_eks_node_group.this.resources : [for g in r.autoscaling_groups : g.name]]), [])
  }
  depends_on = [aws_eks_node_group.this]
  sensitive  = false
}
