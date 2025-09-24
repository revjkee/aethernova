###############################################################################
# aethernova-chain-core/ops/terraform/modules/cicd/runners/outputs.tf
#
# Промышленный набор выходов для модульной подсистемы self-hosted runners
# (GitHub Actions / GitLab Runners) на базе AWS + Kubernetes.
# Предполагается наличие одноимённых ресурсов внутри модуля:
#   - GitHub: aws_launch_template.github, aws_autoscaling_group.github,
#             aws_iam_role.github_runner, aws_iam_instance_profile.github_runner,
#             aws_security_group.github_runners,
#             kubernetes_namespace.ci_runners,
#             kubernetes_secret.github_runner_registration
#   - GitLab: aws_launch_template.gitlab, aws_autoscaling_group.gitlab,
#             aws_iam_role.gitlab_runner, aws_iam_instance_profile.gitlab_runner,
#             aws_security_group.gitlab_runners,
#             kubernetes_secret.gitlab_runner_registration
#
# Все выходы снабжены описаниями; секреты помечены как sensitive.
###############################################################################

############################
# Общие / инфраструктурные #
############################

output "runners_namespace" {
  description = "Kubernetes Namespace, в котором развёрнуты runner-пулы и вспомогательные объекты."
  value       = kubernetes_namespace.ci_runners.metadata[0].name
}

output "runners_namespace_uid" {
  description = "UID Kubernetes Namespace для трассировки и аудита."
  value       = kubernetes_namespace.ci_runners.metadata[0].uid
}

############################
# GitHub Actions Runners   #
############################

output "github_runner_asg_name" {
  description = "Имя Auto Scaling Group для GitHub Actions runners."
  value       = aws_autoscaling_group.github.name
}

output "github_runner_asg_arn" {
  description = "ARN Auto Scaling Group для GitHub Actions runners."
  value       = aws_autoscaling_group.github.arn
}

output "github_runner_asg_capacity_limits" {
  description = "Лимиты масштабирования (min/max/desired) для ASG GitHub runners."
  value = {
    min_size    = aws_autoscaling_group.github.min_size
    max_size    = aws_autoscaling_group.github.max_size
    desired_cap = aws_autoscaling_group.github.desired_capacity
  }
}

output "github_runner_lt_id" {
  description = "ID Launch Template, используемого для GitHub Actions runners."
  value       = aws_launch_template.github.id
}

output "github_runner_lt_latest_version" {
  description = "Последняя версия Launch Template (числовой идентификатор)."
  value       = aws_launch_template.github.latest_version
}

output "github_runner_security_group_id" {
  description = "ID Security Group, применяемой к GitHub Actions runners."
  value       = aws_security_group.github_runners.id
}

output "github_runner_security_group_name" {
  description = "Имя Security Group, применяемой к GitHub Actions runners."
  value       = aws_security_group.github_runners.name
}

output "github_runner_iam_role_arn" {
  description = "ARN IAM роли инстансов GitHub Actions runners (доступ к S3/SSM/CloudWatch и пр.)."
  value       = aws_iam_role.github_runner.arn
}

output "github_runner_instance_profile_arn" {
  description = "ARN Instance Profile для GitHub Actions runners."
  value       = aws_iam_instance_profile.github_runner.arn
}

output "github_runner_vpc_zone_identifiers" {
  description = "Список Subnet ID, привязанных к ASG GitHub runners."
  value       = aws_autoscaling_group.github.vpc_zone_identifier
}

output "github_runner_target_group_arns" {
  description = "Список Target Group ARNs, ассоциированных с ASG GitHub runners (если есть)."
  value       = aws_autoscaling_group.github.target_group_arns
}

output "github_runner_registration_secret_name" {
  description = "Имя Kubernetes Secret с регистрационным токеном GitHub runner."
  value       = kubernetes_secret.github_runner_registration.metadata[0].name
  sensitive   = true
}

output "github_runner_tags" {
  description = "Объединённые теги (tags_all) на ASG GitHub runners для соответствия политикам и биллингу."
  value       = aws_autoscaling_group.github.tags_all
}

output "github_runner_launch_template_tags" {
  description = "Теги Launch Template GitHub runners."
  value       = aws_launch_template.github.tags_all
}

# Аггрегированная сводка по GitHub runners — единая точка интеграции для CI/CD
output "github_runners_summary" {
  description = "Агрегированная сводка по GitHub runner-пулу (ASG, LT, SG, IAM, Namespace)."
  value = {
    namespace = kubernetes_namespace.ci_runners.metadata[0].name
    asg = {
      name            = aws_autoscaling_group.github.name
      arn             = aws_autoscaling_group.github.arn
      min_size        = aws_autoscaling_group.github.min_size
      max_size        = aws_autoscaling_group.github.max_size
      desired_capacity= aws_autoscaling_group.github.desired_capacity
      subnets         = aws_autoscaling_group.github.vpc_zone_identifier
      target_groups   = aws_autoscaling_group.github.target_group_arns
      tags            = aws_autoscaling_group.github.tags_all
    }
    launch_template = {
      id              = aws_launch_template.github.id
      latest_version  = aws_launch_template.github.latest_version
      tags            = aws_launch_template.github.tags_all
    }
    security_group = {
      id   = aws_security_group.github_runners.id
      name = aws_security_group.github_runners.name
    }
    iam = {
      role_arn              = aws_iam_role.github_runner.arn
      instance_profile_arn  = aws_iam_instance_profile.github_runner.arn
    }
    registration_secret = {
      name = kubernetes_secret.github_runner_registration.metadata[0].name
    }
  }
  sensitive = false
}

#########################
# GitLab Runners        #
#########################

output "gitlab_runner_asg_name" {
  description = "Имя Auto Scaling Group для GitLab Runners."
  value       = aws_autoscaling_group.gitlab.name
}

output "gitlab_runner_asg_arn" {
  description = "ARN Auto Scaling Group для GitLab Runners."
  value       = aws_autoscaling_group.gitlab.arn
}

output "gitlab_runner_asg_capacity_limits" {
  description = "Лимиты масштабирования (min/max/desired) для ASG GitLab Runners."
  value = {
    min_size    = aws_autoscaling_group.gitlab.min_size
    max_size    = aws_autoscaling_group.gitlab.max_size
    desired_cap = aws_autoscaling_group.gitlab.desired_capacity
  }
}

output "gitlab_runner_lt_id" {
  description = "ID Launch Template, используемого для GitLab Runners."
  value       = aws_launch_template.gitlab.id
}

output "gitlab_runner_lt_latest_version" {
  description = "Последняя версия Launch Template (числовой идентификатор) для GitLab Runners."
  value       = aws_launch_template.gitlab.latest_version
}

output "gitlab_runner_security_group_id" {
  description = "ID Security Group, применяемой к GitLab Runners."
  value       = aws_security_group.gitlab_runners.id
}

output "gitlab_runner_security_group_name" {
  description = "Имя Security Group, применяемой к GitLab Runners."
  value       = aws_security_group.gitlab_runners.name
}

output "gitlab_runner_iam_role_arn" {
  description = "ARN IAM роли инстансов GitLab Runners."
  value       = aws_iam_role.gitlab_runner.arn
}

output "gitlab_runner_instance_profile_arn" {
  description = "ARN Instance Profile для GitLab Runners."
  value       = aws_iam_instance_profile.gitlab_runner.arn
}

output "gitlab_runner_vpc_zone_identifiers" {
  description = "Список Subnet ID, привязанных к ASG GitLab Runners."
  value       = aws_autoscaling_group.gitlab.vpc_zone_identifier
}

output "gitlab_runner_target_group_arns" {
  description = "Список Target Group ARNs, ассоциированных с ASG GitLab Runners (если есть)."
  value       = aws_autoscaling_group.gitlab.target_group_arns
}

output "gitlab_runner_registration_secret_name" {
  description = "Имя Kubernetes Secret с регистрационным токеном GitLab Runner."
  value       = kubernetes_secret.gitlab_runner_registration.metadata[0].name
  sensitive   = true
}

output "gitlab_runner_tags" {
  description = "Объединённые теги (tags_all) на ASG GitLab Runners."
  value       = aws_autoscaling_group.gitlab.tags_all
}

output "gitlab_runner_launch_template_tags" {
  description = "Теги Launch Template GitLab Runners."
  value       = aws_launch_template.gitlab.tags_all
}

# Агрегированная сводка по GitLab runners — единая точка интеграции для CI/CD
output "gitlab_runners_summary" {
  description = "Агрегированная сводка по GitLab runner-пулу (ASG, LT, SG, IAM, Namespace)."
  value = {
    namespace = kubernetes_namespace.ci_runners.metadata[0].name
    asg = {
      name            = aws_autoscaling_group.gitlab.name
      arn             = aws_autoscaling_group.gitlab.arn
      min_size        = aws_autoscaling_group.gitlab.min_size
      max_size        = aws_autoscaling_group.gitlab.max_size
      desired_capacity= aws_autoscaling_group.gitlab.desired_capacity
      subnets         = aws_autoscaling_group.gitlab.vpc_zone_identifier
      target_groups   = aws_autoscaling_group.gitlab.target_group_arns
      tags            = aws_autoscaling_group.gitlab.tags_all
    }
    launch_template = {
      id              = aws_launch_template.gitlab.id
      latest_version  = aws_launch_template.gitlab.latest_version
      tags            = aws_launch_template.gitlab.tags_all
    }
    security_group = {
      id   = aws_security_group.gitlab_runners.id
      name = aws_security_group.gitlab_runners.name
    }
    iam = {
      role_arn              = aws_iam_role.gitlab_runner.arn
      instance_profile_arn  = aws_iam_instance_profile.gitlab_runner.arn
    }
    registration_secret = {
      name = kubernetes_secret.gitlab_runner_registration.metadata[0].name
    }
  }
  sensitive = false
}

#############################################
# Консолидация: единый объект runners_meta  #
#############################################

output "runners_meta" {
  description = "Единый агрегированный объект для систем оркестрации (ArgoCD/Atlantis/GitHub Environments/GitLab Environments)."
  value = {
    namespace = kubernetes_namespace.ci_runners.metadata[0].name
    github    = {
      asg_name          = aws_autoscaling_group.github.name
      asg_arn           = aws_autoscaling_group.github.arn
      lt_id             = aws_launch_template.github.id
      lt_latest_version = aws_launch_template.github.latest_version
      sg_id             = aws_security_group.github_runners.id
      iam_role_arn      = aws_iam_role.github_runner.arn
      iam_profile_arn   = aws_iam_instance_profile.github_runner.arn
      subnets           = aws_autoscaling_group.github.vpc_zone_identifier
      tags              = aws_autoscaling_group.github.tags_all
      registration_secret_name = kubernetes_secret.github_runner_registration.metadata[0].name
    }
    gitlab    = {
      asg_name          = aws_autoscaling_group.gitlab.name
      asg_arn           = aws_autoscaling_group.gitlab.arn
      lt_id             = aws_launch_template.gitlab.id
      lt_latest_version = aws_launch_template.gitlab.latest_version
      sg_id             = aws_security_group.gitlab_runners.id
      iam_role_arn      = aws_iam_role.gitlab_runner.arn
      iam_profile_arn   = aws_iam_instance_profile.gitlab_runner.arn
      subnets           = aws_autoscaling_group.gitlab.vpc_zone_identifier
      tags              = aws_autoscaling_group.gitlab.tags_all
      registration_secret_name = kubernetes_secret.gitlab_runner_registration.metadata[0].name
    }
  }
  # Метаданные как таковые не содержат секретов; однако имена секретов полезно не светить в логах.
  sensitive = true
}
