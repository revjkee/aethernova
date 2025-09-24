variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID where security group and NACL will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs to associate with the Network ACL"
  type        = list(string)
  default     = []
}

variable "sg_name" {
  description = "Security group name"
  type        = string
  default     = "default-sg"
}

variable "sg_description" {
  description = "Description for the security group"
  type        = string
  default     = "Security group managed by terraform"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "ingress_rules" {
  description = "List of ingress rules for security group"
  type = list(object({
    description      = string
    from_port        = number
    to_port          = number
    protocol         = string
    cidr_blocks      = optional(list(string))
    ipv6_cidr_blocks = optional(list(string))
    security_groups  = optional(list(string))
    prefix_list_ids  = optional(list(string))
    self             = optional(bool, false)
  }))
  default = []
}

variable "egress_rules" {
  description = "List of egress rules for security group"
  type = list(object({
    description      = string
    from_port        = number
    to_port          = number
    protocol         = string
    cidr_blocks      = optional(list(string))
    ipv6_cidr_blocks = optional(list(string))
    security_groups  = optional(list(string))
    prefix_list_ids  = optional(list(string))
    self             = optional(bool, false)
  }))
  default = []
}

variable "nacl_ingress_rules" {
  description = "List of ingress rules for Network ACL"
  type = list(object({
    rule_number     = number
    protocol        = string
    rule_action     = string
    cidr_block      = string
    from_port       = number
    to_port         = number
    ipv6_cidr_block = optional(string)
  }))
  default = []
}

variable "nacl_egress_rules" {
  description = "List of egress rules for Network ACL"
  type = list(object({
    rule_number     = number
    protocol        = string
    rule_action     = string
    cidr_block      = string
    from_port       = number
    to_port         = number
    ipv6_cidr_block = optional(string)
  }))
  default = []
}
