provider "aws" {
  region = var.region
}

resource "aws_db_subnet_group" "default" {
  name       = "${var.name}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = var.tags
}

resource "aws_db_instance" "default" {
  identifier              = var.db_identifier
  engine                  = var.engine
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  allocated_storage       = var.allocated_storage
  storage_type            = var.storage_type
  db_subnet_group_name    = aws_db_subnet_group.default.name
  vpc_security_group_ids  = var.security_group_ids
  multi_az                = var.multi_az
  publicly_accessible     = false
  backup_retention_period = var.backup_retention_period
  skip_final_snapshot     = false
  deletion_protection     = true
  apply_immediately       = var.apply_immediately

  username = var.username
  password = var.password

  parameter_group_name = var.parameter_group_name
  option_group_name    = var.option_group_name

  tags = var.tags
}

resource "aws_db_parameter_group" "default" {
  name        = "${var.name}-param-group"
  family      = var.parameter_group_family
  description = "Parameter group for ${var.name} RDS"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = var.tags
}
