resource "aws_instance" "secure_ec2" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  key_name                   = var.key_name
  associate_public_ip_address = var.associate_public_ip
  monitoring                  = var.enable_monitoring

  vpc_security_group_ids = [
    var.security_group_id
  ]

  iam_instance_profile = var.iam_instance_profile

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    delete_on_termination = true
    encrypted             = true
  }

  ebs_block_device {
    device_name           = var.ebs_device_name
    volume_size           = var.ebs_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = merge(
    {
      Name        = var.instance_name
      Environment = var.environment
    },
    var.additional_tags
  )

  lifecycle {
    create_before_destroy = true
  }

  credit_specification {
    cpu_credits = var.cpu_credits
  }
}
