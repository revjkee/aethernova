output "bucket_id" {
  description = "ID созданного S3 бакета"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN созданного S3 бакета"
  value       = aws_s3_bucket.this.arn
}

output "bucket_domain_name" {
  description = "Доменное имя бакета"
  value       = aws_s3_bucket.this.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "Региональное доменное имя бакета"
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}

output "versioning_enabled" {
  description = "Статус версионности бакета"
  value       = aws_s3_bucket_versioning.this.status
}
