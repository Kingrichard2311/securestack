# Handy values Terraform prints at the end of "terraform apply".

output "website_url" {
  description = "Open this in a browser to see the site (give it ~2 minutes after apply)"
  value       = "http://${aws_lb.main.dns_name}"
}

output "app_server_id" {
  description = "ID of the private web server"
  value       = aws_instance.app.id
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "cloudtrail_bucket" {
  description = "S3 bucket holding the CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.id
}
