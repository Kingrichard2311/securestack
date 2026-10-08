# --- Monitoring and detection ---
# Locking things down PREVENTS problems, but I also wanted something that
# notices if something goes wrong anyway:
#   - GuardDuty watches the account for suspicious activity
#   - CloudTrail records every API call (a record to look back on)
#   - An alarm emails me if the AWS root account is ever used

data "aws_caller_identity" "current" {}

# GuardDuty: AWS's built-in threat detection. Once switched on it analyses
# activity for known attack patterns - I didn't write any detection rules.
resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:This check is about organisation-wide GuardDuty. I only have a single account.
  enable = true
}

# --- Where CloudTrail stores its logs ---
#tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_18:Access logging for the log bucket needs yet another bucket - skipped for the demo.
  #checkov:skip=CKV_AWS_145:Uses standard S3 encryption (AES256) instead of a custom KMS key, to keep the demo simple.
  #checkov:skip=CKV_AWS_144:Cross-region replication is overkill for a demo.
  #checkov:skip=CKV2_AWS_62:Event notifications aren't needed here.
  bucket = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  # Lets terraform destroy delete the bucket even though it has logs in it.
  force_destroy = true
}

# Keeps old versions of files, so logs can't be silently overwritten.
resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Makes sure this bucket can never be made public.
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Deletes old logs after a year so the bucket doesn't grow forever.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  depends_on = [aws_s3_bucket_versioning.cloudtrail]

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Lets CloudTrail (and only CloudTrail) write into the bucket, and refuses
# any connection that isn't encrypted (HTTPS).
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# --- CloudTrail itself ---
#tfsec:ignore:aws-cloudwatch-log-group-customer-key
resource "aws_cloudwatch_log_group" "cloudtrail" {
  #checkov:skip=CKV_AWS_158:Uses AWS default encryption. A custom KMS key adds complexity I left out of this demo.
  name              = "/${var.project_name}/cloudtrail"
  retention_in_days = 365
}

#tfsec:ignore:aws-cloudtrail-enable-at-rest-encryption
resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_35:Uses standard S3 encryption instead of a custom KMS key, to keep the demo simple.
  #checkov:skip=CKV_AWS_252:No SNS topic for CloudTrail notifications - not needed for this demo.
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true

  # Makes the logs tamper-evident: if someone edited a log afterwards, it
  # would be detectable.
  enable_log_file_validation = true

  # Also send the logs to CloudWatch so the alarm below can react quickly.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_iam_role_policy.cloudtrail_logs
  ]
}

# --- Alerting ---
# SNS is a notification service. The alarm publishes a message to this topic
# and the topic forwards it to my email.
#tfsec:ignore:aws-sns-enable-topic-encryption
resource "aws_sns_topic" "security_alerts" {
  #checkov:skip=CKV_AWS_26:CloudWatch alarms can't publish to a topic encrypted with the default AWS key, so it is left unencrypted for the demo.
  name = "${var.project_name}-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Root account usage alarm ---
# The AWS "root" user (the original owner login) should basically never be
# used day-to-day. If it is used for ANYTHING, that's worth an immediate
# alert. This filter searches the CloudTrail logs for root activity and
# turns it into a number the alarm can watch.
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${var.project_name}-root-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${var.project_name}/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  alarm_description   = "Fires if the AWS root user is used for anything"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "${var.project_name}/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
