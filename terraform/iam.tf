# --- IAM (permissions) ---
# IAM mistakes cause a lot of real AWS incidents, so I wanted to get this
# right. The principle is "least privilege": each role can do ONLY the one
# job it needs. It would be quicker to attach a broad admin policy and move
# on, but that is exactly the shortcut that causes problems later.
#
# Note the web server has no role at all, because it doesn't need to call
# any AWS service. These two roles are for AWS services writing logs.

# Lets the VPC Flow Logs service write to ONE log group.
resource "aws_iam_role" "flow_logs" {
  name = "${var.project_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

# The ":*" at the end of the log group ARN means "any log stream INSIDE this one
# log group". AWS needs it for writing logs. It is still scoped to a single group.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.project_name}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ]
      Resource = ["${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"]
    }]
  })
}

# Lets CloudTrail write to ONE log group (used by the root-usage alarm).
resource "aws_iam_role" "cloudtrail_logs" {
  name = "${var.project_name}-cloudtrail-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "${var.project_name}-cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
    }]
  })
}
