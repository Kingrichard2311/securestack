# Experiment 1: baseline vs hardened scan comparison

Run on 2026-10-09 with tfsec `v1.28.14` and Checkov `3.3.26`.

| Version | tfsec findings | tfsec CRITICAL | tfsec HIGH | tfsec MEDIUM | tfsec LOW | Checkov failed checks |
|---|---|---|---|---|---|---|
| A. Baseline (deliberately insecure) | 23 | 4 | 13 | 4 | 2 | 37 |
| B. Hardened (pipeline view, accepted risks documented) | 0 | 0 | 0 | 0 | 0 | 0 |
| C. Hardened with ALL exceptions removed | 10 | 2 | 5 | 1 | 2 | 19 |

**Reduction from baseline to hardened (all exceptions removed, so no findings are hidden):**

- tfsec: 23 -> 10 findings (57% fewer)
- Checkov: 37 -> 19 failed checks (49% fewer)
- tfsec CRITICAL + HIGH: 17 -> 7

## Findings still present in the hardened version when exceptions are removed

These are the risks I consciously accepted. Each has a written reason in the code and in the README.

| Scanner | Rule | Resource |
|---|---|---|
| tfsec (HIGH) | AVD-AWS-0015 | `aws_cloudtrail.main` |
| tfsec (LOW) | AVD-AWS-0017 | `aws_cloudwatch_log_group.cloudtrail` |
| tfsec (LOW) | AVD-AWS-0017 | `aws_cloudwatch_log_group.vpc_flow_logs` |
| tfsec (HIGH) | AVD-AWS-0053 | `aws_lb.main` |
| tfsec (CRITICAL) | AVD-AWS-0054 | `aws_lb_listener.http` |
| tfsec (HIGH) | AVD-AWS-0057 | `aws_iam_role_policy.flow_logs` |
| tfsec (MEDIUM) | AVD-AWS-0089 | `aws_s3_bucket.cloudtrail` |
| tfsec (HIGH) | AVD-AWS-0095 | `aws_sns_topic.security_alerts` |
| tfsec (CRITICAL) | AVD-AWS-0107 | `aws_security_group_rule.alb_http_in` |
| tfsec (HIGH) | AVD-AWS-0132 | `aws_s3_bucket_server_side_encryption_configuration.cloudtrail` |
| Checkov | CKV2_AWS_20 | `aws_lb.main` |
| Checkov | CKV2_AWS_28 | `aws_lb.main` |
| Checkov | CKV2_AWS_3 | `aws_guardduty_detector.main` |
| Checkov | CKV2_AWS_41 | `aws_instance.app` |
| Checkov | CKV2_AWS_62 | `aws_s3_bucket.cloudtrail` |
| Checkov | CKV_AWS_103 | `aws_lb_listener.http` |
| Checkov | CKV_AWS_144 | `aws_s3_bucket.cloudtrail` |
| Checkov | CKV_AWS_145 | `aws_s3_bucket.cloudtrail` |
| Checkov | CKV_AWS_150 | `aws_lb.main` |
| Checkov | CKV_AWS_158 | `aws_cloudwatch_log_group.cloudtrail` |
| Checkov | CKV_AWS_158 | `aws_cloudwatch_log_group.vpc_flow_logs` |
| Checkov | CKV_AWS_18 | `aws_s3_bucket.cloudtrail` |
| Checkov | CKV_AWS_2 | `aws_lb_listener.http` |
| Checkov | CKV_AWS_252 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_26 | `aws_sns_topic.security_alerts` |
| Checkov | CKV_AWS_260 | `aws_security_group_rule.alb_http_in` |
| Checkov | CKV_AWS_35 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_378 | `aws_lb_target_group.app` |
| Checkov | CKV_AWS_91 | `aws_lb.main` |

## Findings in the baseline (for reference)

| Scanner | Rule | Resource |
|---|---|---|
| tfsec (CRITICAL) | AVD-AWS-0029 | `aws_instance.web` |
| tfsec (CRITICAL) | AVD-AWS-0104 | `aws_security_group.web` |
| tfsec (CRITICAL) | AVD-AWS-0107 | `aws_security_group.web` |
| tfsec (CRITICAL) | AVD-AWS-0107 | `aws_security_group.web` |
| tfsec (HIGH) | AVD-AWS-0015 | `aws_cloudtrail.main` |
| tfsec (HIGH) | AVD-AWS-0016 | `aws_cloudtrail.main` |
| tfsec (HIGH) | AVD-AWS-0028 | `aws_instance.web` |
| tfsec (HIGH) | AVD-AWS-0057 | `aws_iam_role_policy.admin` |
| tfsec (HIGH) | AVD-AWS-0057 | `aws_iam_role_policy.admin` |
| tfsec (HIGH) | AVD-AWS-0086 | `aws_s3_bucket_public_access_block.logs` |
| tfsec (HIGH) | AVD-AWS-0087 | `aws_s3_bucket_public_access_block.logs` |
| tfsec (HIGH) | AVD-AWS-0088 | `aws_s3_bucket.logs` |
| tfsec (HIGH) | AVD-AWS-0091 | `aws_s3_bucket_public_access_block.logs` |
| tfsec (HIGH) | AVD-AWS-0093 | `aws_s3_bucket_public_access_block.logs` |
| tfsec (HIGH) | AVD-AWS-0131 | `aws_instance.web` |
| tfsec (HIGH) | AVD-AWS-0132 | `aws_s3_bucket.logs` |
| tfsec (HIGH) | AVD-AWS-0164 | `aws_subnet.public` |
| tfsec (LOW) | AVD-AWS-0162 | `aws_cloudtrail.main` |
| tfsec (LOW) | AVD-AWS-0163 | `aws_s3_bucket.logs` |
| tfsec (MEDIUM) | AVD-AWS-0014 | `aws_cloudtrail.main` |
| tfsec (MEDIUM) | AVD-AWS-0089 | `aws_s3_bucket.logs` |
| tfsec (MEDIUM) | AVD-AWS-0090 | `aws_s3_bucket.logs` |
| tfsec (MEDIUM) | AVD-AWS-0178 | `aws_vpc.main` |
| Checkov | CKV2_AWS_10 | `aws_cloudtrail.main` |
| Checkov | CKV2_AWS_11 | `aws_vpc.main` |
| Checkov | CKV2_AWS_12 | `aws_vpc.main` |
| Checkov | CKV2_AWS_40 | `aws_iam_role_policy.admin` |
| Checkov | CKV2_AWS_6 | `aws_s3_bucket.logs` |
| Checkov | CKV2_AWS_61 | `aws_s3_bucket.logs` |
| Checkov | CKV2_AWS_62 | `aws_s3_bucket.logs` |
| Checkov | CKV_AWS_126 | `aws_instance.web` |
| Checkov | CKV_AWS_130 | `aws_subnet.public` |
| Checkov | CKV_AWS_135 | `aws_instance.web` |
| Checkov | CKV_AWS_144 | `aws_s3_bucket.logs` |
| Checkov | CKV_AWS_145 | `aws_s3_bucket.logs` |
| Checkov | CKV_AWS_18 | `aws_s3_bucket.logs` |
| Checkov | CKV_AWS_21 | `aws_s3_bucket.logs` |
| Checkov | CKV_AWS_24 | `aws_security_group.web` |
| Checkov | CKV_AWS_25 | `aws_security_group.web` |
| Checkov | CKV_AWS_252 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_260 | `aws_security_group.web` |
| Checkov | CKV_AWS_286 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_287 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_288 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_289 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_290 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_35 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_355 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_36 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_382 | `aws_security_group.web` |
| Checkov | CKV_AWS_53 | `aws_s3_bucket_public_access_block.logs` |
| Checkov | CKV_AWS_54 | `aws_s3_bucket_public_access_block.logs` |
| Checkov | CKV_AWS_55 | `aws_s3_bucket_public_access_block.logs` |
| Checkov | CKV_AWS_56 | `aws_s3_bucket_public_access_block.logs` |
| Checkov | CKV_AWS_62 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_63 | `aws_iam_role_policy.admin` |
| Checkov | CKV_AWS_67 | `aws_cloudtrail.main` |
| Checkov | CKV_AWS_79 | `aws_instance.web` |
| Checkov | CKV_AWS_8 | `aws_instance.web` |
| Checkov | CKV_AWS_88 | `aws_instance.web` |

## Limitations of this experiment

- The baseline was written by me to be insecure, so it is a controlled comparison, not a survey of real-world code.
- Static scanners only read code. They cannot tell me whether the deployed system behaves securely (see Experiment 2 and the runtime tests in the report).
- Finding counts are not a perfect measure of risk: one CRITICAL finding matters more than several LOW ones, and different scanners count the same flaw differently.
