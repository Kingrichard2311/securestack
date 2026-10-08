# Experiment 3: runtime testing of the deployed environment

Author: Richard Lamy

**Status: NOT YET RUN.** The tables at the bottom are blank on purpose. Fill them in with the real results from your own deployment, and save evidence (screenshots or command output) in `docs/screenshots/`.

## Why this experiment exists

Experiments 1 and 2 only read the code. Experiment 2 showed that scanners can miss some mistakes entirely (for example a server placed in the wrong subnet). So I also need to test the **deployed** system from the outside, the way an attacker or an auditor would, and check that each control really works.

## Rules

- Only test resources in **your own** AWS account.
- Light checks like these are fine under the AWS penetration testing policy for load balancers and EC2. Read [the current policy](https://aws.amazon.com/security/penetration-testing/) first. Do not run floods or denial-of-service tests.
- Deploy with `terraform apply`, run the tests, then `terraform destroy`.

## Setup

```bash
cd terraform
terraform output
```

Note the values for `website_url`, `app_server_id`, `guardduty_detector_id` and `cloudtrail_bucket`. In the commands below, replace `ALB-DNS` with the website host name (the part of `website_url` after `http://`).

## Tests

### T1. The site works through the load balancer
```bash
curl -i http://ALB-DNS/
curl -i http://ALB-DNS/health
```
**Expected:** HTTP 200 for both. The page says "SecureStack is running", and `/health` returns `ok`.

### T2. The server has no public IP
```bash
aws ec2 describe-instances --instance-ids INSTANCE-ID --query "Reservations[].Instances[].{PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress}"
```
**Expected:** `PublicIp` is `null`, `PrivateIp` is a `10.0.11.x` or `10.0.12.x` address.

### T3. The server can't be reached directly
From your own computer (not inside AWS), using the private IP from T2:
```bash
curl --connect-timeout 5 http://PRIVATE-IP:8080
```
**Expected:** the connection times out. The address is private and not routable from the internet.

### T4. Only port 80 is reachable on the load balancer
```bash
nmap -Pn -p 22,80,443,3389,8080 ALB-DNS
```
**Expected:** port 80 open. The others closed or filtered. In particular **22 and 8080 are not open**.

### T5. IMDSv2 is enforced
```bash
aws ec2 describe-instances --instance-ids INSTANCE-ID --query "Reservations[].Instances[].MetadataOptions.HttpTokens"
```
**Expected:** `"required"`

### T6. The disk is encrypted
```bash
aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=INSTANCE-ID --query "Volumes[].Encrypted"
```
**Expected:** `true`

### T7. The load balancer sees a healthy target
```bash
aws elbv2 describe-target-groups --names securestack-tg --query "TargetGroups[].TargetGroupArn"
aws elbv2 describe-target-health --target-group-arn TARGET-GROUP-ARN
```
**Expected:** target state `healthy`.

### T8. CloudTrail is delivering logs, and they validate
```bash
aws s3 ls s3://CLOUDTRAIL-BUCKET --recursive
aws cloudtrail describe-trails --trail-name-list securestack-trail --query "trailList[].TrailARN"
aws cloudtrail validate-logs --trail-arn TRAIL-ARN --start-time 2026-01-01T00:00:00Z
```
Use a start time from after you deployed. **Expected:** log files are listed (it can take about 15 minutes for the first ones) and validation reports no invalid files.

### T9. The log bucket is not public
```bash
aws s3api get-public-access-block --bucket CLOUDTRAIL-BUCKET
```
**Expected:** all four settings are `true`.

### T10. VPC flow logs are recording
```bash
aws logs describe-log-streams --log-group-name /securestack/vpc-flow-logs
```
**Expected:** at least one log stream exists after some traffic (run T1 a few times first).

### T11. GuardDuty is working
```bash
aws guardduty create-sample-findings --detector-id DETECTOR-ID --finding-types Recon:EC2/PortProbeUnprotectedPort
aws guardduty list-findings --detector-id DETECTOR-ID
```
**Expected:** sample findings appear, also visible in the GuardDuty console. Sample findings are clearly marked as samples.

### T12 (optional). The root-usage alarm fires
Sign in to the AWS console as the **root user** once, do something harmless like opening the billing page, then sign out.
**Expected:** within roughly 10 to 15 minutes the alarm changes to `In alarm` and an email arrives (after you've confirmed the SNS subscription). Only do this if you are comfortable using root once in a practice account.

## Results table (fill in)

| Test | Expected | Actual result | Pass / Fail | Evidence |
|---|---|---|---|---|
| T1 Site works | HTTP 200 | | | |
| T2 No public IP | PublicIp null | | | |
| T3 Direct access blocked | Timeout | | | |
| T4 Port scan | Only 80 open | | | |
| T5 IMDSv2 | required | | | |
| T6 Encrypted disk | true | | | |
| T7 Healthy target | healthy | | | |
| T8 CloudTrail logs valid | No invalid files | | | |
| T9 Bucket not public | All true | | | |
| T10 Flow logs | Streams exist | | | |
| T11 GuardDuty | Sample findings | | | |
| T12 Root alarm (optional) | Alarm and email | | | |

## What to write about

- Which tests passed first time and which didn't. If something failed, explain why and what you changed. That is more valuable than a table of passes.
- What these tests cover that Experiments 1 and 2 couldn't (T2, T3, T4 and T7 test the deployed behaviour, not the code).
- What none of the tests cover (for example application-layer attacks, since the app is a static page).
- Optional extension: run an open-source tool such as Prowler against the account and compare its findings with the scanners' results.
