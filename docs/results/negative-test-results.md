# Experiment 2: negative testing of the security pipeline

Run on 2026-10-09 with tfsec `v1.28.14` and Checkov `3.3.26`.

Method: start from the hardened code (which passes both scanners with zero findings), introduce one deliberate mistake, and record whether each scanner reports it.

| ID | Mistake introduced | Category | tfsec | Checkov | Caught by either? |
|---|---|---|---|---|---|
| M01 | Open SSH (port 22) to the whole internet | Network exposure | caught AVD-AWS-0107 | caught CKV_AWS_24 | yes |
| M02 | Allow the app server to send traffic anywhere (open egress) | Network exposure | caught AVD-AWS-0104 | caught CKV_AWS_382 | yes |
| M03 | Give the app server a public IP address | Network exposure | **MISSED**  | caught CKV_AWS_88 | yes |
| M04 | Auto-assign public IPs in the public subnets | Network exposure | caught AVD-AWS-0164 | caught CKV_AWS_130 | yes |
| M05 | Turn off encryption on the server disk | Encryption | caught AVD-AWS-0131 | caught CKV_AWS_8 | yes |
| M06 | Allow the old metadata service (IMDSv1) | Host hardening | caught AVD-AWS-0028 | caught CKV_AWS_79 | yes |
| M07 | Stop the load balancer dropping invalid headers | Host hardening | caught AVD-AWS-0052 | caught CKV_AWS_131 | yes |
| M08 | Add an all-powerful IAM policy (Action * on Resource *) | Identity and access | caught AVD-AWS-0057 | caught CKV2_AWS_40, CKV_AWS_286, CKV_AWS_287, CKV_AWS_288, CKV_AWS_289, CKV_AWS_290, CKV_AWS_355, CKV_AWS_62, CKV_AWS_63 | yes |
| M09 | Allow the log bucket to be made public | Logging and data protection | caught AVD-AWS-0087 | caught CKV2_AWS_6, CKV_AWS_54 | yes |
| M10 | Suspend versioning on the log bucket | Logging and data protection | caught AVD-AWS-0090 | caught CKV_AWS_21 | yes |
| M11 | Turn off CloudTrail log file validation | Logging and data protection | caught AVD-AWS-0016 | caught CKV_AWS_36 | yes |
| M12 | Make CloudTrail single-region only | Logging and data protection | caught AVD-AWS-0014 | caught CKV_AWS_67 | yes |
| M13 | Delete the VPC flow log | Logging and data protection | caught AVD-AWS-0178 | caught CKV2_AWS_11 | yes |
| M14 | Switch GuardDuty off | Detective controls | **MISSED**  | caught CKV_AWS_238 | yes |
| M15 | Delete the root-account-usage alarm | Detective controls | **MISSED**  | **MISSED**  | **NO** |
| M16 | Move the app server into a PUBLIC subnet | Architecture | **MISSED**  | **MISSED**  | **NO** |

## Detection rates

- tfsec alone: 12/16 (75%)
- Checkov alone: 14/16 (88%)
- Both scanners together: 14/16 (88%)

## What the results show

- Checkov caught everything tfsec caught, plus M03, M14 which tfsec missed. In this test, adding tfsec did not increase the number of mistakes detected, although it gives independent confirmation with a different rule set.
- The mistakes that were missed are the interesting ones. Deleting the alarm entirely, or placing the server in a public subnet, is a perfectly valid configuration as far as a code scanner is concerned. Static scanning checks that the resources that exist are configured safely, not that the right resources exist or that they are in the right place.
- That gap is why the project also deploys runtime monitoring (GuardDuty, CloudTrail, the root-usage alarm) and why a real deployment should be tested from the outside (see the runtime test plan).

## Limitations

- Only 16 hand-written mutations, all chosen by me, so this is not exhaustive and the detection rate is not a general claim about the tools.
- Each mutation is a single change. Real mistakes often combine.
- Scanner rule sets change between versions, so results may differ if re-run later. The versions are recorded above.
