"""
Experiment 2: does the pipeline actually catch security mistakes?

I take my hardened Terraform, introduce ONE deliberate mistake at a time
(a "mutation"), and run both scanners exactly as the pipeline does. The clean
code passes with zero findings, so any finding means the mistake was caught.

Some mutations are things a code scanner SHOULD catch (open SSH, unencrypted
disk). Others are things it probably can't (deleting an alarm, putting the
server in the wrong subnet). Those are included on purpose: they show the
limits of static scanning and why runtime monitoring is also needed.

Run from the project folder:   python tests/negative_tests.py
Results are saved to docs/results/negative-test-results.md
"""

import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

import scanlib as s

# Each mutation: (id, name, category, file, change)
#   change is either ("replace", regex, replacement) or ("append", text)
#   or ("delete_block", resource_type, resource_name)
MUTATIONS = [
    ("M01", "Open SSH (port 22) to the whole internet", "Network exposure", "security_groups.tf",
     ("append", '''
resource "aws_security_group_rule" "oops_ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.app.id
  description       = "TEST ONLY"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}
''')),
    ("M02", "Allow the app server to send traffic anywhere (open egress)", "Network exposure", "security_groups.tf",
     ("append", '''
resource "aws_security_group_rule" "oops_egress" {
  type              = "egress"
  security_group_id = aws_security_group.app.id
  description       = "TEST ONLY"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}
''')),
    ("M03", "Give the app server a public IP address", "Network exposure", "compute.tf",
     ("replace", r'(associate_public_ip_address\s*=\s*)false', r'\1true')),
    ("M04", "Auto-assign public IPs in the public subnets", "Network exposure", "network.tf",
     ("replace", r'(map_public_ip_on_launch\s*=\s*)false', r'\1true')),
    ("M05", "Turn off encryption on the server disk", "Encryption", "compute.tf",
     ("replace", r'(encrypted\s*=\s*)true', r'\1false')),
    ("M06", "Allow the old metadata service (IMDSv1)", "Host hardening", "compute.tf",
     ("replace", r'(http_tokens\s*=\s*)"required"', r'\1"optional"')),
    ("M07", "Stop the load balancer dropping invalid headers", "Host hardening", "alb.tf",
     ("replace", r'(drop_invalid_header_fields\s*=\s*)true', r'\1false')),
    ("M08", "Add an all-powerful IAM policy (Action * on Resource *)", "Identity and access", "iam.tf",
     ("append", '''
resource "aws_iam_role_policy" "oops_admin" {
  name = "oops-admin"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
''')),
    ("M09", "Allow the log bucket to be made public", "Logging and data protection", "monitoring.tf",
     ("replace", r'(block_public_policy\s*=\s*)true', r'\1false')),
    ("M10", "Suspend versioning on the log bucket", "Logging and data protection", "monitoring.tf",
     ("replace", r'(status\s*=\s*)"Enabled"(\s*\n\s*\}\s*\n\})', r'\1"Suspended"\2')),
    ("M11", "Turn off CloudTrail log file validation", "Logging and data protection", "monitoring.tf",
     ("replace", r'(enable_log_file_validation\s*=\s*)true', r'\1false')),
    ("M12", "Make CloudTrail single-region only", "Logging and data protection", "monitoring.tf",
     ("replace", r'(is_multi_region_trail\s*=\s*)true', r'\1false')),
    ("M13", "Delete the VPC flow log", "Logging and data protection", "network.tf",
     ("delete_block", "aws_flow_log", "main")),
    ("M14", "Switch GuardDuty off", "Detective controls", "monitoring.tf",
     ("replace", r'(\benable\s*=\s*)true', r'\1false')),
    ("M15", "Delete the root-account-usage alarm", "Detective controls", "monitoring.tf",
     ("delete_block", "aws_cloudwatch_metric_alarm", "root_usage")),
    ("M16", "Move the app server into a PUBLIC subnet", "Architecture", "compute.tf",
     ("replace", r'aws_subnet\.private\[0\]\.id', 'aws_subnet.public[0].id')),
]


def apply_mutation(directory, filename, change):
    path = Path(directory) / filename
    text = path.read_text(encoding="utf-8")
    kind = change[0]
    if kind == "append":
        new = text + change[1]
    elif kind == "replace":
        new, n = re.subn(change[1], change[2], text)
        if n == 0:
            raise RuntimeError(f"pattern not found in {filename}: {change[1]}")
    elif kind == "delete_block":
        _, rtype, rname = change
        pattern = rf'resource "{rtype}" "{rname}" \{{.*?\n\}}\n'
        new, n = re.subn(pattern, "", text, flags=re.DOTALL)
        if n == 0:
            raise RuntimeError(f"block {rtype}.{rname} not found in {filename}")
    else:
        raise ValueError(kind)
    path.write_text(new, encoding="utf-8")


def run_one(mutation):
    mid, name, category, filename, change = mutation
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "terraform"
        s.copy_tree(s.TF_DIR, dst)
        try:
            apply_mutation(dst, filename, change)
        except RuntimeError as e:
            return {"id": mid, "name": name, "category": category, "error": str(e)}
        tf = s.run_tfsec(dst)
        ck, _, _ = s.run_checkov(dst)
    return {
        "id": mid, "name": name, "category": category,
        "tfsec": sorted({f["id"] for f in tf}),
        "checkov": sorted({f["id"] for f in ck}),
    }


def main():
    # First make sure the clean code really is clean, otherwise results mean nothing.
    tf = s.run_tfsec(s.TF_DIR)
    ck, _, _ = s.run_checkov(s.TF_DIR)
    if tf or ck:
        raise SystemExit(f"The unmodified code has findings (tfsec {len(tf)}, Checkov {len(ck)}). Fix those first.")
    print("Clean code passes both scanners. Running", len(MUTATIONS), "mutations...\n")

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run_one, MUTATIONS))

    errors = [r for r in results if "error" in r]
    if errors:
        for e in errors:
            print("COULD NOT APPLY", e["id"], e["error"])
        raise SystemExit("Fix the mutation definitions above and re-run.")

    tfsec_v, checkov_v = s.tool_versions()
    rows = []
    caught_tf = caught_ck = caught_any = 0
    for r in results:
        t, c = bool(r["tfsec"]), bool(r["checkov"])
        caught_tf += t
        caught_ck += c
        caught_any += (t or c)
        rows.append(
            f"| {r['id']} | {r['name']} | {r['category']} | "
            f"{'caught' if t else '**MISSED**'} {', '.join(r['tfsec'])} | "
            f"{'caught' if c else '**MISSED**'} {', '.join(r['checkov'])} | "
            f"{'yes' if (t or c) else '**NO**'} |"
        )

    n = len(results)
    only_tf = [r["id"] for r in results if r["tfsec"] and not r["checkov"]]
    only_ck = [r["id"] for r in results if r["checkov"] and not r["tfsec"]]
    overlap_lines = []
    if only_tf and only_ck:
        overlap_lines.append(
            f"- The scanners complement each other: only tfsec caught {', '.join(only_tf)}, and only Checkov caught {', '.join(only_ck)}. Running both detected more than either alone."
        )
    elif only_ck:
        overlap_lines.append(
            f"- Checkov caught everything tfsec caught, plus {', '.join(only_ck)} which tfsec missed. In this test, adding tfsec did not increase the number of mistakes detected, although it gives independent confirmation with a different rule set."
        )
    elif only_tf:
        overlap_lines.append(
            f"- tfsec caught everything Checkov caught, plus {', '.join(only_tf)} which Checkov missed. In this test, adding Checkov did not increase the number of mistakes detected, although it gives independent confirmation with a different rule set."
        )
    else:
        overlap_lines.append("- The two scanners detected exactly the same mistakes in this test.")

    lines = [
        "# Experiment 2: negative testing of the security pipeline\n",
        f"Run on {date.today().isoformat()} with tfsec `{tfsec_v}` and Checkov `{checkov_v}`.\n",
        "Method: start from the hardened code (which passes both scanners with zero findings), introduce one deliberate mistake, and record whether each scanner reports it.\n",
        "| ID | Mistake introduced | Category | tfsec | Checkov | Caught by either? |",
        "|---|---|---|---|---|---|",
        *rows,
        "",
        "## Detection rates\n",
        f"- tfsec alone: {caught_tf}/{n} ({round(100 * caught_tf / n)}%)",
        f"- Checkov alone: {caught_ck}/{n} ({round(100 * caught_ck / n)}%)",
        f"- Both scanners together: {caught_any}/{n} ({round(100 * caught_any / n)}%)",
        "",
        "## What the results show\n",
        *overlap_lines,
        "- The mistakes that were missed are the interesting ones. Deleting the alarm entirely, or placing the server in a public subnet, is a perfectly valid configuration as far as a code scanner is concerned. Static scanning checks that the resources that exist are configured safely, not that the right resources exist or that they are in the right place.",
        "- That gap is why the project also deploys runtime monitoring (GuardDuty, CloudTrail, the root-usage alarm) and why a real deployment should be tested from the outside (see the runtime test plan).",
        "",
        "## Limitations\n",
        "- Only 16 hand-written mutations, all chosen by me, so this is not exhaustive and the detection rate is not a general claim about the tools.",
        "- Each mutation is a single change. Real mistakes often combine.",
        "- Scanner rule sets change between versions, so results may differ if re-run later. The versions are recorded above.",
    ]
    text = "\n".join(lines) + "\n"
    s.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (s.RESULTS_DIR / "negative-test-results.md").write_text(text, encoding="utf-8")
    print(text)
    print("Saved to", s.RESULTS_DIR / "negative-test-results.md")


if __name__ == "__main__":
    main()
