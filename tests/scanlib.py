"""
Shared helpers for my evaluation scripts.
Author: Richard Lamy

These run the same two scanners as my GitHub Actions pipeline (tfsec and
Checkov) and turn their output into simple Python lists I can count.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TF_DIR = ROOT / "terraform"
BASELINE_DIR = ROOT / "baseline-insecure"
RESULTS_DIR = ROOT / "docs" / "results"


def find_tfsec():
    """Look for tfsec on the PATH, then in the project folder."""
    candidates = [
        shutil.which("tfsec"),
        ROOT / "tfsec.exe",
        ROOT / "tfsec",
        Path(__file__).parent / "tfsec.exe",
        Path(__file__).parent / "tfsec",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    sys.exit(
        "tfsec was not found.\n"
        "Download it from https://github.com/aquasecurity/tfsec/releases\n"
        "(on Windows: tfsec-windows-amd64.exe), rename it to tfsec.exe and put it\n"
        "in the project folder or somewhere on your PATH."
    )


def tool_versions():
    """Record scanner versions so the results can be reproduced."""
    tfsec = subprocess.run([find_tfsec(), "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    checkov = subprocess.run(
        [sys.executable, "-m", "checkov.main", "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return tfsec.stdout.strip() or "unknown", checkov.stdout.strip().splitlines()[-1] if checkov.stdout.strip() else "unknown"


def run_tfsec(directory):
    """Run tfsec and return a list of findings."""
    p = subprocess.run(
        [find_tfsec(), str(directory), "--format", "json", "--no-colour", "--soft-fail"],
        capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )
    data = json.loads(p.stdout)
    findings = []
    for r in data.get("results") or []:
        findings.append(
            {
                "id": r["rule_id"],
                "name": r.get("long_id", ""),
                "severity": r["severity"],
                "resource": r["resource"],
                "file": Path(r["location"]["filename"]).name,
            }
        )
    return findings


def run_checkov(directory):
    """Run Checkov and return a list of failed checks."""
    p = subprocess.run(
        [
            sys.executable, "-m", "checkov.main",
            "-d", str(directory),
            "--framework", "terraform",
            "-o", "json", "--quiet", "--skip-download",
        ],
        capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )
    out = p.stdout
    data = json.loads(out[out.index("{"):])
    if isinstance(data, list):
        data = data[0]
    failed = []
    for c in data["results"]["failed_checks"]:
        failed.append(
            {
                "id": c["check_id"],
                "name": c["check_name"],
                "resource": c["resource"],
                "file": Path(c["file_path"]).name,
            }
        )
    passed = data["summary"]["passed"]
    skipped = data["summary"]["skipped"]
    return failed, passed, skipped


def copy_tree(src, dst, strip_suppressions=False):
    """
    Copy a Terraform folder somewhere temporary.
    If strip_suppressions is True, remove my '#checkov:skip' and
    '#tfsec:ignore' comments, so the scanners report EVERYTHING, including
    the findings I chose to accept.
    """
    shutil.copytree(
        src, dst, ignore=shutil.ignore_patterns(".terraform", "*.tfstate*", "terraform.tfvars")
    )
    if strip_suppressions:
        for f in Path(dst).rglob("*.tf"):
            kept = [
                line
                for line in f.read_text(encoding="utf-8").splitlines()
                if not re.search(r"#\s*(checkov:skip|tfsec:ignore)", line)
            ]
            f.write_text("\n".join(kept) + "\n", encoding="utf-8")


def count_by_severity(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
