"""
Experiment 1: how much more secure is the hardened version?

Scans three things with tfsec and Checkov and compares the numbers:
  A) baseline-insecure/            the deliberately bad "before" version
  B) terraform/ (as the pipeline sees it)   the hardened version, with my
     documented exceptions switched on
  C) terraform/ with ALL exceptions removed  shows every finding I chose to
     accept, so the result is not hiding anything

Run from the project folder:   python tests/compare_scans.py
Results are printed and saved to docs/results/scan-comparison.md
"""

import tempfile
from datetime import date
from pathlib import Path

import scanlib as s


def scan(directory):
    tf = s.run_tfsec(directory)
    ck, ck_passed, ck_skipped = s.run_checkov(directory)
    return {"tfsec": tf, "checkov": ck, "ck_passed": ck_passed, "ck_skipped": ck_skipped}


def main():
    print("Scanning the baseline (insecure) version...")
    baseline = scan(s.BASELINE_DIR)

    print("Scanning the hardened version (as the pipeline sees it)...")
    hardened = scan(s.TF_DIR)

    print("Scanning the hardened version with all exceptions removed...")
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "terraform"
        s.copy_tree(s.TF_DIR, dst, strip_suppressions=True)
        raw = scan(dst)

    tfsec_v, checkov_v = s.tool_versions()

    b_sev = s.count_by_severity(baseline["tfsec"])
    h_sev = s.count_by_severity(hardened["tfsec"])
    r_sev = s.count_by_severity(raw["tfsec"])

    lines = []
    add = lines.append
    add("# Experiment 1: baseline vs hardened scan comparison\n")
    add(f"Run on {date.today().isoformat()} with tfsec `{tfsec_v}` and Checkov `{checkov_v}`.\n")
    add("| Version | tfsec findings | tfsec CRITICAL | tfsec HIGH | tfsec MEDIUM | tfsec LOW | Checkov failed checks |")
    add("|---|---|---|---|---|---|---|")
    for label, res, sev in [
        ("A. Baseline (deliberately insecure)", baseline, b_sev),
        ("B. Hardened (pipeline view, accepted risks documented)", hardened, h_sev),
        ("C. Hardened with ALL exceptions removed", raw, r_sev),
    ]:
        add(
            f"| {label} | {len(res['tfsec'])} | {sev['CRITICAL']} | {sev['HIGH']} | "
            f"{sev['MEDIUM']} | {sev['LOW']} | {len(res['checkov'])} |"
        )

    def reduction(a, b):
        return "n/a" if a == 0 else f"{round(100 * (a - b) / a)}%"

    add("")
    add("**Reduction from baseline to hardened (all exceptions removed, so no findings are hidden):**\n")
    add(f"- tfsec: {len(baseline['tfsec'])} -> {len(raw['tfsec'])} findings ({reduction(len(baseline['tfsec']), len(raw['tfsec']))} fewer)")
    add(f"- Checkov: {len(baseline['checkov'])} -> {len(raw['checkov'])} failed checks ({reduction(len(baseline['checkov']), len(raw['checkov']))} fewer)")
    add(f"- tfsec CRITICAL + HIGH: {b_sev['CRITICAL'] + b_sev['HIGH']} -> {r_sev['CRITICAL'] + r_sev['HIGH']}")

    add("\n## Findings still present in the hardened version when exceptions are removed\n")
    add("These are the risks I consciously accepted. Each has a written reason in the code and in the README.\n")
    add("| Scanner | Rule | Resource |")
    add("|---|---|---|")
    for f in sorted(raw["tfsec"], key=lambda x: (x["id"], x["resource"])):
        add(f"| tfsec ({f['severity']}) | {f['id']} | `{f['resource']}` |")
    for f in sorted(raw["checkov"], key=lambda x: (x["id"], x["resource"])):
        add(f"| Checkov | {f['id']} | `{f['resource']}` |")

    add("\n## Findings in the baseline (for reference)\n")
    add("| Scanner | Rule | Resource |")
    add("|---|---|---|")
    for f in sorted(baseline["tfsec"], key=lambda x: (x["severity"], x["id"])):
        add(f"| tfsec ({f['severity']}) | {f['id']} | `{f['resource']}` |")
    for f in sorted(baseline["checkov"], key=lambda x: (x["id"], x["resource"])):
        add(f"| Checkov | {f['id']} | `{f['resource']}` |")

    add("\n## Limitations of this experiment\n")
    add("- The baseline was written by me to be insecure, so it is a controlled comparison, not a survey of real-world code.")
    add("- Static scanners only read code. They cannot tell me whether the deployed system behaves securely (see Experiment 2 and the runtime tests in the report).")
    add("- Finding counts are not a perfect measure of risk: one CRITICAL finding matters more than several LOW ones, and different scanners count the same flaw differently.")

    text = "\n".join(lines) + "\n"
    s.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (s.RESULTS_DIR / "scan-comparison.md").write_text(text, encoding="utf-8")
    print("\n" + text)
    print(f"Saved to {s.RESULTS_DIR / 'scan-comparison.md'}")


if __name__ == "__main__":
    main()
