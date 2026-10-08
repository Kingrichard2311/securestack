# Evaluation scripts

Both scripts run the same two scanners as the GitHub Actions pipeline.

| Script | Experiment | What it does |
|---|---|---|
| `compare_scans.py` | 1 | Scans the insecure baseline and the hardened code and compares the findings |
| `negative_tests.py` | 2 | Introduces 16 deliberate mistakes into the hardened code, one at a time, and records which scanner catches each |
| `scanlib.py` | | Shared helper functions |

## Setup

```bash
pip install checkov
```
and put `tfsec` (or `tfsec.exe` on Windows) on your PATH or in the project folder. See the main README.

## Run

From the project root:

```bash
python tests/compare_scans.py
python tests/negative_tests.py
```

Results are printed and saved to `docs/results/`.

## Adding your own mutation

In `negative_tests.py`, add an entry to the `MUTATIONS` list. Each one has an ID, a name, a category, the file to change, and the change (append text, replace text using a regular expression, or delete a resource block). The script refuses to run if a mutation can't be applied, so a typo can't silently produce a false "caught" result.
