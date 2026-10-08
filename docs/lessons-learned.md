# Lessons learned

Author: Richard Lamy

## 1. The first version of my tfsec check never failed the build

**What happened.** On the first push to `main` all three checks went green (run #1). I then pushed a branch containing a deliberate mistake: SSH open to the whole internet (run #2). Checkov failed with `CKV_AWS_24`, as expected, but the **tfsec job stayed green**. Running tfsec on my own machine against the same code reported a CRITICAL finding and exited with an error, so the pipeline and my local test disagreed.

**Cause.** I had used a ready-made GitHub Action for tfsec and set `soft_fail: false`. Reading the action's script showed that it turns soft-fail on whenever the setting contains any text at all. The word "false" counts as text, so tfsec was running in a mode where it reports problems but never fails the job. Nothing in the pipeline's green tick revealed this.

**Fix.** I replaced the action with a step that downloads a pinned version of tfsec (v1.28.14), verifies its checksum, and runs it directly. tfsec exits with an error when it finds a problem, and the job fails.

**Result.** After the fix, the pipeline behaved correctly on both kinds of code:

| Run | Branch | Code | tfsec | Checkov |
|---|---|---|---|---|
| #1 | main | clean | pass | pass |
| #2 | test-insecure-change | open SSH | **pass (wrong)** | fail (`CKV_AWS_24`) |
| #3 | main | clean, tfsec fix | pass | pass |
| #4 | test-insecure-change | open SSH, tfsec fix | **fail** (exit code 1) | fail (`CKV_AWS_24`) |

Runs #2 and #4 use the same insecure change, so the only difference between them is the pipeline fix.

**What it shows.**
- A green tick only means something if you have seen the same check go red. Testing the pipeline with a known-bad change (negative testing) found a flaw that a clean run never would have.
- Third-party tooling can behave differently from what its configuration suggests. Reading the source, or running the tool directly, removes the guesswork.
- Downloading a tool in CI is a supply-chain decision. Pinning the version and verifying the checksum limits the risk.
- This is a concrete example of Experiment 2's main conclusion: automated checks have blind spots, including blind spots in the checking pipeline itself.

Evidence is in `docs/screenshots/`.

## 2. GitHub warnings that are not problems

The Actions summary shows warnings about Node.js 20 being retired and the `ubuntu-latest` label moving to a newer Ubuntu release. They don't fail anything. They mean the versions of the actions I use will eventually need updating, which is worth a mention under maintenance in the report.