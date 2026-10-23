---
name: odg-optimize-perf
description: Optimize performance of ODG running at scale
---

You are driving a performance investigation and fix. Each step uses an isolated agent.
Don't carry conclusions from one step into the next. Ask for evidence & reports first.

---

## Setup

Ask for: issue name (short, hyphenated) + evidence (logs, metrics, memray/py-spy captures).

If the evidence shows multiple issues, ask which one to focus on.

Check if a matching test suite exists. If not, create it:

```sh
mkdir -p test/perf/<test-suite>/results
touch test/perf/<test-suite>/__init__.py
```

Stop if `test/perf/<test-suite>/results/TASK.md` already exists.
If not, write it:

```markdown
# Perf issue: <issue-name>

Status: pending

## Symptom
<!-- What broke, which endpoint, at what scale -->

## Prod evidence
<!-- Summary of logs, metrics, code paths -->

## Code path analysis
<!-- filled after code path analysis: summary + link >

## Fixes

| Possible fix | Tested? | Result? | Learning |
|--------------|---------|---------|----------|
<!-- fixes added after code path analysis and during change-test-loop >

## Changelog

| Code change | Result | Performance impact |
|-------------|--------|--------------------|

## Code review verdict

## Before/after comparison

## Follow-on
<!-- open todos, other issues, refactoring advice -->
```

Fill in `Symptom` and `Prod evidence` now.

---

## Step 2 — Understand the code path

Spawn **`odg-code-path-analysis`**. Give it the test suite name and pointers to prod evidence.

If there are open questions, `odg-code-path-analysis` should surface them. Ask the user, then pass the answer.

It returns the report. Write it to `test/perf/<test-suite>/results/code-path-analysis.md`. Update TASK.md status to `analysis`, link to the report with a 2-3 sentence summary.

---

## Step 3 — Reproduce locally

No test yet → spawn **`odg-implement-perf-test`** with the test suite name and the instruction to write a suitable test.
It writes the test and runs it; wait for it.

Test exists → spawn **`odg-run-perf-test`** with the test suite name.

Ask the user: "Does this reproduce the symptom?" If no, loop back to implement.

Update TASK.md status to `analysis`, link to the report with a 2-3 sentence summary.

---

## Step 4 — Diagnose

Spawn a **Sonnet** agent. Give it TASK.md and the relevant source files (file:line — don't summarise). It proposes a root cause and a concrete fix; writes both into TASK.md.

**Gate:** User must confirm the proposed fix before step 5.

---

## Step 5 — Implement

If fix is clear, span a **Sonnet** agent with the proposed fix verbatim from TASK.md.
Changes must be minimal and, if possible, isolated. The user must refactor later.
It should return a brief summary of the code change.

If the fix is unclear or complicated, span a *planning** agent first.

Then spawn **`/code-review`** on the changed files. Get feedback from the user on those findings.
Then tell the coding agent to implement the fixes.

Log the code change in TASK.md. Do not print the code review verdict yet.

---

## Step 6 — Verify

Spawn **`odg-run-perf-test`** with the test suite name. Don't tell it what result to expect.

| Result | Action |
|--------|--------|
| All pass + snapshot matches + metrics improved | → step 7 |
| Snapshot diff | Ask user: expected or regression? Expected → update snapshot, rebuild, re-verify. Regression → step 4. |
| Tests fail | → step 5 with failure output |
| Metrics unchanged or worse | → step 4 |

Log the test results in TASK.md.

---

## Step 7 — Close out

Update TASK.md: root cause, fix section, reviewer verdict, before/after numbers, follow-on items.

---

## Rules

- No fix without a test that reproduces the issue.
- No "done" without fresh test output.
- One fix per run — smallest possible change, no surrounding cleanup.
- Snapshot diff = the fix is wrong, not the snapshot.
- Never create commits or PRs — let the user sign off.
- Always use `uv run` for Python; never `make setup` or `make run`.
