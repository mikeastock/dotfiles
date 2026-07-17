---
name: review-council
description: Run Fable, Grok, and Thermo-Nuclear code reviews concurrently against one validated, immutable Git scope, while preserving separate outputs and reporting partial failures. Use when the user explicitly asks for a parallel, three-reviewer, multi-model, or strongest available code review of a PR, branch, commit range, or comparison with main.
metadata:
  agents: "claude, codex, pi"
  user-invocable-only: "true"
---

# Review Council

Run the existing Fable, Grok, and Thermo-Nuclear review contracts together. Keep this workflow review-only: never edit source, commit, push, post GitHub comments, deploy, or implement findings.

## Run

From the repository root, choose exactly one fixed point:

```bash
# Explicit branch, tag, or commit SHA
uv run <skill-root>/scripts/run_parallel_reviews.py --base <ref>

# Explicit comparison with the locally known remote default branch
uv run <skill-root>/scripts/run_parallel_reviews.py --against-main

# Prepared local checkout at an exact PR head
uv run <skill-root>/scripts/run_parallel_reviews.py --pr <number-or-url>
```

Every invocation also requires `--brief-file <path>`. Write a concise task-specific brief containing the user goal, project context, intended behavior, constraints, known risks, and verification already run. Keep secrets and raw repository content out of the brief. Fable and Thermo receive it; Grok continues to receive only its exact native `/review --branch` invocation.

Add `--head <ref>` when the reviewed head is not `HEAD`. A PR run requires the PR base and head commits to exist locally and the selected head to equal the PR's recorded head SHA. The runner rejects invalid refs, empty diffs, ambiguous dirty trees, and existing output directories before starting reviewers.

If the source tree is dirty, stop and ask whether the user wants those changes excluded. Pass `--allow-dirty` only after they explicitly confirm that the pinned committed range is the intended scope. The runner never includes dirty changes.

Use `--dry-run` to validate arguments, the review brief, the fixed point, and the non-empty committed diff without inspecting or launching reviewer dependencies. Use `--timeout-seconds <n>` to change the per-reviewer wall-clock limit; the default is 30 minutes.

## Execution Contract

The runner resolves the selected refs to base, merge-base, and head SHAs once. It creates one disposable clone per reviewer, pins each clone to those SHAs, and launches all three concurrently:

- Fable uses `claude -p --model claude-fable-5 --effort high` with stream JSON, Read, and Bash, as defined by `fable-review`.
- Grok uses the canonical `grok-review/scripts/run_review.sh` wrapper and Grok's native `/review --branch` mode. The disposable clone's `origin/main` ref is pinned to the same fixed point so native branch mode cannot drift.
- Thermo-Nuclear runs its installed `SKILL.md` explicitly through non-interactive Pi with only read/search/list/Bash tools. The plugin-owned skill remains the only source of its review and verdict standards, and its output must end in exactly one plugin-defined verdict.

Grok and Thermo resources must resolve from the same managed skill root; the runner fails instead of silently mixing installation snapshots. Each reviewer works in an isolated, non-shared clone with a disabled Git remote. The runner removes those clones only after owned process groups stop, including timeout and cancellation paths. It retains only private, mode-0700 run artifacts containing the scope manifest, reviewer outputs, sanitized diagnostics, and aggregate status.

## Interpret Results

Read `summary.md` first, then inspect each reviewer's separate `review.md`. Never flatten the three voices into a synthetic approval. A reviewer is successful only when its canonical command and validation contract exit successfully and a non-empty final review exists. Missing, empty, timed-out, or cancelled output is a failure, never approval.

This explicit-only skill is built for Claude, Codex, and Pi. The Codex install resolves the canonical reviewer bundle from the sibling Pi or Claude managed skill root created by the full dotfiles install. Amp has no equivalent managed explicit-invocation policy, so the build intentionally omits it.

Validate every finding against the repository before reporting it as true. Classify each as confirmed, plausible but unresolved, or disproven. Do not implement findings unless the user gives a separate implementation request.

The runner exits nonzero when any reviewer fails while preserving successful reviewer outputs and explicit failure diagnostics.
