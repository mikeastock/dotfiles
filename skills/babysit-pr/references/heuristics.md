# CI / Review Heuristics

## CI classification checklist

Treat as **branch-related** when logs clearly indicate a regression caused by the PR branch:

- Compile/typecheck/lint failures in files or modules touched by the branch
- Deterministic unit/integration test failures in changed areas
- Snapshot output changes caused by UI/text changes in the branch
- Static analysis violations introduced by the latest push
- Build script/config changes in the PR causing a deterministic failure

Treat as **likely flaky or unrelated** when evidence points to transient or external issues:

- DNS/network/registry timeout errors while fetching dependencies
- Runner image provisioning or startup failures
- GitHub Actions infrastructure/service outages
- Cloud/service rate limits or transient API outages
- Non-deterministic failures in unrelated integration tests with known flake patterns

Do not patch likely flaky/unrelated failures. Use the retry budget for rerunnable failures, wait for pending jobs, or stop and report the blocker when the failure is persistent or infrastructure-owned.

If uncertain, inspect failed logs once before choosing rerun.

## Decision tree (fix vs rerun vs stop)

1. If PR is merged/closed: stop.
2. If there are failed checks:
   - Diagnose first.
   - If checks are still pending but an individual job has already failed: fetch that job's logs and diagnose now.
   - If branch-related: fix locally, commit, push.
   - If likely flaky/unrelated and all checks for the current SHA are terminal: rerun failed jobs.
   - If likely flaky/unrelated and not safely rerunnable: stop and report the blocker; do not edit unrelated tests, build scripts, CI configuration, dependency pins, or infrastructure code.
   - If checks are still pending and no failed job is available yet: wait.
3. If flaky reruns for the same SHA reach the configured limit (default 3): stop and report persistent failure.
4. Independently, use better-github-skill's full thread report to process all published feedback and every actionable unresolved thread, regardless of author.

## Review comment agreement criteria

Address the comment when:

- The comment is technically correct.
- The change is actionable in the current branch.
- The requested change does not conflict with the user’s intent or recent guidance.
- The change can be made safely without unrelated refactors.

Independently validate every claim, regardless of whether it came from a human, known review bot, or
unknown bot. Fix valid feedback, or reply with concise `[agent]` technical pushback when it is invalid,
obsolete, or out of scope. Resolve a thread only after every substantive point and follow-up is
handled. Do not make an unnecessary code change just to satisfy a reviewer.

Do not auto-fix when:

- The comment is ambiguous and needs clarification.
- The request conflicts with explicit user instructions.
- The proposed change requires product/design decisions the user has not made.
- The codebase is in a dirty/unrelated state that makes safe editing uncertain.
- The comment needs a product decision, an unsupported commitment, or a response that cannot be justified confidently from repository evidence.

## Review-green gate

Do not report a PR as review-clean until all of the following are true:

- CI is terminal and green for the current head SHA.
- GitHub reports no blocking review decision.
- All newly surfaced review feedback has been judged.
- Every substantive published item has been judged and every actionable inline thread has been resolved, regardless of author.

The watcher must continue after this milestone while the PR remains open. New feedback, a new
commit, a changed review decision, or a reopened/unresolved thread resets the gate.

## Stop-and-ask conditions

Stop and ask the user instead of continuing automatically when:

- The local worktree has unrelated uncommitted changes.
- `gh` auth/permissions fail.
- The PR branch cannot be pushed.
- CI failures persist after the flaky retry budget.
- Reviewer feedback requires a product decision or cross-team coordination.
- Feedback requires a product decision or a response the agent cannot support safely from repository evidence.
