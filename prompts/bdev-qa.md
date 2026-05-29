---
argument-hint: "[PR-URL or instructions]"
description: Run bdev QA and optionally post results to a PR
---
Run the Buildr `bdev qa` workflow for the current branch. Extra instructions: $@

Workflow:

1. Inspect the repository state and confirm the current branch, PR, and app target.
2. Read `bdev qa --help` if the flags or posting behavior are uncertain.
3. Run the narrowest appropriate QA command for this branch.
4. If a PR URL or PR number is provided, post the useful QA result summary to the PR.
5. If QA fails, diagnose the first real failure and separate branch-caused failures from environment or flaky failures.
6. Report the command, outcome, and next action.

Do not hide failures behind a broad retry. Retry only when the evidence points to a flaky or environment issue.
