---
argument-hint: "[scope or instructions]"
description: Run a parent-orchestrated adversarial review loop
---
Run a parent-orchestrated review loop for this scope: $@

Use subagents if available. Keep this parent session as the loop controller and final decision-maker.

Rules:

1. Child reviewers must receive concrete role-specific tasks.
2. Child reviewers should inspect the repository, instructions, and current diff directly from files and commands.
3. Prefer fresh context for reviewers unless the user explicitly asks for forked context.
4. Child reviewers must not run subagents or manage the loop themselves.
5. Run at most 3 review rounds unless the user asks for more.
6. Convert findings into a prioritized fix queue.
7. Fix valid findings, verify them, then run another round only when the changes justify it.

Final output should list accepted fixes, rejected findings with reasons, verification run, and remaining risk.
