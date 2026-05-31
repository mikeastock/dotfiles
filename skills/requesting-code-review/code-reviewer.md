# Code Review Dispatch Template

Dispatch the `code-reviewer` agent to review completed work. The reviewer gets precisely crafted context — never your session history.

## Dispatch via pi-subagents

```
/run code-reviewer "Review {WHAT_WAS_IMPLEMENTED}. Compare against {PLAN_OR_REQUIREMENTS}. Git range: {BASE_SHA}..{HEAD_SHA}. Summary: {DESCRIPTION}"
```

Or with inline config overrides:

```
/run code-reviewer[reads=plan.md] "Review the auth system implementation against the plan. Git range: abc1234..def5678"
```

## Placeholders

- `{WHAT_WAS_IMPLEMENTED}` — What you just built
- `{PLAN_OR_REQUIREMENTS}` — What it should do (file path or inline)
- `{BASE_SHA}` — Starting commit
- `{HEAD_SHA}` — Ending commit
- `{DESCRIPTION}` — Brief summary of changes

## Getting Git SHAs

```bash
BASE_SHA=$(git rev-parse HEAD~1)  # or origin/main
HEAD_SHA=$(git rev-parse HEAD)
```

## Acting on Feedback

- **Critical:** Fix immediately — blocks progress
- **Important:** Fix before proceeding
- **Minor:** Note for later
- Push back if reviewer is wrong (with reasoning)

## Example

```
BASE_SHA=$(git log --oneline | grep "Task 1" | head -1 | awk '{print $1}')
HEAD_SHA=$(git rev-parse HEAD)

/run code-reviewer "Review verification and repair functions for conversation index. Compare against Task 2 from docs/plans/deployment-plan.md. Git range: $BASE_SHA..$HEAD_SHA. Added verifyIndex() and repairIndex() with 4 issue types."
```
