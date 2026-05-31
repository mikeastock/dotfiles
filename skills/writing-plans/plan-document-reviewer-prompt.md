# Plan Document Reviewer Dispatch

Dispatch the `document-reviewer` agent to verify a plan is complete and ready for implementation.

**Dispatch after:** The complete plan is written.

## Dispatch via pi-subagents

```
/run document-reviewer "Review the plan at [PLAN_FILE_PATH] against the spec at [SPEC_FILE_PATH]. Check for: completeness (no TODOs/placeholders/missing steps), spec alignment (plan covers all spec requirements, no major scope creep), task decomposition (clear boundaries, actionable steps), and buildability (could an engineer follow this without getting stuck?). Approve unless there are serious gaps."
```

## Acting on Results

- **Approved:** Proceed to execution handoff
- **Issues Found:** Fix issues, re-dispatch reviewer for the whole plan
- If loop exceeds 3 iterations, surface to human for guidance
- Reviewers are advisory — explain disagreements if you believe feedback is incorrect
