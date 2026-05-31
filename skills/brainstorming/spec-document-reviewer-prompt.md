# Spec Document Reviewer Dispatch

Dispatch the `document-reviewer` agent to verify a spec is complete and ready for planning.

**Dispatch after:** Spec document is written to `docs/design/`.

## Dispatch via pi-subagents

```
/run document-reviewer "Review the spec at [SPEC_FILE_PATH]. Check for: completeness (no TODOs/TBD/placeholders), internal consistency (no contradictions), clarity (no ambiguous requirements that could lead to building the wrong thing), scope (focused enough for a single plan), and YAGNI (no unrequested features). Approve unless there are serious gaps that would lead to a flawed plan."
```

## Acting on Results

- **Approved:** Proceed to user review gate
- **Issues Found:** Fix issues, re-dispatch reviewer
- If loop exceeds 3 iterations, surface to human for guidance
- Reviewers are advisory — explain disagreements if you believe feedback is incorrect
