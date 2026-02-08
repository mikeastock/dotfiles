# Global Agent Guidelines

**ALWAYS** use `fd` instead of `find`
**ALWAYS** use `rg` instead of `grep`
**ALWAYS** set a non-interactive editor env for git continuation commands (e.g. `GIT_EDITOR=true`) when running commands like `git rebase --continue`, `git merge --continue`, or similar.

## Mindset & Process

- Think a lot before acting.
- **No breadcrumbs**. If you delete or move code, do not leave a comment in the old place. No "// moved to X", no "relocated". Just remove it.
- **Think hard, do not lose the plot**.
- Instead of applying a bandaid, fix things from first principles, find the source and fix it versus applying a cheap bandaid on top.
- When taking on new work, follow this order:
  1. Think about the architecture.
  1. Research official docs, blogs, or papers on the best architecture.
  1. Review the existing codebase.
  1. Compare the research with the codebase to choose the best fit.
  1. Implement the fix or ask about the tradeoffs the user is willing to make.
- Write idiomatic, simple, maintainable code. Always ask yourself if this is the most simple intuitive solution to the problem.
- Leave each repo better than how you found it. If something is giving a code smell, fix it for the next person.
- Clean up unused code ruthlessly. If a function no longer needs a parameter or a helper is dead, delete it and update the callers instead of letting the junk linger.
- **Search before pivoting**. If you are stuck or uncertain, do a quick web search for official docs or specs, then continue with the current approach. Do not change direction unless asked.
- If code is very confusing or hard to understand:
  1. Try to simplify it.
  1. Add an ASCII art diagram in a code comment if it would help.

## Language Guidance

### Ruby

- Prefer straightforward Ruby control flow over defensive branching when invariants are already enforced upstream.
- In Ruby services, optimize for linear readability: fetch records, transform data, execute side effects.
- Keep service object interfaces lean: remove unused params/dependencies instead of carrying them forward.
- Prefer intent-revealing private method names over clever abstractions.
- Prefer memoization for DB-backed lookups inside a service/object lifecycle to prevent accidental repeat queries and N+1-style footguns.

## Testing Philosophy

- Avoid mock tests; do unit or e2e (end-to-end) instead. Mocks are lies: they invent behaviors that never happen in production and hide the real bugs that do.
- Test everything with rigor. Our intent is ensuring a new person contributing to the same code base cannot break our stuff and that nothing slips by. We love rigour.
- Unless the user asks otherwise, run only the tests you added or modified instead of the entire suite to avoid wasting time.

## Dependencies & External APIs

- If you need to add a new dependency to a project to solve an issue, search the web and find the best, most maintained option. Something most other folks use with the best exposed API. We don't want to be in a situation where we are using an unmaintained dependency, that no one else relies on.
