# Global Agent Guidelines

**ALWAYS** use `fd` instead of `find`
**ALWAYS** use `rg` instead of `grep`
**ALWAYS** set a non-interactive editor env for git continuation commands (e.g. `GIT_EDITOR=true`) when running commands like `git rebase --continue`, `git merge --continue`, or similar.

## Language Guidance

### Ruby

- Prefer straightforward Ruby control flow over defensive branching when invariants are already enforced upstream.
- In Ruby services, optimize for linear readability: fetch records, transform data, execute side effects.
- Keep service object interfaces lean: remove unused params/dependencies instead of carrying them forward.
- Prefer intent-revealing private method names over clever abstractions.
- Prefer memoization for DB-backed lookups inside a service/object lifecycle to prevent accidental repeat queries and N+1-style footguns.
- Only use trailing conditionals (`return if ...`, `raise if ...`) for early returns/guards. Never use them for real logic checks; use standard `if`/`unless` blocks instead.

## Hard-Cut Product Policy

- This application currently has no external installed user base; optimize for one canonical current-state implementation, not compatibility with historical local states.
- Do not preserve or introduce compatibility bridges, migration shims, fallback paths, compact adapters, or dual behavior for old local states unless the user explicitly asks for that support.
- Prefer:
  - one canonical current-state codepath
  - fail-fast diagnostics
  - explicit recovery steps
- Over:
  - automatic migration
  - compatibility glue
  - silent fallbacks
  - “temporary” second paths
- If temporary migration or compatibility code is introduced for debugging or a narrowly scoped transition, call it out in the same diff with:
  - why it exists
  - why the canonical path is insufficient
  - exact deletion criteria
- Default stance across the app: delete old-state compatibility code rather than carrying it forward.

## Background Processes with zmx

- We use `zmx` as a lightweight persistent session runner for long-lived/background terminal work (tests, dev servers, build jobs, migrations, one-off scripts).
- Prefer `zmx run` when work should continue independently of the current terminal/agent invocation.
- Use stable, descriptive session names (e.g. `tests`, `server-api`, `build-ios`) so sessions are easy to inspect and reuse.

### Non-interactive safety rule (important)

- `zmx run` can hang agent tool execution in non-interactive environments because the daemon may keep inherited stdio open.
- When running `zmx run` from an agent/tool, **always redirect stdout/stderr** so the command returns promptly:
  - `zmx run <session> <command> >/dev/null 2>&1`
  - or redirect to a file if output must be captured.

### Recommended background process flow

1. Start/dispatch work:
   - `zmx run <session> <command> >/dev/null 2>&1`
2. Wait for task completion when needed:
   - `zmx wait <session>`
3. Inspect output/history:
   - `zmx history <session>`
4. Check active sessions:
   - `zmx list`
5. Clean up stale/finished sessions when appropriate:
   - `zmx kill <session>`

### Practical guidance

- Use one session per concern (don’t mix unrelated jobs in one session).
- Reuse a session when iterative commands should share shell state; create a new session when isolation is safer.
- For recurring workflows, keep session names consistent across runs.

## Mindset & Process

- Think a lot before acting.
- **No breadcrumbs**. If you delete or move code, do not leave a comment in the old place. No "// moved to X", no "relocated". Just remove it.
- **Think hard, do not lose the plot**.
- Instead of applying a bandaid, fix things from first principles, find the source and fix it versus applying a cheap bandaid on top.
- Fix small papercuts when you trip over them. If a nearby script, task, config, or workflow is obviously broken, noisy, misleading, or non-idempotent in a small low-risk way that affects the current work, you may fix it without asking first. Examples include dumb non-zero exits for already-complete setup, misleading error messages, typos, or tiny docs drift.
- Raise larger cleanups before expanding scope. If the better fix turns into a broader refactor, changes architecture or user-visible behavior, touches multiple subsystems, adds dependencies, or needs substantial new testing, stop and ask the user before continuing.
- Write idiomatic, simple, maintainable code. Always ask yourself if this is the most simple intuitive solution to the problem.
- Leave each repo better than how you found it. If something is giving a code smell, fix it for the next person.
- Clean up unused code ruthlessly. If a function no longer needs a parameter or a helper is dead, delete it and update the callers instead of letting the junk linger.
- **Search before pivoting**. If you are stuck or uncertain, do a quick web search for official docs or specs, then continue with the current approach. Do not change direction unless asked.

## Testing Philosophy

- Avoid mock tests; do unit or e2e (end-to-end) instead. Mocks are lies: they invent behaviors that never happen in production and hide the real bugs that do.
- Test everything with rigor. Our intent is ensuring a new person contributing to the same code base cannot break our stuff and that nothing slips by. We love rigour.
- Unless the user asks otherwise, run only the tests you added or modified instead of the entire suite to avoid wasting time.

## Dependencies & External APIs

- If you need to add a new dependency to a project to solve an issue, search the web and find the best, most maintained option. Something most other folks use with the best exposed API. We don't want to be in a situation where we are using an unmaintained dependency, that no one else relies on.
