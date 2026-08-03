---
name: review-gauntlet
description: >-
  Run a multi-model review → Fable triage → fix loop (Fable, Grok, Codex,
  Thermonuclear) via the Grok review-gauntlet workflow or code-review-loop CLI.
  Use when the user wants a hard multi-reviewer gauntlet, review-and-fix loop,
  or replacement for a one-shot parallel review council on a PR, branch, commit,
  or comparison with main.
metadata:
  agents: "claude, codex, pi"
  user-invocable-only: "true"
---

# Review Gauntlet

Orchestrate the durable multi-reviewer **review → Fable triage → implement →
re-review** loop. Do not reimplement the loop yourself and do not run the old
one-shot parallel review council.

The implementation lives in:

| Piece | Location |
| --- | --- |
| Grok workflow | `~/.grok/workflows/review-gauntlet.rhai` (source: dotfiles `configs/grok/workflows/`) |
| CLI wrapper | `code-review-loop` on `PATH` (source: dotfiles `bin/code-review-loop`) |

Prefer the CLI when you are outside an interactive Grok TUI. Prefer
`/workflow review-gauntlet …` when already inside Grok.

## What it does

Each round:

1. **Review in parallel** — Fable (`claude-fable-5`), independent Grok
   (`/review`), Codex (`codex exec review`), Thermonuclear (Pi skill / in-agent).
2. **Triage** — a separate Fable judge decides `do_now` / skip / defer under an
   anti-over-engineering doctrine. Fable’s `DO_NOW` is authoritative; demotions
   need hard disproof.
3. **Fix** — Grok implements only accepted items (small correct fixes, focused
   tests, local commits; no push).
4. **Loop** until `do_now` is empty, fixes stall, or `max_rounds` (default 3).

This **does change the branch** when Fable accepts work. It is not review-only.

## Prefer the CLI

From the repo root (or with `--cwd`):

```bash
# Open PR for current branch (default); durable zmx + interactive Grok
code-review-loop

code-review-loop --brief "Focus on authz regressions"
code-review-loop --pr 11571
code-review-loop --commit "$(git rev-parse HEAD)"
code-review-loop --base origin/main --brief "Whole branch vs main"
code-review-loop --skip codex --max-rounds 2
code-review-loop --foreground   # attach TUI in this terminal
code-review-loop --print        # show command + args only
```

Defaults:

- No scope flags → open PR via `gh pr view` (brief defaults to PR title).
- Detached durable launch (zmx + pseudo-TTY). Use `--foreground` to attach.
- Does **not** push.

Watch:

```bash
zmx list --short
zmx history code-review-loop-pr<N>
# In Grok TUI for that cwd: /workflows
```

## Prefer the Grok workflow (inside Grok)

Simple args (brief is always optional):

```text
/workflow review-gauntlet
/workflow review-gauntlet 11571
/workflow review-gauntlet "#11571"
/workflow review-gauntlet {"target":"11571"}
/workflow review-gauntlet {"target":"origin/main","rounds":2,"skip":"codex"}
/workflow review-gauntlet {"target":"feature/x","brief":"optional note"}
```

| Args shape | Meaning |
| --- | --- |
| *(none)* / `{}` | Auto: open PR for this branch, else `origin/main` |
| `"11571"` / `#N` / PR URL | PR |
| 7–40 hex | Commit |
| `main` / `origin/main` / `a...b` | Base |
| other string | Branch |
| `{target, brief?, rounds?, skip?, dirty?}` | Same classification + options |

Legacy `{pr, commit, branch, base, …}` still works. Follow progress in
`/workflows`.

## Agent responsibilities

1. Resolve the user’s intent: scope (PR / commit / branch / base), optional
   brief, optional skip list / max rounds.
2. Launch **exactly one** of: `code-review-loop …` or `/workflow review-gauntlet …`.
3. Do **not** manually fan out Fable/Grok/Codex/Thermo yourself.
4. Do **not** invent a second triage layer that second-guesses Fable after the
   workflow finishes—report the workflow report.
5. When the run completes, summarize from the workflow report:
   - stop reason, rounds, fixed / skipped / deferred / overrides
   - paths under `/tmp/review-gauntlet-*/` and scratch `review-gauntlet-report.md`
6. If the workflow or CLI is missing, tell the user to install/update dotfiles
   (`make dot-home-symlinks` / `make install`) so
   `~/.grok/workflows/review-gauntlet.rhai` is a **copied** file (not a symlink)
   and `code-review-loop` is on `PATH`.

## Doctrine (do not dilute)

Accept real correctness, regression, security, data-integrity, missing-test, and
structural problems that matter now.

Skip speculative rare edges, gold-plating, large refactors for one-offs, style
bikesheds, and thermo “code judo” that expands scope without removing real
complexity.

Empty `do_now` after honest triage is success—not a failure to “do more rounds.”

## Boundaries

- Expect long wall-clock time (Fable alone is often 10+ minutes; full loops longer).
- Do not cancel just because a reviewer is quiet.
- Do not push, force-push, open/merge PRs, or post GitHub review comments unless
  the user explicitly asks outside this skill.
- Keep secrets out of briefs and prompts.
- For a single-model review only, use `fable-review`, `grok-review`, or Codex
  review—not this skill.
