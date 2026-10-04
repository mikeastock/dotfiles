---
name: how
description: "Use for \"how does X work\", code walkthroughs before changing something, and placement / ownership / layering questions (\"where should this live\", \"which package owns this\", \"is this the right layer\"). Explains subsystem architecture, runtime flow, onboarding mental models. Use why for motivation."
agents: [pi]
metadata:
  user-invocable-only: "true"
---

# How

> Pi: other pstack skills named here (for example **how** or `principle-prove-it-works`) are installed as siblings of this skill. Read `../<name>/SKILL.md`. A `/name` reference means that skill. Subagents cannot resolve this skill's relative paths, so when a prompt you pass to a subagent names `references/<file>`, give it the absolute path under this skill's directory. Subagents run through the pstack `task` tool, and per-role models come from `~/.pi/agent/pstack-models.md` when it exists.

Explore the codebase to answer "how does X work?" questions. Produce architectural explanations at the level of a senior engineer onboarding onto a subsystem, enough to build a working mental model, not so much that it reads like annotated source code.

Each spawn below names a role line in the pstack model config (`~/.pi/agent/pstack-models.md`) and a default. Set `model` to that line's value, or to the default if the config or the line is missing. Leave `model` unset when the value is `auto` or `inherit-parent`. If a `task` entry fails on its model, rerun it once on the same model with a lower thinking suffix, or none, when the error names the thinking level. If the model itself is unavailable, use the closest model of the same family from `pi --list-models`, never a costlier tier than the one configured, and say so.

## Step 1. Assess Complexity

If the scope is ambiguous, state your interpretation and explore. The user can redirect.

- **Simple** (a single module, a small utility, a narrow question such as "how does function X work"): no explorers. One explainer explores and explains in a single pass. Go to Step 2b.
- **Complex** (a subsystem spanning multiple files or services, a cross-cutting feature, a full architectural overview): spawn parallel explorers first, then hand off to the explainer. Go to Step 2a.

When in doubt, take the simple path.

## Step 2a. Explore (complex questions only)

Decompose the question into 2 to 4 exploration angles, each a distinct slice of the subsystem. Spawn all explorers in a single `task` call:

- `agent`: `general`
- `model`: the `how explorer` line, default `xai/grok-4.7:xhigh`
- `readonly`: `true`

Each explorer gets the prompt in `references/explorer-prompt.md` with its angle filled in. Then go to Step 3.

## Step 2b. Direct Explain (simple questions)

Spawn one `task` subagent that explores and explains in one pass:

- `agent`: `general`
- `model`: the `how explainer` line, default `anthropic/claude-opus-5-5:max`
- `readonly`: `true`

Build its prompt from `references/explainer-prompt.md` without the explorer-findings section. Go to Step 4.

## Step 3. Synthesize (complex questions only)

Once all explorers have returned, spawn one `task` subagent to synthesize their findings into one explanation:

- `agent`: `general`
- `model`: the `how explainer` line, default `anthropic/claude-opus-5-5:max`
- `readonly`: `true`

Build its prompt from `references/explainer-prompt.md` with every explorer's findings filled in.

## Step 4. Present

Present the explainer's output to the user. Light edits for clarity or context from the conversation are fine. Do not substantially rewrite it.

## Output Format

The explanation uses the sections defined in `references/explainer-prompt.md`, dropping any that do not apply: Overview, Key Concepts, How It Works, Where Things Live, Gotchas.
