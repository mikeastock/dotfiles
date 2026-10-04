---
name: setup-pstack
description: Configure which models pstack uses per role and at what reasoning budget. Detects your available Pi models and writes ~/.pi/agent/pstack-models.md, which the pstack extension injects into every session and which overrides the skill defaults. Use for /setup-pstack, "configure pstack models", "pstack budget", or changing pstack's model choices.
agents: [pi]
---

# Setup pstack

Write `~/.pi/agent/pstack-models.md`, the per-role model config. The pstack Pi extension injects it into the system prompt of every session, and every pstack skill reads its roles from there.

A model value is a Pi model reference: `provider/id:thinking`, such as `anthropic/claude-opus-5-5:max`. The thinking suffix is one of `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`.

## Steps

### 1. Detect available models

Run `pi --list-models` and take the `provider/model` pairs it lists. That is the dependable source. Prefer the models in `enabledModels` of `~/.pi/agent/settings.json` when it names any, since those are the ones the user cycles through. Never write a model you have not confirmed is listed. The aliases `inherit-parent` and `auto` are always valid even though they are not listed models.

### 2. Load current state

The default role-to-model mapping is the config shape shown in step 5 below. If `~/.pi/agent/pstack-models.md` already exists, read it and treat its `# budget` line and its role values as the current choices. Otherwise start from those defaults. A line whose role is not in step 5, such as `how critics`, is from a retired role. Drop it.

### 3. Budget, map, and confirm

**(a) Ask for a budget.** Ask with these four numbered options and these exact labels, and name the current budget when the config records one. End the turn and wait for the answer.

1. `unlimited, keep max`
2. `large, xhigh thinking`
3. `medium, high thinking`
4. `small, medium thinking`

**(b) Apply it.** Build the working table from the defaults, and on a re-run keep any role you changed by family, list, or alias (`inherit-parent`, `auto`). `unlimited` leaves every thinking suffix as in that table. `large`, `medium`, and `small` set the thinking suffix of every real model, panel entries included, to `xhigh`, `high`, or `medium`, but never above the model's current suffix. `inherit-parent` and `auto` do not change. So `small` turns `anthropic/claude-opus-5-5:max` into `anthropic/claude-opus-5-5:medium`, and `xai/grok-4.7:xhigh` into `xai/grok-4.7:medium`.

**(c) Show the roles and confirm.** Show every role with its model, marking any model not in the detected set as needing a choice. Also list each line step 2 dropped. Ask whether to accept as-is or change specific roles, offering the detected models plus `inherit-parent` and `auto` (both mean the role runs on the parent session's model and thinking level). For panel roles (arena runners, architect runners, interrogate reviewers) the value is a list, and one subagent runs per entry, alias entries included, so the list length sets the count. `arena cross-judge pool` is also a list, but Arena selects one value from it whose model family differs from the parent's when possible. `swarm workers` is the default model for every worker unless a race or comparison assigns another model per arm.

### 4. Validate

Every real model written must be in the detected set, and must actually run with its thinking suffix: not every model accepts every level. Test each distinct value once with `pi -p --no-session --model <value> "reply ok"`, in parallel. `inherit-parent` and `auto` always pass. If a chosen value fails, drop to the next lower thinking level that runs and say so, or stop and ask again when no level runs.

### 5. Write the config

Write `~/.pi/agent/pstack-models.md` with a `# budget` line with the chosen label, and one line per role, using the same labels poteto-mode uses. Overwrite the whole file so re-runs stay idempotent. Shape:

```
# pstack model configuration. One line per role. Delete a line to fall back to the skill default.
# `inherit-parent` or `auto` as a value: the role runs on the parent session model (omit `task` `model`). Alias entries in a panel list still count toward its fan-out.
# budget: unlimited (max)
feature, refactoring: xai/grok-4.7:xhigh
bug-fix: xai/grok-4.7:xhigh
perf-issue: xai/grok-4.7:xhigh
hillclimb: xai/grok-4.7:xhigh
judgment and prose: anthropic/claude-opus-5-5:max
hardest tasks: anthropic/claude-opus-5-5:max
how explorer: xai/grok-4.7:xhigh
how explainer: anthropic/claude-opus-5-5:max
why investigators: xai/grok-4.7:xhigh
why synthesizer: anthropic/claude-opus-5-5:max
reflect tooling: openai/gpt-5.6-sol:max
reflect judgment, divergent, synthesizer: anthropic/claude-opus-5-5:max
arena runners: anthropic/claude-opus-5-5:max, openai/gpt-5.6-sol:max, xai/grok-4.7:xhigh
arena cross-judge pool: anthropic/claude-opus-5-5:max, openai/gpt-5.6-sol:max, xai/grok-4.7:xhigh
swarm workers: xai/grok-4.7:xhigh
architect runners: anthropic/claude-opus-5-5:max, openai/gpt-5.6-sol:max, xai/grok-4.7:xhigh
interrogate reviewers: anthropic/claude-opus-5-5:max, openai/gpt-5.6-sol:max, xai/grok-4.7:xhigh
```

### 6. Confirm

Tell the user the config was written. It applies from the next turn of every session, including this one. Re-running this skill updates it.

### 7. Offer a verification skill (optional)

Check whether the project has a way to drive the real app for proof (a `verify-*` skill, or an existing harness). If not, offer once: "want a project-local verification skill, so agents can drive the app the way a user does and prove changes work? I can generate one with the create-verification-skill skill." On yes, read `../create-verification-skill/SKILL.md` and follow it. On no, move on without pushing.
