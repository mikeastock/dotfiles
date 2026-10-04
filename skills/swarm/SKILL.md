---
name: swarm
description: "Fan out N parallel workers, drain them, and return one report. Use for /swarm, 'swarm this', or parallel coverage, races, gauntlets, and exploration."
agents: [pi]
metadata:
  user-invocable-only: "true"
---

# Swarm

> Pi: other pstack skills named here (for example **how** or `principle-prove-it-works`) are installed as siblings of this skill. Read `../<name>/SKILL.md`. A `/name` reference means that skill. Subagents cannot resolve this skill's relative paths, so when a prompt you pass to a subagent names `references/<file>`, give it the absolute path under this skill's directory. Subagents run through the pstack `task` tool, and per-role models come from `~/.pi/agent/pstack-models.md` when it exists.

Fan out N parallel workers. They may cover separate slices, race the same brief, or mix both. The parent waits, aggregates, and returns one report.

## Start

Open a todolist with `todo_write` with one entry per phase before launching anything.

1. Frame
2. Fan out
3. Aggregate
4. Report

## Phase A: Frame

1. State the done predicate and the artifact or report the swarm must return.
2. Choose the shape. Partition into slices, race N workers on identical briefs, or mix both. For a race or mixed shape, declare `first pass`, `rank all`, or `best-of` before spawning.
3. Set N from the user or derive it from the shape. N is total workers, not the `task` concurrency limit.
4. Pick the worker model from the `swarm workers` line in `~/.pi/agent/pstack-models.md`. If the config or that line is missing, use `xai/grok-4.7:xhigh`. For `auto` or `inherit-parent`, omit `model` so the workers run on the parent model. If a `task` entry fails on its model, rerun it once on the same model with a lower thinking suffix, or none, when the error names the thinking level. If the model itself is unavailable, use the closest model of the same family from `pi --list-models`, never a costlier tier than the one configured, and say so. For a model race, name each arm's model up front.
5. Give each worker its own writable output when it writes. When workers verify or measure commits, each brief names the exact SHAs. A measurement brief also names the method (sample count, what one sample is, order). The worker records both in its result.

## Phase B: Fan out

Spawn all N workers in one `task` call with `agent: "general"` and the step 4 model, left unset for `auto` or `inherit-parent`. Workers share this machine, so give each one its own worktree or scratch directory when they write. The `task` tool runs at most 12 subagents per call, 6 at a time. Split a larger swarm into several calls.

When a worker must start from a non-default pushed branch, create its worktree at that branch and name both in its brief.

Every brief stands alone. Include the goal, scope, exact slice or race arm, how to verify, and what to report. Reports use `PASS`, `ISSUES`, or `BLOCKED` with evidence. A worker that can prove a defect reports `ISSUES` and lists every issue it can prove, not only the first.

If a worker drops out, proceed with N-1 and note it.

## Phase C: Aggregate

Read the terminal results. Drop a result that does not record the SHAs and method its brief names, and respawn that worker once. After a second miss, record a gap. A gap does not count as a pass. For coverage, every required slice needs a result. For a race, apply the selection rule declared up front. Use first pass, rank all, or best-of. Do not paste raw worker dumps.

Keep a compact result table, one-line evidenced issues, and explicit gaps or dropouts.

## Phase D: Report

Return one consolidated in-chat report with the table, issue one-liners, gaps or dropouts, and the race rule when used.
