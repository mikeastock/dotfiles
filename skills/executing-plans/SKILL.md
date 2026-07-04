---
name: executing-plans
description: Use when you have a written implementation plan to execute
metadata:
  category: superpowers
---

# Executing Plans

## Overview

The plan is a map; you are in the territory. Execute with judgment: honor the plan's decisions and their why, hit its acceptance criteria and gates exactly, and improvise the keystrokes in between. When the territory contradicts the map, that's not a crisis — it's data. Handle it with the deviation protocol.

**Announce at start:** "I'm using the executing-plans skill to implement this plan."

## Step 1: Territory Check

Before writing anything:

1. Read the plan fully — especially Decisions & why, the scope fence, and Residual Unknowns & Deviation Policy.
2. Verify the map against the territory: do the cited files/lines still look like the plan assumes? Has the base branch moved? Do the plan's assumptions hold?
3. Genuine contradictions with the plan's *decisions* (not its mechanics) → raise them with your partner before starting.
4. Map checks out → start. Keep an `implementation-notes.md` beside the work from the first task.

## Step 2: Execute Tasks

For each task:
1. Mark as in_progress.
2. Drive toward its acceptance criteria. Steps in the plan are guidance; the criteria and gates are the contract. Tests first where the plan calls for locks.
3. Run the task's verifications; don't skip gates, don't reinterpret expected output.
4. Mark as completed and commit per the plan's git rules.

**Deviation protocol** (from the plan's Residual Unknowns & Deviation Policy): when implementation reveals the map is wrong — an edge case, a stale assumption, a better local shape —
- take the **conservative** option that preserves the plan's intent,
- log it under **"Deviations"** in `implementation-notes.md` (what you found, what you did, why),
- keep going.

Deviations are reviewed afterward, not litigated mid-flight. The exceptions that DO stop the work:
- the conflict is **architecture-shaping** (invalidates a Decision, not a mechanic),
- staying inside the **scope fence** has become impossible,
- a gate fails repeatedly and the fix isn't inside your fence,
- you genuinely cannot tell what the plan intends.

Ask rather than guess on those — and never force through a blocker.

## Step 3: Complete

- Run the plan's final gates exactly; capture real output.
- Report brief, **leading with deviations and judgment calls** — they are the review surface. Then: verdict, gates output, what was built. A reviewer should be able to read the Deviations log and know exactly where to look hardest.

## Remember

- Territory check before the first edit
- Acceptance criteria and gates are the contract; keystrokes are yours
- Conservative + logged + moving beats stopped + asking, except on architecture
- Never skip or reinterpret a verification
- The Deviations log is the first thing your reviewer reads — write it as you go, not from memory
