---
name: writing-plans
description: Use when you have a spec or requirements for a multi-step task, before touching code
metadata:
  category: superpowers
---

# Writing Plans

## Overview

A plan is a map handed to a capable executor working in real territory. The territory always knows things the map doesn't — so a good plan states **intent, constraints, and acceptance**, and leaves the executor room to improvise through what implementation reveals. Over-specification is a failure mode: an executor following keystroke-level steps will walk off a cliff the plan didn't see. Under-specification fails too: without the *why* behind decisions, the executor substitutes industry defaults for your judgment.

Write for a skilled engineer who has NOT seen your brainstorming session: they need the decisions **with their why**, the constraints that aren't visible in the code, and the exact gates that define done. They do not need prose restating what the codebase already says, or code they could write themselves.

**Announce at start:** "I'm using the writing-plans skill to create the implementation plan."

**Save plans to:** `docs/plans/YYYY-MM-DD-<feature-name>.md`

## Scope Check

If the spec covers multiple independent subsystems, it should have been broken into sub-project specs during brainstorming. If it wasn't, suggest breaking this into separate plans — one per subsystem. Each plan should produce working, testable software on its own.

If the spec has not been through an architecture review and the work changes domain ownership, service boundaries, public APIs, auth, persistence, orchestration, or error contracts, stop and request an `architecture-reviewer` pass before writing the implementation plan.

## Plan Anatomy

Every plan has these sections, in this order. Volatile decisions lead; mechanics trail.

1. **Header** — goal (one sentence), architecture (2-3 sentences), tech stack.
2. **Decisions & why** — the choices most likely to be questioned or changed: data models, type interfaces, UX flows, semantic contracts, naming. Each with its rationale and the alternatives already rejected (so the executor doesn't relitigate them — or knows exactly what evidence would justify reopening one).
3. **Scope fence** — exactly which paths may be touched. "No drive-by refactors" is the default.
4. **Evidence & references** — repro output, error text, links to prior decisions with their why. Where a reference implementation exists (a library, a module, another language), point at it: source code is the highest-bandwidth spec. Never paraphrase what a file already says — cite `path:line`.
5. **Ordered tasks** — each with **acceptance criteria** (observable behavior, not effort). Include code only where the code IS the decision: an interface signature, a tricky invariant, a locked error string. Everything else is the executor's to write.
6. **Gates** — the exact commands that must pass, with expected output, plus environment quirks the executor will hit (toolchain activation, sandbox limits, flaky suites).
7. **Residual Unknowns & Deviation Policy** — carried from the design doc: the unknowns only implementation will resolve, and the standing protocol — *when the territory contradicts the map, take the conservative option, log it under a `## Deviations` section at the bottom of the design doc, and keep going. Stop only for architecture-shaping conflicts or scope-fence pressure.*
8. **Git & report rules** — commit convention; whether pushing/PR is in scope; report shape (verdict + gates output + deviations, brief).

## Task Granularity

A task is a coherent unit of behavior with a verifiable outcome — typically 15 minutes to a few hours of work, ending in passing gates and a commit. Steps inside a task are guidance, not a script. Use checkbox (`- [ ]`) syntax on tasks for tracking.

- State WHAT must be true after the task and HOW to verify it; trust the executor on the keystrokes between.
- TDD remains the default discipline: acceptance criteria phrased as tests the executor writes first. Say which behaviors need test locks; don't write every test body in the plan.
- Exact file paths for created/modified files. Map the file structure before the tasks: one clear responsibility per file, split by responsibility rather than technical layer, following the codebase's existing patterns.
- DRY. YAGNI. Frequent commits.

## Plan Review Loop

After writing the complete plan:

1. For architecture-heavy plans, dispatch architecture-reviewer first with the design path and plan path. Fix blocking boundary, ownership, invariant, failure-mode, compatibility, or architecture-test issues before document review.
2. Dispatch a plan-document-reviewer subagent (see plan-document-reviewer-prompt.md) with precisely crafted review context — never your session history.
   - Provide: path to the plan document, path to spec document
3. If ❌ Issues Found: fix the issues, re-dispatch reviewer for the whole plan
4. If ✅ Approved: proceed to execution handoff

**Review loop guidance:**
- Same agent that wrote the plan fixes it (preserves context)
- If loop exceeds 3 iterations, surface to human for guidance
- Reviewers are advisory — explain disagreements if you believe feedback is incorrect

## Execution Handoff

After saving the plan:

**"Plan saved to `docs/plans/<filename>.md`. Ready to execute?"**

**If yes:**
- **REQUIRED SUB-SKILL:** Use superpowers:executing-plans skill to implement the plan

**If no / new session preferred:**
- User can start fresh session with: "Execute the plan in docs/plans/<filename>.md"

## Remember

- Decisions with their why, up top; mechanics at the bottom
- Exact file paths, exact gate commands with expected output
- Code in the plan only where the code is the decision
- Source-code references beat prose descriptions
- Every plan carries Residual Unknowns & Deviation Policy — no plan pretends the map is complete
- Reference relevant skills with @ syntax
