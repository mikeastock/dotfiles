---
name: brainstorming
description: "You MUST use this before any creative work - creating features, building components, adding functionality, or modifying behavior. Surfaces the unknowns between what was asked and what the territory requires, then turns the idea into an approved design."
metadata:
  category: superpowers
---

# Brainstorming: Finding the Unknowns, Then the Design

The map is not the territory. The prompt, context, and plan are a map; the codebase and its real constraints are the territory. The gap between them is **unknowns** — and the quality of the finished work is bottlenecked by how many unknowns get surfaced *before* they become expensive. This skill turns an idea into an approved design by hunting unknowns first, then designing.

<HARD-GATE>
Do NOT invoke any implementation skill, write any code, scaffold any project, or take any implementation action until you have presented a design and the user has approved it. This applies to EVERY project regardless of perceived simplicity.
</HARD-GATE>

## Anti-Pattern: "This Is Too Simple To Need A Design"

Every project goes through this process. A todo list, a single-function utility, a config change — all of them. "Simple" projects are where unexamined assumptions cause the most wasted work. The design can be short (a few sentences for truly simple projects), but you MUST present it and get approval.

## Checklist

You MUST complete these items in order:

1. **Explore project context** — check files, docs, recent commits
2. **Triage the unknowns** — classify where this problem's risk lives and pick the discovery moves to match (see Unknowns Triage)
3. **Run the discovery moves** — blindspot pass / interview / brainstorm & prototype / references, as triaged; one question at a time throughout
4. **Propose 2-3 approaches** — with trade-offs and your recommendation
5. **Present design section by section** — LEAD with the decisions most likely to change (data models, type interfaces, UX flows, semantics); bury mechanical work at the bottom. Get user approval after each section before continuing
6. **Architecture Checkpoint** — challenge ownership, boundaries, invariants, failure modes, compatibility paths, and tests before writing the design doc
7. **Write design doc** — save to `docs/design/YYYY-MM-DD-<topic>.md`, including a **Residual Unknowns & Deviation Policy** section, and commit
8. **Architecture review loop** — dispatch architecture-reviewer subagent with the design path and relevant code/docs; fix blocking issues and re-dispatch until approved (max 3 iterations, then surface to human)
9. **Spec review loop** — dispatch spec-document-reviewer subagent with precisely crafted review context (never your session history); fix issues and re-dispatch until approved (max 3 iterations, then surface to human)
10. **User reviews written spec** — ask user to review the design file before proceeding
11. **Transition to implementation** — invoke writing-plans skill to create implementation plan (it must carry the Residual Unknowns & Deviation Policy forward)

**The terminal state is invoking writing-plans.** Do NOT invoke frontend-design, mcp-builder, or any other implementation skill. The ONLY skill you invoke after brainstorming is writing-plans.

## Unknowns Triage

After exploring context, classify the problem before asking anything. Four buckets, each with a matching move:

| Bucket | Signal | Move |
|---|---|---|
| **Known knowns** | The user already told you, or the codebase already answers it | Don't re-ask. Confirm only if it conflicts with the territory. |
| **Known unknowns** | Open questions the user is aware of ("not sure how auth should work here") | **Interview** — one question at a time, prioritizing questions whose answer would change the architecture |
| **Unknown knowns** | The user will recognize what they want when they see it (visual design, UX feel, naming, "taste" calls) | **Brainstorm & prototype** — show cheap concrete options to react to |
| **Unknown unknowns** | Unfamiliar territory for the user or for you: new domain, new part of the codebase, no sense of what "good" looks like | **Blindspot pass** — surface what neither of you is considering, THEN interview |

Ask directly where the user thinks they sit: where are they in their thought process, what's their experience with this problem and this part of the codebase. Their starting point determines which moves are worth running. Most sessions need one or two moves, not all four.

## The Discovery Moves

**Blindspot pass** (unknown unknowns) — When the work enters territory the user (or you) doesn't know: enumerate the relevant unknown unknowns and explain them. What questions should they be asking? What does "good" look like here? What historical work exists in this codebase, and what potholes are known? Search the codebase and prior art; teach before asking. If the user says "blindspot pass," this is what they mean.

**Interview** (known unknowns) — Ask questions one at a time. Prioritize by blast radius: questions whose answers would change the architecture come first; cosmetic preferences last. Prefer multiple choice when possible; open-ended is fine too. Only one question per message — if a topic needs more exploration, break it into multiple questions. Focus on purpose, constraints, success criteria.

**Brainstorm & prototype** (unknown knowns) — When the user knows it when they see it, produce cheap concrete things to react to: several distinct design directions, an HTML mock of a screen with fake data, a throwaway spike of an API shape. Finding an unknown known during prototyping is cheap; finding it mid-implementation forces expensive reverts. For visual topics, offer the browser-based visual companion (see `visual-companion.md`) — as its own message, not combined with a clarifying question.

**References** (when words fail) — If the user struggles to articulate what they want, ask for a reference: a library that does it right, a design they like, a module in another language. Source code is the best reference — read the reference's actual implementation, not a description of it, and extract the semantics they want. Offer this move; users rarely think of it themselves.

## The Process

**Understanding the idea:**

- Check out the current project state first (files, docs, recent commits)
- Before asking detailed questions, assess scope: if the request describes multiple independent subsystems (e.g., "build a platform with chat, file storage, billing, and analytics"), flag this immediately. Don't spend questions refining details of a project that needs to be decomposed first.
- If the project is too large for a single spec, help the user decompose into sub-projects: what are the independent pieces, how do they relate, what order should they be built? Then brainstorm the first sub-project through the normal design flow. Each sub-project gets its own spec → plan → implementation cycle.
- For appropriately-scoped projects, run the triage and the moves it selects

**Exploring approaches:**

- Propose 2-3 different approaches with trade-offs
- Present options conversationally with your recommendation and reasoning
- Lead with your recommended option and explain why
- Claude often finds high-value approaches the user would have missed; surfacing them here prevents too-narrow scope. Watch equally for the opposite failure — scope creep past what the user actually needs.

**Presenting the design:**

- Once you believe you understand what you're building, present the design
- **Order sections by likelihood of change, not by execution order**: data models, type interfaces, UX flows, and semantic decisions first — that's where user reactions change the design. Mechanical refactoring and plumbing go last; the user trusts you on those.
- Scale each section to its complexity: a few sentences if straightforward, up to 200-300 words if nuanced
- Present one section at a time, not the whole design in one message
- Ask after each section whether it looks right so far, and wait for the user's response before continuing
- Cover: architecture, components, data flow, error handling, testing
- Be ready to go back and clarify if something doesn't make sense

## Architecture Checkpoint

Before writing the design doc, explicitly challenge the proposed design:

- **Ownership:** Which module owns each domain object, operation, and side effect?
- **Boundaries:** What is the smallest interface each unit exposes, and what does it depend on?
- **Invariants:** What must always be true before and after each operation?
- **Failure modes:** Which errors fail fast, which are recoverable, and where are they translated for users?
- **Compatibility:** Does the design introduce fallback paths, adapters, dual writes, or historical-state bridges? If so, remove them unless the user explicitly asked for compatibility.
- **Existing patterns:** Which local abstractions should be reused, and which old code should be deleted instead of wrapped?
- **Architecture tests:** Which tests prove the boundary, invariant, or orchestration decision rather than only exercising happy-path behavior?

If this review changes the design materially, present the revised section and get approval again before writing the design doc.

**Design for isolation and clarity:**

- Break the system into smaller units that each have one clear purpose, communicate through well-defined interfaces, and can be understood and tested independently
- For each unit, you should be able to answer: what does it do, how do you use it, and what does it depend on?
- Can someone understand what a unit does without reading its internals? Can you change the internals without breaking consumers? If not, the boundaries need work.
- Smaller, well-bounded units are also easier for you to work with - you reason better about code you can hold in context at once, and your edits are more reliable when files are focused. When a file grows large, that's often a signal that it's doing too much.

**Working in existing codebases:**

- Explore the current structure before proposing changes. Follow existing patterns.
- Where existing code has problems that affect the work (e.g., a file that's grown too large, unclear boundaries, tangled responsibilities), include targeted improvements as part of the design - the way a good developer improves code they're working in.
- Don't propose unrelated refactoring. Stay focused on what serves the current goal.

## After the Design

**Documentation:**

- Write the validated design to `docs/design/YYYY-MM-DD-<topic>.md`
- Include a **Residual Unknowns & Deviation Policy** section: the unknowns that survived discovery (things only implementation will reveal), and the standing instruction for the implementer — *when an edge case forces deviation from the plan, take the conservative option, log it under "Deviations" in an `implementation-notes.md` beside the work, and keep going.* Deviations get reviewed, not litigated mid-flight.
- Use elements-of-style:writing-clearly-and-concisely skill if available
- Commit the design document to git

**Spec Review Loop:**

After writing the spec document, first run an architecture review loop:

1. Dispatch architecture-reviewer subagent with precisely crafted context — never your session history.
   - Provide: design path, relevant existing code/docs, core decision points, and known constraints.
   - Ask it to review ownership, boundaries, invariants, failure modes, compatibility paths, existing-pattern fit, and architecture-level tests.
2. If Issues Found: fix the design, re-dispatch reviewer for the whole design.
3. If Approved: continue to document review.
4. If loop exceeds 3 iterations, surface to human for guidance.

Then run the document review loop:

1. Dispatch spec-document-reviewer subagent (see spec-document-reviewer-prompt.md)
2. If Issues Found: fix, re-dispatch, repeat until Approved
3. If loop exceeds 3 iterations, surface to human for guidance

**User Review Gate:**

After the spec review loop passes, ask the user to review the written spec before proceeding:

> "Design written and committed to `<path>`. Please review it and let me know if you want to make any changes before we start writing out the implementation plan."

Wait for the user's response. If they request changes, make them and re-run the spec review loop. Only proceed once the user approves.

**Implementation:**

- Invoke the writing-plans skill to create a detailed implementation plan. The plan MUST carry the Residual Unknowns & Deviation Policy forward so the implementing session keeps the `implementation-notes.md` deviations log.

## Key Principles

- **Unknowns before design** - The gap between map and territory is where work goes wrong; hunt it deliberately
- **One question at a time** - Don't overwhelm with multiple questions
- **Blast radius first** - Ask the questions that would change the architecture before the ones that change a label
- **Show, don't interrogate** - For taste calls, cheap prototypes beat twenty questions
- **References beat descriptions** - Source code is the highest-bandwidth way to say what you want
- **Multiple choice preferred** - Easier to answer than open-ended when possible
- **YAGNI ruthlessly** - Remove unnecessary features from all designs
- **Explore alternatives** - Always propose 2-3 approaches before settling
- **Incremental validation** - Present design in sections, validate each; volatile decisions first
- **Deviations are data** - Residual unknowns get a logged, conservative path through implementation, then a review
