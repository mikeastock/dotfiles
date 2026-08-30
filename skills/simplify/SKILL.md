---
name: simplify
description: Simplify code and comments in the current branch or a given scope - cut over-engineering, speculative structure, and needless defensiveness; tighten names and comments. Use only when the user explicitly asks to simplify code or comments.
metadata:
  user-invocable-only: "true"
---
Review changes in the current branch, or in the scope the user specifies. Only touch code in that scope, and run the tests that cover the touched surface after changes. A failing test means a cut changed behavior: revert the cut, do not delete the test.

Behavior means the same return values, side effects, status codes, and exception classes for every input that currently has a defined response. Inputs that cannot reach the code are not behavior; guards for them are the target of this skill.

Read every caller and the tests that pin the path before the first cut. Be lazy about the solution, never about the reading.

## Word choice in code and comments

Variable names, function names, and comments are all prose. Apply Orwell's rules ("Politics and the English Language") to each:

> Never use a long word where a short one will do.
>
> If it is possible to cut a word out, always cut it out.
>
> Never use the passive where you can use the active.
>
> Never use a foreign phrase, a scientific word, or a jargon word if you can think of an everyday English equivalent.

Latinate vocabulary (reconcile, coalesce, normalize, reconciliation) sounds technical and abstract; Anglo-Saxon words (prune, run, watch, stop, drop, walk) are short and physical. Prefer the Saxon word.

### Names

1. **One word per concept, one concept per word.** Keep a vocabulary. If `sync` names "pulling remote changes," it cannot also name "flushing edits to disk;" rename one of them.
2. **Cut words the context already carries.** A module named `workspaceWatcher` does not need `startNativeWorkspaceWatcher`; `watchWorkspace` says the same thing.
3. **A compound name is usually a hedge:**

- ❌ `lastObservedDiskContent` is a specification to defend
- ✅ `baseline` is a readable description

### Comments

State, in plain English, the constraint the code cannot show: why the **non-obvious** exists.

- ✅ If code is complex and the implementation is non-obvious, add a comment.
- ✅ If a function contains complex behaviors or side effects, add a doc comment.
- 🗑️ If a comment narrates change history from the conversation, delete it.
- 🗑️ If a comment restates code whose behavior is self-evident, delete it.

## Code structure

1. **Inverted pyramid.** Within a file, lead with the exported or significant functions and push helpers below them. Don't bury the lead.
2. **Related concepts over monoliths.** Break a large file into modules that each own one concept.
3. **Combine overlapping concepts.** If two types, functions, or constants overlap significantly, merge them. The fewer distinct concepts a reader must hold in their head, the better.
4. **Use shared code.** Common utilities (ex. file path parsing) may exist in the codebase already. Check for library or utility functions before inlining.
5. **Derivability.** If a value can be computed from values already in scope, don't pass or store it separately. Removing derivable state often simplifies signatures, types, and control flow in one move. Example: an `isDirty` parameter that is always `editorContent !== baseline` can be dropped.

## Overfitting

Code must stand on its own. If a change only makes sense to someone who watched it happen (this conversation, this PR), it is overfitted. Write for the reader who arrives with no history.

- If a name or comment needs the conversation to be understood, rewrite it against the codebase's own vocabulary.
- **No backwards compatibility with unshipped code.** Supporting an old signature, alias, or data shape that only existed earlier in the same branch is compatibility with something that was never deployed. Delete the old path and update its callers. This applies only when both shapes were introduced in this branch; if a deployed client, flag, or migration still needs the old one, that is a rollout, not leftovers.

## Over-engineering

Prefer a smaller concept count. Delete a concept when nothing needs it; otherwise merge or replace it. Over-design for rare cases makes everyday maintenance expensive, and stacking constraints to satisfy existing constraints is how it accumulates.

### Reach for what exists

Before keeping custom code, look in this order and take the first hit that preserves the same behavior and error mapping:

1. Already in this codebase.
2. The standard library.
3. A native platform feature: CSS over JS, a DB constraint alongside (not instead of) the user-facing validation.
4. A dependency that is already installed.

Never add a dependency for what a few lines do.

### Speculative structure

Delete:

- An interface, base class, or protocol with one implementation, unless it marks a package or process boundary.
- A factory or builder for one product.
- Config, options, or parameters that every caller sets to the same value.
- A wrapper whose public methods are all one-liners to a single object and that is not an HTTP, package, or process boundary.
- A second implementation kept alive beside the new one: compat layers, dual paths, copies with one tweak. Do one root-cause change and update the callers.
- Unused types, unused parameters, commented-out code. Not feature flags or migration shims that a rollout still needs.

### Defensiveness

Most defensive code guards against states that cannot happen. It hides the real contract, doubles the branches a reader must hold, and turns bugs into silent fallbacks. Cut it:

- Nil/undefined checks on a value that a runtime check on the same path already rejected.
- Validation repeated at every layer for data that one entry point already validated. Validate once, where data enters.
- Empty `catch`/`rescue`, and catch-and-return-default on the critical path.
- Defaults for parameters every caller passes.
- Early returns for conditions every caller has already ruled out.
- Guards added because of another guard's edge case.

The proof: a guard is dead only when you have named every entry point (callers, jobs, CLI, mailers, webhooks, persisted rows, other packages) and shown none reaches it. A type annotation, YARD tag, schema, or comment is not a runtime guarantee; types are erased and rows outlive migrations. If you have not searched, keep it. If you searched and cannot prove it, keep it and report it under `kept:`.

Not defensiveness:

- Authentication, authorization, idempotency, money, and uniqueness checks. Never delete these because another layer also has one.
- Best-effort side effects that log and continue (notify, cache, metrics), and record-and-rethrow.
- Fallbacks that are product behavior: a `rescue NotFound` that renders 404, a missing asset that becomes `nil`. Fail loudly only where the current code already raises.
- Language-mandated handling: Go `if err != nil`, Swift `guard let`, Rust `Result`, checked exceptions.
- Observability: metrics, structured logs, traces, instrumentation events. Subscribers register at boot, not in the file you are reading.

### Production code that exists only for tests

Never. Production code serves production. If a line exists so a test can reach, replace, or observe something, delete it and fix the test. Signs:

- A constructor or function parameter that only tests pass: an injected clock, logger, HTTP client, or "strategy" with one real value.
- An interface, protocol, or base class created so a test can mock it.
- A public method, accessor, or `attr_reader` that only tests call.
- `if test?` / `ENV["RAILS_ENV"]` branches, test-only config keys, or flags that only the suite sets, in application code (environment config files are fine).
- Hooks, callbacks, or events emitted so a test can assert they fired.
- Indirection through a module-level variable or registry so a test can swap it out.
- Abstractions added under the cover of "making it testable."

Before calling something test-only, search the whole repo: initializers, subscribers, views, serializers, other packages. Then test the behavior through the public surface, stubbing time, randomness, and network with the test framework's tools. Replace the deleted seam's test with one test through the public surface, not a matrix. If code is still hard to test, that is a design problem in the code itself, or a case for a coarser test, not a reason to warp production code into a test fixture.

### Tests

Tests are in scope. Test code longer or more complex than the implementation it covers is over-engineering: snapshot matrices, parametrized grids over one branch, mocks of mocks, assertions on implementation details. Cut to the tests that pin the accepted behavior: main path plus the failure paths that matter.

Never drop an assertion that pins a guard you kept, and never weaken a type or delete a test to make a cut look legal.

### Keep

- Validation where untrusted data enters: user input, external APIs, files, data persisted by older versions.
- Error handling that prevents data loss or partial writes.
- Everything under "Not defensiveness" above.
- Anything the user asked for in the work that produced this code. The `/simplify` request itself is not that.

Two equally short options: take the one that is correct on edge cases, including concurrency, retries, and partial deploys. Less code, not a flimsier algorithm.

### Known ceilings

If a legal cut leaves a known limit (a global lock, an O(n²) scan, a naive heuristic), leave one comment naming the limit and the upgrade path. Never introduce a worse ceiling to shorten the diff.

## Output

Apply the changes, then report them. Diff first, words second.

One line per change: `path: <tag> <what>. <replacement>.`

Tags:

- `delete:` dead code, unreachable branch, speculative structure. Name what covers the case now, or say nothing does and why that is fine.
- `guard:` defensive check for a state that cannot happen. Name the runtime entry points you checked, not the type.
- `stdlib:` / `native:` / `dep:` hand-rolled code the standard library, platform, or an installed dependency already ships. Name the function.
- `yagni:` abstraction with one implementation, config nobody sets, layer with one caller.
- `test-only:` production code that existed for the suite. Name the test that now covers the behavior and the command you ran.
- `test:` test code cut or replaced.

Then `kept: path <guard> because <entry point>` for every candidate you left in because you could not prove it dead. These lines are not counted against the prose cap.

End with `net: <signed> lines (prod), <signed> lines (tests)`, from the git diff, excluding comments and whitespace. A positive number is fine when the replacement is clearer. If there was nothing to cut: `Lean already. Ship.` If the checks did not run, say so; that is not a finished simplify.

Then at most three lines of prose, in the form `skipped: <X>, add when <Y>` for anything deliberately left simpler than it could be. No essays, no design notes; if the explanation is longer than the diff, cut the explanation. A walkthrough the user explicitly asked for is not debt: give it in full.

Do not report rename-only work unless the user asked for names. When the real cuts are done, stop; do not pad the report with renames or reorders.

## Before finishing

- Every deleted guard has a named, searched entry-point set.
- Every deleted seam has a replacement test through the public surface, and the tests ran.
- No new dependency, no new file, no leftover debug code.
- Nothing was done just to make the report look complete.
