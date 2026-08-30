---
name: simplify
description: Cut over-engineering, speculative structure, and needless defensiveness from the current branch or a given scope, then tighten names and comments. Use only when the user explicitly asks to simplify code or comments.
metadata:
  user-invocable-only: "true"
---
Cut over-engineering, needless defensiveness, and production code that exists only for tests from the current branch, or from the scope the user specifies. Names and comments come last, and only when the user asked or a name in scope is wrong.

## Order

1. Read the whole of every function in scope, its callers, and the tests that pin it. Scope is the branch diff unless the user named files; do not simplify untouched functions in the same file unless a cut forces it.
2. Cut dead guards, speculative structure, and test-only seams. Fix the tests they pinned.
3. Replace hand-rolled code with stdlib, platform, or an installed dependency, only where behavior and error mapping match.
4. Names and comments, if asked.
5. Run the tests for every public method, endpoint, or job you changed. Report.

## Behavior

Behavior is what the code does today for every input that has a defined response. That covers return values, side effects, status codes, exception classes and message shapes, response body keys and headers, enqueued job names and arguments, emails, and any log field an alert reads. Inputs that cannot reach the code are not behavior. Guards for them are what this skill deletes.

Unreachable means no runtime entry point can supply the input. Callers, jobs, retries, mailers, rake tasks, CLIs, webhooks, other packages, persisted rows you cannot see, and a second thread mutating the record after load all count as entry points. "No caller in this file" and "callers check first" are not proof. A race or a retry is an input.

Proof means you searched the whole repo for the constant or method, including string and `send` forms, across `app/`, `config/`, `lib/`, engines, packs, jobs, rake, `bin/`, initializers, and tests, opened every hit, and named them in the report. Treat old persisted data as an open entry point unless a migration and a deploy gate already rewrote it. If you did not open a hit, you did not search it.

When a test fails after a cut:

- If it pins accepted behavior (public return values, side effects, status codes, exception classes), revert the cut, not the test.
- If it only reached a deleted seam or a state you proved unreachable, replace it with one test through the public entry point, then delete it.
- If you did not touch it, or it was already red, stop and report. That failure is not proof the cut was wrong, and not a reason to delete the test.

## Word choice in code and comments

Comments are prose; names are search keys. Orwell's rules ("Politics and the English Language") apply to prose. Apply them to comments:

> Never use a long word where a short one will do.
>
> If it is possible to cut a word out, always cut it out.
>
> Never use the passive where you can use the active.
>
> Never use a foreign phrase, a scientific word, or a jargon word if you can think of an everyday English equivalent.

Agents and humans both find code by searching for its name. A name earns its keep by being unique in the repo and saying what the thing is.

### Names

1. **One word per concept, one concept per word.** Keep a vocabulary. If `sync` names "pulling remote changes," it cannot also name "flushing edits to disk;" rename one of them. Never alternate synonyms (`organization`, `customer`, `account`) for one thing.
2. **Exported and public names carry a domain word.** `createStripeClient`, not `create`; `diffUserObjects`, not `diff`. Two or three words is the norm. One-word public names collide with everything; a search for `run` or `handle` returns the whole repo.
3. **Locals can be short.** Inside one function, `user` and `i` are fine; nobody searches for them.
4. **Prefer the concrete word over the abstract one.** `pruneStaleSessions` over `reconcileSessions`. The fix for a vague Latinate verb is a specific verb plus the noun it acts on, not a bare Saxon verb.
5. **Do not shorten a name below uniqueness.** A compound name that reads as a specification (`lastObservedDiskContent`) is still a better search key than a generic one (`baseline`). Cut words only when the remaining name still searches to one concept.
6. **Do not rename shipped words.** Public APIs, job classes, metric names, cache keys, and terms the codebase already uses stay. A rename breaks the trail for every reader and every agent that follows it.

### Comments

A comment states, in plain English, the constraint the code cannot show. It explains why the non-obvious exists.

- Add a comment when the implementation is non-obvious.
- Add a doc comment when a function has complex behavior or side effects.
- Delete a comment that narrates change history from the conversation.
- Delete a comment that restates code whose behavior is self-evident.

## Code structure

1. **Inverted pyramid.** Within a file, lead with the exported or significant functions and push helpers below them. Do not reorder a file unless a cut requires it.
2. **Combine overlapping concepts.** Merge two types, functions, or constants only when every field and every caller of one is valid for the other and the names mean the same thing. Shared fields are not overlap. The fewer distinct concepts a reader must hold in their head, the better.
3. **Use shared code.** Common utilities (ex. file path parsing) may exist in the codebase already. Check for library or utility functions before inlining.
4. **Derivability.** Drop derived arguments and locals that are always recomputed from values in the same call. Example: an `isDirty` parameter that is always `editorContent !== baseline`. Do not drop persisted columns, cache keys, or memoized values that exist to avoid a query or a stale read.

## Overfitting

Code must stand on its own. If a change only makes sense to someone who watched it happen (this conversation, this PR), it is overfitted. Write for the reader who arrives with no history.

- If a name or comment needs the conversation to be understood, rewrite it against the codebase's own vocabulary.
- **No backwards compatibility with unshipped code.** Supporting an old signature, alias, or data shape that only existed earlier in the same branch is compatibility with something that was never deployed. Delete the old path and update its callers. This applies only when this branch introduced both shapes. If a deployed client, flag, or migration still needs the old one, that is a rollout, not leftovers.

## Over-engineering

Prefer a smaller concept count. Delete a concept when nothing needs it; otherwise merge or replace it. Over-design for rare cases makes everyday maintenance expensive, and it accumulates by stacking constraints to satisfy existing constraints.

### Reach for what exists

Before keeping custom code, look in this order:

1. Already in this codebase.
2. The standard library.
3. A native platform feature, such as CSS over JS or a built-in element over a library.
4. A dependency that is already installed.

Take the first hit only after showing the same return values and the same exception class and message shape on the inputs the current tests and callers use, blanks and already-parsed values included. If the replacement is looser, keep the custom code. Never add a dependency, a migration, or a new production file. A DB constraint is a rollout, not a simplify cut, and one that already exists is still not proof that old rows are clean.

### Speculative structure

Delete:

- An interface, base class, or protocol with one implementation, unless it is the API of a gem, app pack, HTTP client, process, or third-party SDK (error mapping counts). A second in-repo class is not a boundary.
- A factory or builder for one product.
- Config, options, or parameters that every caller sets to the same value.
- A wrapper whose public methods are all one-liners to a single object and that is not one of the boundaries above.
- A second implementation kept alive beside the new one (compat layers, dual paths, copies with one tweak), unless a still-live flag, migration, or deployed client selects it. Do one root-cause change and update the callers.
- Unused types, commented-out code, and unused parameters that are not part of a public contract, protocol, or parent signature.

### Defensiveness

Most defensive code guards against states that cannot happen. It hides the real contract and turns bugs into silent fallbacks, and every extra branch is one more thing the reader has to carry. Cut it:

- Nil/undefined checks on a binding that a runtime check in this function, after the last assignment, already rejected. A check in a caller does not cover a helper.
- A repeated check on the same already-narrowed value in the same function, such as `return if x.nil?` after `x = find!(...)`. Controller, model, job, and console are different entry points, not duplicates of each other.
- Empty `catch`/`rescue`, and catch-and-return-default, on a write, charge, enqueue, or response.
- Defaults for parameters every caller passes.
- Early returns for conditions every runtime entry point has ruled out, retries and concurrent writers included. `return if order.refunded?` before a charge is idempotency, not a dead return.

Every deleted guard needs the proof above. If you searched and cannot prove it, keep it and report it under `kept:`.

These are not defensiveness. Never delete them because another layer also checks:

- Authentication, authorization, tenancy scoping (`Current.account.users.find`, not `User.find`), strong params, CSRF, rate limits, idempotency, money, uniqueness, encryption, PII handling, audit logs.
- Best-effort side effects that log and continue (notify, cache, metrics), and record-and-rethrow.
- Fallbacks that are product behavior, such as a `rescue NotFound` that renders 404 or a missing asset that becomes `nil`.
- Language-mandated handling: Go `if err != nil`, Swift `guard let`, Rust `Result`, checked exceptions.
- Metric, log, trace, and instrumentation calls. Their subscribers register elsewhere. That is not evidence they are unused.
- Contracts outside this repo, such as OpenAPI/GraphQL fields, Sidekiq class names already in Redis, cache keys, webhook signatures, metric names, and log fields that dashboards scrape. "No in-repo reader" is not proof.

### Production code that exists only for tests

Never. Production code serves production. If a line exists so a test can reach, replace, or observe something, delete it and fix the test. Signs:

- A constructor or function parameter with one production value, such as an injected clock that is always `Time` in production, or a "strategy" with one real implementation.
- An interface, protocol, or base class created so a test can mock it.
- A public method, accessor, or `attr_reader` that only tests call.
- `if test?` / `ENV["RAILS_ENV"]` branches, test-only config keys, or flags that only the suite sets, in application code (environment config files are fine).
- Hooks, callbacks, or events emitted so a test can assert they fired.
- Indirection through a module-level variable or registry so a test can swap it out.
- Abstractions added under the cover of "making it testable."

A parameter is test-only only if every production construction uses the same default. Check `config/`, engines, packs, jobs, rake, `bin/`, and initializers, not just `app/` and the tests. If production passes a configured logger or HTTP client (retry, auth, tagging), that is wiring. Keep it. You may replace an injected logger with the process logger; you may not drop log calls.

Then test the behavior through the entry point a production caller already uses (HTTP action, job `perform`, public library method), not a new accessor and not a private method the suite used to reach. Stub time, randomness, and network with the test framework's tools. If code is still hard to test, that is a design problem in the code itself, or a case for a coarser test. It is not a reason to warp production code into a test fixture.

### Tests

Tests are in scope. Test code longer or more complex than the implementation it covers is over-engineering. Snapshot matrices, parametrized grids over one branch, mocks of mocks, and assertions on implementation details all qualify.

Keep one test for every production branch you kept, including each kept guard. Drop tests that only pin internals of a deleted seam, or that re-exercise the same branch with different dummy data. A replacement test must fail if you revert the production cut. Never weaken a type or delete a test to make a cut look legal.

### Keep

- Validation where untrusted data enters: user input, external APIs, files, data persisted by older versions.
- Error handling that prevents data loss or partial writes.
- Everything under "Not defensiveness."
- A type, flag, or path the producing PR or issue asked for by name. A TODO or speculative interface in the diff is not that, and the `/simplify` request itself is not that.

Given two equally short options, take the one that is correct on edge cases, including concurrency, retries, and partial deploys. The goal is less code, not a flimsier algorithm.

### Known ceilings

If a legal cut leaves a known limit (a global lock, an O(n²) scan, a naive heuristic), leave one comment naming the limit and the upgrade path. Never introduce a worse ceiling to shorten the diff.

## Output

Apply the changes, then report them. Diff first, words second.

One line per change, one tag per change. If several apply, pick the first in this order: `test-only:` > `guard:` > `yagni:` > `delete:`.

- `test-only:` production code that existed for the suite. Name the replacement test and the command you ran.
- `guard:` defensive check for a state that cannot happen. Name the runtime entry points you opened, not the type.
- `yagni:` abstraction with one implementation, config nobody sets, layer with one caller.
- `delete:` dead code, unreachable branch, second implementation. Name what covers the case now, or say nothing does and why that is fine.
- `stdlib:` / `native:` / `dep:` hand-rolled code the standard library, platform, or an installed dependency already ships. Name the function.
- `test:` test code cut or replaced.

Then `kept:` for every candidate you left in. These do not count against the prose cap, but a `kept:` line is not a substitute for finishing the search.

```
app/models/invoice.rb: guard: drop `return if user.nil?`. Opened: InvoicesController#show, ChargeJob#perform (both `User.find`).
app/services/expire_holds.rb: test-only: drop injected `clock:`. Replacement: spec/requests/holds_spec.rb (travel_to). Ran: bundle exec rspec spec/requests/holds_spec.rb
app/services/refund.rb: kept: `return if order.refunded?` because ChargeJob retries.
app/models/invoice.rb: kept: `rescue Stripe::CardError` unproven: opened app/ and jobs/, could not see rows before the 2024 migration.
net: -24 lines (prod), -12 lines (tests)
```

End with `net:` from `git diff --numstat` on the files you touched, prod and tests separately. A positive number is fine when the replacement is clearer. A negative number earned by deleting comments or a replacement test is a failed simplify. If there was nothing to cut, write `Lean already. Ship.` If the tests for a changed entry point did not run, say so. That is not a finished simplify.

Then at most three lines of prose, in the form `skipped: <X>, add when <Y>`, only for a known ceiling you left in production. It is not a backlog for cuts you did not make. No essays, no design notes. If the explanation is longer than the diff, cut the explanation.

## Before finishing

- Every deleted guard has a named, opened entry-point set.
- Every deleted seam has a replacement test through the public entry point, that test fails if you revert the cut, and it ran.
- No new dependency, migration, or production file. A new test file is fine if the entry point had no test.
- No leftover debug code. No renames or reorders unless the user asked for names.
