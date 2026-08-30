---
name: simplify
description: Cut over-engineering, speculative structure, needless defensiveness, and test-only production code from the current branch or a given scope, then tighten names and comments. Use only when the user explicitly asks to simplify code or comments.
metadata:
  user-invocable-only: "true"
---
Scope is the branch diff unless the user names files. Touch nothing outside it unless a cut forces it.

## Order

1. Read every function in scope, its callers, and the tests that pin it.
2. Cut dead guards, speculative structure, and test-only seams. Fix the tests they pinned.
3. Replace hand-rolled code with stdlib, platform, or an installed dependency where behavior and error mapping match.
4. Names and comments, only if asked.
5. Run the tests for every public method, endpoint, or job you changed. Report.

## Behavior

Behavior is what the code does today for every input with a defined response: return values, side effects, status codes, exception classes and messages, response keys and headers, enqueued jobs, emails, log fields alerts read. Guards for inputs that cannot reach the code are not behavior; they are what this skill deletes.

An input is unreachable only when no runtime entry point can supply it: callers, jobs, retries, mailers, rake, CLI, webhooks, other packages, persisted rows you cannot see, a second thread mutating the record after load. "No caller in this file" and "callers check first" are not proof.

Proof: search the whole repo for the name, including string and `send` forms, across `app/`, `config/`, `lib/`, engines, packs, jobs, rake, `bin/`, initializers, tests. Open every hit. Name them in the report. Old persisted data is an open entry point unless a migration and a deploy gate rewrote it.

When a test fails after a cut:

- It pins accepted behavior: revert the cut.
- It only reached a deleted seam or a proven-unreachable state: replace it with one test through the public entry point, then delete it.
- You did not touch it, or it was already red: stop and report.

## Over-engineering

### Reach for what exists

In order: this codebase, the standard library, the platform (CSS over JS, a built-in element over a library), an installed dependency. Take a hit only if it matches return values, exception class, and message on the inputs current tests and callers use, blanks included. Never add a dependency, migration, or production file.

### Speculative structure

Delete:

- An interface or base class with one implementation, unless it is the API of a gem, pack, process, or third-party SDK. A second in-repo class is not a boundary.
- A factory for one product.
- Config or parameters every caller sets to the same value.
- A wrapper whose methods are one-liners to a single object and is not a boundary above.
- A second implementation beside the new one (compat layer, dual path, old signature or alias this branch replaced), unless a live flag, migration, or deployed client selects it.
- Unused types, commented-out code, and unused parameters not required by a public contract or parent signature.

### Defensiveness

Cut:

- Nil checks on a binding this function already rejected after its last assignment. A check in a caller does not cover a helper.
- A repeated check on the same narrowed value in the same function (`return if x.nil?` after `x = find!(...)`). Controller, model, job, and console are different entry points, not duplicates.
- Empty `catch`/`rescue`, or catch-and-return-default, on a write, charge, enqueue, or response.
- Defaults for parameters every caller passes.
- Early returns for conditions every entry point rules out, retries and concurrent writers included. `return if order.refunded?` before a charge is idempotency, not a dead return.

Every deleted guard needs the proof above. Cannot prove it: keep it, report it under `kept:`.

Never delete because another layer also checks:

- Authn, authz, tenancy scoping (`Current.account.users.find`, not `User.find`), strong params, CSRF, rate limits, idempotency, money, uniqueness, encryption, PII, audit logs.
- Validation where untrusted data enters: user input, external APIs, files, rows written by older versions.
- Error handling that prevents data loss or partial writes.
- Log-and-continue around best-effort side effects (notify, cache, metrics); record-and-rethrow.
- Fallbacks that are product behavior: `rescue NotFound` rendering 404, a missing asset becoming `nil`.
- Language-mandated handling: `if err != nil`, `guard let`, `Result`, checked exceptions.
- Metric, log, trace, and instrumentation calls. Subscribers register elsewhere.
- Contracts outside the repo: API fields, Sidekiq class names in Redis, cache keys, webhook signatures, metric names, log fields dashboards scrape.
- A type, flag, or path the producing PR or issue asked for by name.

Given two equally short options, take the one correct under concurrency, retries, and partial deploys.

### Production code that exists only for tests

If a line exists so a test can reach, replace, or observe something, delete it and fix the test:

- A parameter with one production value: an injected clock that is always `Time`, a "strategy" with one real implementation.
- An interface or base class that exists so a test can mock it.
- A public method or accessor only tests call.
- `if test?` / `ENV["RAILS_ENV"]` branches or test-only flags in application code. Environment config files are fine.
- Hooks or events emitted so a test can assert they fired.
- A module-level variable or registry so a test can swap it out.
- Abstractions added "to make it testable."

A parameter is test-only only if every production construction uses the default; check `config/`, engines, packs, jobs, rake, `bin/`, initializers. A configured logger or HTTP client (retry, auth, tagging) is wiring: keep it. You may replace an injected logger with the process logger, not drop log calls.

Test through the entry point a production caller uses (HTTP action, job `perform`, public method), stubbing time, randomness, and network with the framework's tools. Code still hard to test is a design problem or a case for a coarser test, not a reason to warp production code.

### Tests

Test code more complex than what it covers is over-engineering: snapshot matrices, parametrized grids over one branch, mocks of mocks, assertions on internals.

Keep one test per production branch you kept, including each kept guard. Drop tests that pin internals of a deleted seam or repeat a branch with different dummy data. A replacement test must fail if you revert the cut. Never weaken a type or delete a test to make a cut legal.

### Known ceilings

If a legal cut leaves a known limit (global lock, O(n²) scan, naive heuristic), one comment naming the limit and the upgrade path. Never introduce a worse ceiling to shorten the diff.

## Names, comments, structure

Names are search keys: unique in the repo, saying what the thing is.

- One word per concept, one concept per word. If `sync` means "pull remote changes" it cannot also mean "flush to disk." Never alternate synonyms (`organization`, `customer`, `account`) for one thing.
- Public names carry a domain word, two or three words total: `createStripeClient`, not `create`.
- Locals can be short: `user`, `i`.
- Concrete over abstract: `pruneStaleSessions`, not `reconcileSessions`. A specific verb plus its noun, not a bare short verb.
- Do not shorten below uniqueness. `lastObservedDiskContent` is a better key than `baseline`.
- Do not rename shipped words: public APIs, job classes, metric names, cache keys, terms the codebase already uses.
- Do not reorder a file unless a cut requires it.
- Merge two types or functions only when every field and caller of one is valid for the other and the names mean the same thing.
- Drop derived arguments and locals recomputed from values in the same call (an `isDirty` that is always `content !== baseline`). Not persisted columns, cache keys, or memoized values that avoid a query.

Comments state the constraint the code cannot show. Short words, active voice, no jargon. Add one when the implementation is non-obvious or a function has side effects. Delete one that narrates the conversation or restates the code.

If a name or comment needs this conversation to be understood, rewrite it in the codebase's vocabulary.

## Output

Diff first. One line per change, one tag per change; if several apply, the first of `test-only:` > `guard:` > `yagni:` > `delete:`.

- `test-only:` name the replacement test and the command you ran.
- `guard:` name the entry points you opened, not the type.
- `yagni:` one-implementation abstraction, unset config, one-caller layer.
- `delete:` dead code, unreachable branch, second implementation. Name what covers the case now.
- `stdlib:` / `native:` / `dep:` name the function that replaced the code.
- `test:` test code cut or replaced.
- `kept:` every candidate you left in, with the entry point that reaches it or what you could not see.

```
app/models/invoice.rb: guard: drop `return if user.nil?`. Opened: InvoicesController#show, ChargeJob#perform (both `User.find`).
app/services/expire_holds.rb: test-only: drop injected `clock:`. Replacement: spec/requests/holds_spec.rb (travel_to). Ran: bundle exec rspec spec/requests/holds_spec.rb
app/services/refund.rb: kept: `return if order.refunded?` because ChargeJob retries.
app/models/invoice.rb: kept: `rescue Stripe::CardError` unproven: opened app/ and jobs/, could not see rows before the 2024 migration.
net: -24 lines (prod), -12 lines (tests)
```

End with `net:` from `git diff --numstat`, prod and tests separately. Positive is fine when the replacement is clearer; negative earned by deleting comments or a replacement test is a failed simplify. Nothing to cut: `Lean already. Ship.` Tests did not run: say so.

Then at most three lines, `skipped: <X>, add when <Y>`, one per known ceiling left in production. If the explanation is longer than the diff, cut the explanation.
