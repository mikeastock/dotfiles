# Muse Code provider for BB

Runs [Muse Code](https://developer.meta.com/ai/products/muse-code/) — Meta's
terminal coding agent, powered by Muse Spark — as a first-class BB provider.
Threads on this provider get the same surfaces as a bundled one: streamed
timeline, tool rows, approvals, model picker, health, installation, and a
subscription usage meter.

## How it works

Muse ships an in-process protocol of its own: `muse serve` hosts sessions over
stdio and speaks the **Muse Session Protocol** (MSP) — a JSON-RPC command plane
(`session/start`, `turn/start`, `approval/decide`) plus a view stream of
notifications (`item/started`, `item/delta`, `turn/completed`,
`session/tokenUsage`). The plugin's bridge translates that stream into BB's
delta grammar, so BB's assembler mints every turn and item id and Muse's own
ids stay join keys.

Each thread gets its own `muse serve` child, so no thread can disturb another's
configuration, sandbox posture, or session state.

## Security posture, stated plainly

**This provider runs with Muse's own OS sandbox off, and with network access
allowed.** Both are defaults, both are settings, and the reasons are in
[Why Muse's OS sandbox defaults to off](#why-muses-os-sandbox-defaults-to-off)
and the section after it. What that means in practice:

- A shell command Muse runs is confined by nothing at the OS level. BB's
  permission modes and its approval flow are the enforcement surface. Under
  `full` — BB's documented approval bypass — that surface is deliberately empty.
- Sandboxed shell commands, if you turn the sandbox on, are allowed network by
  default rather than Muse's `proxy-only`, because `proxy-only` truncates the
  `bb` CLI's larger responses.
- Set **Muse's own OS sandbox** to `on` for OS-level containment. It costs you
  native toolchains: nothing that invokes Swift or Clang builds under it.

BB's injected tools reach Muse over a loopback socket on 127.0.0.1, bound to an
ephemeral port. One bridge process serves every thread, so that socket is a
boundary between them: each thread's MCP server holds a credential minted for
that thread and for the exact tools BB declared for it, and a call is answered
only where the presented secret, the stated thread, and the named tool all
belong to the same grant. Credentials are revoked when the thread is discarded
and replaced when its tool set changes. The tool is checked again against the
thread's live declaration before it runs.

Your own `~/.config/muse` is read, never written: the bridge builds a private
config directory per thread, symlinks your credentials and skills into it, and
adds only its own MCP server, so BB's tools never appear in your terminal
sessions.

| BB | Muse |
| --- | --- |
| `thread/start` / `resume` / `fork` | `session/start` / `session/resume` / `session/fork` |
| `turn/start`, `turn/steer` | `turn/start`, `turn/steer` (queued, applied at the turn boundary) |
| `thread/stop { interrupt }` | `turn/interrupt`, settled before the stop is answered |
| permission mode `full` | approval mode `allowAll`, Muse's sandbox off |
| permission mode `auto` (bb reviews) | approval mode `allowAll`, sandbox on |
| permission mode `accept-edits` (you review) | approval mode `onRequest` |
| approval prompts | `approval/requested` → `approval/decide` |
| user questions | `userInput/requested` → `answer` / `clarify` / `cancel` |
| `/compact` | `session/compact` |
| todo snapshots | `session/todoListChanged` → plan-steps rows |
| subagents | `subagent` items → delegation rows |
| bb's injected tools | an MCP server the bridge proxies back to bb |

## How it matches the first-party bridges

The bridge is built on the same two layers codex and Claude Code use. An
**attachment** is what bb owns — one per thread, durable while bb holds the
thread, carrying the provider session id, the construction inputs, and any
rebuild that is owed. A **runtime** is the live `muse serve` child and the
session loaded in it, replaced whenever the child dies, the execution options
change, or Muse refuses to carry on. One child per thread, as codex runs one
app-server per session, so no thread can disturb another's configuration.

Everything that follows from that is theirs too: a serial on every runtime so a
late callback cannot mutate the session that replaced it; deltas buffered until
`thread/identity` is announced; a turn that always settles, including a prompt
the provider handles without doing any work; `session/replaced` on every
rebuild; typed recovery hints for an expired login or a rate limit; and model
listing on a child of its own so a catalog read never disturbs a thread.

## Sessions, routes, and recovery

A Muse session's route belongs to the `muse serve` process that opened it, and
Muse cannot replay its own encrypted reasoning across a route change. Resume a
session on a second process and its next model call after a tool result fails
with `provider-private history is incompatible with the active route` — durably,
because the offending reasoning item stays in the session. Compaction does not
clear it.

This is where the bridge departs from codex, and it has to. Codex kills its
child on `thread/stop { release }` because resuming a rollout is clean; Muse's
resume is not, so a thread's child outlives ordinary release and is reclaimed
only on `thread/discard`, on bridge shutdown, or after a long idle.

When a rebuild is unavoidable anyway — the child died, bb restarted the bridge —
the session is resumed first, because a session that never produced opaque
reasoning resumes fine. If Muse then refuses the history, bb starts a fresh
session and reports `session/replaced` with `contextLost`: the UltraGoal,
findings, and every other durable record live on bb's side, so only the
in-session conversation is at risk.

## The prompt is never the thing that gets dropped

Muse reports a mid-turn failure as the turn's terminal, and the conditions above
are ones bb already knows how to clear. A bridge that only records such a failure
has thrown the user's prompt away — and because the rebuild is owed to the *next*
turn, whatever they type next lands on a brand-new session as the prompt. The
observed shape of that bug: a turn works for 28 seconds, fails on reasoning
replay, and the follow-up "?????" gets answered by a fresh session with "I didn't
catch that."

So the bridge owns the recovery:

- The prompt on the wire is recorded **before** `turn/start` goes out, because
  the terminal can arrive in the same read as the reply that names the turn.
- On a classified failure, or on a child that died mid-turn, bb rebuilds the
  session and resubmits that same prompt, once. A second failure is a real
  failure — a bridge that kept resubmitting would loop on the user's tokens.
- A rebuild that loses context re-delivers bb's session instructions, which rode
  the first turn of the session that was just discarded, and reads the discarded
  session back with `session/read` to carry a bounded transcript of what was
  already said into the replacement as `<session_handoff>`. The user's own words
  come from the view item's `displayText`, so the wrappers bb added do not make
  a second trip.

The rerun is deliberately narrow: it fires only where the rebuild *is* the fix.
An expired login is not cleared by a new session and a rate limit is not cleared
by anything but time, so those settle as failures and go to bb — the same split
codex keeps, which rebuilds for both and reruns neither.

## Working on this bridge without taking threads down with you

`bb plugin reload` builds a new host artifact and points bb at it. It does not
move **running** bridge workers onto it — each keeps serving its attached
threads from the artifact it started on, and a new one is spawned only when a
thread next attaches. So a fix does not reach a thread that is already running.

The tempting shortcut is to kill the workers. Do not. A `muse serve` child is
the live end of somebody's turn, and its own children — a build, a test run, an
`ssh` holding a remote job — go with it. Killed this way they are SIGKILLed
mid-command with no terminal, and anything that survives does so only by being
reparented to init. It has already cost a running GPU training job here, which
is why this section exists.

The safe shape:

- Ship the fix, reload, and let it reach threads as they attach. Threads already
  running keep the build they started on until they end on their own.
- Where one thread genuinely needs the new code now, stop that thread — `bb
  thread stop <id>` settles its turn and releases the runtime — and let it
  rebuild on the next message. One thread, chosen deliberately, with whoever
  owns it told first.
- To confirm what a worker is actually running, compare the artifact hash in its
  command line against `shasum -a 256 dist/host.js`. The artifact directory is
  named for that hash, so they match exactly when the worker is current.

## Selecting `allowAll` is only half a permission policy

Muse's approval mode governs the rules its grammar can match. A shell command
it cannot statically canonicalise — a `$(…)` substitution, a `${VAR}`, a
pipeline, a heredoc, a `for` loop — escalates to a human whatever the mode
says. Nearly every command an agent actually writes is one of those, so a
bridge that sets `allowAll` and then forwards what still arrives asks for
permission constantly while believing it asked for none.

bb's policy has two axes and the bridge reads both. `approvalReviewer` decides
who answers an ordinary call — `automatic` (bb's `auto`) and `full` are the
bridge, `user` (`accept-edits`) is the user. `permissionEscalation` decides
only what happens when the agent reaches past its permission scope, which is
what Muse marks with `protectedWrite` and `judgeEscalated`.

| bb policy | ordinary call | Muse flags an escalation |
| --- | --- | --- |
| `full` | bridge allows | bridge allows — no scope to leave, no reviewer |
| `auto` + escalation `ask` | bridge allows | the user |
| `auto` + escalation `deny` | bridge allows | bridge denies |
| `accept-edits` | the user | the user |

Every stage of a command the bridge answers is still answered, and the tool row
still lands on the timeline, so nothing is hidden — only the question bb had
already answered is.

## A steer lands at the next turn boundary, not in the running turn

MSP documents `turn/steer` as injecting input into the turn the caller names.
Muse's implementation queues it: the session records `inbox_item_queued`, the
running model call finishes on the instructions it already had, and the queued
input is drained at the turn terminal into the run that follows. The result
carries no disposition, so a client cannot tell an injected steer from a queued
one — the bridge sends the steer bb asked it to send and has nothing further to
report.

This matters more here than it would elsewhere, because Muse Spark's model calls
are long. Measured on this host, a steer waited between 33 seconds and 3 minutes
34 seconds before the model saw it, against a turn whose time to first token was
12.5 minutes.

Two things follow, and both have been mistaken for defects:

- **A stale-looking answer right after you steer is the previous prompt
  finishing.** It is not the steer being ignored. The tell is what happens next:
  a new turn opens immediately and starts the steered work.
- **Interrupting at that moment throws the steer away.** The run that was about
  to act on it is the one being cancelled, seconds after it started.

Where the redirection has to be immediate, stop the thread first and then send.
Nothing else cuts an in-flight model call short.

## A view that stops is not a turn that stopped

Muse's live view can die while the session keeps running. Its materialized
projection is marked `unavailable`, push delivery goes silent, and nothing more
arrives — including the turn's own `turn/completed`. Observed here as threads
reading as busy for two hours after Muse's session log recorded the turn
finished, on roughly one session in ten.

Nothing in bb rescues that. `system/provider-turn-watchdog` is decode-only —
bb core has no current producer — so a turn only ends when its bridge says so.

MSP hands a client two things for this, and the bridge now uses both.
`view/gap` brackets a dropped range, so the range is read back rather than
mourned in a warning. And `view/page` serves the view from the session's source
rather than from the projection, so it still answers when push does not — which
makes the recovery a read, not a guess.

The watchdog rests on Muse being noisy: a working turn reports every tool call,
every usage update, every scheduled retry. A turn open and silent for longer
than any of Muse's own silences — its model-call retry announces itself at 180
seconds — is paged. A healthy one returns an empty page and costs nothing; a
stalled one returns everything bb missed, up to and including the terminal.

Where the page cannot be served either, the turn is settled as a typed failure
and the session is owed a rebuild, because a thread that says it failed is
recoverable and a thread that says it is working is not.

Replay carries the fold, not the interaction: an approval Muse has since
resolved is not put back in front of you, and `item/delta` is never replayed by
`view/page`, so a recovered message arrives as one block rather than as it was
typed.

Two corollaries, both of which bit here before they were handled.

**bb will not resume a session Muse cannot show.** A resume of a session whose
projection has gone succeeds — and returns an empty `viewCursor`. Carry the
thread on it and every later turn runs unwatched: it executes, and no
`turn/started` or `turn/completed` ever comes back. So an empty cursor is read
as the refusal it is, the resume is abandoned for a fresh session, and the
conversation rides across as a transcript like any other rebuild.

**A quiet view is not a prompt that needed no work.** A turn that opens nothing
is how Muse answers a prompt it handles without working, and it is also exactly
what a turn running behind a dead view looks like. Settling the second as
completed is worse than hanging: the thread reports success for work that is
still going. So the view is paged before anything is fabricated — a session with
nothing to say returns an empty page, and one that has stopped talking does not.

## Every delta names its turn

bb's assembler mints the ids, and it hangs an `item.*Delta` on the turn the
delta names. A delta that names no turn has nothing to attach to and is dropped
on the floor — silently, because a bridge that streams nothing is
indistinguishable from a provider that says nothing until it is done.

`item/delta` is the one MSP notification that carries no `turnId` of its own:
it is ephemeral-sourced, addressed only by `itemId`. So the turn comes off the
item the delta appends to, recorded when that item opened. Without it, Muse's
live command output and its assistant prose both arrive only as the terminal
snapshot, and a turn that spends forty seconds in a model call and ten in a
`grep` reads, on screen, as forty-eight seconds of nothing followed by a
finished answer.

There is no reasoning stream to lose: Muse Spark commits its reasoning
encrypted, with empty `text` and no summary, so the model's own thinking time
is dead air the bridge cannot fill. What it can show — every tool row, every
byte of command output, every token of the reply — now arrives as it happens.

## Typed failures, so bb's own recovery works

bb core raises `turn.failed` carrying the turn's request id, its attempt number,
and the bridge's `errorInfo`; the `provider-retry` plugin reads the **category**
off that and asks core to re-dispatch the original turn on a schedule. Core owns
the queue and the re-attempt, so a bridge that reports only prose is a bridge
whose threads silently opt out of all of it.

This bridge therefore emits a typed `provider.error` before the boundary that
settles a failed turn, and on Muse's own mid-turn retries, and on a bridge-side
fault. MSP gives a failure an open `kind` and a human message and nothing else,
so the kind decides what it can — `stepLimit` is `max-turns`, `projectionError`
and friends are `internal` — and narrow message patterns decide the rest. An
`httpStatusCode` is reported only where the message names one as a status: a
three-digit run inside an id is not a status code, and inventing one would put
words in the provider's mouth.

One gap is Muse's, not bb's: MSP publishes no rate-limit window — there is no
notification for it and no field on a turn failure — so a rate-limited muse turn
is reported as `rate-limit` but carries no `provider.rateLimits` state. That is
enough for the overload backoff, which is purely time-based, and not enough for
a subscription-window wait, which needs a reset the provider has not told us.

## Why Muse's OS sandbox defaults to off

Muse's sandbox is all or nothing: `muse serve` offers `--disable-sandbox` and no
way to grant a path. It denies the Darwin per-user cache, and that alone means
no Swift or Clang compilation works under it — a two-line `swiftc` file fails
with `ModuleCache/…pcm: 'Operation not permitted'`. Swift macros cannot start
their plugin server, and `xcodebuild` loses its XPC services on top.

Codex ships a sandbox too, but a tuned one that grants the workspace and
`$TMPDIR`; Muse's cannot be tuned. Inside bb the enforcement surface is bb's own
permission modes and approval flow, so this plugin leaves the OS sandbox off and
offers it as a setting for work that needs no native toolchain.

## Why the network sandbox defaults to on

Muse sandboxes shell network access as `proxy-only` by default. Inside bb that
breaks the thing bb tells every agent to use: the `bb` CLI talks to bb's local
server over loopback HTTP, and under proxy-only the larger responses —
`bb thread log`, `bb thread show`, `bb thread tell` against a busy thread — die
with `fetch failed: other side closed` while small ones such as `bb status`
survive.

That failure mode is worse than it sounds. A `bb thread tell` that is cut on the
response leg has already been accepted by the server, so the agent sees a
failure, retries, and the target thread receives the same message several times.

BB threads therefore run with `--sandbox-network enabled`. The filesystem sandbox is
untouched, and the setting still offers `proxy-only` and `off`.

## bb's session instructions

bb tells every agent how to behave inside it — that the `bb` CLI is there, that
`bb thread` reads another thread, plus whatever the user's own plugins add — as
`options.instructions` on session construction. MSP has no system-prompt slot,
so the bridge delivers them on the session's first turn wrapped in
`<system_instructions>`, the way the Claude bridge does, and sets Muse's
`displayText` to the user's own prompt so the transcript still shows what they
typed.

Without this, `Continue from @thread:…` sends Muse hunting through its own
session store for a bb thread id. With it, the first command it runs is
`bb thread show`.

## Permission modes

bb states a permission policy, not a prompt budget. `full` is full access, so
Muse stops asking and its own sandbox stands down — the posture every provider
bb ships takes for that mode. `auto` names bb, not you, as the reviewer, so Muse
stops asking there too while keeping its sandbox. Only `accept-edits`, where you
are the reviewer, leaves Muse asking.

Two approvals are never shown, because they are the bridge asking permission to
be itself: Muse's sandbox gating the loopback connection to the tool proxy this
plugin started, and Muse gating a tool bb injected — which bb already governs on
its own side.

## One command, one question

No approval mode covers everything. Muse decomposes a shell command into argv
stages — `grep … | head; pg_isready; psql "${DB:-…}" -c 'select 1'` is eight —
and reviews every stage its grammar cannot resolve statically. A `${VAR}`
expansion, a substitution, or a heredoc is unresolvable by construction, so
those stages come back for a decision under `allowAll` too. That is Muse being
careful about the fragment it cannot read, not bb failing to pass on the policy.

What bb must not do is ask eight times. The approval subject is the whole
command line, which is what you are shown and what you answer, so the decision
is carried across every remaining stage of the same approval.

The chain is the part that has to be walked to the end. `approval/decide`
settles one stage, and its `terminal` flag reports the *approval*: while stages
remain it is false, Muse keeps holding the tool call, and it owes the next
requirement — over `approval/updated`, or in the `approval/listPending` fold.
The bridge reads both, because a client that answers the first stage and stops
leaves the turn parked with nothing on screen but an approval bb has already
resolved, and a parked turn is indistinguishable from a working one.

Every path out of an approval answers Muse. One it cannot read, cannot render,
or cannot put to you is refused and reported rather than dropped, and one whose
decision Muse offers no choice for interrupts the turn — because the failure
mode this replaces is silence.

## bb's own tools

Muse takes extra tools through MCP and `muse serve` has no per-session tool
channel, so the bridge gives each thread that carries injected tools a Muse host
of its own with a private config directory: the user's own settings and
credentials, plus one added MCP server. Muse spawns that server, the server
proxies every call back to the bridge over a token-guarded loopback socket, and
the bridge asks bb's runtime to run the tool. Your own
`~/.config/muse/settings.json` is never written to, and bb's tools never appear
in your terminal sessions.

Muse reads that configuration once, at host startup, and disables MCP for the
whole runtime if the audit fails — so a config directory belongs to its host for
as long as that host lives. It is keyed by the tools it was built for and never
rewritten underneath a running process; a thread whose injected tools change
gets a new host instead of an edited directory.

That is what puts `mcp__bb_bridge.*` — thread mentions, decisions, findings, and
whatever your other plugins register — in front of Muse.

## Install

```sh
curl -fsSL https://dev.meta.ai/install.sh | bash   # Muse Code itself
muse login                                         # or export META_API_KEY
bb plugin install github:<owner>/bb-plugin-provider-muse
```

The provider hides itself on machines where `muse` is not installed
(`experimental_visibility: "installed"`), and BB's installation surface can run
the installer for you.

## Settings

| Setting | Meaning |
| --- | --- |
| Rolling 5-hour token budget | Fallback denominator for the log-measured meter, used only until Muse reports the plan's own meters. |
| Plan label | How the subscription is labelled in usage surfaces. |
| Load workspace skills and rules | Starts sessions with the workspace trusted. |
| Muse's own OS sandbox | `off` by default — see below. |
| Sandbox network | `enabled` (default here), `proxy-only`, or `restricted`. See below. |

## Usage reporting

Muse Code 1.4 reports the plan's own meters over MSP. Every `muse serve` pushes
`usage/changed` the first time it sees a model response and whenever the
numbers move:

```json
{
  "window": { "usedPercent": 0, "windowDurationMins": 300, "resetsAtMs": 1791520983000 },
  "weekly": { "usedPercent": 40, "resetsAtMs": 1791763200000 },
  "tier": "27681631238169137",
  "observedAtMs": 1791502984748
}
```

The bridge keeps the newest reading from any thread's host — in memory and in
`subscription-usage.json` under the plugin's data directory, so a restarted
bridge still has it — and reports it to bb as two windows: the **5-hour limit**
and the **weekly limit**, with Meta's own percentages and reset times. Those
are what BB's usage surfaces (and plugins built on `system.usageLimits`, such as
Provider Usage) show for Muse.

A reading describes the last response a host received, never a live poll: a
fresh `muse serve` that has made no model call reports nothing, and there is no
request that reads the meters without spending quota. So the bridge never
probes. A reading that outlives its window is reported as unspent — the 5-hour
block with its reset unknown until the next request opens one, the weekly block
rolled forward to its next fixed boundary.

Before the first Muse turn on a machine, or on a Muse build older than 1.4, there
is no reading. The plugin then falls back to measuring the rolling window from
Muse's durable session logs
(`~/.local/share/muse/sessions/<date>/<session>/session.jsonl`), where every
model completion records verbatim provider counters, against the configured
token budget. Without a budget the account is shown with no meter rather than
an invented limit. When Muse's provider actually refuses a call for quota, the
durable record carries the plan's own `resets_at`, and that wins over the local
estimate.

## Development

```sh
npm install
npm run typecheck
bb plugin build
```

Upstream's vitest suites are not vendored in this fork; verify changes end to
end in a real bb thread against a signed-in `muse` binary.

`BB_MUSE_EXECUTABLE` points the bridge at a different `muse` binary;
`BB_PROVIDER_BRIDGE_RECORD_DIR` records both wire lanes for debugging.

## License

MIT
