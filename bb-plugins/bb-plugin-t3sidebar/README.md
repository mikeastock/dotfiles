# T3 Sidebar

An inbox-style replacement for bb's sidebar thread list, and the reference
example for `app.slots.experimental_threadList`.

This plugin started as an example in the BB repository. Install its public
release from GitHub:

```sh
bb plugin install git:https://github.com/SawyerHood/bb-plugin-t3sidebar.git@^0.1.0
```

Turn it on in **Settings → Appearance → Sidebar**. bb's own list stays the
default, and comes back the moment you switch away or disable this plugin.

The plugin replaces the scrolling list only. bb's New-thread button, search
field, plugin nav rows, and footer stay exactly where they are — this list
filters by the host's search and adds just one control of its own, a project
scope picker.

## The idea

The list never re-orders itself. Threads sort by creation time, newest first,
and hold that place until you park them. Status lives inside each card instead
of in its position, so the sidebar only moves when you act — no row slides
away under your cursor because an agent finished something.

Children nest under their parent, and a parent folds shut. Nesting is
structural, not a ranking: siblings still sort newest-first at every level, so
what moves a row is parentage, which does not change on its own.

Three shelves:

- **Inbox** — two-line cards: the title and one fixed-width status slot on the
  first line; the project, activity counts, the pull-request number and the
  agent glyph on the second. Pinned threads sit above. A row is ~48px against
  bb's own 28px, and against the ~77px this card used to take.

  The project had a line of its own above the title once. It repeats down the
  whole column and the scope picker above already implies it, so it was never
  worth a line — and reading it before the title had the hierarchy backwards.

  No branch and no machine either. bb derives a branch from the thread's own
  title, so the row's widest column restated the line directly above it in
  mono, and once truncated a screenful of them shared a prefix and differed
  only past the ellipsis. The machine is the same one for nearly every thread.
  Both spent that column on something that never told two rows apart; the
  pull-request number identifies the work when it matters.

  The second line has one leading slot, filled by whichever the row has, most
  specific first: a collapsed row's summary of what it hides, then a promoted
  child's parent, then the project.

  One slot, one marker, one width, so the whole column lines up. The slot
  shows the status glyph while a thread has something to say, and the age
  ("now", "7m") once it does not. The glyphs are bb's own: the red circle-x
  for a failure, the spinner for live work, and a blue notification dot for a
  thread that finished while you were not looking. Both lists sit in the same
  window, so they speak one language.

  **A thread waiting on you is the exception.** It takes an orange rail down
  the card's left edge and spends the slot on a pill saying how long it has
  been stuck — the one row allowed to break the fixed width, because it is the
  only row that cannot make progress without you. The rank matters more than
  the volume: before this, a raised hand drew a muted glyph that read _quieter_
  than the blue dot of a thread that had merely finished.

  Deliberately no background tint. Tint is how this list says "selected", and
  letting it also say "blocked" would make the two states cousins; the rail is
  a channel nothing else uses, so it survives selection rather than competing
  with it. The pill's clock reads `latestAttentionAt` — bb's own "newest thing
  you have not seen" — which for a thread that is asking is the moment it
  started asking.

- **Snoozed** — hidden until a wake time you chose. A snoozed thread comes
  back early if it starts working or asks you something.
- **Settled** — work you are done with, collapsed to one line each.

## Child threads nest, and fold away

Every thread is a row, children included, indented 14px per level under the
thread that spawned it. bb's own sidebar indents 24px; a card is far taller
than bb's 28px row and its title needs the width more.

A parent carries a chevron. Folding it shut hides its whole subtree — and the
row then spends its otherwise-empty third line saying what it is hiding: "2
threads", and "1 waiting" in orange if any descendant is blocked. Collapsing
must never be a way to lose a thread that wants something from you.

Which rows nest is decided per shelf, and a thread is a root here when it has
no parent **or when its parent is not in the list being folded** — deleted,
archived, filtered out by search, or sitting on another shelf. That promotion
is what makes nesting safe: a row can never be tucked inside a parent that is
not on screen to be expanded. A promoted child names its parent on the third
line, because that is the only thing explaining why it sits at the left edge;
a nested child does not, since the row directly above it already is the parent.

Parentage arrives from the server and nothing guarantees it is acyclic, so the
tree walk carries ancestor and visited guards, and anything a cycle keeps out
is appended as a root rather than dropped.

Collapse state lives in `localStorage`, per browser, the same choice bb makes
for its own sidebar (`bb.sidebar.collapsedThreads`). It is a per-screen
preference, not something to sync through the plugin's database the way
settled and snoozed are.

The snoozed and settled shelves stay flat. They are one-line rows for work you
have already dismissed, and a hierarchy there would be structure without a job.

Two chips in the thread header still carry the relation for whoever is reading
a thread rather than the list:

- On a parent: a chip with one coloured disc per child, saying whether any is
  waiting on you — useful when the sidebar is scrolled elsewhere or that
  subtree is folded shut.
- On a child: a chip that names the parent and opens it. The row nests under
  the parent but cannot open it — a second link inside the row would fight the
  full-bleed anchor.

The parent chip sits on the left of the children chip, so the header reads up
then down. A child that has children of its own shows both. Each disc takes
its colour from the thread id, so the same thread keeps one colour in the list
and in both chips.

An orphan — a child whose parent is deleted — gets a row at the left edge, and
its header shows no parent chip.

## What it demonstrates

| Plugin API                                         | Used for                                                                                    |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `experimental_threadList`                          | the sidebar's scrolling list (bb keeps the New-thread button, search, nav rows, and footer) |
| `experimental_threadHeaderAction`                  | the two header chips: children on a parent, and the way back on a child                     |
| `experimental_useSidebarThreads`                   | live threads and projects, from the host's own cache                                        |
| `experimental_useSidebarThreadActions`             | open, open-in-split, new thread                                                             |
| `experimental_useSidebarThreadSplit`               | dragging a card out to a split pane                                                         |
| `experimental_useSidebarThreadPullRequest`         | the `#412` badge, coloured by bb's attention state                                          |
| `@radix-ui/react-context-menu` (shimmed)           | this plugin's own right-click menu, built on the action hook                                |
| `bb.storage.database()` + `bb.rpc` + `bb.realtime` | the settled/snoozed store                                                                   |
| `bb.background.schedule` + `bb.settings`           | the `pr-merge-sweep` auto-settle tick and its two toggles                                   |
| `bb.sdk.environments.pullRequest`                  | per-environment PR state, routed to the right host by bb                                    |

The plugin API ships **no components**. Status glyphs and the right-click menu
are both this plugin's own: `indicator` arrives as data, and every menu item is
one call on `experimental_useSidebarThreadActions`. Choosing them is the point
of a replaced sidebar. Deletion still routes through `requestDelete`, so BB
shows its confirmation dialog rather than a plugin deleting a subtree silently.
The small icon and select components also live in this example. The example
does not import BB's private shared UI package.

## Where the lifecycle lives

Settled and snoozed state is in **this plugin's** SQLite database, never on
bb's thread. Putting it on the thread would mean a schema change, a wire
change, and a `HOST_DAEMON_PROTOCOL_VERSION` bump for a concept only this
sidebar understands. Uninstalling the plugin takes its state with it.

One rule matters more than the rest: **a thread that is working can never be
parked.** bb has more kinds of live work than a session status — workflows,
background agents, background commands, plan mode, goals — and every one of
them blocks parking and wakes a parked thread. Hiding running work is the one
failure this feature cannot afford. See `canPark` in `src/lifecycle.ts`.

## Auto-settle on merged PRs

A `*/10 * * * *` background schedule (`pr-merge-sweep`) parks threads whose
pull request has merged, so the inbox empties itself of finished work. The
sweep only writes the same lifecycle rows the right-click **Settle** writes,
through the same code path — every guard above applies to it unchanged, and a
settled thread that starts working or gains new attention comes straight back.

Each tick enumerates quiet threads (idle status, no pending interaction, all
five activity counters at zero, unpinned, visible), dedupes them by
environment, and calls bb's own `environments.pullRequest` once per
environment — bb routes the lookup to the right host, so multi-machine
workspaces need no extra machinery. Decisions follow one policy table:

| PR lookup result | Sweep action |
| --- | --- |
| `merged`, thread has no other open PRs | Settle the thread |
| `merged`, but sibling `bb/<slug>-<threadId>` PRs are still open | Nothing — one merged PR does not make a serial-PR thread terminal |
| `closed` (unmerged) | Settle only when the `settleClosed` setting is on (default off) |
| `open` / `draft` | Nothing |
| `absent` (branch has no PR) | Nothing; remember for a day before re-probing |
| `unavailable` (gh or host failure) | Nothing — a failed lookup is not information |
| open-PR verification fails | Nothing — never settle on uncertain evidence |

Three rules keep the sweep polite. Decisions key on **stable fields only**
(`state`, `mergedAt`) — never on volatile check or mergeability fields, which
churn and would re-fire on the same user-visible state. **One merged PR does
not make the thread terminal**: a thread can produce a series of PRs from one
environment, and bb names those branches `bb/<slug>-<threadId>`, so before
settling, the sweep lists the repo's open PRs and refuses to park a thread
that still has any in flight. And the overrule is **per PR, not per thread**:
a `pr_watch` table records `auto_settled_pr_url`, so if you pull a thread back
out of the settled shelf the sweep never re-settles it for that same PR — but
when its NEXT pull request merges, it may park the thread again.

Two settings control it, editable in Extensions → Plugins or via `bb plugin
config t3sidebar set <key> <value>`; both take effect on the next tick without
a reload:

- `autoSettle` (default on) — the master switch.
- `settleClosed` (default off) — also park threads whose PR closed unmerged.

One `bb.log.info` line per settle is the only explanation surface; the thread
simply settles and disappears from the inbox. The plan this implemented is in
`PLAN-auto-settle.md`.
