# Changelog

## Unreleased

## [0.2.21] - 2026-09-23

### Added

- Show a spinner and "Loading threads…" while bb loads the thread list, instead of an empty list. It appears only if loading takes longer than 200 ms, so fast loads do not flicker.
- The delete confirmation now names the thread and its project, and says how many child threads go with it, so a right-click delete in a busy list cannot be mistaken for another thread. The sidebar owns this dialog and deletes through bb's SDK instead of opening bb's generic "Delete thread?" prompt.

### Fixed

- A project icon that failed to load once, for example while bb's host was still starting, no longer stays hidden until the sidebar reloads. The sidebar retries with backoff, and the server reports a read failure as temporary instead of caching it as "no icon".

## [0.2.20] - 2026-09-21

### Added

- Show every child-thread status in expanded rows: Failed, Needs you, Unread, Working or Monitoring with duration, Planning, Workflow, Agent, Command, Goal, Draft, and Drafting, using the same vocabulary as thread cards.
- Keep every child that reports a status visible while its section is collapsed, not only running ones. The "Show running children" setting is now "Show children that need attention"; its saved value carries over.

### Improved

- Child-thread rows size the status column to its label, so short statuses and ages leave more room for the title in a narrow sidebar.
- Search results give the title priority over a long project name in a narrow sidebar.
- The dark needs-you child row has a stronger tint and a leading amber edge.

### Fixed

- Status colours follow bb's theme instead of the OS colour scheme, so a dark bb on a light OS (or the reverse) no longer shows low-contrast statuses or a light needs-you band.
- On touch screens, Failed, Unread, and idle ages stay visible beside the snooze and settle actions instead of being hidden behind them.
- A woken thread shows "Woke" beside its current status in cards and search results instead of replacing it.

## [0.2.19] - 2026-09-19

### Added

- Support configurable snooze shortcuts for this evening, tomorrow morning, and next week, using local calendar times.

### Improved

- Sort parent-thread choices by recent activity in a single list.

### Fixed

- After parking or snoozing the open thread, select the first Pinned thread, then the first Active thread, or open the new-thread page when both sections are empty.

## [0.2.18] - 2026-09-19

### Improved

- Show one branch-name line in thread hover cards, using the worktree icon for worktrees and the branch icon for plain checkouts, matching the thread card.
- Add Park thread at the bottom of the snooze icon's menu.
- Reuse the section status icons for thread context-menu actions and Park thread in the snooze menu.

### Fixed

- Pinning a thread clears Settled, Snoozed, and Parked states. Settling, snoozing, or parking a thread removes its pin.

## [0.2.17] - 2026-09-18

### Added

- Add small rounded icons to Pinned, Active, Inactive, Snoozed, Parked, and Settled section headers.

### Improved

- Move Parked directly below Snoozed, before Settled.

### Fixed

- After settling the open thread, select the first Pinned thread, then the first Active thread in its current sort order, or open the new-thread page when both sections are empty.

## [0.2.16] - 2026-09-18

### Added

- Add a Parked section for threads waiting on others, with Resume, Undo, waiting age, and protection from automatic cleanup.
- Add a searchable Parent submenu for assigning or removing a thread's parent.
- Add expandable subthreads to thread hover cards.
- Offer to close thread-owned ports when settling a thread.

### Improved

- Improve drag-and-drop thread reordering and keyboard accessibility.

### Fixed

- Preserve inbox order across remounts and respect disabled inactivity settings.

## [0.2.15] - 2026-09-16

### Added

- Add Undo actions after settling, un-settling, and waking a snoozed thread.

### Removed

- Remove thread multi-selection and bulk actions.
- Remove project icon lookup through `t3.json`.

### Improved

- Shorten the README feature documentation.

## [0.2.14] - 2026-09-15

### Improved

- Add a green glow, gentle checkmark tilt, and five sparkles to the settle button, with light and dark styling, keyboard focus, and reduced-motion support.
- Keep the settle button's hit area fixed so hovering near a corner does not cause flickering.
- Remove the settle tooltip while preserving its accessible label.

## [0.2.12] - 2026-09-12

### Fixed

- Keep snooze, settle, and restore actions visible on touch devices, with parked thread labels and snooze countdowns beside the restore button.
- Group the unpin button with card actions, or with the status and Woke label when parking actions are unavailable.
- Keep the status visible when focusing Unpin on cards without parking actions.

## [0.2.11] - 2026-09-11

### Added

- Show monitoring runtimes as "Monitoring" on thread cards when BB reports that state.
- Added compact hover cards to main, child, grandchild, snoozed, and settled threads, showing project, machine, branch, provider, model, and reasoning details.
- Show project icons in hover cards when available, with a folder icon as fallback.

### Improved

- Moved thread details from the provider icon tooltip to the thread row, with support for keyboard focus.

## [0.2.10] - 2026-09-10

### Added

- Kept running child and grandchild threads visible while their child sections are collapsed. A new setting controls the behavior and is enabled by default.

### Improved

- Released thread runtimes when work is settled and closed only terminal sessions without user input, while preserving terminals the user interacted with.

## [0.2.9] - 2026-09-09

### Added

- Added a search row to the project scope card. Opening the scope picker puts the caret in a filter field above the list, so a long project list is reachable by typing, with arrow keys and Enter to pick a match.

## [0.2.8] - 2026-09-08

### Added

- Rolled child thread state up into the parent card's child badge. The badge now carries a glyph and tint for the most urgent child or grandchild: failed, needs you, done, or working, and its tooltip lists the counts.
- Highlighted the active child or grandchild row in the sidebar tree, the same way the active parent card is highlighted.

### Fixed

- Let a parent card collapse while one of its children is the active thread. A collapsed list now keeps only the active child visible, the same way a collapsed shelf keeps its active thread, and the grandchild disclosure behaves the same way.

## [0.2.7] - 2026-09-06

### Added

- Showed how long a thread has been working next to its live status, such as "Working · 5m" or "Planning · 2h". The count starts when the sidebar first sees the thread busy, survives reloads, and resets after the thread stops or asks for input.
- Added a Project submenu to thread cards with project settings, rename, local path setup, and removal with typed confirmation.
- Added Copy thread link for project and personal threads.
- Added inline rename to child and grandchild thread menus.
- Added discovery of conventional root-level project icons.

### Fixed

- Avoided pull request lookups for pinned, running, pending, snoozed, and manually overridden threads during automatic cleanup.
- Added inline validation for automatic cleanup thresholds and snooze shortcuts, including a preview of the saved snooze menu.
- Fixed styling scope for project menus and dialogs, including padding, typography, and focus rings.

### Improved

- Updated the plugin description and source comments to reflect optional sort modes.
- Documented how closed and merged pull requests participate in automatic cleanup.

## [0.2.6] - 2026-09-05

### Fixed

- Bounded the browser cache to 500 lifecycle records and 100 expanded-thread IDs to prevent unbounded storage growth.
- Recovered from storage-quota errors by evicting sidebar caches one at a time, stopping as soon as the write succeeds to preserve remaining preferences.
- Preserved expansion recency across restarts so pruning removes the oldest entries.

Thanks to [@elianiva](https://github.com/elianiva) for identifying the storage issue and contributing the fix in [#1](https://github.com/yusuf8834/bb-sidebar/pull/1).

## [0.2.5] - 2026-09-05

### Added

- Added **Regenerate title** to thread context menus. Titles use only the last three accepted user-message texts, or fewer when available.
- Added a subtle spinner beside the title during generation, shared across cards, shelves, child rows, and search results, with reduced-motion support.

### Improved

- Used bb's configured inference model and fallback through a temporary hidden helper, with cleanup after generation and protection for manual title changes.
- Kept pending threads available instead of automatically settling them.
- Aligned the development CLI with Plugin SDK 0.4.47. Requires bb 0.42.0 or later and Plugin SDK 0.4.47 or later.

## [0.2.4] - 2026-08-30

### Added

- Added project removal to plugin settings with a compact two-step confirmation and server-side checks.
- Added archive actions to child and grandchild thread menus. Archived descendants no longer appear in badges, counts, or lists.
- Added CI checks for the SDK contract, tests, type checking, and production build.

### Improved

- Kept active child and grandchild threads visible when their surrounding shelves or lists are collapsed.
- Included matching child threads in search and made lifecycle, ordering, icon, and settings refreshes resilient to stale responses.
- Kept thread-card metadata in a stable reading order.

## [0.2.3] - 2026-08-26

### Added

- Added a collapsed grandchild level to the shared header and sidebar child-thread list, with per-child counts, disclosures, status styling, and thread navigation.

### Improved

- Kept parent badges scoped to direct children while exposing one nested level beneath each child.
- Matched child-title typography between the header menu and sidebar rows.

## [0.2.2] - 2026-08-26

### Added

- Added expandable child-thread badges to parent cards, including identity colors, direct-child counts, running and attention states, and persistent inline child lists.

### Improved

- Refreshed thread card styling and tightened child-row typography.
- Updated the README screenshots to show child threads in light and dark modes.

## [0.2.1] - 2026-08-25

### Fixed

- Prevented inactive, snoozed, and settled threads from briefly appearing under Active when returning from Settings or restarting bb.

## [0.2.0] - 2026-08-24

### Added

- Added a separate Pinned shelf above Active.
- Added an optional Inactive shelf for unpinned threads without recent activity, with a configurable hour threshold.
- Added automatic project icon detection and per-project image uploads.
- Added an empty state when no active threads remain.

### Improved

- Rebuilt the plugin settings page with related controls grouped into clear sections.
- Added a native file picker and current-icon preview to the project icon settings.
- Kept Pinned, Active, Inactive, Snoozed, and Settled expansion states across reloads.

### Fixed

- Kept the settings toggle thumb inside its track in both states.

## [0.1.3] - 2026-08-24

### Added

- Added an Active sort menu with Manual order, Recent activity, Date created, and Project options.
- Added project grouping with a faint outline around projects that contain multiple active threads.

### Improved

- Preserved saved manual order when viewing activity or creation-date sorts.
- Remembered the selected Active sort mode across reloads.
- Replaced the project-grouping icon with a simpler sort icon.

### Fixed

- Removed the focus outline that remained around the sort icon after choosing an option with the pointer.

## [0.1.2] - 2026-08-24

### Fixed

- Corrected the package and plugin identity to `bb-sidebar`, matching the repository and marketplace entry.
- Rebuilt frontend styles for the `bb-sidebar` scope so hover actions load correctly after installation.
- Removed the obsolete internal product name from source comments and release notes.

## [0.1.1] - 2026-08-24

### Added

- Added a collapsible Active section that remembers its state and keeps the open thread visible.
- Added project names to Snoozed rows, matching Settled rows.

### Improved

- Tightened spacing between the Snooze and Settle hover actions.
- Increased parked-row title contrast, muted project labels, and enlarged the separator dot.

### Fixed

- Hid the extra Snooze dropdown chevron without changing menu behavior.
- Fixed plugin stylesheet scoping after the BB Sidebar rename.

## [0.1.0] - 2026-08-23

- Initial public release.

[0.2.9]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yusuf8834/bb-sidebar/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/yusuf8834/bb-sidebar/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/yusuf8834/bb-sidebar/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/yusuf8834/bb-sidebar/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/yusuf8834/bb-sidebar/releases/tag/v0.1.0

[0.2.16]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.15...v0.2.16
[0.2.17]: https://github.com/yusuf8834/bb-sidebar/compare/v0.2.16...v0.2.17
