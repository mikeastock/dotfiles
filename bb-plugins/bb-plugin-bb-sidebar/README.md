# BB Sidebar

A stable thread list for [bb](https://github.com/get-bb/bb). Threads stay where you put them while status, snooze, and settle actions remain close at hand.

![BB Sidebar in light mode](docs/screenshots/sidebar-light.jpeg)

![BB Sidebar in dark mode](docs/screenshots/sidebar-dark.jpeg)

![BB Sidebar empty state](docs/screenshots/sidebar-empty.jpeg)

## Features

- Manual ordering plus Recent activity, Date created, and Project sort modes
- Subtle project grouping for projects with multiple active threads
- Pinned, Active, Inactive, Snoozed, Parked, and Settled shelves
- Project filtering
- Automatic project icons with custom overrides
- Expandable child-thread indicators with running and attention states
- Live status, branch, pull request, and provider details
- Workspace port discovery, hover-card details, and optional browser links
- Configurable inactive-thread and automatic cleanup rules
- Native bb navigation, split, rename, archive, and delete flows
- Project submenu on thread cards for settings, rename, local paths, and removal
- Regenerate a thread title from its last three accepted user messages
- A **Channels** shelf for [Bot Teams](https://github.com/patleeman/bb-plugins/tree/main/packages/bb-plugin-bot-teams) channels (this fork)

## This fork

This copy lives in [mikeastock/dotfiles](https://github.com/mikeastock/dotfiles)
under `bb-plugins/bb-plugin-bb-sidebar/`, vendored from
[yusuf8834/bb-sidebar](https://github.com/yusuf8834/bb-sidebar) at v0.2.21
(`4fffb49`). bb loads it from that path:

```sh
cd bb-plugins/bb-plugin-bb-sidebar
npm ci
bb plugin install "$PWD" --yes
```

bb refuses to install over the upstream git install; `bb plugin uninstall
bb-sidebar` first. That keeps `~/.bb/plugins/bb-sidebar/data.db`, and the
plugin id stays `bb-sidebar`, so lifecycle rows, manual order, project icons,
and settings carry over. Stay on or ahead of the upstream version you last
ran: the database records each migration's statement hash, and bb refuses to
load a plugin whose migration list disagrees with it.

### Channels

bb shows one thread-list plugin at a time, so choosing this sidebar used to
mean giving up Bot Teams' channel list. With Bot Teams installed, a
**Channels** shelf sits above Pinned: one row per open channel, pinned
channels first, then the most recently updated. Rows show `#`, a pin, or a
"needs you" icon (with a count past one), a spinner while bots work, and an
unread dot. A row is a plain link to the channel's Bot Teams page, which bb
opens in place (Cmd/Ctrl-click opens a split); opening an unread channel marks
it read. Right-click for Open in split, Pin/Unpin, Mark as read/unread, and
Archive channel. Collapsed, the shelf still shows the channel on screen and any
channel that needs you. Renaming, deleting, members, search, and archived
channels stay on Bot Teams' Channels page.

How it reads them: a plugin frontend can only call its own backend, so this
plugin's server asks bb to call Bot Teams' `list` RPC
(`bb.sdk.plugins.callRpc`) and re-serves a narrowed snapshot as
`listChannels`; writes go through Bot Teams' `channelState` as
`setChannelState`. Bot Teams publishes changes on its own realtime channel,
which this plugin cannot hear, so the shelf re-reads when any thread changes
(bot work runs in threads), after its own writes, on reconnect, and every 10
seconds. Without Bot Teams, `listChannels` answers "unavailable" and the shelf
does not exist. The code is in `src/channels*.ts`, `src/useChannels.ts`, and
`src/ChannelsShelf.tsx`; `ThreadInbox.tsx` only mounts the shelf.

## Install (upstream)

```sh
bb plugin install git:https://github.com/yusuf8834/bb-sidebar.git
```

Then choose **BB Sidebar** under **Settings > Appearance > Sidebar**.

## Development

```sh
npm install
npm run build
bb plugin install path:. --yes
```

## Credits

This project includes code adapted from [bb-plugin-t3sidebar](https://github.com/SawyerHood/bb-plugin-t3sidebar). Its MIT copyright notice remains in [LICENSE](LICENSE).

The sidebar design and interactions are directly inspired by [T3 Code](https://github.com/pingdotgg/t3code), which is also released under the MIT License. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for details.

Park threads while waiting on someone else. Use **Park thread** in the context menu and **Resume** when ready. Parked threads have no timer and are excluded from automatic cleanup. Opening one leaves it parked; new thread activity brings it back to Active.

Use **Parent** in a thread's context menu to search threads in the same project, choose a parent, or select **None** to remove it. The current parent is checked; the thread itself and its descendants are excluded.
