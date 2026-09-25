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

## Install

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
