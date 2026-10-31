# inbox-sidebar

Makes the **Archived** section of OpenCode Desktop's Inbox sidebar collapsible, like Working, and collapses it by
default. Everything else is OpenCode's own Inbox. Turn the Inbox on under **Settings > Preferences > Interface**.

Click the Archived header, or focus it and press Enter or Space, to expand or collapse it. The header shows how many
sessions it holds, and the choice is remembered across restarts.

## Limits

- **Desktop only.** OpenCode's web app does not load external GUI plugins.
- **Follows the app's markup.** OpenCode has no inbox API, so `src/gui.tsx` finds the section through the list's
  `data-slot` and `data-status` attributes. If an update changes them, Archived shows expanded as before; nothing else
  breaks.
- Desktop loads plugins from its own local server, so install this on the machine that runs Desktop.

## Develop

`make install DOTFILES=1` builds the bundle and links this directory to `~/.config/opencode/plugins/inbox-sidebar`.
`npm run dev` rebuilds on change, and each rebuild reloads the plugin in open windows. Disable it with
`"-inbox-sidebar"` in the global `opencode.jsonc` `plugins` list.
