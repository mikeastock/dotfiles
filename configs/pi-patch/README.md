# Pi Ghostty/tmux image patch

This directory contains a local patch for Pi's bundled `@mariozechner/pi-tui` build.

## Files

- `apply-pi-ghostty-tmux-image-patch.sh` — applies the patch to a Pi install
- `pi-ghostty-tmux-image.patch` — patch for `terminal-image.js` and `components/image.js`
- `kitty-unicode-placeholder-diacritics.js` — Unicode placeholder table used by the patch

## What it fixes

This patch adjusts Pi's terminal image handling so kitty-style images work more reliably in Ghostty when Pi is running inside tmux.

## Usage

Apply to the latest Pi install:

```bash
configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh
```

Apply to a specific Pi install by Node version:

```bash
configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh 24.14.0
```

Apply to an explicit Pi package path:

```bash
configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh \
  ~/.local/share/mise/installs/node/24.14.0/lib/node_modules/@mariozechner/pi-coding-agent
```

## Behavior

- Creates a backup under `~/.config/tmux/pi-patches/backups/`
- Applies the patch if needed
- Exits cleanly if the patch is already applied
- Verifies the patched files after installation

## After applying

Restart any active Pi sessions so the patched TUI code is reloaded.
