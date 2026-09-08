# Pi Ghostty/tmux image patch

This directory contains a local patch for Pi's bundled `@earendil-works/pi-tui` build.

## Files

- `apply-pi-ghostty-tmux-image-patch.sh` — applies the patch to a Pi install
- `pi-ghostty-tmux-image.patch` — patch for `terminal-image.js` and `components/image.js`
- `kitty-unicode-placeholder-diacritics.js` — Unicode placeholder table used by the patch

## What it fixes

This patch adjusts Pi's terminal image handling so kitty-style images work more reliably in Ghostty when Pi is running inside tmux.

## Usage

Apply to the current managed Pi install under `~/.pi`:

```bash
pi-configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh
```

Apply to an explicit Pi package path:

```bash
pi-configs/pi-patch/apply-pi-ghostty-tmux-image-patch.sh \
  ~/.pi/agent/install/releases/0.85.1
```

## Behavior

- Creates a backup under `~/.config/tmux/pi-patches/backups/`
- Applies the patch if needed
- Exits cleanly if the patch is already applied
- Verifies the patched files after installation

## After applying

Restart any active Pi sessions so the patched TUI code is reloaded.
