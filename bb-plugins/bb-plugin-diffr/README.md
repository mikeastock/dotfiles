# bb-plugin-diffr

[diffr](https://github.com/devdotfast/whiteboard/tree/main/diffr)'s structural, AST-aware diffs in a bb thread's right panel.

diffr runs on the machine that holds the thread's workspace (through the plugin's `bb.host` entry), so it works for remote hosts too. Its NDJSON output is drawn with diffr's own fold model: unchanged stretches, test bodies, deleted bodies, and any other folds diffr's plugins collapse arrive collapsed, and each fold opens from its chevron.

## Requirements

`diffr` on the workspace's machine:

```bash
curl -fsSL https://install.dev.fast/diffr | sh
```

The plugin runs the `diffr binary` setting (default `diffr`) and falls back to `~/.local/bin/diffr`, where the install script puts it. diffr's own configuration (`diffr config`) applies, including its bundled plugins and pseudocode summaries.

## Use

Open **Diffr** from the thread header button, the right panel's new-tab launcher, or the command palette ("Diffr: open structural diff").

- **Changes** — `diffr HEAD`: every uncommitted change.
- **Branch** — `diffr --merge-base <base>`: everything the branch would ship. The base is the environment's merge-base branch, then its base branch, then its default branch, each tried as given and on `origin`, then `origin/HEAD`.
- **Custom** — any revisions and paths, as `git diff` takes them (`main...HEAD -- src/`).

Changes and Branch compare against the working tree and include untracked files: the plugin copies the index to a temporary file, marks untracked files intent-to-add there, and points diffr at it with `GIT_INDEX_FILE`. The repository's real index is never touched.

The toolbar switches unified and split layouts, opens every fold, restores diffr's folds, and runs diffr again. The panel also runs again when the thread's agent finishes a turn. Click a file header to close it, a line number to select a line, and shift-click to extend the selection; **Add … to chat** appends `path:start-end` to the thread's composer.

Colours come from bb's active code theme, so the diff follows the user's palette and light/dark mode.

## Limits

- Host RPC output is capped at 8 MiB, so the plugin refuses a diff whose NDJSON exceeds 6 MB. Narrow it with Custom paths.
- diffr's subcommands (`config`, `upgrade`, …) are refused in Custom; only revisions, paths, and diff options pass through.
- Fold state resets whenever diffr runs again, because fold ids belong to one run. Closed and loaded files are kept by path.

## Development

```bash
npm install
npm run typecheck
bb plugin build
bb plugin install "$PWD" --yes   # once
bb plugin reload diffr           # after server or host changes
```

## Attribution

`src/vendor/diffr/` is copied from diffr's `packages/viewer` at [`d739cec`](https://github.com/devdotfast/whiteboard/tree/d739cece163673ce4c01c8c3a6a0e8bcbd193ece/diffr/packages/viewer) (the protocol types, region flattening, and row builder), and `src/app/args.ts` from its Claude Code plugin. diffr is MIT licensed (`src/vendor/diffr/LICENSE`); its viewer derives from [hunk](https://github.com/modem-dev/hunk), also MIT (`src/vendor/diffr/LICENSE.hunk`).
