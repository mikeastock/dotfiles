# bb-plugin-diffr

[diffr](https://github.com/devdotfast/whiteboard/tree/main/diffr)'s structural, AST-aware diffs in a bb thread's right panel.

diffr runs on the machine that holds the thread's workspace (through the plugin's `bb.host` entry), so it works for remote hosts too. Its NDJSON output is drawn with diffr's own fold model: unchanged stretches, test bodies, deleted bodies, and any other folds diffr's plugins collapse arrive collapsed, and each fold opens from its chevron.

## Requirements

`diffr` on the workspace's machine:

```bash
curl -fsSL https://install.dev.fast/diffr | sh
```

The plugin runs the `diffr binary` setting (default `diffr`) and falls back to `~/.local/bin/diffr`, where the install script puts it. diffr's own configuration (`diffr config`) applies, including its bundled plugins and pseudocode summaries, except that the plugin passes `--byte-limit` from its **Structural diff size limit** setting (default 262144 bytes; empty keeps diffr's limit). diffr's own 1 MB default lets one large JSON or data file take minutes to diff structurally; above the limit a file gets a plain line diff.

## How a diff reaches the panel

diffr's NDJSON carries each changed file's full text on both sides plus a capture name for every token, so a one-line change in a 5,000-line file is about 4 MB, and a modest branch can be tens of megabytes. Host RPC responses are capped at 8 MiB, so the host never returns the stream itself:

1. `diff` runs diffr, writes the NDJSON to the plugin's data directory on that machine, and returns the manifest plus each file's byte range and a summary (line counts, line-diff fallback, hidden by default, or the file's error).
2. The panel draws every file header from those summaries, then reads records with `read`, three at a time in manifest order, in gzip-compressed ranges of at most 4 MiB.
3. Records over 8 MiB, and files diffr hides (generated, vendored, deleted), wait for **Load diff**.

Runs are deleted after an hour, or once 10 newer runs exist. If a run has expired, run diffr again.

## Use

Open **Diffr** from the thread header button, the right panel's new-tab launcher, or the command palette ("Diffr: open structural diff").

- **Changes** — `diffr HEAD`: every uncommitted change.
- **Branch** — `diffr --merge-base <base>`: everything the branch would ship. The base is the environment's merge-base branch, then its base branch, then its default branch, each tried as given and on `origin`, then `origin/HEAD`.
- **Custom** — any revisions and paths, as `git diff` takes them (`main...HEAD -- src/`).

Changes and Branch compare against the working tree and include untracked files: the plugin copies the index to a temporary file, marks untracked files intent-to-add there, and points diffr at it with `GIT_INDEX_FILE`. The repository's real index is never touched.

The toolbar switches unified and split layouts, opens every fold, restores diffr's folds, and runs diffr again. The panel also runs again when the thread's agent finishes a turn. Click a file header to close it and a line number to select a line. Selecting a second line on the same side makes a range (shift-click also extends one); **Add to chat** appends `path:start-end` to the thread's composer.

On phones (bb's compact viewport, under 768px) the panel fills the screen: it stays unified, keeps each file name visible in its header, and confirms **Add to chat** with a toast because the composer is hidden behind it. On touch screens rows, chevrons, and toolbar controls grow to at least 24px.

Colours come from bb's active code theme, so the diff follows the user's palette and light/dark mode.

## Limits

- diffr gets 100 seconds per run. A run that takes longer is stopped with a message suggesting a lower size limit or Custom paths.
- Runs over 512 MB of NDJSON are refused.
- diffr exits with status 2 when some files fail (for example, a PDF that is not UTF-8). The panel still shows the run and each failed file's error.
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
