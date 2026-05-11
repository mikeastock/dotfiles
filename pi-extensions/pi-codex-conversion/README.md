# pi-codex-conversion

Codex-style tools for [Pi](https://github.com/badlogic/pi-mono).

> [!NOTE]
> Use the npm package for normal installs. Avoid `pi install git:...` unless you know you want the development checkout; see [Development checkout](#development-checkout).

GPT/Codex models are strongest when the tool surface looks like the Codex CLI they were trained around: shell commands and patch-based edits. This extension brings that workflow to Pi while keeping Pi's runtime, sessions, project context, skills, and UI.

The point is to give the model tools it already knows how to use well while delegating execution to Pi's native tool implementations wherever possible.

## Install

```bash
pi install npm:@howaboua/pi-codex-conversion
```

## Development checkout

The Git checkout is mostly for development and mirrors the maintainer workflow. If you run it directly, you may need to build the bundled `apply_patch` binary for your platform.

Run the current checkout without installing globally:

```bash
pi --no-extensions --no-skills -e /path/to/pi-codex-conversion
```

![Available tools](./available-tools.png)

## Active tools in adapter mode

When the adapter is active, the LLM sees these tools:

- `exec_command` — shell execution with Codex-style `cmd` parameters, delegated to Pi's native bash tool
- `apply_patch` — patch tool
- `web_search` — native OpenAI Codex Responses web search, enabled only on the `openai-codex` provider
- `image_generation` — native OpenAI Codex Responses image generation, enabled only on image-capable `openai-codex` models
- `view_image` — image-only wrapper around Pi's native image reading, enabled only for image-capable models

Notably:

- there is **no** dedicated `read`, `edit`, or `write` tool in adapter mode
- local text-file inspection should happen through `exec_command`
- file creation and edits should default to `apply_patch`
- Pi may still expose additional runtime tools such as `parallel`; the prompt is written to tolerate that instead of assuming a fixed four-tool universe

## What changes in Pi

- Adapter mode activates automatically for OpenAI `gpt*` and `codex*` models, then restores the previous tool set when you switch away.
- Pi's composed prompt is preserved; the extension only adds a small Codex-style tool-use nudge.
- Shell activity uses Pi's native bash execution and rendering.
- `apply_patch` renders as Codex-style `Added` / `Edited` / `Deleted` blocks, including inline partial-failure state.
- Native web search appears as a compact expandable summary after a turn, with queries and sources in the expanded view.
- Generated images are saved under `.pi/openai-codex-images/` at the workspace/repo root, with the latest image mirrored to `latest.png`.

## Details worth knowing

- `exec_command` maps Codex-style `{ "cmd": "..." }` input to Pi's native bash `{ "command": "..." }` execution.
- `apply_patch` accepts absolute paths as-is and resolves relative paths against the current working directory.
- Shell `apply_patch` is also available inside `exec_command`, but the dedicated `apply_patch` tool is preferred unless you are chaining edits with other shell steps.
- Native `web_search` and `image_generation` are forwarded to OpenAI Codex Responses tools rather than executed as local function tools.

## License

MIT
