# dotfiles

Personal dotfiles for macOS, Omarchy, and Ubuntu 24.x. Omarchy setup does not use Homebrew and leaves Omarchy-owned terminal/theme files alone.

## Quick Start

### macOS

```bash
git clone https://github.com/mikeastock/dotfiles.git ~/code/personal/dotfiles
cd ~/code/personal/dotfiles
make dot-all
```

### Omarchy

```bash
git clone https://github.com/mikeastock/dotfiles.git ~/code/personal/dotfiles
cd ~/code/personal/dotfiles
make dot-omarchy
```

`make dot-omarchy` claims home/config links around existing Omarchy files, installs `fish` and `atuin` with `omarchy pkg add`, switches the login shell to fish, and installs TPM. It leaves Ghostty, Alacritty, and Starship on Omarchy's copies, and removes `~/.config/tmux/tmux.conf` so `~/.tmux.conf` is the only tmux config. A post-update hook drops that XDG file again if `omarchy update` puts it back.

Do not run **Update → Config → Tmux** in the Omarchy menu. Log out once after the first install so the fish login shell applies. Then `make install` for agent skills.

### Ubuntu 24.x

Install Homebrew/Linuxbrew first, then:

```bash
git clone https://github.com/mikeastock/dotfiles.git ~/code/personal/dotfiles
cd ~/code/personal/dotfiles
make dot-all
```

`make dot-all` skips macOS-only defaults on Linux.

## Agent Skills / Extensions Tooling

This repo also contains reusable skills, prompt templates, and extensions for Amp, Claude Code, and Pi Coding Agent.

### Requirements

- Python 3.11+
- Git
- Homebrew or Linuxbrew for `make dot-install`

### Agent commands

```bash
make install                 # install agent skills/prompts/themes/extensions and Amp plugins
make install-skills
make install-amp-plugins
make install-prompts
make install-themes
make install-extensions
make install-configs
make build                   # build agent artifacts only
make clean                   # clean agent build/install artifacts
make plugin-update           # update plugin submodules
```

### Amp plugin development

Personal Amp plugins live in `amp-plugins/*.ts`. `make install-amp-plugins` copies them into `~/.config/amp/plugins/`. This repo also includes a local TypeScript declaration refresh so plugin files can import `PluginAPI` from `@ampcode/plugin` without publishing or installing a separate package.

```bash
make amp-plugin-types        # generate types/ampcode-plugin.d.ts from this Amp CLI
make amp-plugin-check        # refresh plugin types and run TypeScript
make install-amp-plugins     # copy amp-plugins/*.ts into ~/.config/amp/plugins/
```

After changing a plugin, rerun `make install-amp-plugins`, then run `plugins: reload` from Amp's command palette or restart Amp. See `amp-plugins/README.md` for the plugin development loop and example.

### bb plugin development

Forked bb plugins live in `bb-plugins/<plugin>/`, vendored as plain source so they can be modified in place. They are not part of `make install`; bb loads each one directly from its path in this repo.

```bash
cd bb-plugins/bb-plugin-t3sidebar
npm install
bb plugin install "$PWD" --yes    # register with bb (once)
npx bb plugin dev                 # watch sources, hot-reload the frontend
```

A plugin's bb id is its `package.json` name with the `bb-plugin-` prefix stripped, and its data lives in `~/.bb/plugins/<id>/`, so renaming the package orphans that data. Backend changes (`src/server.ts`) need `npm run build && bb plugin reload <id>`. Each plugin keeps `upstream` pointing at the repo it was forked from; sync by diffing against that remote.

### Amp config

Amp settings live in `amp-configs/settings.json`. `make install-configs` merges those managed settings into `~/.config/amp/settings.json` while preserving any other local Amp settings already present.

### OpenCode config

OpenCode config lives in `configs/opencode/opencode.jsonc`. `make install-configs` overlays the managed RunInfra provider, default model, and small model onto `~/.config/opencode/opencode.jsonc` (or `opencode.json` if that file already exists) while preserving any other local providers. A locally hardcoded `provider.runinfra.options.apiKey` is kept; the tracked file uses `{env:RUNINFRA_GATEWAY_KEY}` so the secret is not in git.

### Managed install behavior

`make install` preserves manually installed skills, Amp plugins, Pi extensions, prompts, and themes that live beside dotfiles-managed artifacts. The installer tracks top-level managed names in `~/.local/state/dotfiles/agent-install-manifest.json`, overwrites those managed artifacts on each install, and removes managed artifacts that are no longer built. If a built artifact conflicts with an existing unmanaged path, the install fails; rerun the underlying build script with `--force` only when you want dotfiles to claim that path.

Plugin skills can be restricted to explicit user invocation with `skills_user_invocable_only` in `plugins.toml`. Custom skills use `metadata.user-invocable-only: true` in `SKILL.md`. The build emits `disable-model-invocation: true` for Claude and Pi, plus `policy.allow_implicit_invocation: false` in `agents/openai.yaml` for Codex. The Codex metadata is included in the Pi/shared build because Codex also scans `~/.agents/skills`.

### Canonical Pi install

```bash
pi-install
pi
```

- Canonical Pi tool: `npm:@earendil-works/pi-coding-agent@latest` in global mise config
- `pi-install` installs or updates Pi through mise, runs `make install-configs`, and applies `pi-configs/pi-patch/` to the mise-managed package root
- `pi` is provided by mise after installation/reshim

### Notable custom skills

- `babysit-pr` — GitHub PR monitoring/babysitting workflow imported from `openai/codex` commit `7e569f1`
- `editorial-sketches` — editorial article illustration skill vendored from `helloianneo/ian-xiaohei-illustrations` commit `91b5608`
- `technical-explainer-comic` — evidence-backed technical comic workflow with editorial panels, expandable traces, responsive HTML, browser QA, and static publication
- `fable-review` — trusted Claude Fable code review workflow using `claude -p --model claude-fable-5-1`
- `grok-review` — safe Grok Build review workflow delegating branch and explicit dirty-tree reviews to Grok's native `/review` skill
- `grok-driver` — headless Grok as implementation driver for frozen work orders, with the host agent as coordinator (complement of `grok-review`)
- `writing-mike-ruby-style` — Mike's personal Ruby/Rails style (mirrors his canonical style rules)
- `prepare-branch-context` — read-only branch diff, commit, and PR context gathering skill vendored from `jnsahaj/skills`
- `simplify` — code and comment simplification skill vendored from `bholmesdev/skills`, extended to cut over-engineering and needless defensiveness (explicit invocation only)
- `unslop` — AI-writing cleanup and human-voice editing skill vendored from `cursor/plugins` commit `99559f2` (explicit invocation only)
- `zmx` — guidance for managing persistent background terminal work
- `skill-doctor` — grade installed skills from real local sessions, then draft skill edits and a report; adapted from `warpdotdev/common-skills` with the collector rewritten on a bundled Letta trajectory pipeline (each run builds its own throwaway data root: `scripts/ingest.sh` pnpm-installs `@letta-ai/trajectory` with a bundled grok-build patch and normalizes recent sessions from every local agent into it) (explicit invocation only)
- `tmux` — remote control tmux sessions through the active server, with an agent-neutral fallback socket when no server is running
- `buildr-artifacts` — publish browser-viewable Buildr artifacts as static S3-hosted HTML/assets or stateful Vite apps served from Codexbox with `bld.run` URLs
- `socratic-quiz` — guided Socratic questioning for deep understanding, vendored from `pchalasani/claude-code-tools` commit `29ae733`
- `eli5` — dead-simple HTML picture explainer for any topic, vendored from `anthropics/claude-plugins-community` (`eli5@claude-community`) commit `863e70d`
- `bro` — restate the last message in plain human language, vendored from `dmmulroy/skills` commit `cbd1929` (explicit invocation only)
- `product-description` — outside-in, feature-by-feature behavior spec of a product from its code and tests, vendored from `steveruizok` gist `83ae5c53` revision `f9435a3`

### Notable plugin skills

- `shaping`, `breadboarding`, and `breadboard-reflection` — explicit-only product shaping and breadboard workflows from `rjs/shaping-skills`
- `prototype`, `grill-with-docs`, `teach`, and `writing-great-skills` — workflow and teaching skills from `mattpocock/skills`
- `improve` — codebase audit and self-contained implementation planning skill from `shadcn/improve`
- `impeccable` — frontend design, critique, polish, and live iteration skill from `pbakaus/impeccable`
- `thermo-nuclear-code-review` — strict structural and architectural code review skill from `intercom/2x-skills`
- `effect` — opinionated production Effect v4 guide from `kitlangton/skills`, pinned as a plugin submodule at commit `30dee860`
- `better-github-skill` — agent-optimized `gh` workflows (PR snapshot, review threads, CI failures) from `AVGVSTVS96/better-github-skill`
- `show-me` — concise visual explanations (diagrams, code-shape sketches, HTML artifacts) from `humanlayer/skills`

### Notable custom Pi prompt templates

- `/bdev-qa` - run Buildr `bdev qa`, diagnose failures, and optionally post results to a PR
- `/commit` - create a focused Conventional Commit from task-related changes
- `/merge-main` - merge the latest base branch into the current branch with conflict and verification guardrails
- `/open-pr` - push the current branch and open a PR with summary and verification
- `/pr-comments` - fetch PR review comments and evaluate them before changing code
- `/review-loop` - run a parent-orchestrated adversarial review loop

### Notable custom Pi extensions

- `handoff` and `session-query` — vendored from `buildrtech/dotagents` commit `a484ad4`
- `openai-fast` — mirrors `calesennett/pi-codex-fast`; `/codex-fast` toggles priority service-tier requests for supported OpenAI Codex models, shows an inline `⚡` beside the model without adding a status line, and stores state under `pi-codex-fast.enabled` in Pi settings
- `pi-prompt-shelf` — local copy of `tanishqkancharla/pi-prompt-shelf`; shelves editor prompts per session with shortcuts and `/shelf`
- `pi-codex-conversion` — local copy of `IgorWarzocha/pi-codex-conversion`; adds Codex-style tools and prompt adaptation for OpenAI/Codex models in Pi
- `full-read-for-paths` — upgrades partial `read` calls to full reads for configured resource-file paths
- `revdiff` — adds `/revdiff` to launch the revdiff TUI and send captured annotations back to Pi

## Structure

```text
dotfiles/
├── .config/                 # shell/editor/terminal configs
├── skills/                  # custom agent skills
├── amp-configs/             # managed Amp settings
├── configs/                 # managed agent configs (Codex, OpenCode, Grok)
├── amp-plugins/             # custom Amp plugins
├── pi-extensions/           # Pi extensions
├── pi-themes/               # Pi themes
├── prompts/                 # Pi prompt templates
├── plugins/                 # plugin submodules
├── bb-plugins/              # forked bb plugins
├── scripts/build.py         # agent build/install system
├── tests/                   # agent tooling tests
└── Makefile                 # dotfiles + agent commands
```

## Ubuntu notes

Recommended apt packages before or after `make dot-all`:

```bash
sudo apt update
sudo apt install -y fish tmux ripgrep fd-find xclip wl-clipboard xsel fonts-firacode
```

- Linux clipboard integration in tmux uses the first available tool from: `wl-copy`, `xclip`, `xsel`
- Herdr config is symlinked to `~/.config/herdr/config.toml` and uses tmux-like `Ctrl-a` prefix bindings
- `tmux-mem-cpu-load` is optional; the tmux status bar falls back to `uptime`
- Install the configured fonts (`Fira Code` / `FiraCode Nerd Font`) if you want terminal rendering to match macOS
- If you prefer one package manager across macOS and Linux, install Homebrew/Linuxbrew and use `make dot-install`

## Omarchy notes

- Hyprland config lives in `.config/hypr` and is claimed by `make dot-omarchy`
- Ghostty, Alacritty, and Starship stay on Omarchy so theme switches keep working
- tmux is only `~/.tmux.conf`; the installer removes `~/.config/tmux/tmux.conf` and installs `configs/omarchy/hooks/post-update.d/drop-omarchy-tmux.hook`
- Existing Omarchy files that get replaced are copied to `~/.config/dotfiles-setup-backup-<timestamp>`

## Notes

If having issues with VIM and paths in macOS:

```bash
sudo mv /etc/zshenv /etc/zprofile
```

See: http://stackoverflow.com/questions/13708719/vim-path-configuration-in-os-x
