# dotfiles

Personal dotfiles for macOS, with Ubuntu 24.x/Linuxbrew support for the shell, tmux, Herdr, and agent-tooling setup.

## Quick Start

### macOS

```bash
git clone https://github.com/mikeastock/dotfiles.git ~/code/personal/dotfiles
cd ~/code/personal/dotfiles
make dot-all
```

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
make install                 # install agent skills/prompts/themes/extensions
make install-skills
make install-prompts
make install-themes
make install-extensions
make install-configs
make build                   # build agent artifacts only
make clean                   # clean agent build/install artifacts
make plugin-update           # update plugin submodules
```

### Managed install behavior

`make install` preserves manually installed skills, Pi extensions, prompts, subagents, and themes that live beside dotfiles-managed artifacts. The installer tracks top-level managed names in `~/.local/state/dotfiles/agent-install-manifest.json`, overwrites those managed artifacts on each install, and removes managed artifacts that are no longer built. If a built artifact conflicts with an existing unmanaged path, the install fails; rerun the underlying build script with `--force` only when you want dotfiles to claim that path.

### Canonical Pi install

```bash
pi-install
pi
```

- Canonical Pi tool: `npm:@earendil-works/pi-coding-agent@latest` in global mise config
- `pi-install` installs or updates Pi through mise, runs `make install-configs`, and applies `configs/pi-patch/` to the mise-managed package root
- `pi` is provided by mise after installation/reshim

### Notable custom skills

- `brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `semantic-commit`, `requesting-code-review`, `receiving-code-review`, `dispatching-parallel-agents`, and `fetch-ci-build` — vendored superpower skills from `buildrtech/dotagents`, installed for all supported coding agents
- `browser-harness` — Direct browser control via CDP for automation, scraping, testing, and interaction with web pages (connects to user's already-running Chrome)
- `layered-rails` — Rails layered architecture guidance (copied locally from `palkan/skills`, not managed as a plugin)
- `babysit-pr` — GitHub PR monitoring/babysitting workflow imported from `openai/codex` commit `7e569f1`
- `how` — architectural explanation and critique skill vendored from `poteto/how`
- `editorial-sketches` — editorial article illustration skill vendored from `helloianneo/ian-xiaohei-illustrations` commit `91b5608`
- `oracle` — @steipete/oracle CLI workflow for second-model reviews with selected repo context
- `session-learning-miner` — mine Pi session history for repeated prompts, friction, reusable workflows, and skill/template candidates
- `zmx` — Pi-only guidance for managing persistent background terminal work
- `buildr-artifacts` — publish browser-viewable Buildr artifacts as static S3-hosted HTML/assets or stateful Vite apps served from Codexbox with `bld.run` URLs

### Notable plugin skills

- `improve` — codebase audit and self-contained implementation planning skill from `shadcn/improve`
- `impeccable` — frontend design, critique, polish, and live iteration skill from `pbakaus/impeccable`

### Notable custom Pi prompt templates

- `/bdev-qa` - run Buildr `bdev qa`, diagnose failures, and optionally post results to a PR
- `/commit` - create a focused Conventional Commit from task-related changes
- `/merge-main` - merge the latest base branch into the current branch with conflict and verification guardrails
- `/open-pr` - push the current branch and open a PR with summary and verification
- `/pr-comments` - fetch PR review comments and evaluate them before changing code
- `/review-loop` - run a parent-orchestrated adversarial review loop

### Notable custom Pi subagents

- `architecture-reviewer` — reviews designs and plans for ownership, boundaries, invariants, failure modes, compatibility paths, and architecture-level tests before implementation

### Notable custom Pi extensions

- `buildr-artifacts` — installed from `buildrtech/dotagents`; provides `share_artifact` and `/share_artifact` for publishing local HTML artifacts to Buildr artifact storage
- `openai-fast` — installed from `buildrtech/dotagents`; provides a `/fast` toggle that applies OpenAI `service_tier=priority` for configured models
- `pi-prompt-shelf` — local copy of `tanishqkancharla/pi-prompt-shelf`; shelves editor prompts per session with shortcuts and `/shelf`
- `pi-codex-conversion` — local copy of `IgorWarzocha/pi-codex-conversion`; adds Codex-style tools and prompt adaptation for OpenAI/Codex models in Pi
- `full-read-for-paths` — upgrades partial `read` calls to full reads for configured resource-file paths
- `revdiff` — adds `/revdiff` to launch the revdiff TUI and send captured annotations back to Pi
- `mac-system-theme` — syncs Pi to macOS dark/light appearance locally, or to a remote override pushed with `pi-theme-push`/`pi-theme-watch` for SSH/mosh/tmux sessions

## Structure

```text
dotfiles/
├── .config/                 # shell/editor/terminal configs
├── skills/                  # custom agent skills
├── subagents/               # custom Pi subagents
├── pi-extensions/           # Pi extensions
├── pi-themes/               # Pi themes
├── prompts/                 # Pi prompt templates
├── plugins/                 # plugin submodules
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

### Remote Pi theme sync from macOS

When Pi runs on an Ubuntu server through SSH/mosh/tmux, the server cannot query macOS appearance directly. From the Mac, install `dark-notify` and run:

```bash
brew install cormacrelf/tap/dark-notify
pi-theme-watch user@server
```

`pi-theme-watch` pushes dark/light changes over SSH to `~/.pi/agent/theme-sync-override.json`; the `mac-system-theme` Pi extension reads that file and applies the matching Catppuccin theme.

## Notes

If having issues with VIM and paths in macOS:

```bash
sudo mv /etc/zshenv /etc/zprofile
```

See: http://stackoverflow.com/questions/13708719/vim-path-configuration-in-os-x
