# dotfiles

Personal dotfiles for macOS, with Ubuntu 24.x/Linuxbrew support for the shell, tmux, and agent-tooling setup.

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
make agents-clean            # clean agent build/install artifacts
make plugin-update           # update plugin submodules
```

### Canonical Pi install

```bash
pi-install
pi
```

- Canonical Pi tool: `npm:@earendil-works/pi-coding-agent@latest` in global mise config
- `pi-install` installs or updates Pi through mise, runs `make install-configs`, and applies `configs/pi-patch/` to the mise-managed package root
- `pi` is provided by mise after installation/reshim

### Notable custom skills

- `browser-harness` — Direct browser control via CDP for automation, scraping, testing, and interaction with web pages (connects to user's already-running Chrome)
- `layered-rails` — Rails layered architecture guidance (copied locally from `palkan/skills`, not managed as a plugin)
- `babysit-pr` — GitHub PR monitoring/babysitting workflow imported from `openai/codex` commit `7e569f1`
- `how` — architectural explanation and critique skill vendored from `poteto/how`
- `oracle` — @steipete/oracle CLI workflow for second-model reviews with selected repo context
- `swiss-design` — Swiss International Style design system vendored locally from `zeke/swiss-design-skill`

### Notable custom Pi extensions

- `openai-fast` — installed from `buildrtech/dotagents`; provides a `/fast` toggle that applies OpenAI `service_tier=priority` for configured models
- `pi-prompt-shelf` — local copy of `tanishqkancharla/pi-prompt-shelf`; shelves editor prompts per session with shortcuts and `/shelf`

## Structure

```text
dotfiles/
├── .config/                 # shell/editor/terminal configs
├── skills/                  # custom agent skills
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
- `tmux-mem-cpu-load` is optional; the tmux status bar falls back to `uptime`
- Install the configured fonts (`Fira Code` / `FiraCode Nerd Font`) if you want terminal rendering to match macOS
- If you prefer one package manager across macOS and Linux, install Homebrew/Linuxbrew and use `make dot-install`

## Notes

If having issues with VIM and paths in macOS:

```bash
sudo mv /etc/zshenv /etc/zprofile
```

See: http://stackoverflow.com/questions/13708719/vim-path-configuration-in-os-x
