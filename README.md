# dotfiles

Personal dotfiles for macOS and OrbStack Linux VMs, plus AI agent skills/extensions infrastructure migrated from `dotagents`.

## Quick Start (macOS)

```bash
git clone git@github.com:mikeastock/dotfiles.git ~/code/personal/dotfiles
cd ~/code/personal/dotfiles
./setup
```

## OrbStack VM Setup

For setting up a consistent dev environment in OrbStack Linux VMs:

```bash
cd ~/code/personal/dotfiles/orb-vm
./setup-orb-vm.sh ubuntu
```

See [orb-vm/README.md](orb-vm/README.md) for full documentation.

## Agent Skills / Extensions Tooling

This repo also contains reusable skills, prompt templates, and extensions for Amp, Claude Code, Codex CLI, and Pi Coding Agent.

### Requirements

- Python 3.11+
- Git

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

### Notable custom skills

- `layered-rails` — Rails layered architecture guidance (copied locally from `palkan/skills`, not managed as a plugin)
- `babysit-pr` — GitHub PR monitoring/babysitting workflow imported from `openai/codex` commit `7e569f1`

### Notable custom Pi extensions

- `web-access` — Exa-powered web search and content extraction tools for Pi
- `pi-memory-md` — Git-backed markdown memory for Pi with per-project indexes, memory tools, and slash commands

## Structure

```text
dotfiles/
├── .config/                 # shell/editor/terminal configs
├── orb-vm/                  # OrbStack VM setup
├── skills/                  # custom agent skills
├── pi-extensions/           # Pi extensions
├── pi-themes/               # Pi themes
├── prompts/                 # Pi prompt templates
├── plugins/                 # plugin submodules
├── scripts/build.py         # agent build/install system
├── tests/                   # agent tooling tests
└── Makefile                 # dotfiles + agent commands
```

## Notes

If having issues with VIM and paths in macOS:

```bash
sudo mv /etc/zshenv /etc/zprofile
```

See: http://stackoverflow.com/questions/13708719/vim-path-configuration-in-os-x
