# dotfiles

Personal dotfiles for macOS and OrbStack Linux VMs.

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

## Structure

```
dotfiles/
├── .config/
│   ├── fish/           # Fish shell config
│   ├── nvim/           # Neovim config
│   ├── atuin/          # Shell history
│   ├── starship.toml   # Prompt
│   └── ...
├── .gitconfig          # Git config
├── .tmux.conf          # Tmux config
├── orb-vm/             # OrbStack VM setup
│   ├── setup-orb-vm.sh # Setup script
│   └── AGENTS.md       # Documentation
├── Brewfile            # Homebrew packages
└── setup               # macOS setup script
```

## Notes

If having issues with VIM and paths in macOS:

```bash
sudo mv /etc/zshenv /etc/zprofile
```

See: http://stackoverflow.com/questions/13708719/vim-path-configuration-in-os-x
