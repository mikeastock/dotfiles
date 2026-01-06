# Autonomous Coding Sandbox

A devcontainer for running Claude Code, Codex, and Pi Coding Agent in autonomous mode.

Based on Anthropic's Claude Code devcontainer.

## Requirements

- Docker (or [OrbStack](https://orbstack.dev/))
- devcontainer CLI (`npm install -g @devcontainers/cli`)
- 1Password CLI (`brew install 1password-cli`) - optional, for secret injection

## Quickstart

```bash
# Install devc command globally
./devcontainer/install.sh self-install

# Run in any project folder
devc <repo>
# or
cd <repo> && devc .
```

You're now in tmux with Claude, Codex, and Pi ready to go, with permissions preconfigured.

To use with VS Code, run `devc install <repo>` and choose "Reopen in Container" in the editor.

## Features

### Pre-installed Tools

| Tool | Version | Notes |
|------|---------|-------|
| Node | 22.x | Via official Node image |
| Ruby | 3.4.7 | Via ruby-install, with Bundler 2.7.2 |
| Python | 3.14 | Via uv |
| Rust | stable | Via rustup |
| Claude Code | latest | `claude` command |
| Codex CLI | latest | `codex` command |
| Pi Coding Agent | latest | `pi` command |

### Service Discovery

Connects to local Docker containers via `host.docker.internal`:

| Service | Environment Variable |
|---------|---------------------|
| PostgreSQL | `PGHOST=host.docker.internal` |
| Redis | `REDIS_URL=redis://host.docker.internal:6379` |
| Meilisearch | `MEILISEARCH_URL=http://host.docker.internal:7700` |
| Dolt | `DOLT_HOST=host.docker.internal` |
| MinIO | `MINIO_ENDPOINT=host.docker.internal:9000` |

### Secret Injection via 1Password

Secrets are fetched from 1Password at container start using a service account token.

1. Create a service account at [1password.com](https://my.1password.com) → Developer → Service Accounts
2. Grant access to the vault containing your secrets (e.g., `dev-shared-with-robots`)
3. Set the token in your shell profile:
   ```bash
   export DEVCONTAINER_OP_SERVICE_ACCOUNT_TOKEN="ops_..."
   ```

Currently injected secrets:
- `CEREBRAS_API_KEY`
- `BUILDKITE_API_TOKEN`

### Bind Mounts from Host

| Host Path | Container Path | Notes |
|-----------|----------------|-------|
| `~/.claude` | `/home/dev/.claude` | Claude Code config, history, skills |
| `~/.codex` | `/home/dev/.codex` | Codex CLI config |
| `~/.pi` | `/home/dev/.pi` | Pi agent config |
| `~/.gitconfig` | `/home/dev/.gitconfig` | Git config (readonly) |

### Ruby/Bundler Configuration

- Bundler 2.7.2 installed automatically (matches typical Gemfile.lock)
- `BUNDLE_PATH=vendor/bundle` - gems installed to project directory
- `libmariadb-dev` included for mysql2 gem native extensions
- `/usr/local` is writable by the `dev` user

## Commands

| Command | Description |
|---------|-------------|
| `devc <repo>` | Install template, start container, attach tmux |
| `devc install <repo>` | Install template only (for VS Code) |
| `devc rebuild <repo>` | Remove container, rebuild image, start fresh |
| `devc exec <repo> -- <cmd>` | Run command in container |
| `devc self-install` | Install devc to `~/.local/bin` |

## Notes

- **Overwrites `.devcontainer/`** on every run
- Default shell is Fish, Zsh/Bash available
- Container user is `dev` with passwordless sudo
- Command history persists across rebuilds via Docker volume
- Set `DEVC_TEMPLATE_DIR` to override template source location
