# autonomous coding sandbox

a devcontainer for running claude code, codex, and pi coding agent in autonomous mode.

based on anthropic's claude code devcontainer.

## requirements

- docker (or [orbstack](https://orbstack.dev/))
- devcontainer cli (`npm install -g @devcontainers/cli`)
- 1password cli (`brew install 1password-cli`) - optional, for secret injection

## quickstart

```bash
# install devc command globally
./devcontainer/install.sh self-install

# run in any project folder
devc <repo>
# or
cd <repo> && devc .
```

you're now in tmux with claude, codex, and pi ready to go, with permissions preconfigured.

to use with vscode, run `devc install <repo>` and choose "reopen in container" in the editor.

## features

### pre-installed tools

| tool | version | notes |
|------|---------|-------|
| node | 22.x | via official node image |
| ruby | 3.4.7 | via ruby-install, with bundler 2.7.2 |
| python | 3.14 | via uv |
| rust | stable | via rustup |
| claude code | latest | `claude` command |
| codex cli | latest | `codex` command |
| pi coding agent | latest | `pi` command |

### service discovery

connects to local docker containers via `host.docker.internal`:

| service | environment variable |
|---------|---------------------|
| postgresql | `PGHOST=host.docker.internal` |
| redis | `REDIS_URL=redis://host.docker.internal:6379` |
| meilisearch | `MEILISEARCH_URL=http://host.docker.internal:7700` |
| dolt | `DOLT_HOST=host.docker.internal` |
| minio | `MINIO_ENDPOINT=host.docker.internal:9000` |

### secret injection via 1password

secrets are fetched from 1password at container start using a service account token.

1. create a service account at [1password.com](https://my.1password.com) → Developer → Service Accounts
2. grant access to the vault containing your secrets (e.g., `dev-shared-with-robots`)
3. set the token in your shell profile:
   ```bash
   export DEVCONTAINER_OP_SERVICE_ACCOUNT_TOKEN="ops_..."
   ```

currently injected secrets:
- `CEREBRAS_API_KEY`
- `BUILDKITE_API_TOKEN`

### bind mounts from host

| host path | container path | notes |
|-----------|----------------|-------|
| `~/.claude` | `/home/dev/.claude` | claude code config, history, skills |
| `~/.codex` | `/home/dev/.codex` | codex cli config |
| `~/.pi` | `/home/dev/.pi` | pi agent config |
| `~/.gitconfig` | `/home/dev/.gitconfig` | git config (readonly) |

### ruby/bundler configuration

- bundler 2.7.2 installed automatically (matches typical Gemfile.lock)
- `BUNDLE_PATH=vendor/bundle` - gems installed to project directory
- `libmariadb-dev` included for mysql2 gem native extensions
- `/usr/local` is writable by the `dev` user

## commands

| command | description |
|---------|-------------|
| `devc <repo>` | install template, start container, attach tmux |
| `devc install <repo>` | install template only (for vscode) |
| `devc rebuild <repo>` | remove container, rebuild image, start fresh |
| `devc exec <repo> -- <cmd>` | run command in container |
| `devc self-install` | install devc to `~/.local/bin` |

## notes

- **overwrites `.devcontainer/`** on every run
- default shell is fish, zsh/bash available
- container user is `dev` with passwordless sudo
- command history persists across rebuilds via docker volume
- set `DEVC_TEMPLATE_DIR` to override template source location
