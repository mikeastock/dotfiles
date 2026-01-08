# syntax=docker/dockerfile:1.7

# Based on Anthropic's Claude Code devcontainer template, with:
# - Codex CLI installed
# - Passwordless sudo for the non-root user
# - NO firewall / network restrictions (internet enabled)
# - tmux installed

ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE} AS node

ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG PI_VERSION=latest

# Build-time npm defaults.
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_PROGRESS=false \
    NPM_CONFIG_CACHE=/root/.npm \
    PATH="/usr/local/share/npm-global/bin:${PATH}"

RUN mkdir -p /usr/local/share/npm-global

# Install Claude Code + Codex CLI + Pi Coding Agent + pnpm in the node stage for faster rebuilds.
RUN --mount=type=cache,target=/root/.npm \
  npm install -g \
    "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    "@openai/codex@${CODEX_VERSION}" \
    "@mariozechner/pi-coding-agent@${PI_VERSION}" \
  && corepack enable --install-directory /usr/local/share/npm-global/bin \
  && corepack prepare pnpm@latest --activate

FROM ubuntu:25.10

ARG TZ
ENV TZ="${TZ}"

ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG PI_VERSION=latest

# Install common dev tools.
# Note: we intentionally do NOT install iptables/ipset or ship a firewall script.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    less \
    procps \
    sudo \
    zsh \
    fish \
    unzip \
    openssh-client \
    gh \
    jq \
    vim \
    tmux \
    ncurses-term \
    git \
    git-lfs \
    ripgrep \
    zoxide \
    fd-find \
    libmariadb-dev \
  && rm -rf /var/lib/apt/lists/*
RUN if command -v fdfind >/dev/null 2>&1 && [ ! -e /usr/local/bin/fd ]; then \
    ln -s /usr/bin/fdfind /usr/local/bin/fd; \
  fi

# Bring in node + npm from the official node image (fast, no apt deps).
COPY --from=node /usr/local/ /usr/local/
RUN node -v && npm -v

# Ensure git worktrees use relative paths by default.
RUN git config --system worktree.useRelativePaths true \
  && git config --system --add safe.directory /workspace

RUN if ! id -u "dev" >/dev/null 2>&1; then \
    useradd -m -s /usr/bin/fish "dev"; \
  fi

# Ensure dev user has access to the global npm prefix.
RUN mkdir -p /usr/local/share/npm-global \
  && chown -R "dev:dev" /usr/local/share

# Persist shell history across container rebuilds.
RUN mkdir -p /commandhistory \
  && touch /commandhistory/.bash_history /commandhistory/.zsh_history \
  && chown -R "dev:dev" /commandhistory \
  && cat >/etc/profile.d/00-commandhistory.sh <<'EOF'
# Persist interactive shell history in /commandhistory.
if [ -d /commandhistory ]; then
  export HISTSIZE=100000
  export HISTFILESIZE=200000

  if [ -n "${BASH_VERSION:-}" ]; then
    export HISTFILE=/commandhistory/.bash_history
    shopt -s histappend 2>/dev/null || true
    PROMPT_COMMAND="history -a; ${PROMPT_COMMAND:-}"
  fi

  if [ -n "${ZSH_VERSION:-}" ]; then
    export HISTFILE=/commandhistory/.zsh_history
    export SAVEHIST=200000
    setopt APPEND_HISTORY INC_APPEND_HISTORY SHARE_HISTORY HIST_IGNORE_ALL_DUPS HIST_REDUCE_BLANKS
  fi
fi
EOF

RUN echo '. /etc/profile.d/00-commandhistory.sh' >> /etc/bash.bashrc \
  && touch /etc/zsh/zshrc \
  && echo 'source /etc/profile.d/00-commandhistory.sh' >> /etc/zsh/zshrc

# Helpful marker for shell prompts / scripts.
ENV DEVCONTAINER=true

# Create workspace + agent config dirs and set permissions.
RUN mkdir -p /workspace /home/dev/.claude /home/dev/.codex /home/dev/.npm /home/dev/.config/fish /home/dev/.cache \
  && touch /home/dev/.zshrc \
  && chown -R dev:dev /workspace /home/dev/.claude /home/dev/.codex /home/dev/.npm /home/dev/.config /home/dev/.cache /home/dev/.zshrc

WORKDIR /workspace

# Install global packages.
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH="${PATH}:/usr/local/share/npm-global/bin"
ENV NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_PROGRESS=false

# Switch to non-root for normal dev.
USER dev

# Runtime npm cache should be writable by dev user.
ENV NPM_CONFIG_CACHE=/home/dev/.npm

# Default shell + editor.
ENV HOME=/home/dev
ENV XDG_CONFIG_HOME=/home/dev/.config
ENV SHELL=/usr/bin/fish
ENV EDITOR=vim
ENV VISUAL=vim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Ensure uv is on PATH for the dev user.
ENV PATH="/home/dev/.local/bin:${PATH}"

# Preinstall managed Python for uv.
RUN uv python install 3.14

# Install Ruby 3.4.7 via ruby-install.
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    bison \
    libssl-dev \
    libyaml-dev \
    libreadline-dev \
    zlib1g-dev \
    libncurses-dev \
    libffi-dev \
    libgdbm-dev \
    rustc \
  && rm -rf /var/lib/apt/lists/*

ARG RUBY_INSTALL_VERSION=0.9.4
RUN curl -fsSL "https://github.com/postmodern/ruby-install/releases/download/v${RUBY_INSTALL_VERSION}/ruby-install-${RUBY_INSTALL_VERSION}.tar.gz" \
    | tar -xz -C /tmp \
  && cd /tmp/ruby-install-${RUBY_INSTALL_VERSION} \
  && make install \
  && rm -rf /tmp/ruby-install-${RUBY_INSTALL_VERSION}

ARG RUBY_VERSION=3.4.7
RUN ruby-install --system ruby ${RUBY_VERSION} -- --disable-install-doc \
  && rm -rf /usr/local/src/ruby-${RUBY_VERSION}* \
  && ruby -v

# Allow dev user to install gems and other tools without sudo.
RUN chown -R dev:dev /usr/local

USER dev

# Passwordless sudo for the non-root user (for unattended / automation workflows).
USER root
RUN echo "dev ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/yolo \
  && chmod 0440 /etc/sudoers.d/yolo

USER dev
