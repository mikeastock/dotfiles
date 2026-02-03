# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim

ARG GO_VERSION=1.25.1
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    tmux \
    jq \
    bash \
    procps \
    ripgrep \
  && rm -rf /var/lib/apt/lists/*

RUN arch="${TARGETARCH:-amd64}"; \
  case "$arch" in \
    amd64|arm64) ;; \
    *) arch="amd64" ;; \
  esac; \
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
  | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:${PATH}"

RUN npm install -g @openai/codex @mariozechner/pi-coding-agent

RUN useradd -m -s /bin/bash dev

USER dev
ENV HOME=/home/dev
WORKDIR /workspace
