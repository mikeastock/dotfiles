# Agent Status Multi-Arch Build

## Problem

The tmux agent status binary can be overwritten by a Linux build from e2e tests. A macOS install then links to an ELF binary and fails to run.

## Goals

- Build Linux and macOS binaries without clobbering each other.
- Keep install logic selecting the host binary.
- Keep e2e tests working without writing into the source tree.

## Non-goals

- Change runtime behavior of the daemon or CLI.
- Move tmux build logic into `scripts/build.py`.

## Design

### Build outputs

Write all Go builds to `build/agent-status/<os>-<arch>/agent-status`. Treat `tmux-agent-status/` as source only.

### Target selection

Introduce `HOST_GOOS` and `HOST_GOARCH` using `go env`. Compute `HOST_TARGET := $(HOST_GOOS)/$(HOST_GOARCH)`.

Define `AGENT_STATUS_TARGETS` as a space-separated list of `os/arch` pairs. On macOS, default to `linux/amd64` plus the host target. On Linux, default to only the host target. Allow overrides like:

```
make AGENT_STATUS_TARGETS="linux/amd64 linux/arm64" build-agent-status
```

### Build rule

Add a `build/agent-status/.stamp` target that depends on Go sources and `go.mod`. The recipe loops over `AGENT_STATUS_TARGETS`, sets `GOOS` and `GOARCH`, and writes binaries into the build tree. It then touches the stamp.

### Install rule

Set `AGENT_STATUS_HOST_BIN := build/agent-status/$(HOST_GOOS)-$(HOST_GOARCH)/agent-status` and link that path into `~/.local/bin/agent-status`. If the host binary is missing, fail with a clear error.

### Test harness

Update `tmux-agent-status/test-harness.sh` to use `AGENT_STATUS_BIN` if set. Otherwise, resolve the host binary in `build/agent-status/` and build it there if missing.

## Verification

- `make build-agent-status` produces both host and Linux binaries on macOS.
- `make install-tmux` installs the host binary and starts launchd.
- `tmux-agent-status/test-harness.sh` runs without writing `tmux-agent-status/agent-status`.
