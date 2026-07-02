#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: find-sessions.sh [-S socket-path|-A] [-q pattern]

List tmux sessions on the active/default server, or on a fallback socket when provided.

Options:
  -S, --socket-path  fallback tmux socket path (passed to tmux -S)
  -A, --all          scan all sockets under TMUX_FALLBACK_SOCKET_DIR
  -q, --query        case-insensitive substring to filter session names
  -h, --help         show this help
USAGE
}

socket_path=""
query=""
scan_all=false
runtime_dir="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
socket_dir="${TMUX_FALLBACK_SOCKET_DIR:-$runtime_dir/agent-tmux-sockets-$(id -u)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -S|--socket-path) socket_path="${2-}"; shift 2 ;;
    -A|--all)         scan_all=true; shift ;;
    -q|--query)       query="${2-}"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$scan_all" == true && -n "$socket_path" ]]; then
  echo "Cannot combine --all with -S" >&2
  exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux not found in PATH" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "rg not found in PATH" >&2
  exit 1
fi

list_sessions() {
  local label="$1"; shift
  local tmux_cmd=(tmux "$@")
  local sessions

  if ! sessions="$("${tmux_cmd[@]}" list-sessions -F $'#{session_name}\t#{session_attached}\t#{t:session_created}' 2>/dev/null)"; then
    echo "No tmux server found on $label" >&2
    return 1
  fi

  if [[ -n "$query" ]]; then
    sessions="$(printf '%s\n' "$sessions" | rg -i -- "$query" || true)"
  fi

  if [[ -z "$sessions" ]]; then
    echo "No sessions found on $label"
    return 0
  fi

  echo "Sessions on $label:"
  while IFS=$'\t' read -r name attached created; do
    attached_label=$([[ "$attached" == "1" ]] && echo "attached" || echo "detached")
    printf '  - %s (%s, started %s)\n' "$name" "$attached_label" "$created"
  done <<< "$sessions"
}

if [[ "$scan_all" == true ]]; then
  if [[ ! -d "$socket_dir" ]]; then
    echo "Socket directory not found: $socket_dir" >&2
    exit 1
  fi

  shopt -s nullglob
  sockets=("$socket_dir"/*)
  shopt -u nullglob

  if [[ "${#sockets[@]}" -eq 0 ]]; then
    echo "No sockets found under $socket_dir" >&2
    exit 1
  fi

  exit_code=0
  found_socket=false
  for sock in "${sockets[@]}"; do
    if [[ ! -S "$sock" ]]; then
      continue
    fi
    found_socket=true
    list_sessions "socket path '$sock'" -S "$sock" || exit_code=$?
  done

  if [[ "$found_socket" == false ]]; then
    echo "No sockets found under $socket_dir" >&2
    exit 1
  fi

  exit "$exit_code"
fi

tmux_cmd=(tmux)
socket_label="active/default socket"

if [[ -n "$socket_path" ]]; then
  tmux_cmd+=(-S "$socket_path")
  socket_label="socket path '$socket_path'"
fi

list_sessions "$socket_label" "${tmux_cmd[@]:1}"
