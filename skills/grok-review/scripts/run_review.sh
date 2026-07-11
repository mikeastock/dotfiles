#!/usr/bin/env bash

set -euo pipefail

usage() {
    printf 'Usage: %s <repository> <prompt-file> <run-directory> [max-turns]\n' "$0" >&2
}

fail() {
    printf 'grok-review: %s\n' "$1" >&2
    exit 1
}

if [[ $# -lt 3 || $# -gt 4 ]]; then
    usage
    exit 2
fi

REPO="$(cd "$1" 2>/dev/null && pwd -P)" || fail "repository is not readable: $1"
PROMPT_FILE="$(cd "$(dirname "$2")" 2>/dev/null && pwd -P)/$(basename "$2")" \
    || fail "prompt directory is not readable: $(dirname "$2")"
[[ -f "$PROMPT_FILE" ]] || fail "prompt file is missing: $PROMPT_FILE"

RUN_PARENT="$(dirname "$3")"
mkdir -p "$RUN_PARENT"
RUN_DIR="$(cd "$RUN_PARENT" && pwd -P)/$(basename "$3")"
mkdir -p "$RUN_DIR"
[[ ! -e "$RUN_DIR/result.json" ]] || fail "result already exists: $RUN_DIR/result.json"
[[ ! -e "$RUN_DIR/zmx-session" ]] || fail "session marker already exists: $RUN_DIR/zmx-session"

MAX_TURNS="${4:-60}"
[[ "$MAX_TURNS" =~ ^[1-9][0-9]*$ ]] || fail "max-turns must be a positive integer"

GROK_BIN="${GROK_BIN:-$HOME/.grok/bin/grok}"
[[ -x "$GROK_BIN" ]] || fail "Grok is unavailable at $GROK_BIN"
GROK_VERSION="$("$GROK_BIN" --version 2>/dev/null)" \
    || fail "could not read Grok version from $GROK_BIN"
case "$GROK_VERSION" in
    "grok 0.2.93"|"grok 0.2.93 "*) ;;
    *) fail "unsupported Grok version: $GROK_VERSION" ;;
esac

NATIVE_SKILL="$HOME/.grok/skills/code-review/SKILL.md"
[[ -f "$NATIVE_SKILL" ]] || fail "Grok native /code-review skill is missing: $NATIVE_SKILL"
command -v zmx >/dev/null 2>&1 || fail "zmx is unavailable"
command -v rg >/dev/null 2>&1 || fail "rg is unavailable for sandbox verification"

GROK_SANDBOX_EVENTS="${GROK_SANDBOX_EVENTS:-$HOME/.grok/sandbox-events.jsonl}"
EVENT_LINES=0
if [[ -f "$GROK_SANDBOX_EVENTS" ]]; then
    EVENT_LINES="$(wc -l < "$GROK_SANDBOX_EVENTS")"
fi

SESSION="grok-review-$(date -u +%Y%m%dT%H%M%SZ)-$$"
RESULT="$RUN_DIR/result.json"
ERR="$RUN_DIR/stderr.log"
START_LOG="$RUN_DIR/zmx-start.log"
SESSION_FILE="$RUN_DIR/zmx-session"

export REPO GROK_BIN PROMPT_FILE RESULT ERR MAX_TURNS

if ! zmx run "$SESSION" -d bash -lc \
    'exec "$GROK_BIN" --cwd "$REPO" --prompt-file "$PROMPT_FILE" \
      --sandbox read-only --always-approve --no-plan --no-memory \
      --output-format json --max-turns "$MAX_TURNS" \
      > "$RESULT" 2> "$ERR"' >"$START_LOG" 2>&1; then
    fail "zmx could not start the review; see $START_LOG"
fi
printf '%s\n' "$SESSION" > "$SESSION_FILE"

new_events() {
    if [[ -f "$GROK_SANDBOX_EVENTS" ]]; then
        tail -n +$((EVENT_LINES + 1)) "$GROK_SANDBOX_EVENTS" 2>/dev/null || true
    fi
}

event_matches() {
    local event_type="$1"
    local enforced="$2"
    local events
    events="$(new_events)"
    printf '%s\n' "$events" \
        | rg -F "\"event_type\":\"$event_type\"" \
        | rg -F '"profile":"read-only"' \
        | rg -F "\"workspace\":\"$REPO\"" \
        | rg -F "\"enforced\":$enforced" >/dev/null
}

for _ in $(seq 1 30); do
    if event_matches ApplyFailed false; then
        zmx kill "$SESSION" >/dev/null 2>&1 || true
        fail "Grok read-only sandbox failed to apply; see $START_LOG"
    fi
    if event_matches ProfileApplied true; then
        printf 'Sandbox enforced for %s\n' "$SESSION"
        printf 'Run directory: %s\n' "$RUN_DIR"
        exit 0
    fi
    sleep 1
done

zmx kill "$SESSION" >/dev/null 2>&1 || true
fail "Grok read-only sandbox did not report enforced=true; see $START_LOG"
