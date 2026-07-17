#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  run_review.sh start <repository> <prompt-file> <run-directory> [max-turns]
  run_review.sh resume <repository> <prompt-file> <run-directory> <grok-session-id> [max-turns]
  run_review.sh wait <run-directory>
  run_review.sh stop <run-directory>
EOF
}

fail() {
    printf 'grok-review: %s\n' "$1" >&2
    exit 1
}

canonical_directory() {
    local directory="$1"
    [[ -d "$directory" ]] || fail "directory is not readable: $directory"
    (cd "$directory" 2>/dev/null && pwd -P) \
        || fail "directory is not readable: $directory"
}

validate_result() {
    local run_dir="$1"
    local result="$run_dir/result.json"
    local expected_session
    expected_session="$(<"$run_dir/grok-session")"

    [[ -s "$run_dir/sandbox-enforced" ]] \
        || fail "sandbox enforcement marker is missing: $run_dir/sandbox-enforced"
    [[ "$(<"$run_dir/sandbox-enforced")" == "$(<"$run_dir/zmx-session")" ]] \
        || fail "sandbox enforcement marker does not match the zmx session: $run_dir/sandbox-enforced"
    [[ -s "$result" ]] || fail "result is missing or empty: $result"
    if ! jq -s -e --arg session_id "$expected_session" '
        length == 1 and
        .[0].type == null and
        (.[0].text | type == "string" and length > 0) and
        (.[0].stopReason == "EndTurn") and
        (.[0].sessionId == $session_id) and
        (.[0].requestId | type == "string" and length > 0)
    ' "$result" >/dev/null; then
        fail "result is malformed, incomplete, nonterminal, or for another session: $result"
    fi

    jq -r '.text' "$result" > "$run_dir/review.md"
    printf 'Validated review: %s\n' "$run_dir/review.md"
}

session_is_active() {
    local session="$1"
    local sessions
    sessions="$(zmx list --short 2>/dev/null)" || return 2
    printf '%s\n' "$sessions" | rg -Fx "$session" >/dev/null
}

release_workspace_lock() {
    local lock_dir="$1"
    local expected_owner="$2"
    local lock_owner="$lock_dir/zmx-session"
    [[ -s "$lock_owner" ]] || return 1
    [[ "$(<"$lock_owner")" == "$expected_owner" ]] || return 1
    rm -f "$lock_owner"
    if ! rmdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$expected_owner" > "$lock_owner"
        return 1
    fi
}

stop_review() {
    [[ $# -eq 1 ]] || { usage; exit 2; }

    local run_dir
    run_dir="$(canonical_directory "$1")"
    [[ -s "$run_dir/zmx-session" ]] || fail "zmx session marker is missing: $run_dir/zmx-session"
    [[ -s "$run_dir/workspace-lock" ]] || fail "workspace lock marker is missing: $run_dir/workspace-lock"

    local zmx_session lock_dir expected_parent wait_attempts session_status
    zmx_session="$(<"$run_dir/zmx-session")"
    [[ "$zmx_session" == grok-review-* ]] || fail "unexpected zmx session marker: $zmx_session"
    lock_dir="$(<"$run_dir/workspace-lock")"
    expected_parent="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" \
        || fail "temporary directory is not readable: ${TMPDIR:-/tmp}"
    [[ "$(dirname "$lock_dir")" == "$expected_parent" ]] \
        || fail "unexpected workspace lock path: $lock_dir"
    [[ "$(basename "$lock_dir")" =~ ^grok-review-lock-([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
        || fail "unexpected workspace lock name: $lock_dir"
    wait_attempts="${GROK_ABORT_WAIT_ATTEMPTS:-10}"
    [[ "$wait_attempts" =~ ^[1-9][0-9]*$ ]] \
        || fail "GROK_ABORT_WAIT_ATTEMPTS must be a positive integer"

    zmx kill "$zmx_session" >/dev/null 2>&1 || true
    for _ in $(seq 1 "$wait_attempts"); do
        if session_is_active "$zmx_session"; then
            sleep 1
            continue
        else
            session_status=$?
        fi
        if [[ "$session_status" -eq 1 ]]; then
            if [[ -d "$lock_dir" ]]; then
                if [[ -s "$lock_dir/zmx-session" && "$(<"$lock_dir/zmx-session")" != "$zmx_session" ]]; then
                    printf 'Stopped review: %s (workspace lock belongs to a newer session)\n' "$zmx_session"
                    return
                fi
                release_workspace_lock "$lock_dir" "$zmx_session" \
                    || fail "process stopped but lock could not be released: $lock_dir"
            fi
            printf 'Stopped review: %s\n' "$zmx_session"
            return
        fi
        sleep 1
    done

    fail "could not verify process termination, lock retained at $lock_dir"
}

wait_for_review() {
    [[ $# -eq 1 ]] || { usage; exit 2; }

    local run_dir
    run_dir="$(canonical_directory "$1")"
    [[ -s "$run_dir/zmx-session" ]] || fail "zmx session marker is missing: $run_dir/zmx-session"
    [[ -s "$run_dir/grok-session" ]] || fail "Grok session marker is missing: $run_dir/grok-session"

    local zmx_session
    zmx_session="$(<"$run_dir/zmx-session")"
    zmx wait "$zmx_session" || fail "Grok review did not exit successfully; inspect $run_dir"
    validate_result "$run_dir"
}

if [[ $# -lt 1 ]]; then
    usage
    exit 2
fi

MODE="$1"
shift

if [[ "$MODE" == "wait" ]]; then
    command -v zmx >/dev/null 2>&1 || fail "zmx is unavailable"
    command -v jq >/dev/null 2>&1 || fail "jq is unavailable for result validation"
    wait_for_review "$@"
    exit 0
fi

if [[ "$MODE" == "stop" ]]; then
    command -v zmx >/dev/null 2>&1 || fail "zmx is unavailable"
    command -v rg >/dev/null 2>&1 || fail "rg is unavailable for zmx session validation"
    stop_review "$@"
    exit 0
fi

case "$MODE" in
    start)
        [[ $# -ge 3 && $# -le 4 ]] || { usage; exit 2; }
        ;;
    resume)
        [[ $# -ge 4 && $# -le 5 ]] || { usage; exit 2; }
        ;;
    *)
        usage
        exit 2
        ;;
esac

REPO="$(canonical_directory "$1")"
GIT_ROOT="$(git -C "$REPO" rev-parse --show-toplevel 2>/dev/null)" \
    || fail "repository is not a Git checkout: $REPO"
GIT_ROOT="$(canonical_directory "$GIT_ROOT")"
[[ "$REPO" == "$GIT_ROOT" ]] || fail "repository must be the Git root: $GIT_ROOT"
PROMPT_FILE="$(cd "$(dirname "$2")" 2>/dev/null && pwd -P)/$(basename "$2")" \
    || fail "prompt directory is not readable: $(dirname "$2")"
[[ -f "$PROMPT_FILE" ]] || fail "prompt file is missing: $PROMPT_FILE"

RUN_PARENT="$(dirname "$3")"
mkdir -p "$RUN_PARENT"
RUN_DIR="$(cd "$RUN_PARENT" && pwd -P)/$(basename "$3")"
mkdir -p "$RUN_DIR"
for artifact in result.json review.md stderr.log zmx-start.log zmx-session grok-session mode sandbox-enforced workspace-lock; do
    [[ ! -e "$RUN_DIR/$artifact" ]] || fail "run artifact already exists: $RUN_DIR/$artifact"
done

if [[ "$MODE" == "start" ]]; then
    MAX_TURNS="${4:-60}"
    command -v uuidgen >/dev/null 2>&1 || fail "uuidgen is unavailable"
    GROK_SESSION_ID="${GROK_REVIEW_TEST_SESSION_ID:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"
else
    GROK_SESSION_ID="$4"
    MAX_TURNS="${5:-60}"
fi
[[ "$MAX_TURNS" =~ ^[1-9][0-9]*$ ]] || fail "max-turns must be a positive integer"
[[ "$GROK_SESSION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || fail "Grok session id must be a UUID: $GROK_SESSION_ID"

GROK_BIN="${GROK_BIN:-$HOME/.grok/bin/grok}"
[[ -x "$GROK_BIN" ]] || fail "Grok is unavailable at $GROK_BIN"
GROK_VERSION="$("$GROK_BIN" --version 2>/dev/null)" \
    || fail "could not read Grok version from $GROK_BIN"
case "$GROK_VERSION" in
    "grok 0.2.99"|"grok 0.2.99 "*) ;;
    *) fail "unsupported Grok version: $GROK_VERSION" ;;
esac

NATIVE_SKILL="$HOME/.grok/bundled/skills/review/SKILL.md"
[[ -f "$NATIVE_SKILL" ]] || fail "Grok native /review skill is missing: $NATIVE_SKILL"
command -v zmx >/dev/null 2>&1 || fail "zmx is unavailable"
command -v jq >/dev/null 2>&1 || fail "jq is unavailable for sandbox and result validation"
command -v rg >/dev/null 2>&1 || fail "rg is unavailable for zmx session validation"
SANDBOX_WAIT_ATTEMPTS="${GROK_SANDBOX_WAIT_ATTEMPTS:-30}"
[[ "$SANDBOX_WAIT_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] \
    || fail "GROK_SANDBOX_WAIT_ATTEMPTS must be a positive integer"
ABORT_WAIT_ATTEMPTS="${GROK_ABORT_WAIT_ATTEMPTS:-10}"
[[ "$ABORT_WAIT_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] \
    || fail "GROK_ABORT_WAIT_ATTEMPTS must be a positive integer"

LOCK_KEY="$(printf '%s\n' "$REPO" | git hash-object --stdin)"
LOCK_PARENT="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" \
    || fail "temporary directory is not readable: ${TMPDIR:-/tmp}"
LOCK_DIR="$LOCK_PARENT/grok-review-lock-$LOCK_KEY"
LOCK_OWNER="$LOCK_DIR/zmx-session"
ZMX_SESSION="grok-review-$(date -u +%Y%m%dT%H%M%SZ)-$$"

release_lock() {
    local expected_owner="$1"
    release_workspace_lock "$LOCK_DIR" "$expected_owner"
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    if [[ ! -s "$LOCK_OWNER" ]]; then
        fail "workspace lock has no owner; verify no review is active before removing it: $LOCK_DIR"
    fi
    EXISTING_SESSION="$(<"$LOCK_OWNER")"
    if session_is_active "$EXISTING_SESSION"; then
        fail "another Grok review is active for this workspace: $EXISTING_SESSION"
    else
        SESSION_STATUS=$?
    fi
    [[ "$SESSION_STATUS" -eq 1 ]] \
        || fail "could not verify stale workspace lock owner: $EXISTING_SESSION"
    release_lock "$EXISTING_SESSION" || fail "could not remove stale workspace lock: $LOCK_DIR"
    mkdir "$LOCK_DIR" 2>/dev/null || fail "could not acquire workspace lock: $LOCK_DIR"
fi
DETACHED_SESSION_STARTED=false
cleanup_startup_lock() {
    if [[ "$DETACHED_SESSION_STARTED" == false ]]; then
        if [[ -s "$LOCK_OWNER" && "$(<"$LOCK_OWNER")" == "$ZMX_SESSION" ]]; then
            release_lock "$ZMX_SESSION" || true
        elif [[ -d "$LOCK_DIR" && ! -e "$LOCK_OWNER" ]]; then
            rmdir "$LOCK_DIR" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup_startup_lock EXIT
printf '%s\n' "$ZMX_SESSION" > "$LOCK_OWNER"
printf '%s\n' "$LOCK_DIR" > "$RUN_DIR/workspace-lock"

GROK_SANDBOX_EVENTS="${GROK_SANDBOX_EVENTS:-$HOME/.grok/sandbox-events.jsonl}"
EVENT_LINES=0
if [[ -f "$GROK_SANDBOX_EVENTS" ]]; then
    EVENT_LINES="$(wc -l < "$GROK_SANDBOX_EVENTS")"
fi

RESULT="$RUN_DIR/result.json"
ERR="$RUN_DIR/stderr.log"
START_LOG="$RUN_DIR/zmx-start.log"

printf '%s\n' "$ZMX_SESSION" > "$RUN_DIR/zmx-session"
printf '%s\n' "$GROK_SESSION_ID" > "$RUN_DIR/grok-session"
printf '%s\n' "$MODE" > "$RUN_DIR/mode"

export MODE REPO GROK_BIN PROMPT_FILE RESULT ERR MAX_TURNS GROK_SESSION_ID LOCK_DIR LOCK_OWNER ZMX_SESSION

if ! zmx run "$ZMX_SESSION" -d bash -lc '
    cleanup() {
        if [[ -s "$LOCK_OWNER" && "$(<"$LOCK_OWNER")" == "$ZMX_SESSION" ]]; then
            rm -f "$LOCK_OWNER"
            rmdir "$LOCK_DIR" >/dev/null 2>&1 || true
        fi
    }
    trap cleanup EXIT
    session_args=(--session-id "$GROK_SESSION_ID")
    if [[ "$MODE" == "resume" ]]; then
        session_args=(--resume "$GROK_SESSION_ID")
    fi
    "$GROK_BIN" --cwd "$REPO" --prompt-file "$PROMPT_FILE" \
      "${session_args[@]}" \
      --sandbox read-only --no-plan --no-memory \
      --disable-web-search \
      --disallowed-tools "search_replace,write,web_search,web_fetch" \
      --deny Edit --deny Write --deny MCPTool \
      --output-format json --max-turns "$MAX_TURNS" \
      > "$RESULT" 2> "$ERR"
' >"$START_LOG" 2>&1; then
    release_lock "$ZMX_SESSION" || true
    fail "zmx could not start the review; see $START_LOG"
fi
DETACHED_SESSION_STARTED=true

new_events() {
    if [[ -f "$GROK_SANDBOX_EVENTS" ]]; then
        tail -n +$((EVENT_LINES + 1)) "$GROK_SANDBOX_EVENTS" 2>/dev/null || true
    fi
}

event_matches() {
    local event_type="$1"
    local enforced="$2"
    new_events | jq -e -c \
        --arg event_type "$event_type" \
        --arg workspace "$REPO" \
        --argjson enforced "$enforced" '
            select(
                .event_type == $event_type and
                .profile == "read-only" and
                .workspace == $workspace and
                .enforced == $enforced
            )
        ' >/dev/null 2>&1
}

abort_review() {
    local message="$1"

    zmx kill "$ZMX_SESSION" >/dev/null 2>&1 || true
    for _ in $(seq 1 "$ABORT_WAIT_ATTEMPTS"); do
        if session_is_active "$ZMX_SESSION"; then
            sleep 1
            continue
        else
            SESSION_STATUS=$?
        fi
        if [[ "$SESSION_STATUS" -eq 1 ]]; then
            if release_lock "$ZMX_SESSION"; then
                fail "$message"
            fi
            fail "$message; process stopped but lock could not be released: $LOCK_DIR"
        fi
        sleep 1
    done

    fail "$message; could not verify process termination, lock retained at $LOCK_DIR"
}

for _ in $(seq 1 "$SANDBOX_WAIT_ATTEMPTS"); do
    if event_matches ApplyFailed false; then
        abort_review "Grok read-only sandbox failed to apply; see $START_LOG"
    fi
    if event_matches ProfileApplied true; then
        printf '%s\n' "$ZMX_SESSION" > "$RUN_DIR/sandbox-enforced"
        printf 'Sandbox enforced for %s\n' "$ZMX_SESSION"
        printf 'Grok session: %s\n' "$GROK_SESSION_ID"
        printf 'Run directory: %s\n' "$RUN_DIR"
        exit 0
    fi
    sleep 1
done

abort_review "Grok read-only sandbox did not report enforced=true; see $START_LOG"
