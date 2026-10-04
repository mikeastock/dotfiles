#!/usr/bin/env bash
#
# Tests scripts/pstack_upstream.py against a throwaway upstream repo.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

UPSTREAM="$TMP_DIR/upstream"
PORT="$TMP_DIR/port"

git_upstream() { git -C "$UPSTREAM" -c user.name=t -c user.email=t@t "$@"; }

# Upstream at the base commit.
mkdir -p "$UPSTREAM/pstack/skills/how" "$UPSTREAM/pstack/skills/teach" "$UPSTREAM/pstack/agents"
printf 'line 1\nline 2\nline 3\nline 4\nline 5\n' > "$UPSTREAM/pstack/skills/how/SKILL.md"
printf 'teach\n' > "$UPSTREAM/pstack/skills/teach/SKILL.md"
printf 'sicko 1\nsicko 2\nsicko 3\n' > "$UPSTREAM/pstack/agents/comment-sicko.md"
git -C "$UPSTREAM" init -q
git_upstream add -A
git_upstream commit -qm base
BASE_SHA="$(git -C "$UPSTREAM" rev-parse HEAD)"

# The port, edited locally since the base.
mkdir -p "$PORT/scripts" "$PORT/skills/how" "$PORT/pi-extensions/pstack/agents"
cp "$PROJECT_DIR/scripts/pstack_upstream.py" "$PORT/scripts/"
printf 'line 1 ported to Pi\nline 2\nline 3\nline 4\nline 5\n' > "$PORT/skills/how/SKILL.md"
printf 'sicko 1\nsicko 2 ported\nsicko 3\n' > "$PORT/pi-extensions/pstack/agents/comment-sicko.md"
echo "$BASE_SHA" > "$PORT/pi-extensions/pstack/UPSTREAM"

# Upstream moves on.
printf 'line 1\nline 2\nline 3\nUse subagent_type: generalPurpose here.\nline 5 updated\n' > "$UPSTREAM/pstack/skills/how/SKILL.md"
mkdir -p "$UPSTREAM/pstack/skills/how/references" "$UPSTREAM/pstack/skills/brand-new"
printf 'new reference\n' > "$UPSTREAM/pstack/skills/how/references/new.md"
printf 'brand new\n' > "$UPSTREAM/pstack/skills/brand-new/SKILL.md"
printf 'teach v2\n' > "$UPSTREAM/pstack/skills/teach/SKILL.md"
printf 'sicko 1\nsicko 2 upstream\nsicko 3\n' > "$UPSTREAM/pstack/agents/comment-sicko.md"
git_upstream add -A
git_upstream commit -qm update
NEW_SHA="$(git -C "$UPSTREAM" rev-parse HEAD)"

log_test "a sync reports conflicts with a nonzero exit"
set +e
OUTPUT="$(python3 "$PORT/scripts/pstack_upstream.py" HEAD --repo "$UPSTREAM" 2>&1)"
STATUS=$?
set -e
assert_success "exits 1 when a file conflicts (got $STATUS)" test "$STATUS" -eq 1

log_test "upstream edits merge into ported lines without losing either side"
HOW="$(cat "$PORT/skills/how/SKILL.md")"
assert_output_contains "$HOW" "line 1 ported to Pi" "keeps the local port"
assert_output_contains "$HOW" "line 5 updated" "takes the upstream edit"
assert_output_not_contains "$HOW" "<<<<<<<" "no conflict markers in a clean merge"

log_test "new upstream files in vendored skills are added"
assert_file_exists "$PORT/skills/how/references/new.md" "new reference copied"
assert_output_contains "$OUTPUT" "added skills/how/references/new.md" "addition reported"

log_test "skills that are not vendored are left alone, and new ones are only listed"
assert_file_not_exists "$PORT/skills/teach/SKILL.md" "teach not vendored"
assert_file_not_exists "$PORT/skills/brand-new/SKILL.md" "brand-new not copied"
assert_output_contains "$OUTPUT" "new upstream skill not vendored: brand-new" "new skill listed"

log_test "both sides editing the same line leaves conflict markers"
SICKO="$(cat "$PORT/pi-extensions/pstack/agents/comment-sicko.md")"
assert_output_contains "$SICKO" "<<<<<<< ours" "conflict marker"
assert_output_contains "$SICKO" "sicko 2 upstream" "upstream side kept in the conflict"
assert_output_contains "$OUTPUT" "CONFLICT pi-extensions/pstack/agents/comment-sicko.md" "conflict reported"

log_test "merged upstream text that only makes sense in Cursor is flagged"
assert_output_contains "$OUTPUT" "needs Pi port skills/how/SKILL.md:4" "Cursor-ism flagged with its line"

log_test "the recorded upstream commit advances"
assert_output_contains "$(cat "$PORT/pi-extensions/pstack/UPSTREAM")" "$NEW_SHA" "UPSTREAM updated"

print_summary
