#!/usr/bin/env bash
#
# Test skill-doctor collector and report renderer against a fixture
# trajectories root.
#
# Usage: ./tests/test-skill-doctor.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-helpers.sh"

SKILL_DIR="$PROJECT_DIR/skills/skill-doctor"
COLLECT="$SKILL_DIR/scripts/collect_sessions.py"
RENDER="$SKILL_DIR/scripts/render_report.py"

FIXTURE=""
REPO=""
OUT=""

cleanup_fixture() {
    [ -n "$FIXTURE" ] && rm -rf "$FIXTURE"
    [ -n "$REPO" ] && rm -rf "$REPO"
    [ -n "$OUT" ] && rm -rf "$OUT"
}
trap cleanup_fixture EXIT

now_iso() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

write_session() {
    # write_session <source> <id> <cwd> <records-json>
    local source="$1" id="$2" cwd="$3" records="$4"
    local file="$FIXTURE/normalized/$source/$id.json"
    mkdir -p "$(dirname "$file")"
    cat > "$file" <<EOF
{"provenance":{"source":"$source","id":"$id","sourcePath":"/fake/$source/$id.jsonl"},"records":$records}
EOF
    local roles
    roles="$(python3 -c "
import json,sys
recs=json.load(open('$file'))['records']
c={}
for r in recs: c[r['role']]=c.get(r['role'],0)+1
print(json.dumps(c))")"
    local ts; ts="$(now_iso)"
    printf '%s\n' "{\"source\":\"$source\",\"id\":\"$id\",\"file\":\"$file\",\"sourcePath\":\"/fake/$source/$id.jsonl\",\"sourceUpdatedAt\":\"$ts\",\"firstTimestamp\":\"$ts\",\"lastTimestamp\":\"$ts\",\"cwd\":\"$cwd\",\"gitBranch\":\"main\",\"model\":\"m\",\"roleCounts\":$roles}" \
        >> "$FIXTURE/state/history.jsonl"
}

setup_fixture() {
    FIXTURE="$(mktemp -d)"
    mkdir -p "$FIXTURE/state"
    REPO="$(mktemp -d)"
    git -C "$REPO" init -q
    mkdir -p "$REPO/.claude/skills/alpha" "$REPO/.agents/skills/beta"
    printf -- '---\nname: alpha\ndescription: Alpha skill\n---\n# Alpha\n' > "$REPO/.claude/skills/alpha/SKILL.md"
    printf -- '---\nname: beta\ndescription: >-\n  Beta skill\n  wrapped\n---\n# Beta\n' > "$REPO/.agents/skills/beta/SKILL.md"

    local meta="{\"role\":\"meta\",\"source\":\"claude-code\",\"cwd\":\"$REPO\"}"
    # Session using alpha via Skill tool call, with a code edit.
    write_session claude-code s-alpha "$REPO" "[$meta,
      {\"role\":\"user\",\"content\":\"do the thing\",\"timestamp\":\"2026-01-01T00:00:00Z\"},
      {\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"c1\",\"name\":\"Skill\",\"args\":\"{\\\"skill\\\":\\\"alpha\\\"}\"}]},
      {\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":\"loaded\",\"ok\":true},
      {\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"c2\",\"name\":\"Edit\",\"args\":\"{\\\"file_path\\\":\\\"x.py\\\"}\"}]},
      {\"role\":\"tool\",\"tool_call_id\":\"c2\",\"content\":\"ok\",\"ok\":false},
      {\"role\":\"assistant\",\"content\":\"done\"}]"
    # Session using beta via pi-style injected skill block; no code edits.
    write_session pi s-beta "$REPO" "[{\"role\":\"meta\",\"source\":\"pi\",\"cwd\":\"$REPO\"},
      {\"role\":\"user\",\"content\":\"<skill name=\\\"beta\\\" location=\\\"/x/skills/beta/SKILL.md\\\">body</skill>\\nplease help\"},
      {\"role\":\"assistant\",\"content\":\"sure\"},
      {\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"c1\",\"name\":\"bash\",\"args\":\"{\\\"command\\\":\\\"ls\\\"}\"}]},
      {\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":\"a\"},
      {\"role\":\"assistant\",\"content\":\"done\"}]"
    # Session in another repo: filtered out by --repo.
    write_session codex s-other /tmp/elsewhere "[{\"role\":\"meta\",\"source\":\"codex\",\"cwd\":\"/tmp/elsewhere\"},
      {\"role\":\"user\",\"content\":\"<recommended_plugins>junk</recommended_plugins>\\nreal prompt\"},
      {\"role\":\"assistant\",\"content\":\"a\"},{\"role\":\"assistant\",\"content\":\"b\"},{\"role\":\"assistant\",\"content\":\"c\"}]"
    # Helper-prompt session: skipped unless --include-subagents.
    write_session claude-code s-helper "$REPO" "[$meta,
      {\"role\":\"user\",\"content\":\"You are the trusted senior reviewer for this change.\"},
      {\"role\":\"assistant\",\"content\":\"a\"},{\"role\":\"assistant\",\"content\":\"b\"},{\"role\":\"assistant\",\"content\":\"c\"}]"
}

test_collect_repo_scope() {
    log_test "Testing collect_sessions.py with --repo scope"
    OUT="$(mktemp -d)"

    assert_success "collector runs" python3 "$COLLECT" --trajectories-root "$FIXTURE" --repo "$REPO" --out "$OUT" --dotfiles-root /nonexistent

    assert_file_exists "$OUT/inventory.json" "inventory.json written"
    local inv; inv="$(cat "$OUT/inventory.json")"
    assert_output_contains "$inv" '"skills_found": 2' "both project skills discovered"
    assert_output_contains "$inv" '"sessions_scanned": 2' "helper prompt and other-repo sessions excluded"
    assert_output_contains "$inv" '"sessions_sampled": 2' "both in-scope sessions sampled"
    assert_output_contains "$inv" '"harness": "mixed"' "mixed sources reported"
    assert_output_contains "$inv" '"description": "Beta skill wrapped"' "folded description parsed"

    assert_file_exists "$OUT/transcripts/claude-code--s-alpha.md" "alpha transcript written"
    local t; t="$(cat "$OUT/transcripts/claude-code--s-alpha.md")"
    assert_output_contains "$t" "skills_used: alpha" "Skill tool call detected"
    assert_output_contains "$t" "code_edits: yes" "code edit detected"
    assert_output_contains "$t" "tool_errors: 1" "tool error counted"
    assert_output_contains "$t" "## tool_result Edit ERROR" "failed tool result labelled"

    t="$(cat "$OUT/transcripts/pi--s-beta.md")"
    assert_output_contains "$t" "skills_used: beta" "injected skill block detected"
    assert_output_contains "$t" "code_edits: no" "no code edit detected"
    assert_output_contains "$t" "[skill injected]" "injected skill body stripped"
}

test_collect_all_conversations() {
    log_test "Testing collect_sessions.py with --all-conversations --include-subagents"
    local out; out="$(mktemp -d)"

    assert_success "collector runs" python3 "$COLLECT" --trajectories-root "$FIXTURE" --all-conversations --include-subagents --out "$out" --dotfiles-root /nonexistent --source claude-code --source codex

    local inv; inv="$(cat "$out/inventory.json")"
    assert_output_contains "$inv" '"sessions_scanned": 3' "pi excluded by --source, helper included"
    assert_output_contains "$inv" '"real prompt"' "injected codex block stripped from first prompt"
    assert_output_not_contains "$inv" 'recommended_plugins' "recommended_plugins not in inventory"
    rm -rf "$out"
}

test_collect_missing_history() {
    log_test "Testing collect_sessions.py without history.jsonl"
    local empty; empty="$(mktemp -d)"
    local err
    if err="$(python3 "$COLLECT" --trajectories-root "$empty" --all-conversations --out "$empty/out" 2>&1)"; then
        log_error "FAIL: collector should fail without history.jsonl"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "PASS: collector fails without history.jsonl"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    assert_output_contains "$err" "ingest.sh" "error message points at ingest"
    rm -rf "$empty"
}

test_combine_pipeline() {
    log_test "Testing vendored combine.mjs rebuilds history.jsonl"
    local before; before="$(wc -l < "$FIXTURE/state/history.jsonl")"
    rm "$FIXTURE/state/history.jsonl"
    assert_success "combine runs" node "$SKILL_DIR/scripts/trajectories/combine.mjs" --root "$FIXTURE"
    assert_file_exists "$FIXTURE/state/history.jsonl" "history.jsonl rebuilt"
    assert_file_exists "$FIXTURE/state/history.json" "history.json written"
    local after; after="$(wc -l < "$FIXTURE/state/history.jsonl")"
    if [ "$after" -eq "$before" ]; then
        log_info "PASS: history row count preserved ($after)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_error "FAIL: history row count changed ($before -> $after)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    local row; row="$(grep '"id":"s-alpha"' "$FIXTURE/state/history.jsonl")"
    assert_output_contains "$row" "\"cwd\":\"$REPO\"" "combine extracts cwd from meta record"
    assert_output_contains "$row" '"assistant":3' "combine counts roles"
}

test_normalize_without_package() {
    log_test "Testing normalize.mjs fails clearly without @letta-ai/trajectory"
    local err
    if err="$(node "$SKILL_DIR/scripts/trajectories/normalize.mjs" --root "$FIXTURE" --dry-run 2>&1)"; then
        log_error "FAIL: normalize should fail without the package"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "PASS: normalize fails without the package"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    assert_output_contains "$err" "ingest.sh" "error points at ingest.sh"
}

test_ingest_help() {
    log_test "Testing ingest.sh --help"
    local out; out="$("$SKILL_DIR/scripts/ingest.sh" --help)"
    assert_output_contains "$out" "--root PATH" "help documents required root"
    if "$SKILL_DIR/scripts/ingest.sh" >/dev/null 2>&1; then
        log_error "FAIL: ingest.sh should fail without --root"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "PASS: ingest.sh fails without --root"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

test_root_required() {
    log_test "Testing pipeline scripts require --root"
    local err
    if err="$(node "$SKILL_DIR/scripts/trajectories/combine.mjs" 2>&1)"; then
        log_error "FAIL: combine.mjs should fail without --root"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "PASS: combine.mjs fails without --root"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    assert_output_contains "$err" "--root PATH is required" "combine error names --root"
    if err="$(python3 "$COLLECT" --all-conversations --out "$FIXTURE/x" 2>&1)"; then
        log_error "FAIL: collector should fail without --trajectories-root"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "PASS: collector fails without --trajectories-root"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    assert_output_contains "$err" "--trajectories-root" "collector error names the flag"
}

test_pipeline_manifest() {
    log_test "Testing bundled pnpm manifest and grok-build patch are consistent"
    local pdir="$SKILL_DIR/scripts/trajectories"
    local version
    version="$(python3 -c "import json; print(json.load(open('$pdir/package.json'))['dependencies']['@letta-ai/trajectory'])")"
    assert_file_exists "$pdir/patches/@letta-ai__trajectory@$version.patch" "patch file matches pinned version $version"
    local ws; ws="$(cat "$pdir/pnpm-workspace.yaml")"
    assert_output_contains "$ws" "'@letta-ai/trajectory@$version': patches/@letta-ai__trajectory@$version.patch" "pnpm-workspace.yaml maps the patch"
    local patch; patch="$(cat "$pdir/patches/@letta-ai__trajectory@$version.patch")"
    assert_output_contains "$patch" '+++ b/dist/adapters/grok-build/index.js' "patch adds grok-build adapter"
    assert_output_contains "$patch" '+    "grok-build": grokBuildAdapter,' "patch registers adapter"
    assert_output_contains "$patch" '+    "grok-build": listGrokBuildTrajectories,' "patch registers lister"
}

test_render_report() {
    log_test "Testing render_report.py"
    local dir; dir="$(mktemp -d)"
    cat > "$dir/report.json" <<'EOF'
{"title":"Agent Skill Report","generated_at":"2026-08-30T10:00:00Z","sources":["pi"],"handle":"repo",
 "stats":{"sessions_analyzed":1,"sessions_scanned":2,"skills_found":2,"skills_used":1,"window_days":45},
 "scores":{"efficiency":0.9,"code_quality":0.6,"skill_coverage":0.5,"overall":0.75},
 "top_findings":["Finding <one>"],
 "sessions":[{"id":"s1","source":"pi","efficiency":0.4,"code_quality":null,"skills":["alpha"],"note":"n"}],
 "suggestions":[{"skill":"alpha","change":"Add check","evidence":"s1","proposed_path":"proposed/alpha/SKILL.md","diff":"--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n"}]}
EOF
    assert_success "renderer runs" python3 "$RENDER" "$dir/report.json"
    assert_file_exists "$dir/report.html" "report.html written"
    local h; h="$(cat "$dir/report.html")"
    assert_output_contains "$h" "Finding &lt;one&gt;" "findings escaped"
    assert_output_contains "$h" '<td class="fail">0.4' "failed score highlighted"
    assert_output_contains "$h" '<span class="add">+new</span>' "diff rendered"
    assert_output_not_contains "$h" 'warp.dev' "no upstream branding"
    rm -rf "$dir"
}

setup_fixture
test_collect_repo_scope
test_collect_all_conversations
test_collect_missing_history
test_combine_pipeline
test_normalize_without_package
test_ingest_help
test_root_required
test_pipeline_manifest
test_render_report
print_summary
