let meta = #{
    name: "review-gauntlet",
    description: "Multi-model review loop: Fable, Grok, Codex, and Thermonuclear in parallel; Fable triages what is worth fixing; Grok implements; re-review until dry",
    when_to_use: "When you want a hard multi-reviewer gauntlet with a Fable-judged fix loop instead of a one-shot review — real bugs and GAFs only, no over-engineering",
    phases: [
        #{ title: "Scope", detail: "resolve immutable git base/head and write the review brief" },
        #{ title: "Review", detail: "parallel Fable, Grok, Codex, Thermonuclear reviews" },
        #{ title: "Triage", detail: "separate Fable judge decides what is worth fixing" },
        #{ title: "Fix", detail: "Grok implements accepted items on the branch" },
        #{ title: "Report", detail: "ledger of fixed, skipped, and remaining items" },
    ],
};

// --- schemas -----------------------------------------------------------------

let scope_schema = #{
    "type": "object",
    "required": ["ok", "base_ref", "base_sha", "head_ref", "head_sha", "merge_base_sha", "diff_stat", "changed_files", "branch_name", "artifact_dir", "brief", "error"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "base_ref": #{ "type": "string" },
        "base_sha": #{ "type": "string" },
        "head_ref": #{ "type": "string" },
        "head_sha": #{ "type": "string" },
        "merge_base_sha": #{ "type": "string" },
        "diff_stat": #{ "type": "string" },
        "changed_files": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 200 },
        "branch_name": #{ "type": "string" },
        "artifact_dir": #{ "type": "string" },
        "brief": #{ "type": "string" },
        "error": #{ "type": "string" },
    },
};

let review_schema = #{
    "type": "object",
    "required": ["reviewer", "status", "review_path", "summary", "finding_count", "findings_excerpt", "error"],
    "properties": #{
        "reviewer": #{ "type": "string", "enum": ["fable", "grok", "codex", "thermo"] },
        "status": #{ "type": "string", "enum": ["completed", "failed", "skipped", "empty"] },
        "review_path": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "finding_count": #{ "type": "integer", "minimum": 0 },
        "findings_excerpt": #{ "type": "string" },
        "error": #{ "type": "string" },
    },
};

let triage_item_schema = #{
    "type": "object",
    "required": ["id", "title", "severity", "source", "files", "action", "why_worth_doing"],
    "properties": #{
        "id": #{ "type": "string" },
        "title": #{ "type": "string" },
        "severity": #{ "type": "string", "enum": ["blocker", "major", "minor"] },
        "source": #{ "type": "string" },
        "files": #{ "type": "array", "items": #{ "type": "string" } },
        "action": #{ "type": "string" },
        "why_worth_doing": #{ "type": "string" },
    },
};

let triage_schema = #{
    "type": "object",
    "required": ["round", "fable_do_now", "do_now", "skip", "defer", "overrides", "rationale", "stop", "stop_reason", "fable_judge_path"],
    "properties": #{
        "round": #{ "type": "integer" },
        "fable_do_now": #{
            "type": "array",
            "maxItems": 12,
            "items": triage_item_schema,
            "description": "Exact DO_NOW list from Fable BEFORE any orchestrator demotion",
        },
        "do_now": #{
            "type": "array",
            "maxItems": 12,
            "items": triage_item_schema,
            "description": "Final DO_NOW after rare hard-disproof demotions only",
        },
        "skip": #{
            "type": "array",
            "maxItems": 30,
            "items": #{
                "type": "object",
                "required": ["id", "title", "source", "why_skip"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "source": #{ "type": "string" },
                    "why_skip": #{ "type": "string" },
                },
            },
        },
        "defer": #{
            "type": "array",
            "maxItems": 20,
            "items": #{
                "type": "object",
                "required": ["id", "title", "source", "why_defer"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "source": #{ "type": "string" },
                    "why_defer": #{ "type": "string" },
                },
            },
        },
        "overrides": #{
            "type": "array",
            "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["id", "title", "reason", "evidence"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "reason": #{ "type": "string" },
                    "evidence": #{ "type": "string" },
                },
            },
            "description": "Items Fable put in DO_NOW that the orchestrator demoted; must be rare and hard-disproven",
        },
        "rationale": #{ "type": "string" },
        "stop": #{ "type": "boolean" },
        "stop_reason": #{ "type": "string" },
        "fable_judge_path": #{ "type": "string" },
    },
};

let fix_schema = #{
    "type": "object",
    "required": ["round", "status", "fixed", "blocked", "commit_shas", "files_touched", "verification", "summary"],
    "properties": #{
        "round": #{ "type": "integer" },
        "status": #{ "type": "string", "enum": ["done", "partial", "blocked", "noop"] },
        "fixed": #{
            "type": "array",
            "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["id", "title", "how"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "how": #{ "type": "string" },
                },
            },
        },
        "blocked": #{
            "type": "array",
            "maxItems": 12,
            "items": #{
                "type": "object",
                "required": ["id", "title", "reason"],
                "properties": #{
                    "id": #{ "type": "string" },
                    "title": #{ "type": "string" },
                    "reason": #{ "type": "string" },
                },
            },
        },
        "commit_shas": #{ "type": "array", "items": #{ "type": "string" } },
        "files_touched": #{ "type": "array", "items": #{ "type": "string" } },
        "verification": #{ "type": "string" },
        "summary": #{ "type": "string" },
    },
};

// --- helpers -----------------------------------------------------------------

fn trimmed(s) {
    if type_of(s) == "string" {
        s.trim();
        s
    } else {
        ""
    }
}

fn max_rounds_from_args(a) {
    if a == () { return 3; }
    let n = a.max_rounds;
    if n == () { return 3; }
    if type_of(n) == "i64" || type_of(n) == "f64" {
        let i = n;
        if i < 1 { return 1; }
        if i > 5 { return 5; }
        return i;
    }
    3
}

fn brief_from_args(a) {
    if a == () { return ""; }
    let b = a.brief;
    if b == () { return ""; }
    trimmed(b)
}

fn scope_mode_label(a) {
    if a == () { return "default-main"; }
    if a.commit != () && trimmed(a.commit.to_string()) != "" { return "commit"; }
    if a.pr != () && trimmed(a.pr.to_string()) != "" { return "pr"; }
    if a.branch != () && trimmed(a.branch.to_string()) != "" { return "branch"; }
    if a.base != () && trimmed(a.base.to_string()) != "" { return "base"; }
    "default-main"
}

fn reviewer_enabled(a, name) {
    if a == () { return true; }
    let skip = a.skip_reviewers;
    if skip == () { return true; }
    if type_of(skip) != "array" { return true; }
    for s in skip {
        if trimmed(s.to_string()) == name { return false; }
    }
    true
}

fn empty_review(reviewer, status, err) {
    #{
        reviewer: reviewer,
        status: status,
        review_path: "",
        summary: "",
        finding_count: 0,
        findings_excerpt: "",
        error: err,
    }
}

fn do_now_fingerprint(items) {
    if items == () { return ""; }
    if type_of(items) != "array" { return ""; }
    let parts = [];
    for it in items {
        if it == () { continue; }
        let id = "";
        let title = "";
        if it.id != () { id = trimmed(it.id.to_string()); }
        if it.title != () { title = trimmed(it.title.to_string()); }
        parts.push(id + "|" + title);
    }
    fingerprint(json_encode(parts))
}

fn format_do_now(items) {
    if items == () { return "(none)"; }
    if type_of(items) != "array" || items.len() == 0 { return "(none)"; }
    let text = "";
    for it in items {
        if it == () { continue; }
        let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
        let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
        let severity = if it.severity != () { trimmed(it.severity.to_string()) } else { "?" };
        let source = if it.source != () { trimmed(it.source.to_string()) } else { "?" };
        let action = if it.action != () { trimmed(it.action.to_string()) } else { "" };
        let why = if it.why_worth_doing != () { trimmed(it.why_worth_doing.to_string()) } else { "" };
        let files = "";
        if it.files != () && type_of(it.files) == "array" {
            files = json_encode(it.files);
        }
        text += "- [" + severity + "] " + id + ": " + title + " (source=" + source + ")\n";
        if files != "" { text += "  files: " + files + "\n"; }
        if action != "" { text += "  action: " + action + "\n"; }
        if why != "" { text += "  why: " + why + "\n"; }
    }
    if text == "" { return "(none)"; }
    text
}

fn append_ledger_line(ledger, line) {
    ledger + line + "\n"
}

// Anti-over-engineering doctrine for the Fable judge (and local-fallback only).
fn triage_doctrine() {
    let d = "";
    d += "JUDGMENT DOCTRINE (binding for the Fable judge):\n";
    d += "Accept (DO_NOW) ONLY items that are real problems in THIS change:\n";
    d += "- Correctness bugs, broken behavior, data integrity, authz/authn holes\n";
    d += "- Clear regressions vs intended behavior\n";
    d += "- Missing tests for non-trivial new logic that can actually fail\n";
    d += "- Security issues with a plausible exploit path in this codebase\n";
    d += "- Structural problems that make the change harder to maintain RIGHT NOW\n";
    d += "  (e.g. file pushed past ~1000 lines, logic in the wrong layer, duplicated helper)\n\n";
    d += "SKIP (do not implement) items that are:\n";
    d += "- Speculative rare edge cases that almost never happen in production\n";
    d += "- Gold-plating, 'proper architecture' rewrites, or large refactors for a one-off\n";
    d += "- Style nits, naming bikesheds, or pure preference without a real risk\n";
    d += "- 'While we're here' cleanups outside the change's blast radius\n";
    d += "- Abstract future-proofing for problems that are not present\n";
    d += "- Thermo 'code judo' ideas that expand scope without removing real complexity\n";
    d += "- Suggestions that require new frameworks, layers, or indirection for a simple fix\n\n";
    d += "DEFER only when the issue is real but correctly belongs to a separate follow-up\n";
    d += "(e.g. pre-existing debt the PR merely touched, not introduced).\n\n";
    d += "Bias: fewer, higher-signal fixes. An empty DO_NOW after honest inspection is a SUCCESS.\n";
    d += "When two reviewers contradict, prefer concrete code evidence over rhetoric.\n";
    d += "When a finding is only plausible, not proven, skip or defer — do not invent work.\n";
    d
}

fn fable_authority_rules() {
    let d = "";
    d += "FABLE AUTHORITY (binding for YOU, the orchestrator):\n";
    d += "Fable is the high-authority judge. Your job is to RUN Fable and MAP its decision —\n";
    d += "not to re-litigate the review as a second, stricter judge.\n\n";
    d += "1. Copy Fable's DO_NOW into fable_do_now EXACTLY (same ids/titles/actions).\n";
    d += "2. Final do_now MUST start as a copy of fable_do_now.\n";
    d += "3. You may demote a Fable DO_NOW item ONLY with HARD DISPROOF, meaning you can\n";
    d += "   point to an existing test or code path that already asserts the EXACT behavior\n";
    d += "   Fable asked for (file + test name + what it asserts). Vague 'probably covered'\n";
    d += "   or 'nearby helper tests something similar' is NOT disproof — KEEP the item.\n";
    d += "4. Every demotion goes in overrides[] with {id, title, reason, evidence} and also\n";
    d += "   appears in skip[] with why_skip mentioning fable_do_now_overridden.\n";
    d += "5. Prefer keeping Fable's minor DO_NOW items when local reading is inconclusive.\n";
    d += "6. Do NOT add new do_now items Fable did not accept (unless Fable was unavailable\n";
    d += "   and you are judge:local-fallback — label source accordingly).\n";
    d += "7. stop=true only when final do_now is empty.\n";
    d
}

// --- args --------------------------------------------------------------------

if args == () {
    pause("verification", "Pass args for review-gauntlet. Examples:\n  #{ base: \"origin/main\", brief: \"...\" }\n  #{ commit: \"abc123\", brief: \"...\" }\n  #{ pr: 123, brief: \"...\" }\n  #{ branch: \"feature/x\", brief: \"...\" }\nOptional: max_rounds (1-5, default 3), head, skip_reviewers: [\"codex\"], allow_dirty: true");
}

let max_rounds = max_rounds_from_args(args);
let user_brief = brief_from_args(args);
let mode = scope_mode_label(args);
let allow_dirty = false;
if args.allow_dirty != () && args.allow_dirty == true {
    allow_dirty = true;
}

log("review-gauntlet mode=" + mode + " max_rounds=" + max_rounds.to_string() + " allow_dirty=" + allow_dirty.to_string());

// --- Phase: Scope ------------------------------------------------------------

phase("Scope");

let scope_prompt = "";
scope_prompt += "You resolve an immutable git review scope for a multi-reviewer gauntlet. Do not edit source.\n";
scope_prompt += "Work at the repo root (git rev-parse --show-toplevel).\n\n";
scope_prompt += "ARGS (JSON):\n";
scope_prompt += json_encode(args) + "\n\n";
scope_prompt += "Resolve exactly one scope:\n";
scope_prompt += "1. args.commit set → review that single commit (base=commit^, head=commit) or the range it introduced.\n";
scope_prompt += "2. args.pr set → ensure local checkout is at the PR head; base = PR base ref/SHA; head = PR head SHA.\n";
scope_prompt += "3. args.branch set → head = that branch tip; base = merge-base with origin/main (or args.base if set).\n";
scope_prompt += "4. args.base set (no commit/pr/branch) → head = args.head or HEAD; base = merge-base(args.base, head).\n";
scope_prompt += "5. none of the above → base = origin/main (fetch if needed), head = HEAD, merge-base comparison.\n\n";
scope_prompt += "Rules:\n";
scope_prompt += "- Record base_sha, head_sha, merge_base_sha via git rev-parse (full SHAs).\n";
scope_prompt += "- Diff is three-dot: git diff <merge_base_sha>...<head_sha> (or single-commit range for commit mode).\n";
scope_prompt += "- Reject empty diffs (ok=false, error explains).\n";
scope_prompt += "- If the worktree is dirty and allow_dirty is not true, set ok=false and explain; do not stash/clean.\n";
scope_prompt += "- Create artifact_dir under ${TMPDIR:-/tmp}/review-gauntlet-<utc>-<pid> with mode 0700.\n";
scope_prompt += "- Write scope.json and brief.md into artifact_dir.\n";
scope_prompt += "- brief: combine args.brief with observed diff_stat and key changed paths; no secrets, no .env contents.\n";
scope_prompt += "- branch_name: current or reviewed branch short name for Grok /review --branch.\n";
scope_prompt += "- changed_files: list from git diff --name-only (cap 200).\n";
scope_prompt += "- Use shell (git, mkdir, python3). Read AGENTS.md / README only as needed for brief context.\n";
scope_prompt += "- Return the schema fields. ok=true only when SHAs resolve and the diff is non-empty.\n";

let scope_res = agent(scope_prompt, #{
    label: "scope",
    capability_mode: "execute",
    output_schema: scope_schema,
});

let scope_ok = false;
let base_ref = "";
let base_sha = "";
let head_ref = "HEAD";
let head_sha = "";
let merge_base_sha = "";
let diff_stat = "";
let changed_files = [];
let branch_name = "";
let artifact_dir = "";
let brief = user_brief;
let scope_error = "scope agent failed";

if scope_res != () && scope_res.success && scope_res.output != () {
    let o = scope_res.output;
    if o.ok != () { scope_ok = o.ok == true; }
    if o.base_ref != () { base_ref = trimmed(o.base_ref.to_string()); }
    if o.base_sha != () { base_sha = trimmed(o.base_sha.to_string()); }
    if o.head_ref != () { head_ref = trimmed(o.head_ref.to_string()); }
    if o.head_sha != () { head_sha = trimmed(o.head_sha.to_string()); }
    if o.merge_base_sha != () { merge_base_sha = trimmed(o.merge_base_sha.to_string()); }
    if o.diff_stat != () { diff_stat = trimmed(o.diff_stat.to_string()); }
    if o.branch_name != () { branch_name = trimmed(o.branch_name.to_string()); }
    if o.artifact_dir != () { artifact_dir = trimmed(o.artifact_dir.to_string()); }
    if o.brief != () {
        let b = trimmed(o.brief.to_string());
        if b != "" { brief = b; }
    }
    if o.error != () { scope_error = trimmed(o.error.to_string()); }
    if o.changed_files != () && type_of(o.changed_files) == "array" {
        changed_files = o.changed_files;
    }
}

if !scope_ok {
    // Smoke-check / partial path: synthesize a minimal scope so later phases can run closed.
    if artifact_dir == "" {
        artifact_dir = "scratch";
    }
    if base_sha == "" { base_sha = "UNKNOWN_BASE"; }
    if head_sha == "" { head_sha = "UNKNOWN_HEAD"; }
    if merge_base_sha == "" { merge_base_sha = base_sha; }
    if branch_name == "" { branch_name = "HEAD"; }
    if brief == "" { brief = user_brief; }
    if brief == "" { brief = "Review current branch changes."; }
    log("Scope incomplete (" + scope_error + ") — continuing with best-effort scope for this run");
}

log("Scope base=" + base_sha + " head=" + head_sha + " merge_base=" + merge_base_sha + " artifacts=" + artifact_dir);

let ledger = "";
ledger = append_ledger_line(ledger, "# Review Gauntlet Ledger");
ledger = append_ledger_line(ledger, "");
ledger = append_ledger_line(ledger, "- mode: " + mode);
ledger = append_ledger_line(ledger, "- base: " + base_ref + " (" + base_sha + ")");
ledger = append_ledger_line(ledger, "- head: " + head_ref + " (" + head_sha + ")");
ledger = append_ledger_line(ledger, "- merge_base: " + merge_base_sha);
ledger = append_ledger_line(ledger, "- max_rounds: " + max_rounds.to_string());
ledger = append_ledger_line(ledger, "- artifact_dir: " + artifact_dir);
ledger = append_ledger_line(ledger, "");

let all_fixed = [];
let all_skipped = [];
let all_deferred = [];
let all_overrides = [];
let round_summaries = [];
let prev_do_fp = "";
let stall_streak = 0;
let stop_reason = "";
let final_round = 0;

// --- Loop: Review → Triage → Fix --------------------------------------------

let round = 0;
while round < max_rounds {
    round += 1;
    final_round = round;
    log("=== Round " + round.to_string() + " / " + max_rounds.to_string() + " ===");

    // Refresh head SHA each round after fixes land on the branch.
    phase("Review");
    let round_dir = artifact_dir + "/round-" + round.to_string();

    let scope_blob = "";
    scope_blob += "Immutable comparison for THIS round:\n";
    scope_blob += "- original_base_sha: " + base_sha + "\n";
    scope_blob += "- merge_base_sha: " + merge_base_sha + "\n";
    scope_blob += "- review head: current HEAD of the working branch (re-resolve with git rev-parse HEAD)\n";
    scope_blob += "- three-dot diff: git diff " + merge_base_sha + "...HEAD\n";
    scope_blob += "- branch_name for Grok: " + branch_name + "\n";
    scope_blob += "- round artifact dir: " + round_dir + "\n";
    scope_blob += "- brief:\n" + brief + "\n";

    let review_jobs = [];

    // --- Fable ---------------------------------------------------------------
    if reviewer_enabled(args, "fable") {
        let p = "";
        p += "Run an EXTERNAL Fable code review. You orchestrate only; Fable authors the findings.\n";
        p += "Do not edit application source. Do not implement fixes.\n\n";
        p += scope_blob + "\n";
        p += "Steps:\n";
        p += "1. mkdir -p the round artifact dir and a fable/ subdir (mode 0700).\n";
        p += "2. Write prompt.md for Fable. Prompt must say:\n";
        p += "   - You are the trusted senior reviewer (claude-fable-5).\n";
        p += "   - Review-only: no edits, commits, pushes, or GitHub comments.\n";
        p += "   - Focus: correctness, regressions, architecture, security, data integrity, missing tests.\n";
        p += "   - Ignore pure style nits unless they hide a real risk.\n";
        p += "   - Inspect with Read+Bash: git diff " + merge_base_sha + "...HEAD and full files for large changes.\n";
        p += "   - Output: findings first by severity with file/line refs; explicit no-findings if clean.\n";
        p += "   - Include the brief and scope SHAs.\n";
        p += "3. Run (expect 10+ minutes; do not cancel early):\n";
        p += "   SESSION=fable-r" + round.to_string() + "-$(date -u +%Y%m%dT%H%M%SZ)\n";
        p += "   Use zmx if available, else run foreground:\n";
        p += "   claude -p --model claude-fable-5 --effort high \\\n";
        p += "     --output-format stream-json --include-partial-messages --include-hook-events \\\n";
        p += "     --tools 'Read,Bash' --allowedTools 'Read,Bash' \\\n";
        p += "     < prompt.md > stream.jsonl 2> stderr.log\n";
        p += "4. Parse the final stream-json event type=result with non-empty result text → review.md.\n";
        p += "5. Return status=completed with review_path, finding_count estimate, findings_excerpt (first ~4k chars),\n";
        p += "   summary one paragraph. On failure: status=failed and error. Never invent findings.\n";
        review_jobs.push(#{
            prompt: p,
            label: "review:fable:r" + round.to_string(),
            capability_mode: "execute",
            output_schema: review_schema,
        });
    } else {
        log("Skipping fable (args.skip_reviewers)");
    }

    // --- Grok ----------------------------------------------------------------
    if reviewer_enabled(args, "grok") {
        let p = "";
        p += "Run an EXTERNAL independent Grok Build code review via the grok-review skill wrapper.\n";
        p += "Do not edit application source. Do not implement fixes.\n\n";
        p += scope_blob + "\n";
        p += "Steps:\n";
        p += "1. mkdir -p round artifact grok/ subdir.\n";
        p += "2. Resolve wrapper: $HOME/.agents/skills/grok-review/scripts/run_review.sh\n";
        p += "   (or search nearby managed skill roots if missing).\n";
        p += "3. Write prompt.md containing EXACTLY one line:\n";
        p += "   /review --branch " + branch_name + "\n";
        p += "   If branch_name is empty or detached, use the current branch short name from git.\n";
        p += "4. REPO=$(git rev-parse --show-toplevel)\n";
        p += "   RUN_DIR=<artifact>/grok/run\n";
        p += "   bash run_review.sh start \"$REPO\" \"$PROMPT\" \"$RUN_DIR\"\n";
        p += "   bash run_review.sh wait \"$RUN_DIR\"\n";
        p += "5. Copy RUN_DIR/review.md to <artifact>/grok/review.md when non-empty.\n";
        p += "6. On hang/timeout use run_review.sh stop. Do not drop the read-only sandbox.\n";
        p += "7. Return schema: reviewer=grok, status, review_path, findings_excerpt, finding_count, summary, error.\n";
        p += "   Never invent findings. status=empty if review says no findings.\n";
        review_jobs.push(#{
            prompt: p,
            label: "review:grok:r" + round.to_string(),
            capability_mode: "execute",
            output_schema: review_schema,
        });
    } else {
        log("Skipping grok (args.skip_reviewers)");
    }

    // --- Codex ---------------------------------------------------------------
    if reviewer_enabled(args, "codex") {
        let p = "";
        p += "Run an EXTERNAL Codex non-interactive code review. Do not edit application source.\n\n";
        p += scope_blob + "\n";
        p += "Steps:\n";
        p += "1. mkdir -p round artifact codex/ subdir.\n";
        p += "2. Prefer: codex exec review --base " + merge_base_sha + " \\\n";
        p += "     -o <artifact>/codex/review.md --ephemeral\n";
        p += "   If --base with a SHA fails, try --base with the base branch name (" + base_ref + ").\n";
        p += "   For single-commit mode when args said commit, you may use: codex exec review --commit <sha> -o ...\n";
        p += "3. Sandbox: read-only is fine; do not pass dangerously-bypass flags.\n";
        p += "4. Custom prompt via stdin optional: focus on correctness, regressions, API contracts, tests.\n";
        p += "5. If review.md missing, capture stdout/stderr into review.md / error logs.\n";
        p += "6. Return schema reviewer=codex with status completed|failed|empty, paths, excerpts. No invented findings.\n";
        review_jobs.push(#{
            prompt: p,
            label: "review:codex:r" + round.to_string(),
            capability_mode: "execute",
            output_schema: review_schema,
        });
    } else {
        log("Skipping codex (args.skip_reviewers)");
    }

    // --- Thermonuclear -------------------------------------------------------
    if reviewer_enabled(args, "thermo") {
        let p = "";
        p += "Run a Thermonuclear (thermo-nuclear-code-review) structural review. Review-only; no edits.\n\n";
        p += scope_blob + "\n";
        p += "Steps:\n";
        p += "1. mkdir -p round artifact thermo/ subdir.\n";
        p += "2. Locate the skill SKILL.md at:\n";
        p += "   $HOME/.agents/skills/thermo-nuclear-code-review/SKILL.md\n";
        p += "   (search managed skill roots if needed).\n";
        p += "3. Preferred runner — Pi non-interactive with the skill:\n";
        p += "   Write prompt.md that says: use thermo-nuclear-code-review standards on\n";
        p += "   git diff " + merge_base_sha + "...HEAD ; full-file reads for large changes;\n";
        p += "   end with exactly one verdict line: **APPROVE** / **RETHINK** / **REFINE**.\n";
        p += "   pi --print --no-session --no-extensions --no-prompt-templates \\\n";
        p += "     --skill <path-to-SKILL.md> --tools read,bash,grep,find,ls @prompt.md\n";
        p += "     > review.partial.md 2> stderr.log\n";
        p += "4. If pi is unavailable, YOU perform the thermonuclear review yourself by reading\n";
        p += "   the SKILL.md standards and applying them with read_file/grep/git diff — same output format.\n";
        p += "5. Validate final line is a single plugin verdict. Move to review.md.\n";
        p += "6. Return schema reviewer=thermo. Structural findings only; no fake correctness bugs.\n";
        review_jobs.push(#{
            prompt: p,
            label: "review:thermo:r" + round.to_string(),
            capability_mode: "execute",
            output_schema: review_schema,
        });
    } else {
        log("Skipping thermo (args.skip_reviewers)");
    }

    if review_jobs.len() == 0 {
        pause("verification", "All reviewers were skipped via args.skip_reviewers. Enable at least one of: fable, grok, codex, thermo.");
    }

    let review_results = parallel(review_jobs);

    let reviews = [];
    let review_bundle = "";
    review_bundle += "# Round " + round.to_string() + " raw reviews\n\n";
    let completed_reviews = 0;
    let total_findings = 0;

    for r in review_results {
        if r == () || !r.success || r.output == () {
            let failed = empty_review("unknown", "failed", "reviewer agent failed or returned no output");
            reviews.push(failed);
            review_bundle += "## (failed reviewer slot)\nAgent failed.\n\n";
            continue;
        }
        let o = r.output;
        let reviewer = if o.reviewer != () { trimmed(o.reviewer.to_string()) } else { "unknown" };
        let status = if o.status != () { trimmed(o.status.to_string()) } else { "failed" };
        let review_path = if o.review_path != () { trimmed(o.review_path.to_string()) } else { "" };
        let summary = if o.summary != () { trimmed(o.summary.to_string()) } else { "" };
        let excerpt = if o.findings_excerpt != () { trimmed(o.findings_excerpt.to_string()) } else { "" };
        let err = if o.error != () { trimmed(o.error.to_string()) } else { "" };
        let fc = 0;
        if o.finding_count != () {
            if type_of(o.finding_count) == "i64" || type_of(o.finding_count) == "f64" {
                fc = o.finding_count;
            }
        }
        if status == "completed" || status == "empty" {
            completed_reviews += 1;
        }
        total_findings += fc;
        reviews.push(o);
        review_bundle += "## " + reviewer + " (" + status + ")\n";
        if review_path != "" { review_bundle += "path: " + review_path + "\n"; }
        if summary != "" { review_bundle += "summary: " + summary + "\n"; }
        if err != "" { review_bundle += "error: " + err + "\n"; }
        review_bundle += "\n" + excerpt + "\n\n";
        log("Reviewer " + reviewer + " status=" + status + " findings~" + fc.to_string());
    }

    let bundle_name = "round-" + round.to_string() + "-reviews.md";
    let bundle_path = write_scratch_file(bundle_name, review_bundle);
    log("Review bundle " + bundle_path + " completed_reviewers=" + completed_reviews.to_string() + " finding_signal~" + total_findings.to_string());

    // --- Triage (Fable judge) ------------------------------------------------
    phase("Triage");

    let prior = "";
    prior += "Previously fixed this run: " + json_encode(all_fixed) + "\n";
    prior += "Previously skipped: " + json_encode(all_skipped) + "\n";
    prior += "Previously deferred: " + json_encode(all_deferred) + "\n";

    // Snapshot reviewer rows for the final report (before triage mutates nothing).
    let reviewer_rows = [];
    for o in reviews {
        if o == () { continue; }
        let rn = if o.reviewer != () { trimmed(o.reviewer.to_string()) } else { "unknown" };
        let st = if o.status != () { trimmed(o.status.to_string()) } else { "failed" };
        let rp = if o.review_path != () { trimmed(o.review_path.to_string()) } else { "" };
        let fc = 0;
        if o.finding_count != () {
            if type_of(o.finding_count) == "i64" || type_of(o.finding_count) == "f64" {
                fc = o.finding_count;
            }
        }
        let sm = if o.summary != () { trimmed(o.summary.to_string()) } else { "" };
        reviewer_rows.push(#{
            reviewer: rn,
            status: st,
            finding_count: fc,
            review_path: rp,
            summary: sm,
        });
    }

    let triage_prompt = "";
    triage_prompt += "You orchestrate a SEPARATE Fable judge that triages multi-reviewer feedback.\n";
    triage_prompt += "You do not implement code. You produce the triage schema after Fable decides.\n\n";
    triage_prompt += "Round: " + round.to_string() + "\n";
    triage_prompt += scope_blob + "\n";
    triage_prompt += "Prior decisions this run:\n" + prior + "\n";
    triage_prompt += "Review bundle path (scratch): " + bundle_path + "\n";
    triage_prompt += "Also re-read each reviewer review_path when present on disk.\n\n";
    triage_prompt += triage_doctrine() + "\n";
    triage_prompt += fable_authority_rules() + "\n";
    triage_prompt += "How to run the Fable judge:\n";
    triage_prompt += "1. Write judge-prompt.md under " + round_dir + "/triage/ including doctrine, scope, prior decisions,\n";
    triage_prompt += "   and the full review bundle text (read the scratch file / review.md files).\n";
    triage_prompt += "2. Ask Fable to return markdown with three sections: DO_NOW, SKIP, DEFER, each with id, title,\n";
    triage_prompt += "   source reviewer(s), files, and reasons. Cap DO_NOW at 12 high-signal items.\n";
    triage_prompt += "3. Run: claude -p --model claude-fable-5 --effort high --output-format stream-json \\\n";
    triage_prompt += "     --tools 'Read,Bash' --allowedTools 'Read,Bash' < judge-prompt.md > stream.jsonl\n";
    triage_prompt += "   (zmx optional). Parse final result text into fable-judge-result.md; set fable_judge_path.\n";
    triage_prompt += "4. If claude/Fable is unavailable, YOU apply the same doctrine yourself as a strict judge,\n";
    triage_prompt += "   reading the cited code paths before accepting any item — label source as judge:local-fallback.\n";
    triage_prompt += "5. Map Fable's decision into the output schema per FABLE AUTHORITY rules above.\n";
    triage_prompt += "   fable_do_now = Fable's DO_NOW verbatim. do_now = fable_do_now minus hard-disproven only.\n";
    triage_prompt += "   overrides = demotions with concrete evidence. stop=true only when final do_now is empty.\n";
    triage_prompt += "6. ids: stable like r" + round.to_string() + "-fable-1, r" + round.to_string() + "-codex-2, etc.\n";

    let triage_res = agent(triage_prompt, #{
        label: "triage:fable:r" + round.to_string(),
        capability_mode: "execute",
        output_schema: triage_schema,
    });

    let do_now = [];
    let fable_do_now = [];
    let skip = [];
    let defer = [];
    let overrides = [];
    let triage_rationale = "";
    let triage_stop = false;
    let triage_stop_reason = "";
    let fable_judge_path = "";

    if triage_res != () && triage_res.success && triage_res.output != () {
        let t = triage_res.output;
        if t.fable_do_now != () && type_of(t.fable_do_now) == "array" { fable_do_now = t.fable_do_now; }
        if t.do_now != () && type_of(t.do_now) == "array" { do_now = t.do_now; }
        if t.skip != () && type_of(t.skip) == "array" { skip = t.skip; }
        if t.defer != () && type_of(t.defer) == "array" { defer = t.defer; }
        if t.overrides != () && type_of(t.overrides) == "array" { overrides = t.overrides; }
        if t.rationale != () { triage_rationale = trimmed(t.rationale.to_string()); }
        if t.stop != () { triage_stop = t.stop == true; }
        if t.stop_reason != () { triage_stop_reason = trimmed(t.stop_reason.to_string()); }
        if t.fable_judge_path != () { fable_judge_path = trimmed(t.fable_judge_path.to_string()); }

        // If the agent forgot fable_do_now but filled do_now, treat do_now as Fable's list.
        if fable_do_now.len() == 0 && do_now.len() > 0 {
            fable_do_now = do_now;
        }
        // Soft guard: if fable_do_now is non-empty but do_now was emptied without overrides,
        // restore Fable's list (orchestrator may not silently veto).
        if fable_do_now.len() > 0 && do_now.len() == 0 && overrides.len() == 0 {
            log("Triage emptied do_now without overrides — restoring fable_do_now (Fable authority)");
            do_now = fable_do_now;
            triage_stop = false;
            triage_stop_reason = "";
        }
    } else {
        log("Triage agent failed — treating as stop with no fixes this round");
        triage_stop = true;
        triage_stop_reason = "triage agent failed; fail closed without inventing work";
    }

    // Accumulate skip/defer/overrides ledger
    for s in skip {
        all_skipped.push(s);
    }
    for d in defer {
        all_deferred.push(d);
    }
    for ov in overrides {
        all_overrides.push(ov);
        log("fable_do_now_overridden id=" + (if ov.id != () { trimmed(ov.id.to_string()) } else { "?" }));
    }

    ledger = append_ledger_line(ledger, "## Round " + round.to_string() + " triage");
    ledger = append_ledger_line(ledger, "- fable_do_now: " + fable_do_now.len().to_string());
    ledger = append_ledger_line(ledger, "- do_now (final): " + do_now.len().to_string());
    ledger = append_ledger_line(ledger, "- overrides: " + overrides.len().to_string());
    ledger = append_ledger_line(ledger, "- skip: " + skip.len().to_string());
    ledger = append_ledger_line(ledger, "- defer: " + defer.len().to_string());
    if fable_judge_path != "" {
        ledger = append_ledger_line(ledger, "- fable_judge_path: " + fable_judge_path);
    }
    if triage_rationale != "" {
        ledger = append_ledger_line(ledger, "- rationale: " + triage_rationale);
    }
    for ov in overrides {
        let oid = if ov.id != () { trimmed(ov.id.to_string()) } else { "?" };
        let otitle = if ov.title != () { trimmed(ov.title.to_string()) } else { "?" };
        let oreason = if ov.reason != () { trimmed(ov.reason.to_string()) } else { "" };
        let oev = if ov.evidence != () { trimmed(ov.evidence.to_string()) } else { "" };
        ledger = append_ledger_line(ledger, "- OVERRIDE " + oid + ": " + otitle);
        if oreason != "" { ledger = append_ledger_line(ledger, "  reason: " + oreason); }
        if oev != "" { ledger = append_ledger_line(ledger, "  evidence: " + oev); }
    }

    let do_fp = do_now_fingerprint(do_now);
    if do_fp != "" && do_fp == prev_do_fp {
        stall_streak += 1;
        log("Stall detected: identical do_now fingerprint (" + stall_streak.to_string() + " streak)");
    } else {
        stall_streak = 0;
    }
    prev_do_fp = do_fp;

    if do_now.len() == 0 || triage_stop {
        stop_reason = triage_stop_reason;
        if stop_reason == "" {
            stop_reason = "No do_now items after Fable triage on round " + round.to_string();
        }
        log("Stopping: " + stop_reason);
        round_summaries.push(#{
            round: round,
            reviewers: reviewer_rows,
            review_bundle: bundle_path,
            fable_do_now_count: fable_do_now.len(),
            fable_do_now: fable_do_now,
            do_now_count: 0,
            do_now: [],
            overrides: overrides,
            fable_judge_path: fable_judge_path,
            fixed_count: 0,
            stop: true,
            reason: stop_reason,
        });
        break;
    }

    if stall_streak >= 2 {
        stop_reason = "Stall: the same do_now set repeated twice — stopping to avoid thrash";
        log(stop_reason);
        round_summaries.push(#{
            round: round,
            reviewers: reviewer_rows,
            review_bundle: bundle_path,
            fable_do_now_count: fable_do_now.len(),
            fable_do_now: fable_do_now,
            do_now_count: do_now.len(),
            do_now: do_now,
            overrides: overrides,
            fable_judge_path: fable_judge_path,
            fixed_count: 0,
            stop: true,
            reason: stop_reason,
        });
        break;
    }

    // --- Fix -----------------------------------------------------------------
    phase("Fix");

    let fix_prompt = "";
    fix_prompt += "You implement ONLY the accepted review items below on the current branch.\n";
    fix_prompt += "Do not expand scope. Do not over-engineer. Prefer the smallest correct fix.\n\n";
    fix_prompt += scope_blob + "\n";
    fix_prompt += "ACCEPTED ITEMS (do_now) — implement these and nothing else:\n";
    fix_prompt += format_do_now(do_now) + "\n";
    fix_prompt += "Rules:\n";
    fix_prompt += "1. Read the cited code before editing. Verify each item still exists on HEAD.\n";
    fix_prompt += "2. If an item is wrong, already fixed, or would require a large speculative rewrite, put it in blocked with reason — do not force it.\n";
    fix_prompt += "3. No drive-by refactors, no new frameworks, no golden-path rewrites for rare edges.\n";
    fix_prompt += "4. Match repo patterns (AGENTS.md and nearby code). Add/adjust the smallest test that proves a real fix when appropriate.\n";
    fix_prompt += "5. Run the most focused verification you can (targeted test/lint). Record what you ran.\n";
    fix_prompt += "6. Commit logical units on the current branch with clear messages like:\n";
    fix_prompt += "   review-gauntlet(r" + round.to_string() + "): <short why>\n";
    fix_prompt += "   Do NOT push. Do NOT open/modify PRs. Do NOT force-push.\n";
    fix_prompt += "7. Return fixed[], blocked[], commit_shas, files_touched, verification, summary, status.\n";

    let fix_res = agent(fix_prompt, #{
        label: "fix:r" + round.to_string(),
        capability_mode: "all",
        output_schema: fix_schema,
    });

    let fixed = [];
    let blocked = [];
    let fix_status = "blocked";
    let fix_summary = "";
    let commit_shas = [];
    let files_touched = [];
    let verification = "";

    if fix_res != () && fix_res.success && fix_res.output != () {
        let f = fix_res.output;
        if f.fixed != () && type_of(f.fixed) == "array" { fixed = f.fixed; }
        if f.blocked != () && type_of(f.blocked) == "array" { blocked = f.blocked; }
        if f.status != () { fix_status = trimmed(f.status.to_string()); }
        if f.summary != () { fix_summary = trimmed(f.summary.to_string()); }
        if f.verification != () { verification = trimmed(f.verification.to_string()); }
        if f.commit_shas != () && type_of(f.commit_shas) == "array" { commit_shas = f.commit_shas; }
        if f.files_touched != () && type_of(f.files_touched) == "array" { files_touched = f.files_touched; }
    } else {
        fix_summary = "fix agent failed";
        log("Fix agent failed on round " + round.to_string());
    }

    for item in fixed {
        all_fixed.push(item);
    }
    for item in blocked {
        // Blocked accepted items become ledger skips so the next triage sees them.
        all_skipped.push(#{
            id: if item.id != () { item.id } else { "" },
            title: if item.title != () { item.title } else { "" },
            source: "fix-blocked",
            why_skip: if item.reason != () { item.reason } else { "blocked during fix" },
        });
    }

    ledger = append_ledger_line(ledger, "### Fix");
    ledger = append_ledger_line(ledger, "- status: " + fix_status);
    ledger = append_ledger_line(ledger, "- fixed: " + fixed.len().to_string());
    ledger = append_ledger_line(ledger, "- blocked: " + blocked.len().to_string());
    if fix_summary != "" {
        ledger = append_ledger_line(ledger, "- summary: " + fix_summary);
    }
    if verification != "" {
        ledger = append_ledger_line(ledger, "- verification: " + verification);
    }

    round_summaries.push(#{
        round: round,
        reviewers: reviewer_rows,
        review_bundle: bundle_path,
        fable_do_now_count: fable_do_now.len(),
        fable_do_now: fable_do_now,
        do_now_count: do_now.len(),
        do_now: do_now,
        overrides: overrides,
        fable_judge_path: fable_judge_path,
        fixed_count: fixed.len(),
        blocked_count: blocked.len(),
        fix_status: fix_status,
        commit_shas: commit_shas,
        stop: false,
        reason: fix_summary,
    });

    // If nothing was fixed, stop rather than re-reviewing the same tree forever.
    if fixed.len() == 0 {
        stop_reason = "Fix round produced no changes; stopping to avoid empty re-review loop";
        log(stop_reason);
        break;
    }

    // Budget headroom: each remaining round needs ~6 agents.
    let b = budget();
    let need = 6;
    if b.remaining < need && round < max_rounds {
        stop_reason = "Agent budget remaining (" + b.remaining.to_string() + ") too low for another full round";
        log(stop_reason);
        break;
    }
}

if stop_reason == "" {
    if final_round >= max_rounds {
        stop_reason = "Reached max_rounds=" + max_rounds.to_string();
    } else {
        stop_reason = "Loop finished";
    }
}

// --- Report ------------------------------------------------------------------

phase("Report");

let report = "";
report += "# Review Gauntlet Report\n\n";
report += stop_reason + "\n\n";
report += "## Scope\n\n";
report += "- mode: `" + mode + "`\n";
report += "- base: `" + base_ref + "` (`" + base_sha + "`)\n";
report += "- head (initial): `" + head_ref + "` (`" + head_sha + "`)\n";
report += "- merge_base: `" + merge_base_sha + "`\n";
report += "- branch: `" + branch_name + "`\n";
report += "- rounds_run: " + final_round.to_string() + " / " + max_rounds.to_string() + "\n";
report += "- artifact_dir: `" + artifact_dir + "`\n";
if changed_files.len() > 0 {
    report += "- changed_files (initial count): " + changed_files.len().to_string() + "\n";
}
report += "\n## Brief\n\n";
report += brief + "\n\n";
report += "## Totals\n\n";
report += "- fixed: " + all_fixed.len().to_string() + "\n";
report += "- skipped: " + all_skipped.len().to_string() + "\n";
report += "- deferred: " + all_deferred.len().to_string() + "\n";
report += "- fable_do_now_overridden: " + all_overrides.len().to_string() + "\n\n";

// Per-round reviewer signal + Fable pre/post
report += "## Per-round review signal\n\n";
if round_summaries.len() == 0 {
    report += "_No rounds completed._\n\n";
} else {
    for rs in round_summaries {
        let rn = if rs.round != () { rs.round.to_string() } else { "?" };
        report += "### Round " + rn + "\n\n";
        if rs.review_bundle != () && trimmed(rs.review_bundle.to_string()) != "" {
            report += "- review bundle (scratch): `" + trimmed(rs.review_bundle.to_string()) + "`\n";
        }
        if rs.fable_judge_path != () && trimmed(rs.fable_judge_path.to_string()) != "" {
            report += "- Fable judge writeup: `" + trimmed(rs.fable_judge_path.to_string()) + "`\n";
        }
        report += "\n| Reviewer | Status | Findings ~ | Path |\n";
        report += "|---|---|---:|---|\n";
        if rs.reviewers != () && type_of(rs.reviewers) == "array" {
            for row in rs.reviewers {
                let name = if row.reviewer != () { trimmed(row.reviewer.to_string()) } else { "?" };
                let st = if row.status != () { trimmed(row.status.to_string()) } else { "?" };
                let fc = "0";
                if row.finding_count != () { fc = row.finding_count.to_string(); }
                let path = if row.review_path != () { trimmed(row.review_path.to_string()) } else { "" };
                if path == "" { path = "_(none)_"; } else { path = "`" + path + "`"; }
                report += "| " + name + " | " + st + " | " + fc + " | " + path + " |\n";
            }
        } else {
            report += "| _(no reviewer rows)_ | | | |\n";
        }
        report += "\n";

        let fable_n = 0;
        let final_n = 0;
        if rs.fable_do_now_count != () { fable_n = rs.fable_do_now_count; }
        if rs.do_now_count != () { final_n = rs.do_now_count; }
        report += "**Fable judge DO_NOW (pre-override):** " + fable_n.to_string() + "\n\n";
        if rs.fable_do_now != () && type_of(rs.fable_do_now) == "array" && rs.fable_do_now.len() > 0 {
            for it in rs.fable_do_now {
                let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
                let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
                let sev = if it.severity != () { trimmed(it.severity.to_string()) } else { "?" };
                report += "- `[" + sev + "]` **" + id + "**: " + title + "\n";
            }
            report += "\n";
        } else {
            report += "_Empty._\n\n";
        }

        report += "**Final do_now (post-override):** " + final_n.to_string() + "\n\n";
        if rs.do_now != () && type_of(rs.do_now) == "array" && rs.do_now.len() > 0 {
            for it in rs.do_now {
                let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
                let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
                let sev = if it.severity != () { trimmed(it.severity.to_string()) } else { "?" };
                report += "- `[" + sev + "]` **" + id + "**: " + title + "\n";
            }
            report += "\n";
        } else {
            report += "_Empty._\n\n";
        }

        if rs.overrides != () && type_of(rs.overrides) == "array" && rs.overrides.len() > 0 {
            report += "**Overrides (Fable DO_NOW demoted by orchestrator):**\n\n";
            for ov in rs.overrides {
                let id = if ov.id != () { trimmed(ov.id.to_string()) } else { "?" };
                let title = if ov.title != () { trimmed(ov.title.to_string()) } else { "?" };
                let reason = if ov.reason != () { trimmed(ov.reason.to_string()) } else { "" };
                let evidence = if ov.evidence != () { trimmed(ov.evidence.to_string()) } else { "" };
                report += "- **" + id + "**: " + title + "\n";
                if reason != "" { report += "  - reason: " + reason + "\n"; }
                if evidence != "" { report += "  - evidence: " + evidence + "\n"; }
            }
            report += "\n";
        } else {
            report += "**Overrides:** none\n\n";
        }
    }
}

report += "## Fixed\n\n";
if all_fixed.len() == 0 {
    report += "_None._\n\n";
} else {
    for it in all_fixed {
        let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
        let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
        let how = if it.how != () { trimmed(it.how.to_string()) } else { "" };
        report += "- **" + id + "**: " + title + "\n";
        if how != "" { report += "  - " + how + "\n"; }
    }
    report += "\n";
}

report += "## Skipped (not worth doing / blocked)\n\n";
if all_skipped.len() == 0 {
    report += "_None._\n\n";
} else {
    let shown = 0;
    for it in all_skipped {
        if shown >= 40 {
            report += "- … truncated …\n";
            break;
        }
        let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
        let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
        let why = "";
        if it.why_skip != () { why = trimmed(it.why_skip.to_string()); }
        report += "- **" + id + "**: " + title;
        if why != "" { report += " — " + why; }
        report += "\n";
        shown += 1;
    }
    report += "\n";
}

report += "## Deferred\n\n";
if all_deferred.len() == 0 {
    report += "_None._\n\n";
} else {
    for it in all_deferred {
        let id = if it.id != () { trimmed(it.id.to_string()) } else { "?" };
        let title = if it.title != () { trimmed(it.title.to_string()) } else { "?" };
        let why = if it.why_defer != () { trimmed(it.why_defer.to_string()) } else { "" };
        report += "- **" + id + "**: " + title;
        if why != "" { report += " — " + why; }
        report += "\n";
    }
    report += "\n";
}

report += "## Fable DO_NOW overrides (all rounds)\n\n";
if all_overrides.len() == 0 {
    report += "_None — Fable's DO_NOW was not demoted._\n\n";
} else {
    for ov in all_overrides {
        let id = if ov.id != () { trimmed(ov.id.to_string()) } else { "?" };
        let title = if ov.title != () { trimmed(ov.title.to_string()) } else { "?" };
        let reason = if ov.reason != () { trimmed(ov.reason.to_string()) } else { "" };
        let evidence = if ov.evidence != () { trimmed(ov.evidence.to_string()) } else { "" };
        report += "- **" + id + "**: " + title + "\n";
        if reason != "" { report += "  - reason: " + reason + "\n"; }
        if evidence != "" { report += "  - evidence: " + evidence + "\n"; }
    }
    report += "\n";
}

report += "## Round log (JSON)\n\n";
report += "```json\n";
report += json_encode(round_summaries) + "\n";
report += "```\n\n";
report += "## Ledger\n\n";
report += ledger + "\n";

let report_path = write_scratch_file("review-gauntlet-report.md", report);
log("Report written to " + report_path);

complete(#{
    summary: stop_reason,
    report_path: report_path,
    artifact_dir: artifact_dir,
    rounds_run: final_round,
    max_rounds: max_rounds,
    fixed_count: all_fixed.len(),
    skipped_count: all_skipped.len(),
    deferred_count: all_deferred.len(),
    override_count: all_overrides.len(),
    fixed: all_fixed,
    skipped: all_skipped,
    deferred: all_deferred,
    overrides: all_overrides,
    round_summaries: round_summaries,
    scope: #{
        mode: mode,
        base_ref: base_ref,
        base_sha: base_sha,
        head_sha: head_sha,
        merge_base_sha: merge_base_sha,
        branch_name: branch_name,
    },
});
