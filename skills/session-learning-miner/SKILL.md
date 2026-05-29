---
name: session-learning-miner
description: Mine Pi or coding-agent session histories for repeated prompts, friction, workflows, and reusable learnings. Use when asked to comb through ~/.pi/agent/sessions, analyze agent sessions, extract prompt templates, identify skill candidates, or turn repeated session behavior into reusable agent assets.
---

# Session Learning Miner

Turn agent session history into reusable skills, prompt templates, docs, or workflow fixes.

## Workflow

1. Inventory the session store:
   - Count JSONL files under `~/.pi/agent/sessions`.
   - Group sessions by `cwd` from the first `session` record.
   - Note date ranges and the largest sessions.
2. Extract signal:
   - Read only structured JSONL records.
   - Pull user messages, assistant final summaries, command failures, review comments, and repeated short commands.
   - Normalize paths, URLs, SHAs, IDs, and quoted code before counting repeats.
3. Classify repeats:
   - **Prompt template**: short recurring invocation with stable steps.
   - **Skill**: multi-step workflow, domain taxonomy, tool protocol, or repeated judgment pattern.
   - **Config/script fix**: recurring failure that should disappear with automation.
   - **Ignore**: one-off project context, secrets, stale detours, or already-covered behavior.
4. Validate candidates:
   - Check this repo's `prompts/`, `skills/`, `plugins.toml`, and installed plugin skills to avoid duplicates.
   - Prefer improving an existing artifact when it clearly owns the workflow.
   - Add new artifacts only when session evidence shows repeat use.
5. Implement and verify:
   - Put Pi prompt templates in `prompts/*.md`.
   - Put custom skills in `skills/<skill-name>/SKILL.md`.
   - Follow https://agentskills.io/specification.md for skill frontmatter.
   - Follow Pi prompt-template docs for `description`, `argument-hint`, and argument expansion.
   - Run the build or targeted tests that prove artifacts are discoverable.

## Heuristics

- High exact-repeat count usually becomes a prompt template.
- Repeated corrections like "talk through this first" become guardrails inside the relevant template or skill.
- Repeated pasted skill bodies usually indicate the skill exists but needs a shorter prompt template to trigger it.
- Repeated project-specific domain taxonomies usually deserve a skill if they require consistent classification.
- Repeated operational failures may deserve a shell script, extension, or config change instead of a prompt.

## Privacy

- Do not quote long private transcript sections in final output.
- Summarize evidence with counts, categories, and short paraphrases.
- Redact secrets, tokens, private URLs, customer data, and long proprietary snippets.
- If a candidate depends on sensitive project details, keep those details in the local repo only and avoid public plugin paths.

## Minimal Analysis Snippet

Use Python when a quick structured pass is enough:

```bash
python3 - <<'PY'
import json, re
from collections import Counter
from pathlib import Path

root = Path.home() / ".pi" / "agent" / "sessions"
prompts = []

for path in sorted(root.rglob("*.jsonl")):
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        message = record.get("message")
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        text = "\n".join(
            part.get("text", "")
            for part in message.get("content", [])
            if isinstance(part, dict) and part.get("type") == "text"
        ).strip()
        if text:
            normalized = " ".join(text.lower().split())
            normalized = re.sub(r"https?://\S+", "URL", normalized)
            normalized = re.sub(r"@[\w./-]+", "@PATH", normalized)
            normalized = re.sub(r"\b[0-9a-f]{8,}\b", "HASH", normalized)
            prompts.append(normalized[:220])

for prompt, count in Counter(prompts).most_common(40):
    if count < 2:
        break
    print(f"{count:4d} {prompt}")
PY
```
