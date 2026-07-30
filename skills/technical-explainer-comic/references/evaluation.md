# Evaluating this skill

Test the deterministic surface first, then instruction following in a fresh session.

## 1. Contract tests

Run from the dotfiles repository:

```bash
./tests/test-technical-explainer-comic.sh
python3 "${CODEX_HOME:-$HOME/.codex}/skills/.system/skill-creator/scripts/quick_validate.py" \
  skills/technical-explainer-comic
make build
./tests/test-make.sh
git diff --check
```

These prove manifest validation, HTML escaping, 16:9 checks, resource packaging, and the normal
dotfiles build.

## 2. Invocation tests

Use a fresh agent session with the installed skill catalog.

Positive prompts:

- `Explain this OAuth service as a technical comic with expandable request traces.`
- `Show me how this queue worker handles one job and 500 concurrent jobs in one HTML artifact.`
- `Use $technical-explainer-comic to trace sign-in, refresh, and a normal API request.`
- `Explain this pipeline as a technical comic, but use my mascot instead of the default character.`

Negative prompts that should not invoke it:

- `Generate one hero illustration for this article.`
- `Review this pull request for correctness.`
- `Give me a two-paragraph explanation of PKCE.`

Pass when all positive prompts select this skill and none of the negative prompts do.

## 3. Bounded forward test

Choose a small system with no user-facing authorization flow, such as a queue consumer,
scheduled job, event handler, or cache-invalidation path. It should have:

- one entry endpoint
- one persistent record
- one downstream call
- one expiry or failure path

Ask a fresh session:

```text
Use $technical-explainer-comic to inspect this implementation and build a four-panel
explainer. Stop after local browser QA; do not upload.
```

The session must produce:

- `evidence.md`
- `shot-list.md`
- `manifest.json`
- four separately generated 16:9 panel images
- rendered `index.html`
- deterministic validation output
- desktop and mobile browser evidence

Do not give the session the expected trace or panel content. The implementation under test is
the evidence. Pass only when:

- the story distinguishes establishment from one normal operation, or explicitly proves there
  is no separate establishment path
- the lifecycle or failure beat remains present
- registration, callback, token, refresh, or other authorization beats appear only when the
  evidence packet cites implementation code for them
- the legend labels describe how the three colors are actually used

## 4. Scoring rubric

Score each category from 0 to 2:

| Category | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Source accuracy | Unsupported claims | Mostly sourced | Every material claim sourced |
| Trace completeness | Major transition missing | Main path only | Establishment, normal operation, lifecycle, failure |
| Visual explanation | Decorative or slide-like | Mixed | One clear metaphor per panel |
| Technical drill-down | Vague details | Some exact mechanics | Entry points, state, lifetimes, checks |
| Artifact quality | Broken or unreadable | Works in one viewport | Desktop/mobile and interaction pass |

Require at least 9/10.

Hard failures:

- invented throughput guarantee
- combined multi-panel image instead of separate images
- credentials or customer data in the artifact
- broken image or missing alt text
- no expandable technical trace
- legend labels that do not match the panels
- upload claimed without a verified URL

## 5. Publication test

After the bounded test passes, repeat with publication enabled. Fetch the hosted index and every
panel asset. Record the URL and HTTP results. Missing credentials are a test-environment blocker,
not a skill failure, when the local artifact and validation evidence are complete.
