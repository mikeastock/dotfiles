# Buildkite Reference (`bk` CLI first)

Use `bk` as the primary way to fetch and diagnose Buildkite failures.

## Prerequisites

- `bk` installed and authenticated
- organization selected (`bk use <org>`)

Quick auth check:

```bash
bk version
bk whoami
```

## Quick Reference

### Fetch latest failed build for current branch

```bash
pipeline=my-pipeline
branch=$(git branch --show-current)

bk build list --pipeline "$pipeline" --state failed --branch "$branch" --limit 1 --output json
```

### Fetch a specific build

```bash
pipeline=my-pipeline
build=1723
bk build view "$build" --pipeline "$pipeline" --output json
```

### Fetch failed jobs for a build

```bash
pipeline=my-pipeline
build=1723

bk api "/pipelines/$pipeline/builds/$build/jobs" \
  | jq '[.[] | select(.state == "failed") | {id, name, web_url, exit_status}]'
```

### Fetch logs for a failed job

```bash
pipeline=my-pipeline
build=1723
job=<job-id>

bk job log "$job" --pipeline "$pipeline" --build-number "$build" --no-timestamps
```

## URL Patterns

Buildkite URLs:

```
https://buildkite.com/<org>/<pipeline>/builds/<build-number>
https://buildkite.com/<org>/<pipeline>/builds/<build-number>#<job-id>
```

Extract pipeline + build from URL:

```bash
url='https://buildkite.com/myorg/app/builds/1234'
pipeline=$(printf '%s' "$url" | sed -E 's#https://buildkite.com/[^/]+/([^/]+)/builds/.*#\1#')
build=$(printf '%s' "$url" | sed -E 's#.*builds/([0-9]+).*#\1#')
```

## Failure Extraction Tips

After pulling job logs, extract actionable failures first:

```bash
rg -n "FAIL|FAILED|Error:|AssertionError|TypeError|SyntaxError|undefined method|cannot find" build.log
```

Prioritize:
- failing test + file + line
- compiler/linter/type-check errors
- first concrete root error (skip cascaded noise)

## Fallback Path (if `bk` is unavailable)

If `bk` cannot be used, fall back to API calls with:
- `BUILDKITE_API_TOKEN`
- `BUILDKITE_ORGANIZATION_SLUG`

Example:

```bash
curl -s -H "Authorization: Bearer $BUILDKITE_API_TOKEN" \
  "https://api.buildkite.com/v2/organizations/$BUILDKITE_ORGANIZATION_SLUG/pipelines/app/builds/1234"
```

## Troubleshooting

| Issue | Solution |
|------|----------|
| `bk` not installed | Install Buildkite CLI, then re-run |
| Not authenticated | Run `bk configure add` then `bk use <org>` |
| "No builds found" | Check pipeline slug, branch, and selected org |
| Build still running | Use `bk build watch <build> --pipeline <pipeline>` |
| API rate limiting | Wait and retry |
