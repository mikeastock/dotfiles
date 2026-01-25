# Buildkite Reference

## Prerequisites

Environment variables must be set:
- `BUILDKITE_API_TOKEN` - Buildkite API token with read access
- `BUILDKITE_ORGANIZATION_SLUG` - Organization slug (e.g., `myorg`)

## Quick Reference

**Fetch failures for current branch:**
```bash
uv run {baseDir}/scripts/fetch_buildkite_failures.py
```

**Fetch specific build:**
```bash
uv run {baseDir}/scripts/fetch_buildkite_failures.py --build 1723
```

**Fetch different branch:**
```bash
uv run {baseDir}/scripts/fetch_buildkite_failures.py --branch main
```

**Fetch from specific pipeline:**
```bash
uv run {baseDir}/scripts/fetch_buildkite_failures.py --pipeline my-pipeline
```

## Script Output

The script outputs JSON with:
- Build info (number, branch, state, URL)
- Failed jobs with extracted errors
- Summary counts by error type

Example output:
```json
{
  "build": {
    "number": 1234,
    "branch": "feature-branch",
    "state": "failed",
    "commit": "abc123",
    "web_url": "https://buildkite.com/org/pipeline/builds/1234",
    "message": "Fix the thing"
  },
  "failures": [
    {
      "job_name": "rspec tests",
      "job_id": "job-uuid",
      "web_url": "https://buildkite.com/...",
      "errors": [
        {
          "test_name": "UserTest#test_validation",
          "file": "test/models/user_test.rb",
          "line": 42,
          "message": "Expected true, got false",
          "type": "test_failure"
        }
      ]
    }
  ],
  "summary": {
    "total_failed_jobs": 1,
    "test_failures": 1,
    "lint_errors": 0
  }
}
```

## URL Patterns

Buildkite URLs follow this pattern:
```
https://buildkite.com/<org>/<pipeline>/builds/<build-number>
https://buildkite.com/<org>/<pipeline>/builds/<build-number>#<job-id>
```

Extract build number from URL:
```bash
# From: https://buildkite.com/myorg/app/builds/1234
uv run {baseDir}/scripts/fetch_buildkite_failures.py --build 1234
```

## Error Types Detected

The script parses logs and extracts:

| Type | Detection Pattern |
|------|-------------------|
| `test_failure` | Minitest/RSpec failure output |
| `rubocop` | Rubocop violation format |
| `lint` | ESLint/Biome output |
| `typescript` | TSC error format |
| `pytest` | pytest FAILED lines |
| `ruff` | Ruff linting output |
| `go_test` | Go test failures |
| `go_compile` | Go compilation errors |
| `docker` | Docker errors |
| `permission` | Permission denied errors |

## API Direct Access

If you need to access the API directly:

**List builds for a pipeline:**
```bash
curl -s -H "Authorization: Bearer $BUILDKITE_API_TOKEN" \
  "https://api.buildkite.com/v2/organizations/$BUILDKITE_ORGANIZATION_SLUG/pipelines/app/builds?branch=$(git branch --show-current)&per_page=1"
```

**Get specific build:**
```bash
curl -s -H "Authorization: Bearer $BUILDKITE_API_TOKEN" \
  "https://api.buildkite.com/v2/organizations/$BUILDKITE_ORGANIZATION_SLUG/pipelines/app/builds/1234"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "BUILDKITE_API_TOKEN not set" | Export the environment variable |
| "BUILDKITE_ORGANIZATION_SLUG not set" | Export the environment variable |
| "No builds found" | Check branch name, pipeline slug |
| "Invalid token" | Regenerate token in Buildkite settings |
| Rate limiting | Wait and retry (API limit: 200 req/min) |
