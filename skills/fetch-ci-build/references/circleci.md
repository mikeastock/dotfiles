# CircleCI Reference

## Prerequisites

Environment variables must be set:
- `CIRCLECI_TOKEN` - CircleCI personal API token

The script auto-detects project slug from git remote URL.

## Quick Reference

**Fetch failures for current branch:**
```bash
uv run {baseDir}/scripts/fetch_circleci_failures.py
```

**Fetch specific pipeline/workflow:**
```bash
uv run {baseDir}/scripts/fetch_circleci_failures.py --pipeline <pipeline-id>
```

**Fetch different branch:**
```bash
uv run {baseDir}/scripts/fetch_circleci_failures.py --branch main
```

**Specify project explicitly:**
```bash
uv run {baseDir}/scripts/fetch_circleci_failures.py --project gh/owner/repo
```

## Script Output

The script outputs JSON with:
- Pipeline/workflow info
- Failed jobs with extracted errors
- Summary counts by error type

Example output:
```json
{
  "pipeline": {
    "id": "pipeline-uuid",
    "number": 456,
    "branch": "feature-branch",
    "state": "failed",
    "web_url": "https://app.circleci.com/pipelines/github/owner/repo/456"
  },
  "failures": [
    {
      "job_name": "test",
      "job_id": "job-uuid",
      "web_url": "https://app.circleci.com/...",
      "errors": [
        {
          "test_name": "test_user_creation",
          "file": "tests/test_user.py",
          "line": 25,
          "message": "AssertionError: expected 1, got 0",
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

CircleCI URLs follow these patterns:
```
https://app.circleci.com/pipelines/github/<owner>/<repo>/<pipeline-number>
https://app.circleci.com/pipelines/github/<owner>/<repo>/<pipeline-number>/workflows/<workflow-id>
https://app.circleci.com/pipelines/github/<owner>/<repo>/<pipeline-number>/workflows/<workflow-id>/jobs/<job-number>
```

Extract from URL:
```bash
# From: https://app.circleci.com/pipelines/github/owner/repo/456
uv run {baseDir}/scripts/fetch_circleci_failures.py --project gh/owner/repo --pipeline 456
```

## Error Types Detected

The script parses logs and extracts:

| Type | Detection Pattern |
|------|-------------------|
| `test_failure` | pytest/unittest/RSpec output |
| `lint` | Linter output (file:line format) |
| `typescript` | TSC error format |
| `build_error` | Compilation failures |
| `exit_status` | Non-zero exit codes |

## API Direct Access

If you need to access the API directly:

**Get project pipelines:**
```bash
curl -s -H "Circle-Token: $CIRCLECI_TOKEN" \
  "https://circleci.com/api/v2/project/gh/owner/repo/pipeline?branch=$(git branch --show-current)"
```

**Get pipeline workflows:**
```bash
curl -s -H "Circle-Token: $CIRCLECI_TOKEN" \
  "https://circleci.com/api/v2/pipeline/<pipeline-id>/workflow"
```

**Get workflow jobs:**
```bash
curl -s -H "Circle-Token: $CIRCLECI_TOKEN" \
  "https://circleci.com/api/v2/workflow/<workflow-id>/job"
```

**Get job details (includes output URL):**
```bash
curl -s -H "Circle-Token: $CIRCLECI_TOKEN" \
  "https://circleci.com/api/v2/project/gh/owner/repo/job/<job-number>"
```

## CircleCI CLI

The `circleci` CLI is primarily for config validation and local execution, not for fetching build results. Use the script or API for that.

**Useful CLI commands:**
```bash
# Validate config
circleci config validate

# Run job locally
circleci local execute --job <job-name>

# Open project in browser
circleci open
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "CIRCLECI_TOKEN not set" | Export the environment variable |
| "Project not found" | Check project slug format (gh/owner/repo or bb/owner/repo) |
| "No pipelines found" | Check branch name, ensure CI has run |
| "Unauthorized" | Regenerate token in CircleCI user settings |
| Rate limiting | Wait and retry |
