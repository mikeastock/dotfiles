# GitHub Actions Reference

## Prerequisites

- `gh` CLI installed and authenticated (`gh auth login`)
- Repository access (push or collaborator permissions for private repos)

## Quick Reference

**List recent workflow runs:**
```bash
gh run list
```

**List failed runs only:**
```bash
gh run list --status failure
```

**List runs for current branch:**
```bash
gh run list --branch "$(git branch --show-current)"
```

**View a specific run:**
```bash
gh run view <run-id>
```

**View with job details:**
```bash
gh run view <run-id> --verbose
```

**View logs for failed steps only:**
```bash
gh run view <run-id> --log-failed
```

**View full log:**
```bash
gh run view <run-id> --log
```

**View specific job:**
```bash
gh run view --job <job-id>
```

**Get JSON output for parsing:**
```bash
gh run view <run-id> --json jobs,conclusion,name,headBranch
```

**Open in browser:**
```bash
gh run view <run-id> --web
```

## URL Patterns

GitHub Actions URLs follow this pattern:
```
https://github.com/<owner>/<repo>/actions/runs/<run-id>
https://github.com/<owner>/<repo>/actions/runs/<run-id>/job/<job-id>
```

Extract run ID from URL:
```bash
# From: https://github.com/owner/repo/actions/runs/12345678
run_id="12345678"
gh run view "$run_id" --log-failed
```

## Common Workflows

### Get latest failed run for current branch

```bash
# Get the run ID
run_id=$(gh run list --branch "$(git branch --show-current)" --status failure --limit 1 --json databaseId --jq '.[0].databaseId')

# View the failures
gh run view "$run_id" --log-failed
```

### Get all failed jobs from a run

```bash
gh run view <run-id> --json jobs --jq '.jobs[] | select(.conclusion == "failure") | {name: .name, steps: [.steps[] | select(.conclusion == "failure")]}'
```

### Re-run failed jobs

```bash
gh run rerun <run-id> --failed
```

## Output Parsing Tips

The `--log-failed` output shows logs for failed steps. Common patterns:

**Test failures** - Look for:
- `FAIL` or `FAILED` keywords
- Stack traces with file:line references
- Assertion errors

**Build failures** - Look for:
- `error:` or `Error:` prefixes
- Exit code messages
- Missing dependency errors

**Lint failures** - Look for:
- File:line:column format
- Rule names/codes
- `warning:` and `error:` prefixes

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "not logged in" | Run `gh auth login` |
| "repository not found" | Check you have access, or use `-R owner/repo` |
| "run not found" | Verify run ID, check if run was deleted |
| Truncated logs | Use `gh run view --log` for full output, or download artifacts |
