# GitHub CLI / API Notes For `babysit-pr`

Use `gh` for every GitHub operation. Do not use a harness-provided GitHub connector.

## Primary commands used

### PR metadata

- `gh pr view --json number,url,state,mergedAt,closedAt,headRefName,headRefOid,headRepository,headRepositoryOwner`

Used to resolve PR number, URL, branch, head SHA, and closed/merged state.

### PR checks summary

- `gh pr checks --json name,state,bucket,link,workflow,event,startedAt,completedAt`

Used to compute pending/failed/passed counts and whether the current CI round is terminal.

### Workflow runs for head SHA

- `gh api repos/{owner}/{repo}/actions/runs -X GET -f head_sha=<sha> -f per_page=100`

Used to discover failed workflow runs and rerunnable run IDs.

### Failed log inspection

- `gh run view <run-id> --json jobs,name,workflowName,conclusion,status,url,headSha`
- `gh api repos/{owner}/{repo}/actions/runs/{run_id}/jobs -X GET -f per_page=100`
- `gh api repos/{owner}/{repo}/actions/jobs/{job_id}/logs > /tmp/codex-gh-job-{job_id}-logs.zip`
- `gh run view <run-id> --log-failed`

Used by Codex to classify branch-related vs flaky/unrelated failures. Prefer the direct job log endpoint as soon as a job has failed because `gh run view --log-failed` may not produce failed-job logs until the overall workflow run completes.

### Retry failed jobs only

- `gh run rerun <run-id> --failed`

Reruns only failed jobs (and dependencies) for a workflow run.

## Review-related endpoints

Use better-github-skill's reports as the primary read path:

- `node ~/.agents/skills/better-github-skill/scripts/pr-snapshot.ts <pr> --json`
- `node ~/.agents/skills/better-github-skill/scripts/pr-threads.ts <pr> --all --full --json`

The thread report combines review bodies, issue comments, and inline threads with resolution and
outdated state. `--all` and `--full` ensure hidden or truncated feedback is not missed. The underlying
REST endpoints are:

- Issue comments on PR:
  - `gh api repos/{owner}/{repo}/issues/<pr_number>/comments?per_page=100`
- Inline PR review comments:
  - `gh api repos/{owner}/{repo}/pulls/<pr_number>/comments?per_page=100`
- Review submissions:
  - `gh api repos/{owner}/{repo}/pulls/<pr_number>/reviews?per_page=100`

Use each inline comment's `pull_request_review_id` to find its parent review. Ignore parent reviews
whose `state` is `PENDING`, along with their inline comments, until the review is submitted.

### Review-thread state and resolution

REST review comments do not expose whether their thread is resolved. Query the pull request's
`reviewThreads` through `gh api graphql` to get each thread's GraphQL ID, `isResolved`, and the
comments' REST `fullDatabaseId` values. The watcher exposes those as `rest_comment_id` and uses that
data to retain unresolved threads authored
by Greptile, Codex, or Cursor Bugbot as a review-green blocker.

- Reply to an inline bot comment:
  - `gh api repos/{owner}/{repo}/pulls/{pr_number}/comments -X POST -f body='[agent] <rationale>' -F in_reply_to={rest_comment_id}`
- Resolve a verified tracked-bot thread:
  - `python3 ~/.agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --resolve-review-thread {thread_id}`

The watcher resolves through `gh api graphql` and refuses a thread unless it is currently unresolved
and contains feedback from a tracked bot. For other fully handled threads, use the same
`resolveReviewThread` GraphQL mutation directly with the thread ID from better-github-skill. Never
resolve a thread until every substantive point and follow-up has been handled.

## JSON fields consumed by the watcher

### `gh pr view`

- `number`
- `url`
- `state`
- `mergedAt`
- `closedAt`
- `headRefName`
- `headRefOid`

### `gh pr checks`

- `bucket` (`pass`, `fail`, `pending`, `skipping`)
- `state`
- `name`
- `workflow`
- `link`

### Actions runs API (`workflow_runs[]`)

- `id`
- `name`
- `status`
- `conclusion`
- `html_url`
- `head_sha`

### Actions run jobs API (`jobs[]`)

- `id`
- `name`
- `status`
- `conclusion`
- `html_url`

### Review-thread GraphQL query

- Thread `id`, `isResolved`, and `isOutdated`
- Inline comment `fullDatabaseId`, author login, body, path, line, creation time, URL, and parent review state

Only unresolved threads with an author login that identifies Greptile, Codex, or Cursor Bugbot are
returned as `unresolved_bot_review_threads`; comments from a pending review are excluded until the
review is published. This watcher field is not complete feedback. Always inspect the full
better-github-skill thread report from every author before deciding that review is clean.
