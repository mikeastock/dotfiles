# bb-plugin-plannotator

A thin BB adapter around the official [Plannotator](https://github.com/backnotprop/plannotator) runtime, for plan reviews and code reviews. Plannotator owns the review experience; BB launches it in the thread's right panel and sends the decision to the agent as a new thread message.

Forked from [patleeman/bb-plugins](https://github.com/patleeman/bb-plugins/tree/main/packages/bb-plugin-plannotator) at `d8edb69` (v0.3.1). Changes from upstream:

- Adds `plannotator_review_code` for code review (see below).
- Drops the vitest suites, the unused `plan-review` skill, and the staged-preview screenshot.

## Install

```sh
npm install
bb plugin install "$PWD" --yes
```

Backend changes need `npm run build && bb plugin reload plannotator`. Start a new agent session after installing or reloading so the tools appear.

There is no separate Plannotator installation. On the first review, the plugin downloads the pinned official Plannotator release (`v0.27.1`) for the current OS/CPU, verifies its SHA-256 digest, and caches it under BB's plugin data directory. To use another build, set **Plannotator binary** under BB → Extensions → Plannotator, or set `PLANNOTATOR_BIN` for the BB server. Use `bundled` to restore the default.

## Tools

The agent uses these only when you explicitly ask for a Plannotator review.

- `plannotator_review_plan` — reviews a Markdown plan.
- `plannotator_review_code` — reviews code changes. Without `prUrl`, it shows the changes in the thread's workspace: uncommitted work and the branch against its base, switchable in the UI. With a GitHub pull request or GitLab merge request URL in `prUrl`, it shows that diff instead; this needs `gh` or `glab` signed in on the BB machine.
- `plannotator_review_status` — recovers a decision by review ID if its message went missing.

Each review tool returns a review ID promptly, and the agent ends its turn. Approve or annotate in the panel tab. BB then closes the tab and sends the decision as a new message in the same thread, which wakes the agent. The message is queued if the agent is still working. Reviews have no deadline: one stays open until Plannotator returns a decision or you use **Cancel review** in the tab. Approval is not a permission grant.

Only one review, of either kind, can be pending per thread. If you close its tab, open the **Plannotator** thread panel action to bring it back. A second review call while one is pending returns `status: "already_active"`; it does not start a new review and is not a cancellation.

BB stores the review state until it delivers the decision. If the plugin restarts during a review, it sends a cancellation message after restarting, and retries deliveries that fail temporarily.

## How code review runs

Code review uses upstream's structured `opencode-review` entrypoint instead of `plannotator review`, because it prints a JSON decision record rather than prose that depends on configurable prompt text. Two consequences:

- The upstream UI labels the agent as OpenCode in code reviews.
- A PR review uses the platform diff only. Upstream's `review` command would also check the PR out into a background git worktree or shallow clone; this entrypoint does not, so features that need the PR's full files are limited.

The child runs on the BB server's machine with `PLANNOTATOR_CWD` set to the thread's workspace. A workspace on another enrolled host is refused.

In PR mode, Plannotator's UI can post approvals and comments to GitHub or GitLab with your `gh`/`glab` credentials, and its AI review features can launch agent CLIs on this machine. Use them deliberately.

## Embedding and remote access

Plannotator's plan history and configuration are stored under the plugin's BB data directory. The panel loads the upstream UI through a session-scoped same-origin relay (`/api/v1/plugins/plannotator/http/review`). That route needs no BB authentication: the random review ID is the only capability, and the route works only while that review is open. The relayed page runs on BB's origin with the upstream CSP and frame headers removed, so a script-injection bug in Plannotator's renderer would run with BB's privileges.

When BB is configured with a non-loopback `BB_APP_URL`, or with `BB_SERVER_BIND_HOST=0.0.0.0`, the plugin starts Plannotator in remote mode: the upstream listener binds beyond loopback on a port in `19432-19441`, without authentication. The embedded panel still uses the relay, so a one-port Tailscale Serve endpoint is enough. **Open externally** over plain HTTP needs that port range reachable.

## Boundary

BB does not intercept provider text or require a review before edits. Native provider Plan mode is separate and remains provider-controlled. Skipping or cancelling Plannotator does not authorize or prohibit implementation.

The upstream project is dual-licensed under Apache-2.0 or MIT; the plugin does not copy or reimplement its UI.
