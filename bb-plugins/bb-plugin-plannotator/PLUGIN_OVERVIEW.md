Review a plan or code changes in Plannotator without keeping an agent tool call open while you decide.

## How it works

When an agent calls `plannotator_review_plan` or `plannotator_review_code`, the plugin opens the official Plannotator app in the BB thread panel. Code review shows the thread workspace's changes, or a GitHub pull request or GitLab merge request when the agent passes its URL. The tool returns a review ID promptly so the agent can end its turn. Approve or send annotated feedback in Plannotator. The plugin sends that decision as a new message in the same thread and wakes the agent.

If the agent misses a decision, it can check `plannotator_review_status` with the review ID. A review interrupted by a plugin restart sends a cancellation message.

## Requirements

The plugin downloads a pinned official Plannotator binary on first use and caches it locally. You can configure another binary in the plugin settings. PR reviews need `gh` or `glab` signed in on the BB machine.
