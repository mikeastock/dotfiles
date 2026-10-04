### Autonomous run

**You own the exit condition. Define done, then drive to it without stopping.**

1. State the exit condition as a checkable predicate before the first iteration (tests green, repro fixed, all N PRs merged, pixel-diff zero).
2. Pick the wake mechanism. Pi has no loop command, but a background `task` (`background: true`) wakes you when it reports. An event to watch (CI, a merge, a ref advancing) gets a background watcher subagent whose brief runs the blocking watch command (`gh pr checks --watch`, `scripts/watch-pr/watch-pr`) and reports the event, with a long time-based heartbeat as fallback. No event gets a fixed-interval heartbeat: a background `task` with `agent: "general"` on the cheapest model, whose brief runs `sleep <seconds>` and reports. It does nothing else, so it never needs `poteto-agent`. Size the interval to when the result is worth re-checking. Re-arm it at each wake. Never a foreground `sleep` loop in bash: it blocks steering, pause, and every other wake until it returns. Keep doing reversible work while the background task runs, or end the turn and let its report wake you.
3. Each iteration makes the smallest change the evidence justifies, verifies it against the predicate, commits if it advanced, discards changes that didn't help. Belt-and-suspenders that "might help" gets reverted, not left to ride.
   Sequence the work via the **sequence-verifiable-units** principle skill, verifying each unit before the next instead of batching checks at the end.
4. Mid-run discoveries are yours. Address broken skills, related bugs, flaky verifiers, review noise, tooling failures, orphaned follow-ups, and fixable drift yourself via poteto-mode. Put out-of-band fixes in their own PR. Do not park reversible work for the human or stop to ask. Surface only irreversible actions, genuine product or preference calls no experiment can settle, or a real dead end. Keep the predicate as the main drive, and return to it after each side fix.
5. Checkpoint every iteration via the **show-me-your-work** skill, a row for what changed and whether the predicate moved.
6. Stop when the predicate is met. A plateau is not a stop, so keep going and pivot your approach to push past it. Surface a genuine dead end rather than spinning, and never relax the predicate to declare victory.

**Reply:** the exit condition, iterations run, what landed, what was discarded, final predicate state.
