---
name: deepen
description: Rewrite a task prompt into a deeper version of the same task (not a bigger one) by naming what a top professional would do, the raw material they would start from, their methods and tools, and the external evidence that would prove the result right. Use when the user types /deepen or asks to deepen a prompt or task.
metadata:
  user-invocable-only: "true"
---

# deepen

I want a deeper version of this task, not a bigger one. Keep the same goal and scope; increase rigor, not breadth.

Task: $ARGUMENTS

If no task is given, use the most recent prompt or task in this conversation.

Before rewriting it:

1. **What a top professional would do.** Say what a top professional in this field would do here that I'm not asking for.
2. **Rawest material.** Name the rawest material they would start from instead of what has already been digested for me (e.g. primary sources, raw data, logs, source code, original specs, rather than summaries, dashboards, or secondhand write-ups).
3. **Methods and tools.** Name the specific methods and tools they would use.
4. **Independent proof.** Say what, other than you or me, would show the result is right (e.g. a test, a measurement, a reproduction, an external source, a real user).

Then rewrite my prompt to ask for exactly that.

## Output

- Four short sections answering 1–4 above, specific to this task. No generic advice.
- The rewritten prompt in a fenced code block, ready to paste.
- Do not execute the task. Stop after the rewritten prompt.
