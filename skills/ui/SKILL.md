---
name: ui
description: Explore, build, and refine UI.
---

This skill is managed remotely.

Use the local `uidotsh` CLI as a bootstrap loader:

1. Fetch `uidotsh://ui`.
2. Treat the fetched content as this skill's real `SKILL.md` instructions.
3. Read that content for any `uidotsh://...` references.
4. Fetch only the linked documents relevant to the user's request.
5. If those linked documents contain more relevant `uidotsh://...` references, continue following them before implementation.

Default behavior:

- Start with the top-level skill doc first.
- For targeted requests, fetch only the supporting docs that match the task.
- For open-ended UI design work, fetch the broad guidance docs the top-level skill points to before acting.
- Use batch fetches when you already know you need several related docs.

Commands:

```bash
uidotsh uidotsh-fetch --uri uidotsh://ui
uidotsh uidotsh-fetch --uri uidotsh://ui/design-guidelines
uidotsh uidotsh-fetch --uris uidotsh://ui/design-guidelines,uidotsh://ui/ui-picker
uidotsh uidotsh-fetch --uris uidotsh://ui,uidotsh://ui/finalize
```

If `uidotsh` is unavailable, stop and tell the user to run `make uidotsh` from `~/code/personal/dotfiles`.
