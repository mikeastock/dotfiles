# pi-prompt-shelf

A [Pi](https://github.com/mariozechner/pi-coding-agent) extension that lets you stash prompts from the editor into a persistent, per-session shelf instead of submitting them. Each session in each project gets its own shelf, and shelved prompts survive restarts. The shelf is always visible as a widget above the editor input.

https://github.com/user-attachments/assets/cb8b28b4-bd8b-41d4-9e0f-a3dc3bac4981

## Installation

```bash
# From GitHub
pi install https://github.com/tanishqkancharla/pi-prompt-shelf

# Try without installing
pi -e https://github.com/tanishqkancharla/pi-prompt-shelf
```

## Features

- **Session-scoped persistence** — each session gets its own shelf at `<cwd>/.pi/prompt-shelf/<sessionId>.json`; `/new` starts clean, `/resume` restores the shelf
- **Widget display** — a bordered widget above the editor shows all shelved prompts with timestamps
- **Quick restore** — restore any prompt by number with `Alt+1..9`
- **Interactive picker** — browse, restore, or delete shelved prompts with the `/shelf` command

## Shortcuts

| Key       | Action                           |
|-----------|----------------------------------|
| `Alt+S`   | Shelve current editor text       |
| `Alt+1-9` | Restore shelved prompt by number |
| `Alt+X`   | Clear all shelved prompts        |

## Command

| Command  | Description                          |
|----------|--------------------------------------|
| `/shelf` | Open shelf picker (restore / delete) |

## License

MIT
