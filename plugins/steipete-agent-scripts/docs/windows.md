---
summary: "Windows setup notes for running agent scripts"
read_when:
  - Working on Windows or PowerShell setups for agent scripts.
---

# Windows notes

- Install Git for Windows and ensure git is on PATH.
- Install Bun (needed to run the Bun-based shims in `bin/`): `irm https://bun.sh/install.ps1 | iex`. The installer drops `bun.exe` in `%USERPROFILE%\.bun\bin` and adds it to the user PATH; restart shells to pick it up.
- Running the shims from PowerShell:
  - `bun bin/docs-list`

> Note: Windows may not honor the UNIX shebang line when launching shims in `bin/` directly. Using `bun bin/<tool> ...` is the most reliable cross-shell invocation.
