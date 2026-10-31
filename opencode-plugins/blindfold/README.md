# opencode-blindfold

OpenCode plugin that lets agents use secrets you provide without seeing their values.

Forked from [vimtor/opencode-plugins](https://github.com/vimtor/opencode-plugins/tree/main/packages/opencode-blindfold) at `9d1e947` (v0.5.0). The source files are unchanged from upstream's `plugin/src/`. This copy drops the OpenCode Desktop GUI part (`gui.ts`, which needs a Vite build) and the tests, so secrets are entered in the TUI only. Requires OpenCode V2.

## How it works

1. When a task needs a secret, the agent calls `blindfold.get` with a name, such as `GITHUB_TOKEN`, and a reason. If the secret isn't stored yet, you're asked for it. The plugin's system instructions tell the agent to do this instead of asking you to paste secrets into the chat.
   - In Code Mode (preferred), `tools.blindfold.get({ name, reason })` returns the value to the running code only.
   - With Code Mode disabled, `blindfold_get` is a regular tool that stores the secret and never returns the value.
2. The TUI opens a dialog where you paste the value. The value goes to the plugin and never to the agent. If you don't answer within 10 minutes, the request fails.
3. The agent uses the secret without reading it:
   - In Code Mode, through the value `tools.blindfold.get` returns, e.g. in a `fetch` header.
   - A shell command receives it as an environment variable only when the command names it, e.g. `GH_TOKEN="$GITHUB_TOKEN" gh api user`. OpenCode asks you to approve such commands. Commands that don't name it, such as `printenv`, never get the value.
4. The plugin replaces the value, and its JSON, URL, base64, and hex encodings, with `[REDACTED:GITHUB_TOKEN]` in:
   - tool results and errors
   - every message and system prompt sent to the model
   - raw provider HTTP requests, as a final safeguard

Secrets are kept in memory and are lost when the OpenCode service restarts. Encoded forms are only redacted when at least 8 characters long, so very short secrets are redacted only in their raw form.

## Install

`make dotfiles` links this directory to `~/.config/opencode/plugins/blindfold`. OpenCode discovers it there and loads its server, TUI, and RPC parts; no `opencode.jsonc` or `cli.json` entry is needed. If no TUI responds to a secret request within 5 seconds, the request fails.

## Configure

Options require configuring the plugin by path in `~/.config/opencode/opencode.jsonc` instead of relying on discovery:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "./plugins/blindfold",
      "options": {
        "shell": { "enabled": true, "approve": true },
        "codemode": { "enabled": true }
      }
    }
  ]
}
```

The values shown are the defaults.

- `shell.enabled`: set secrets as environment variables for shell commands that name them.
- `shell.approve`: ask for your approval before running shell commands that name a secret.
- `codemode.enabled`: provide `blindfold.get` in Code Mode. When `false`, it's a regular tool that never returns the value. At least one of `shell.enabled` and `codemode.enabled` must be `true`.

### Configured secrets

To skip the dialog, list secrets in the `secrets` option. Each one maps a name to a value:

```json
{
  "package": "./plugins/blindfold",
  "options": {
    "secrets": {
      "OPENCODE_API_KEY": "op://Agents/OpenCode Zen/credential",
      "GITHUB_TOKEN": "{env:GITHUB_TOKEN}"
    }
  }
}
```

- Values starting with `op://` are 1Password [secret references](https://developer.1password.com/docs/cli/secret-reference-syntax/). They're read with the 1Password CLI (`op read`) the first time the agent asks for them, so 1Password may ask you to unlock it. If the read fails, the agent gets an error explaining why instead of a dialog.
- Any other value is the secret itself. Use OpenCode's `{env:NAME}` or `{file:path}` substitution to keep it out of the config file.
- An empty value, such as an `{env:NAME}` whose variable isn't set, is an error when the agent asks for it.

The agent is told which names are configured. Other names still open the dialog.

If you're signed in to more than one 1Password account, blindfold reads from `my.1password.com`. To use another account, set `1password.account`:

```json
{
  "package": "./plugins/blindfold",
  "options": {
    "1password": { "account": "acme.1password.com" },
    "secrets": { "OPENCODE_API_KEY": "op://Agents/OpenCode Zen/credential" }
  }
}
```

Options are read when the OpenCode service starts. After changing them, run `opencode service restart`; restarting the app alone keeps the running service.

## Limitations

Redaction guards against accidental exposure, not a hostile agent. Once you approve a shell command, that program has the real value and can send it anywhere. An agent can transform a value in ways redaction cannot recognize, such as reversing it or printing part of it, or send it to a server it controls. Live shell output shown in the TUI while a command runs is not redacted; the final result is.

## Syncing with upstream

```sh
git clone https://github.com/vimtor/opencode-plugins /tmp/opencode-plugins
git -C /tmp/opencode-plugins diff 9d1e947 HEAD -- packages/opencode-blindfold/plugin/src
```

Copy changed files from `plugin/src/` (except `gui.ts`) and update the commit here and in the repo README.

## License

MIT, see `LICENSE`.
