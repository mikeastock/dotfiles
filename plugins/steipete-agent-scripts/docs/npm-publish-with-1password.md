---
summary: "Publish to npm via tmux + 1Password CLI (op)"
read_when:
  - "Need npm publish without copy/paste secrets."
  - "Need npm OTP/TOTP from 1Password."
---

# npm publish via tmux + op

Goal: publish to npm without pasting tokens/passwords into terminal logs.

## Prereqs

- 1Password desktop app unlocked + CLI integration enabled.
- `op` installed.
- `tmux` installed.

## tmux session (required)

Use a persistent tmux session so `op` auth survives across commands.

```bash
SOCKET_DIR="${CLAWDBOT_TMUX_SOCKET_DIR:-${TMPDIR:-/tmp}/clawdbot-tmux-sockets}"
mkdir -p "$SOCKET_DIR"
SOCKET="$SOCKET_DIR/op-auth.sock"
SESSION="op-auth-$(date +%Y%m%d-%H%M%S)"

tmux -S "$SOCKET" new -d -s "$SESSION" -n shell
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "op signin" Enter
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "op whoami" Enter
```

## Preferred: granular automation token (+ optional OTP)

Store a granular npm token in 1Password (item field `token`), plus TOTP if required.

```bash
TOKEN_REF='op://<Vault>/<Item>/token'
OTP_REF='op://<Vault>/<Item>/one-time password?attribute=otp'

tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "NODE_AUTH_TOKEN=\"\$(op read \"$TOKEN_REF\" | tr -d \"\\n\")\" npm publish --otp \"\$(op read \"$OTP_REF\" | tr -d \"\\n\")\"" Enter
```

Notes:
- `tr -d "\n"` avoids accidental extra submits when pasting/reading.
- Avoid printing token/OTP (no `echo`, no `set -x`, no pane capture right after OTP).

## If you’re already logged in: OTP-only publish

If `npm whoami` works, you usually only need OTP for publish:

```bash
OTP_REF='op://<Vault>/<Item>/one-time password?attribute=otp'
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "npm publish --otp \"\$(op read \"$OTP_REF\" | tr -d \"\\n\")\"" Enter
```

Tip: unset CI tokens so you don’t accidentally override your local login:

```bash
env -u NPM_TOKEN -u NODE_AUTH_TOKEN npm whoami
```

## Fallback: `npm login` using op buffers (no echo)

When password auth is unavoidable, avoid typing secrets by piping into tmux buffers and pasting.

```bash
USER_REF='op://<Vault>/<Item>/name'
PASS_REF='op://<Vault>/<Item>/password'
EMAIL_REF='op://<Vault>/<Item>/email'
OTP_REF='op://<Vault>/<Item>/one-time password?attribute=otp'

# load buffers (strip trailing newline)
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "op read \"$USER_REF\"  | tr -d \"\\n\" | tmux -S \"$SOCKET\" load-buffer -b npm_user  -" Enter
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "op read \"$PASS_REF\"  | tr -d \"\\n\" | tmux -S \"$SOCKET\" load-buffer -b npm_pass  -" Enter
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "op read \"$EMAIL_REF\" | tr -d \"\\n\" | tmux -S \"$SOCKET\" load-buffer -b npm_email -" Enter

# run login; paste at prompts (repeat pattern for Email/OTP)
tmux -S "$SOCKET" send-keys -t "$SESSION":1.1 -- "npm login --auth-type=legacy" Enter
tmux -S "$SOCKET" paste-buffer -t "$SESSION":1.1 -b npm_user
tmux -S "$SOCKET" send-keys    -t "$SESSION":1.1 -- Enter
tmux -S "$SOCKET" paste-buffer -t "$SESSION":1.1 -b npm_pass
tmux -S "$SOCKET" send-keys    -t "$SESSION":1.1 -- Enter
```

Gotchas:
- If npm says “Incorrect or missing password”, the 1Password password is stale or the paste didn’t reach the prompt.
- Don’t run `tmux capture-pane` after pasting OTP (it may echo); wait 30–60s if you must debug.
- Repeated reads of the password field can trigger multiple 1Password “password used/copied” alerts; OTP-only flow avoids that entirely.

## Verify

```bash
npm whoami
npm view <pkg> version
```

## Cleanup

```bash
tmux -S "$SOCKET" kill-session -t "$SESSION"
rm -f "$SOCKET"
```
