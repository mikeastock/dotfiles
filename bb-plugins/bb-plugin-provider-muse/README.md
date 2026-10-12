# Muse Code provider for BB

Runs [Muse Code](https://developer.meta.com/ai/products/muse-code/), Meta's
terminal coding agent, as a BB agent provider. Muse threads get the same
surfaces as a bundled provider: a streamed timeline, tool rows, approvals, a
model picker, health and installation checks, and a subscription usage meter.

Vendored from
[braedonsaunders/bb-plugin-provider-muse](https://github.com/braedonsaunders/bb-plugin-provider-muse)
at `d6b808d` (v0.16.1). The only local change is the `BB_MUSE_HTTPS_PROXY`
override described below.

## How it works

`muse serve` hosts sessions over stdio using the Muse Session Protocol (MSP),
a JSON-RPC command plane plus a stream of view notifications. The plugin's
provider bridge (`src/provider-bridge.ts`) translates that stream into BB's
delta grammar. Each thread runs its own `muse serve` child, so threads never
share configuration, sandbox posture, or session state. Model listing runs on
a separate child, and the models come from Muse's catalog for your account.

## Requirements

- bb 0.41 or later
- Muse Code installed and signed in on each host that runs Muse threads:

  ```sh
  curl -fsSL https://dev.meta.ai/install.sh | bash
  muse login    # or set META_API_KEY in the bb daemon's environment
  ```

The provider hides itself on hosts where `muse` is not installed.

## Install

```sh
cd bb-plugins/bb-plugin-provider-muse
npm install
bb plugin install "$PWD" --yes
```

The plugin's bb id is `provider-muse` and its provider id is `muse`. Pick
**Muse Code** in the thread provider picker, or spawn from the CLI:

```sh
bb thread spawn --provider muse --model muse-wonder-1.0 --prompt "..."
bb provider models muse    # list the models your account can use
```

## Settings

Change these in bb's plugin settings, or with
`bb plugin config provider-muse set <key> <value>`.

| Key | Default | Meaning |
| --- | --- | --- |
| `windowTokenBudget` | empty | Fallback 5-hour token budget for the usage meter, used only until Muse reports the plan's own meters. |
| `planLabel` | empty | How the subscription is labelled in usage surfaces. |
| `trustWorkspace` | `true` | Start sessions with the workspace trusted so its `AGENTS.md`, skills, and rules load. |
| `sandbox` | `off` | Muse's own OS sandbox. Off by default because it blocks native toolchains; BB's permission modes and approvals still apply. |
| `sandboxNetwork` | `enabled` | Network policy for sandboxed shell commands: `enabled`, `proxy-only`, or `restricted`. Applies only when the sandbox is on. |

## Permission modes

- **Full access:** Muse stops asking and its own sandbox stands down.
- **Auto:** bb is the reviewer, so Muse stops asking but keeps its sandbox.
- **Accept edits:** you are the reviewer, so Muse asks before commands.

## Environment variables

Set these in the bb daemon's environment (for the systemd unit,
`~/.bb/bb-service.env`), then restart bb.

| Variable | Purpose |
| --- | --- |
| `BB_MUSE_EXECUTABLE` | Path to a different `muse` binary. |
| `BB_MUSE_HTTPS_PROXY` | `http://` proxy for every Muse child. See below. |
| `MUSE_HOME` | Muse's data directory. |
| `META_API_KEY` | API key, used instead of the stored `muse login` session. |

### Reaching Muse through a proxy

From some datacenter IPs, Meta's API accepts your key but serves no models:
the model list is empty and every model returns `model_not_found`. Setting
`BB_MUSE_HTTPS_PROXY` makes every Muse child, including the model-list probe,
route through that proxy as `HTTPS_PROXY`, with loopback excluded. Muse only
honors `http://` proxies, not SOCKS, so put an HTTP proxy in front of an SSH
SOCKS tunnel:

```sh
ssh -N -D 127.0.0.1:1080 user@other-host
uvx --python 3.12 pproxy -l http://127.0.0.1:8888 -r socks5://127.0.0.1:1080
echo 'BB_MUSE_HTTPS_PROXY=http://127.0.0.1:8888' >> ~/.bb/bb-service.env
systemctl --user restart bb
```

Both proxy processes must stay running. If they stop, Muse threads fail to
reach Meta.

## Development

```sh
npm install
npm run typecheck
npm run build && bb plugin reload provider-muse
```

`server.ts` registers the provider and its settings, and `host.ts` exports the
bridge from `src/provider-bridge.ts`. Keep `@get-bb/plugin-sdk` in
`dependencies`, because provider bridges are bundled from the production
install. After upgrading bb, run `bb plugin types --check` and repin the SDK to
a published version no newer than the running host.
