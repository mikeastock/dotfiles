# OpenAI Fast / Ultrafast

Select OpenAI's service tier without changing the model, thinking effort, conversation, or tools. This extension targets the new `openai` provider, not the legacy `openai-codex` provider.

## Usage

```text
/openai-fast fast
/openai-fast ultrafast
/openai-fast off
/openai-fast status
```

With no argument, `/openai-fast` toggles Fast/off. If Ultrafast is active, it turns the override off. `status` reports the selected mode and whether the current model supports it, without changing settings.

```bash
pi --model openai/gpt-6.1-sol --fast
pi --model openai/gpt-6-astra --ultrafast
```

Startup flags override saved settings for that launch without saving the override. Passing both flags is an error and leaves the extension inactive.

The default footer shows `⚡` for Fast or `⚡⚡` for Ultrafast next to supported models. The indicator disappears on unsupported models and is omitted when the line has insufficient space. Non-interactive sessions still apply the request tier, without patching the footer.

## Supported models

| Mode | `openai` model IDs | Request field |
|---|---|---|
| Fast | `gpt-5.4`, `gpt-5.5`, `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-6-astra`, `gpt-6-sol`, `gpt-6-luna`, `gpt-6.1-sol` | `service_tier: "fast"` |
| Ultrafast | `gpt-6-astra`, `gpt-5.6-sol` | `service_tier: "ultrafast"` |

Capabilities are explicitly allowlisted; new model names are not automatically assumed to support a tier. On unsupported models/providers, the selected mode remains saved but does not modify the request. Ultrafast never silently falls back to Fast. Provider errors remain visible to Pi.

`off` stops this extension from overriding the request; it does not remove a service tier configured elsewhere, such as model sampling parameters or OpenAI project defaults.

## Settings

Commands save the mode in the global Pi settings file (`~/.pi/agent/settings.json`, or the directory selected by `PI_CODING_AGENT_DIR`):

```json
{
  "openai-fast": {
    "mode": "fast"
  }
}
```

Valid modes are `off`, `fast`, and `ultrafast`; absence defaults to `off`. A mode in `.pi/settings.json` overrides the global mode on startup. Commands still write globally. Other settings are preserved, and invalid JSON is not overwritten.

The old `/codex-fast` command and `pi-codex-fast.enabled` setting are no longer used. Set the new mode explicitly; no legacy-settings migration is performed.

## Availability and cost

- **Fast:** OpenAI renamed API Priority processing to Fast mode. `fast` and `priority` are equivalent on supported models; this extension sends the new `fast` spelling. Higher usage costs apply.
- **Ultrafast:** OpenAI documents broad API access for **GPT-6 Astra** at limited rate limits, and limited-preview access for **GPT-5.6 Sol**. Availability still depends on your account and region. Ultrafast supports global processing and US data residency, not EU or other non-US regional processing endpoints.
- **Authentication:** The request override itself works with either authentication method on `openai`. OpenAI documents Ultrafast for the API; access through Pi's **Sign in with ChatGPT** subscription flow is unconfirmed. Selecting it does not grant access or switch credentials.
- **Transport:** OpenAI recommends persistent WebSockets for Ultrafast, but HTTP is supported. This extension only selects the service tier; it does not change Pi's transport or add WebSocket support to its OpenAI adapter.
- **Cost display:** Pi **0.99.1** recognizes Fast/priority pricing but does not account for Ultrafast pricing. Its displayed Ultrafast costs may be too low. Use OpenAI's usage/billing dashboard and current pricing as the authority, not Pi's estimate. The extension warns when an active Ultrafast mode is selected or loaded.

## Sources

Verified against OpenAI documentation on September 29, 2026:

- [Fast mode](https://developers.openai.com/api/docs/guides/fast-mode)
- [Ultrafast mode](https://developers.openai.com/api/docs/guides/ultrafast-mode)
- [GPT-6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol)
- [API pricing](https://developers.openai.com/api/docs/pricing)

## Development

```bash
pnpm exec node --import tsx --test pi-extensions/openai-fast/index.test.ts
pnpm typecheck
make install-extensions
```

After installing, run `/reload` in Pi. Tests use temporary settings directories and the real Pi SDK extension runtime; they make no model-provider calls.
