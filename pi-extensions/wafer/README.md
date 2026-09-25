# Wafer Serverless

Registers `wafer` using Pi's built-in OpenAI Chat Completions implementation. No extra dependencies, custom streaming, or startup network requests.

## Setup

1. Create a Serverless API key at https://app.wafer.ai/signup and load credits.
2. Export `WAFER_API_KEY` in the environment that starts Pi. Never commit the key.
3. Run `make install-extensions`, then restart Pi (or `/reload` if the key is already in its environment).
4. Select a Wafer model with `/model`, or launch directly:

   ```bash
   pi --provider wafer --model Kimi-K3
   ```

For development without installing:

```bash
pi -e ./pi-extensions/wafer/index.ts --provider wafer --model Kimi-K3
```

This does not change your default model or `enabledModels` cycle. Use `/scoped-models` to add Wafer models to the cycle.

## Catalog and limits

`index.ts` contains a snapshot of the public https://pass.wafer.ai/v1/models catalog retrieved on 2026-09-25: GLM-5.2, GLM-5.3, Kimi-K3, Qwen3.8-27B, GLM-5.3-Flash, DeepSeek-V4-Pro, DeepSeek-V4.1-Flash, and DeepSeek-V4-Flash-0731-Fast. Availability may depend on your account; GLM-5.3-Flash is described as available to gateway partners.

Context windows, image support, reasoning tiers, and USD-per-million-token prices come from the catalog. Cache-read prices use its more precise microcent values. The catalog does not publish cache-write prices; these are recorded as zero, so Pi's costs are estimates, not billing authority.

Kimi-K3 publishes a 131,072-token output limit. Other models publish `null`; the extension uses a conservative **32,768-token client cap**, not a verified backend limit. Update this snapshot when Wafer changes its catalog. No automatic discovery is performed.

Pi's `off` maps to Wafer's `none`, and `xhigh` to `max`. Unsupported levels are disabled. Wafer handles the actual model-specific reasoning controls behind its API.

ZDR is not requested by default. See [Wafer's Serverless docs](https://docs.wafer.ai/serverless) for privacy guarantees and account setup.

## Verification

```bash
node --import tsx --test pi-extensions/wafer/index.test.ts
pnpm typecheck
```

Tests cover registration, catalog metadata, reasoning mappings, and credential resolution using Pi's real registry. Authenticated inference (streaming, tools, images, usage, and cancellation) requires a live key and is not covered by these tests.
