import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  pi.registerProvider("fireworks", {
    baseUrl: "https://api.fireworks.ai/inference/v1",
    apiKey: "FIREWORKS_API_KEY",
    api: "openai-completions",
    models: [
      {
        id: "accounts/fireworks/routers/kimi-k2p5-turbo",
        name: "Kimi K2.5 Turbo (Fireworks)",
        reasoning: false,
        input: ["text", "image"],
        cost: { input: 0.6, output: 3, cacheRead: 0.1, cacheWrite: 0 },
        contextWindow: 256000,
        maxTokens: 65536,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
      {
        id: "accounts/fireworks/models/kimi-k2p6",
        name: "K2.6 (Fireworks)",
        reasoning: false,
        input: ["text", "image"],
        cost: { input: 0.95, output: 4, cacheRead: 0.16, cacheWrite: 0 },
        contextWindow: 262000,
        maxTokens: 65536,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
    ],
  });
}
