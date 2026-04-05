import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  pi.registerProvider("novita", {
    baseUrl: "https://api.novita.ai/openai/v1",
    apiKey: "NOVITA_API_KEY",
    api: "openai-completions",
    models: [
      {
        id: "minimax/minimax-m2.7",
        name: "MiniMax M2.7 (Novita)",
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 131072,
        maxTokens: 131072,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
    ],
  });
}
