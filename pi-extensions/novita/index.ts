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
        cost: { input: 0.3, output: 1.2, cacheRead: 0.06, cacheWrite: 0 },
        contextWindow: 204800,
        maxTokens: 131072,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
      {
        id: "zai-org/glm-5.1",
        name: "GLM 5.1 (Novita)",
        reasoning: true,
        input: ["text"],
        cost: { input: 1.4, output: 4.4, cacheRead: 0.26, cacheWrite: 0 },
        contextWindow: 204800,
        maxTokens: 131072,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
      {
        id: "deepseek/deepseek-v4-pro",
        name: "DeepSeek V4 Pro (Novita)",
        reasoning: true,
        input: ["text"],
        cost: { input: 1.74, output: 3.48, cacheRead: 0.145, cacheWrite: 0 },
        contextWindow: 1048576,
        maxTokens: 393216,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
    ],
  });
}
