import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  pi.registerProvider("atlas", {
    baseUrl: "https://api.atlascloud.ai/v1",
    apiKey: "ATLASCLOUD_API_KEY",
    api: "openai-completions",
    models: [
      {
        id: "zai-org/glm-5-turbo",
        name: "GLM 5 Turbo (Atlas)",
        reasoning: false,
        input: ["text"],
        cost: { input: 1.2, output: 4.0, cacheRead: 0.24, cacheWrite: 0 },
        contextWindow: 202752,
        maxTokens: 202752,
        compat: {
          supportsDeveloperRole: false,
          maxTokensField: "max_tokens",
        },
      },
    ],
  });
}
