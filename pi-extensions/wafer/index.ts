import type { ExtensionAPI, ProviderConfig, ProviderModelConfig } from "@earendil-works/pi-coding-agent";

// Snapshot of https://pass.wafer.ai/v1/models (2026-09-25).
// Prices are USD per million tokens. Null output limits use a 32K client cap,
// not a claimed backend limit. No network calls or credentials at load time.
const catalog = [
  { id: "GLM-5.2", vision: false, context: 1048576, output: 32768, inputPrice: 1.4, outputPrice: 4.4, cachePrice: 0.26 },
  { id: "GLM-5.3", vision: false, context: 1048576, output: 32768, inputPrice: 1.4, outputPrice: 4.4, cachePrice: 0.26 },
  { id: "Kimi-K3", vision: true, context: 1048576, output: 131072, inputPrice: 1.99, outputPrice: 15, cachePrice: 0.3 },
  { id: "Qwen3.8-27B", vision: true, context: 262144, output: 32768, inputPrice: 0.09, outputPrice: 4.4, cachePrice: 0.085 },
  { id: "GLM-5.3-Flash", vision: true, context: 1048576, output: 32768, inputPrice: 0.09, outputPrice: 0.35, cachePrice: 0.03 },
  { id: "DeepSeek-V4-Pro", vision: false, context: 1048576, output: 32768, inputPrice: 0.25, outputPrice: 3.5, cachePrice: 0.249 },
  { id: "DeepSeek-V4.1-Flash", vision: true, context: 1048576, output: 32768, inputPrice: 0.1, outputPrice: 0.6, cachePrice: 0.06 },
  { id: "DeepSeek-V4-Flash-0731-Fast", vision: false, context: 1048576, output: 32768, inputPrice: 0.08, outputPrice: 0.35, cachePrice: 0.06 },
];

export const waferProvider: ProviderConfig = {
  name: "Wafer",
  baseUrl: "https://pass.wafer.ai/v1",
  apiKey: "$WAFER_API_KEY",
  api: "openai-completions",
  models: catalog.map((model): ProviderModelConfig => ({
    id: model.id,
    name: `${model.id} (Wafer)`,
    reasoning: true,
    input: model.vision ? ["text", "image"] : ["text"],
    contextWindow: model.context,
    maxTokens: model.output,
    cost: {
      input: model.inputPrice,
      output: model.outputPrice,
      cacheRead: model.cachePrice,
      cacheWrite: 0,
    },
    // Wafer accepts "max", not Pi's "xhigh". Only expose advertised tiers.
    thinkingLevelMap: {
      off: "none",
      minimal: null,
      low: model.id === "Kimi-K3" ? null : "low",
      medium: model.id === "Qwen3.8-27B" ? "medium" : null,
      high: "high",
      xhigh: "max",
    },
  })),
};

export default function (pi: ExtensionAPI) {
  pi.registerProvider("wafer", waferProvider);
}
