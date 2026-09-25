import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthStorage, ModelRegistry } from "@earendil-works/pi-coding-agent";
import { waferProvider } from "./index.ts";

function registry() {
  const result = ModelRegistry.inMemory(AuthStorage.inMemory());
  result.registerProvider("wafer", waferProvider);
  return result;
}

test("Wafer catalog registers with the real Pi model registry", () => {
  const models = registry().getAll().filter((model) => model.provider === "wafer");
  assert.equal(models.length, 8);
  assert.equal(new Set(models.map((model) => model.id)).size, 8);
  for (const model of models) {
    assert.equal(model.api, "openai-completions");
    assert.equal(model.baseUrl, "https://pass.wafer.ai/v1");
    assert.equal(model.reasoning, true);
    assert.equal(model.thinkingLevelMap?.off, "none");
    assert.equal(model.thinkingLevelMap?.xhigh, "max");
    assert.equal(model.thinkingLevelMap?.minimal, null);
    assert.ok(model.maxTokens > 0 && model.maxTokens < model.contextWindow);
  }
  const kimi = models.find((model) => model.id === "Kimi-K3")!;
  assert.deepEqual(kimi.input, ["text", "image"]);
  assert.equal(kimi.maxTokens, 131072);
  assert.equal(kimi.contextWindow, 1048576);
  assert.equal(kimi.thinkingLevelMap?.low, null);
  assert.equal(kimi.thinkingLevelMap?.medium, null);
  const qwen = models.find((model) => model.id === "Qwen3.8-27B")!;
  assert.equal(qwen.contextWindow, 262144);
  assert.equal(qwen.thinkingLevelMap?.medium, "medium");
  assert.equal(qwen.cost.cacheRead, 0.085);
  const glm = models.find((model) => model.id === "GLM-5.3")!;
  assert.deepEqual(glm.input, ["text"]);
  assert.equal(glm.maxTokens, 32768);
  assert.deepEqual(glm.cost, { input: 1.4, output: 4.4, cacheRead: 0.26, cacheWrite: 0 });
  assert.equal(glm.thinkingLevelMap?.medium, null);
});

test("Wafer resolves its key from the environment without embedding credentials", async () => {
  const previous = process.env.WAFER_API_KEY;
  try {
    delete process.env.WAFER_API_KEY;
    const models = registry();
    const model = models.find("wafer", "Kimi-K3")!;
    assert.equal(models.hasConfiguredAuth(model), false);
    process.env.WAFER_API_KEY = "wafer-unit-test-key";
    assert.equal(models.hasConfiguredAuth(model), true);
    const auth = await models.getApiKeyAndHeaders(model);
    assert.equal(auth.ok, true);
    if (auth.ok) assert.equal(auth.apiKey, "wafer-unit-test-key");
    assert.equal(waferProvider.apiKey, "$WAFER_API_KEY");
  } finally {
    if (previous === undefined) delete process.env.WAFER_API_KEY;
    else process.env.WAFER_API_KEY = previous;
  }
});
