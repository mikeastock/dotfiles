import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fireworks from "./index.js";

describe("fireworks extension", () => {
	it("registers the K2.6 model with the Fireworks pricing and context length", () => {
		let providerName: string | undefined;
		let providerConfig: any;

		fireworks({
			registerProvider(name: string, config: unknown) {
				providerName = name;
				providerConfig = config;
			},
		} as any);

		assert.equal(providerName, "fireworks");

		const model = providerConfig.models.find(
			(candidate: { id: string }) =>
				candidate.id === "accounts/fireworks/models/kimi-k2p6",
		);

		assert.deepEqual(model, {
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
		});
	});
});
