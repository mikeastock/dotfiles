import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { resolveFastConfig } from "./config.js";

describe("openai-fast config", () => {
	it("uses the global config as canonical for persisted state", () => {
		const root = mkdtempSync(join(tmpdir(), "openai-fast-config-"));
		const cwd = join(root, "project");
		const homeDir = join(root, "home");

		mkdirSync(join(homeDir, ".pi", "agent", "extensions"), { recursive: true });
		mkdirSync(join(cwd, ".pi", "extensions"), { recursive: true });

		writeFileSync(
			join(homeDir, ".pi", "agent", "extensions", "openai-fast.json"),
			JSON.stringify({
				persistState: false,
				active: false,
				supportedModels: ["openai/gpt-5.4"],
			}),
		);
		writeFileSync(
			join(cwd, ".pi", "extensions", "openai-fast.json"),
			JSON.stringify({
				persistState: true,
				active: true,
				supportedModels: ["openai/gpt-5.5"],
			}),
		);

		const config = resolveFastConfig(cwd, homeDir);

		assert.equal(config.configPath, join(homeDir, ".pi", "agent", "extensions", "openai-fast.json"));
		assert.equal(config.persistState, false);
		assert.equal(config.active, false);
		assert.deepEqual(config.supportedModels, [{ provider: "openai", id: "gpt-5.5" }]);
	});
});
