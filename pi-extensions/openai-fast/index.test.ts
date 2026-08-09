import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import codexFast, { _test } from "./index.js";

interface Harness {
	flags: Map<string, unknown>;
	commands: Map<string, (args: string, ctx: any) => Promise<void>>;
	events: Map<string, (event: any, ctx: any) => any>;
}

const temporaryDirectories: string[] = [];
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;

async function temporaryDirectory(): Promise<string> {
	const path = await mkdtemp(join(tmpdir(), "pi-codex-fast-"));
	temporaryDirectories.push(path);
	return path;
}

function createHarness(fastFlag = false): Harness {
	const harness: Harness = {
		flags: new Map(),
		commands: new Map(),
		events: new Map(),
	};

	codexFast({
		registerFlag(name: string, options: unknown) {
			harness.flags.set(name, options);
		},
		registerCommand(name: string, options: any) {
			harness.commands.set(name, options.handler);
		},
		on(name: string, handler: any) {
			harness.events.set(name, handler);
		},
		getFlag(name: string) {
			return name === "fast" && fastFlag;
		},
	} as any);

	return harness;
}

function createContext(cwd: string, provider = "openai-codex", id = "gpt-5.6-sol") {
	const notifications: Array<[string, string]> = [];
	return {
		cwd,
		hasUI: true,
		model: { provider, id },
		notifications,
		ui: {
			notify(message: string, level: string) {
				notifications.push([message, level]);
			},
		},
	};
}

afterEach(async () => {
	if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
	await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("pi-codex-fast", () => {
	it("registers the upstream flag, command, and hooks", () => {
		const harness = createHarness();

		assert.deepEqual([...harness.flags.keys()], ["fast"]);
		assert.deepEqual([...harness.commands.keys()], ["codex-fast"]);
		assert.deepEqual([...harness.events.keys()].sort(), ["before_provider_request", "session_shutdown", "session_start"]);
	});

	it("supports only the upstream OpenAI Codex priority models", () => {
		assert.equal(
			_test.supportsPriorityServiceTier({ model: { provider: "openai-codex", id: "gpt-5.6-luna" } as any }),
			true,
		);
		assert.equal(
			_test.supportsPriorityServiceTier({ model: { provider: "openai", id: "gpt-5.6-luna" } as any }),
			false,
		);
		assert.equal(
			_test.supportsPriorityServiceTier({ model: { provider: "openai-codex", id: "gpt-5.3" } as any }),
			false,
		);
	});

	it("adds the fast indicator to the existing model footer line", () => {
		const originalLine = "0.0%/128k                     (openai-codex) gpt-5.6-sol • high";
		const updatedLine = _test.injectFastIntoFooterLine(
			originalLine,
			{ provider: "openai-codex", id: "gpt-5.6-sol", reasoning: true } as any,
			"high",
			"⚡",
		);

		assert.equal(updatedLine, "0.0%/128k                (openai-codex) gpt-5.6-sol • high • ⚡");
		assert.equal(updatedLine.split("\n").length, 1);
	});

	it("loads the project setting over the global setting", async () => {
		const root = await temporaryDirectory();
		const agentDir = join(root, "agent");
		const cwd = join(root, "project");
		process.env.PI_CODING_AGENT_DIR = agentDir;
		await mkdir(join(cwd, ".pi"), { recursive: true });
		await mkdir(agentDir, { recursive: true });
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ "pi-codex-fast": { enabled: false } }));
		await writeFile(join(cwd, ".pi", "settings.json"), JSON.stringify({ "pi-codex-fast": { enabled: true } }));

		assert.equal(await _test.loadPersistedFastMode(cwd), true);
	});

	it("enables priority requests from persisted state", async () => {
		const root = await temporaryDirectory();
		const agentDir = join(root, "agent");
		const cwd = join(root, "project");
		process.env.PI_CODING_AGENT_DIR = agentDir;
		await mkdir(agentDir, { recursive: true });
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ "pi-codex-fast": { enabled: true } }));

		const harness = createHarness();
		const ctx = createContext(cwd);
		await harness.events.get("session_start")?.({}, ctx);
		const payload = harness.events.get("before_provider_request")?.({ payload: { model: "gpt-5.6-sol" } }, ctx);

		assert.deepEqual(payload, { model: "gpt-5.6-sol", service_tier: "priority" });
	});

	it("leaves unsupported requests unchanged", async () => {
		const root = await temporaryDirectory();
		process.env.PI_CODING_AGENT_DIR = join(root, "agent");
		const harness = createHarness(true);
		const ctx = createContext(join(root, "project"), "openai", "gpt-5.6-sol");

		await harness.events.get("session_start")?.({}, ctx);
		const payload = harness.events.get("before_provider_request")?.({ payload: { model: "gpt-5.6-sol" } }, ctx);

		assert.equal(payload, undefined);
	});

	it("persists toggles under pi-codex-fast.enabled without replacing other settings", async () => {
		const root = await temporaryDirectory();
		const agentDir = join(root, "agent");
		process.env.PI_CODING_AGENT_DIR = agentDir;
		await mkdir(agentDir, { recursive: true });
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ theme: "dark", "pi-codex-fast": { note: "keep" } }));

		await _test.persistFastMode(true);

		assert.deepEqual(JSON.parse(await readFile(join(agentDir, "settings.json"), "utf8")), {
			theme: "dark",
			"pi-codex-fast": { note: "keep", enabled: true },
		});
	});
});
