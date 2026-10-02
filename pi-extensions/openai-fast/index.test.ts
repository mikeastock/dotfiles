import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { AgentSession } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";
import openaiFast, { _test } from "./index.js";

const temporaryDirectories: string[] = [];
const sessions: AgentSession[] = [];
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;

async function sandbox() {
	const root = await mkdtemp(join(tmpdir(), "pi-openai-fast-"));
	temporaryDirectories.push(root);
	const agentDir = join(root, "agent");
	const cwd = join(root, "project");
	await mkdir(agentDir);
	await mkdir(join(cwd, ".pi"), { recursive: true });
	process.env.PI_CODING_AGENT_DIR = agentDir;
	return { agentDir, cwd };
}

async function createSession(options: { fast?: boolean; ultrafast?: boolean; mode?: string } = {}) {
	const { InMemoryCredentialStore, InMemoryModelsStore } = await import("@earendil-works/pi-ai");
	const { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } = await import(
		"@earendil-works/pi-coding-agent"
	);
	const { agentDir, cwd } = await sandbox();
	if (options.mode) {
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ "openai-fast": { mode: options.mode } }));
	}
	const settingsManager = SettingsManager.inMemory();
	const modelRuntime = await ModelRuntime.create({
		credentials: new InMemoryCredentialStore(),
		modelsPath: null,
		modelsStore: new InMemoryModelsStore(),
		refreshOnCreate: false,
	});
	await modelRuntime.setRuntimeApiKey("openai", "test-key-not-sent-to-any-provider");
	const model = modelRuntime.getModel("openai", "gpt-5.4");
	assert.ok(model);
	const resourceLoader = new DefaultResourceLoader({
		cwd,
		agentDir,
		settingsManager,
		extensionFactories: [openaiFast],
		noExtensions: true,
		noSkills: true,
		noPromptTemplates: true,
		noThemes: true,
		noContextFiles: true,
	});
	await resourceLoader.reload();
	assert.deepEqual(resourceLoader.getExtensions().errors, []);
	const { session } = await createAgentSession({
		cwd,
		agentDir,
		model,
		modelRuntime,
		settingsManager,
		resourceLoader,
		sessionManager: SessionManager.inMemory(cwd),
		tools: [],
	});
	sessions.push(session);
	session.extensionRunner.setFlagValue("fast", options.fast ?? false);
	session.extensionRunner.setFlagValue("ultrafast", options.ultrafast ?? false);
	const errors: string[] = [];
	await session.bindExtensions({ mode: "print", onError: (error) => errors.push(error.error) });
	return { session, errors, agentDir };
}

async function settings(agentDir: string) {
	return JSON.parse(await readFile(join(agentDir, "settings.json"), "utf8"));
}

afterEach(async () => {
	for (const session of sessions.splice(0)) {
		await session.extensionRunner.emit({ type: "session_shutdown", reason: "quit" });
		session.dispose();
	}
	if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
	await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("OpenAI service tiers", () => {
	it("supports Fast on the existing and new OpenAI models", () => {
		for (const id of [
			"gpt-5.4",
			"gpt-5.5",
			"gpt-5.6-sol",
			"gpt-5.6-terra",
			"gpt-5.6-luna",
			"gpt-6-astra",
			"gpt-6-sol",
			"gpt-6-luna",
			"gpt-6.1-sol",
		]) {
			assert.equal(_test.serviceTier({ provider: "openai", id }, "fast"), "fast", id);
		}
	});

	it("supports Ultrafast only on Astra and Sol preview, without falling back to Fast", () => {
		for (const id of ["gpt-6-astra", "gpt-5.6-sol"]) {
			assert.equal(_test.serviceTier({ provider: "openai", id }, "ultrafast"), "ultrafast");
		}
		for (const id of ["gpt-5.5", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"]) {
			assert.equal(_test.serviceTier({ provider: "openai", id }, "ultrafast"), undefined, id);
		}
	});

	it("does not guess support for future models, other providers, or the retired Codex path", () => {
		for (const mode of ["fast", "ultrafast"] as const) {
			for (const provider of ["openai-codex", "openrouter", "azure-openai-responses"]) {
				assert.equal(_test.serviceTier({ provider, id: "gpt-6-astra" }, mode), undefined);
			}
			for (const id of ["gpt-4o", "gpt-7", "gpt-6-astra-pro", "gpt-6-astra-custom"]) {
				assert.equal(_test.serviceTier({ provider: "openai", id }, mode), undefined);
			}
			assert.equal(_test.serviceTier(undefined, mode), undefined);
		}
		assert.equal(_test.serviceTier({ provider: "openai", id: "gpt-6-astra" }, "off"), undefined);
	});

	it("sets the exact documented tier without mutating the payload or reasoning", () => {
		const payload = Object.freeze({ model: "gpt-6-astra", service_tier: "flex", reasoning: { effort: "high" }, input: [] });
		for (const mode of ["fast", "ultrafast"] as const) {
			assert.deepEqual(_test.applyServiceTier(payload, { provider: "openai", id: payload.model }, mode), {
				...payload, service_tier: mode,
			});
		}
		assert.equal(payload.service_tier, "flex");
	});

	it("leaves off, unsupported, and non-object payloads untouched", () => {
		const model = { provider: "openai", id: "gpt-6-astra" };
		assert.equal(_test.applyServiceTier({ service_tier: "flex" }, model, "off"), undefined);
		assert.equal(_test.applyServiceTier({}, { ...model, id: "gpt-6-sol" }, "ultrafast"), undefined);
		for (const payload of [undefined, null, "payload", 0, []]) {
			assert.equal(_test.applyServiceTier(payload, model, "fast"), undefined);
		}
	});
});

describe("speed selection", () => {
	it("accepts explicit modes and status, and toggles off/fast without arguments", () => {
		for (const current of ["off", "fast", "ultrafast"] as const) {
			for (const command of ["off", "fast", "ultrafast", "status"] as const) {
				assert.equal(_test.commandMode(` ${command.toUpperCase()} `, current), command);
			}
			assert.equal(_test.commandMode("", current), current === "off" ? "fast" : "off");
		}
	});

	it("rejects unknown modes and extra arguments", () => {
		for (const args of ["on", "priority", "ultrafast on", "fast status"]) {
			assert.throws(() => _test.commandMode(args, "off"), /Usage: \/openai-fast/);
		}
	});

	it("uses startup flags over persisted state, and rejects conflicting flags", () => {
		assert.equal(_test.startupMode(undefined, false, false), "off");
		assert.equal(_test.startupMode("ultrafast", false, false), "ultrafast");
		assert.equal(_test.startupMode("ultrafast", true, false), "fast");
		assert.equal(_test.startupMode("off", false, true), "ultrafast");
		assert.throws(() => _test.startupMode("fast", true, true), /not both/);
	});
});

describe("settings", () => {
	it("defaults to off with no settings and does not load the old Codex setting", async () => {
		const { agentDir, cwd } = await sandbox();
		assert.equal(await _test.loadPersistedMode(cwd), undefined);
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ "pi-codex-fast": { enabled: true } }));
		assert.equal(await _test.loadPersistedMode(cwd), undefined);
	});

	it("lets an explicit project mode override the global mode, including off", async () => {
		const { agentDir, cwd } = await sandbox();
		await _test.persistMode("ultrafast");
		for (const mode of ["off", "fast", "ultrafast"] as const) {
			await writeFile(join(cwd, ".pi", "settings.json"), JSON.stringify({ "openai-fast": { mode } }));
			assert.equal(await _test.loadPersistedMode(cwd), mode);
		}
		assert.equal((await settings(agentDir))["openai-fast"].mode, "ultrafast");
	});

	it("inherits the global mode when the project only specifies unrelated fields", async () => {
		const { cwd } = await sandbox();
		await _test.persistMode("fast");
		await writeFile(join(cwd, ".pi", "settings.json"), JSON.stringify({ "openai-fast": { note: "keep" } }));
		assert.equal(await _test.loadPersistedMode(cwd), "fast");
	});

	it("persists each mode without replacing other settings", async () => {
		const { agentDir } = await sandbox();
		await writeFile(join(agentDir, "settings.json"), JSON.stringify({ theme: "dark", "openai-fast": { note: "keep" } }));
		for (const mode of ["off", "fast", "ultrafast"] as const) {
			await _test.persistMode(mode);
			assert.deepEqual(await settings(agentDir), { theme: "dark", "openai-fast": { note: "keep", mode } });
		}
	});

	it("rejects invalid modes and malformed JSON without overwriting the file", async () => {
		const { agentDir, cwd } = await sandbox();
		await _test.persistMode("fast");
		await writeFile(join(cwd, ".pi", "settings.json"), JSON.stringify({ "openai-fast": { mode: "turbo" } }));
		await assert.rejects(_test.loadPersistedMode(cwd), /must be off, fast, or ultrafast/);
		await writeFile(join(agentDir, "settings.json"), "{");
		await assert.rejects(_test.persistMode("ultrafast"), SyntaxError);
		assert.equal(await readFile(join(agentDir, "settings.json"), "utf8"), "{");
	});
});

describe("inline footer", () => {
	const model = { provider: "openai", id: "gpt-6-astra", reasoning: true } as any;
	it("adds distinct fast and ultrafast indicators without changing terminal width", () => {
		const original = "0.0%/272k                     (openai) gpt-6-astra • high\x1b[0m";
		for (const indicator of ["⚡", "⚡⚡"]) {
			const updated = _test.injectFastIntoFooterLine(original, model, "high", indicator);
			assert.ok(updated.endsWith(`(openai) gpt-6-astra • high • ${indicator}\x1b[0m`));
			assert.equal(visibleWidth(updated), visibleWidth(original));
			assert.equal(updated.split("\n").length, 1);
		}
	});

	it("does not overflow narrow footers or change unrelated lines", () => {
		for (const line of ["0.0%/272k (openai) gpt-6-astra • high", "unrelated"]) {
			assert.equal(_test.injectFastIntoFooterLine(line, model, "high", "⚡⚡"), line);
		}
	});

	it("handles hidden providers, thinking off, and non-reasoning models", () => {
		for (const [footerModel, thinking, text] of [
			[model, "off", "gpt-6-astra • thinking off"],
			[model, undefined, "gpt-6-astra • thinking off"],
			[{ ...model, reasoning: false }, undefined, "gpt-6-astra"],
		] as const) {
			const line = `usage                ${text}`;
			const updated = _test.injectFastIntoFooterLine(line, footerModel, thinking, "⚡⚡");
			assert.ok(updated.endsWith(`${text} • ⚡⚡`));
			assert.equal(visibleWidth(updated), visibleWidth(line));
		}
	});
});

describe("real Pi extension runtime (no provider calls)", () => {
	it("registers the new command and flags and transforms requests through Pi's runner", async () => {
		const { session, errors, agentDir } = await createSession();
		assert.deepEqual([...session.extensionRunner.getFlags().keys()], ["fast", "ultrafast"]);
		assert.equal(session.extensionRunner.getCommand("codex-fast"), undefined);
		assert.ok(session.extensionRunner.getCommand("openai-fast"));
		const payload = { model: "gpt-5.4", input: [] };
		assert.equal(await session.extensionRunner.emitBeforeProviderRequest(payload), payload);
		await session.prompt("/openai-fast fast");
		assert.deepEqual(await session.extensionRunner.emitBeforeProviderRequest(payload), { ...payload, service_tier: "fast" });
		assert.equal((await settings(agentDir))["openai-fast"].mode, "fast");
		await session.prompt("/openai-fast off");
		assert.equal(await session.extensionRunner.emitBeforeProviderRequest(payload), payload);
		assert.equal(session.messages.length, 0);
		assert.deepEqual(errors, []);
	});

	it("sends Ultrafast on Astra and becomes inactive after switching to unsupported Sol", async () => {
		const { session, errors } = await createSession({ mode: "ultrafast" });
		const base = session.model!;
		await session.setModel({ ...base, id: "gpt-6-astra" });
		const astra = { model: "gpt-6-astra", reasoning: { effort: "high" } };
		assert.deepEqual(await session.extensionRunner.emitBeforeProviderRequest(astra), { ...astra, service_tier: "ultrafast" });
		await session.setModel({ ...base, id: "gpt-6-sol" });
		const sol = { model: "gpt-6-sol" };
		assert.equal(await session.extensionRunner.emitBeforeProviderRequest(sol), sol);
		await session.setModel({ ...base, id: "gpt-5.6-sol" });
		assert.deepEqual(await session.extensionRunner.emitBeforeProviderRequest({ model: "gpt-5.6-sol" }), {
			model: "gpt-5.6-sol", service_tier: "ultrafast",
		});
		assert.deepEqual(errors, []);
	});

	it("does not persist startup flags or status, and supports the no-argument toggle", async () => {
		const { session, agentDir, errors } = await createSession({ fast: true, mode: "off" });
		const payload = { model: "gpt-5.4" };
		assert.deepEqual(await session.extensionRunner.emitBeforeProviderRequest(payload), { ...payload, service_tier: "fast" });
		await session.prompt("/openai-fast status");
		assert.equal((await settings(agentDir))["openai-fast"].mode, "off");
		await session.prompt("/openai-fast");
		assert.equal(await session.extensionRunner.emitBeforeProviderRequest(payload), payload);
		await session.prompt("/openai-fast");
		assert.equal((await settings(agentDir))["openai-fast"].mode, "fast");
		assert.deepEqual(errors, []);
	});

	it("rejects conflicting startup flags and leaves requests unchanged", async () => {
		const { session, errors } = await createSession({ fast: true, ultrafast: true, mode: "ultrafast" });
		assert.equal(errors.length, 1);
		assert.match(errors[0], /not both/);
		const payload = { model: "gpt-5.4" };
		assert.equal(await session.extensionRunner.emitBeforeProviderRequest(payload), payload);
	});

	it("validates commands before changing state and recovers after a settings write failure", async () => {
		const { session, agentDir, errors } = await createSession();
		const command = session.extensionRunner.getCommand("openai-fast")!;
		const ctx = session.extensionRunner.createCommandContext();
		await assert.rejects(command.handler("turbo", ctx), /Usage/);
		await writeFile(join(agentDir, "settings.json"), "{");
		await assert.rejects(command.handler("fast", ctx), SyntaxError);
		await writeFile(join(agentDir, "settings.json"), "{}");
		await command.handler("ultrafast", ctx);
		assert.equal((await settings(agentDir))["openai-fast"].mode, "ultrafast");
		assert.deepEqual(errors, []);
	});
});
