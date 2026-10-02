import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";

const SETTINGS_KEY = "openai-fast";
type SpeedMode = "off" | "fast" | "ultrafast";
type OpenAIModel = Pick<NonNullable<ExtensionContext["model"]>, "provider" | "id">;

// Explicit capabilities, not a GPT prefix match: new models do not necessarily support these tiers.
// https://developers.openai.com/api/docs/guides/fast-mode
const FAST_MODELS = new Set([
	"gpt-5.4",
	"gpt-5.5",
	"gpt-5.6-sol",
	"gpt-5.6-terra",
	"gpt-5.6-luna",
	"gpt-6-astra",
	"gpt-6-sol",
	"gpt-6-luna",
	"gpt-6.1-sol",
]);
// https://developers.openai.com/api/docs/guides/ultrafast-mode
// GPT-5.6 Sol requires preview access; GPT-6 Astra is available at limited API rate limits.
const ULTRAFAST_MODELS = new Set(["gpt-5.6-sol", "gpt-6-astra"]);

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSpeedMode(value: unknown): value is SpeedMode {
	return value === "off" || value === "fast" || value === "ultrafast";
}

function serviceTier(model: OpenAIModel | undefined, mode: SpeedMode): "fast" | "ultrafast" | undefined {
	if (!model || model.provider !== "openai" || mode === "off") return;
	const supportedModels = mode === "ultrafast" ? ULTRAFAST_MODELS : FAST_MODELS;
	return supportedModels.has(model.id) ? mode : undefined;
}

function applyServiceTier(payload: unknown, model: OpenAIModel | undefined, mode: SpeedMode): unknown {
	const tier = serviceTier(model, mode);
	if (!tier || !isRecord(payload)) return;
	return { ...payload, service_tier: tier };
}

function commandMode(args: string, current: SpeedMode): SpeedMode | "status" {
	const value = args.trim().toLowerCase();
	if (!value) return current === "off" ? "fast" : "off";
	if (value === "status" || isSpeedMode(value)) return value;
	throw new Error("Usage: /openai-fast [off|fast|ultrafast|status]");
}

function startupMode(persisted: SpeedMode | undefined, fast: boolean, ultrafast: boolean): SpeedMode {
	if (fast && ultrafast) throw new Error("Choose either --fast or --ultrafast, not both.");
	if (ultrafast) return "ultrafast";
	if (fast) return "fast";
	return persisted ?? "off";
}

type FooterModel = NonNullable<ExtensionContext["model"]> & { reasoning?: boolean };
type FooterComponentLike = { prototype: { render(width: number): string[] } };
let originalFooterRender: ((width: number) => string[]) | undefined;
let patchedFooterComponent: FooterComponentLike | undefined;

function buildFooterRightSideCandidates(model: FooterModel, thinkingLevel: string | undefined): string[] {
	let rightSideWithoutProvider = model.id;
	if (model.reasoning) {
		const level = thinkingLevel || "off";
		rightSideWithoutProvider = level === "off" ? `${model.id} • thinking off` : `${model.id} • ${level}`;
	}
	return [`(${model.provider}) ${rightSideWithoutProvider}`, rightSideWithoutProvider];
}

function injectFastIntoFooterLine(
	line: string,
	model: FooterModel,
	thinkingLevel: string | undefined,
	indicator: string,
): string {
	for (const candidate of buildFooterRightSideCandidates(model, thinkingLevel)) {
		const candidateStart = line.lastIndexOf(candidate);
		if (candidateStart === -1) continue;
		let paddingStart = candidateStart;
		while (paddingStart > 0 && line[paddingStart - 1] === " ") paddingStart -= 1;
		const availableWidth = candidateStart - paddingStart + visibleWidth(candidate);
		const desiredWidth = visibleWidth(`${candidate} • ${indicator}`);
		if (desiredWidth > availableWidth) return line;
		const prefix = line.slice(0, paddingStart);
		const suffixAnsi = line.slice(candidateStart + candidate.length);
		const nextPadding = " ".repeat(availableWidth - desiredWidth);
		return `${prefix}${nextPadding}${candidate} • ${indicator}${suffixAnsi}`;
	}
	return line;
}

async function patchFooterRender(getIndicator: (model: FooterModel) => string | undefined): Promise<void> {
	if (patchedFooterComponent) return;
	const { FooterComponent } = await import("@earendil-works/pi-coding-agent");
	originalFooterRender = FooterComponent.prototype.render;
	patchedFooterComponent = FooterComponent;
	FooterComponent.prototype.render = function renderWithFast(width: number): string[] {
		const lines = originalFooterRender?.call(this, width) ?? [];
		if (lines.length < 2) return lines;
		const session = (this as unknown as {
			session?: { state?: { model?: FooterModel; thinkingLevel?: string } };
		}).session;
		const model = session?.state?.model;
		if (!model) return lines;
		const indicator = getIndicator(model);
		if (!indicator) return lines;
		const nextLines = [...lines];
		nextLines[1] = injectFastIntoFooterLine(lines[1] ?? "", model, session?.state?.thinkingLevel, indicator);
		return nextLines;
	};
}

function unpatchFooterRender(): void {
	if (!patchedFooterComponent || !originalFooterRender) return;
	patchedFooterComponent.prototype.render = originalFooterRender;
	patchedFooterComponent = undefined;
	originalFooterRender = undefined;
}

function globalSettingsPath(): string {
	return join(process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ".pi", "agent"), "settings.json");
}

async function readSettings(path: string): Promise<Record<string, unknown>> {
	try {
		const settings: unknown = JSON.parse(await readFile(path, "utf8"));
		return isRecord(settings) ? settings : {};
	} catch (error) {
		if (isRecord(error) && error.code === "ENOENT") return {};
		throw error;
	}
}

async function loadPersistedMode(cwd: string): Promise<SpeedMode | undefined> {
	const global = (await readSettings(globalSettingsPath()))[SETTINGS_KEY];
	const project = (await readSettings(join(cwd, ".pi", "settings.json")))[SETTINGS_KEY];
	const mode = isRecord(project) && "mode" in project ? project.mode : isRecord(global) ? global.mode : undefined;
	if (mode !== undefined && !isSpeedMode(mode)) {
		throw new Error("openai-fast.mode must be off, fast, or ultrafast.");
	}
	return mode;
}

async function persistMode(mode: SpeedMode): Promise<void> {
	const path = globalSettingsPath();
	const settings = await readSettings(path);
	const extensionSettings = settings[SETTINGS_KEY];
	settings[SETTINGS_KEY] = { ...(isRecord(extensionSettings) ? extensionSettings : {}), mode };
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, `${JSON.stringify(settings, null, 2)}\n`);
}

export default function openaiFastExtension(pi: ExtensionAPI): void {
	let mode: SpeedMode = "off";
	let settingsWriteQueue: Promise<void> = Promise.resolve();

	function notifyState(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		if (mode === "off") {
			ctx.ui.notify("OpenAI speed override disabled. Requests keep their configured service tier.", "info");
			return;
		}
		const modelLabel = ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : "no active model";
		if (!serviceTier(ctx.model, mode)) {
			ctx.ui.notify(`${mode} enabled but inactive (${modelLabel}); no supported service tier requested.`, "warning");
			return;
		}
		ctx.ui.notify(`${mode} enabled (${modelLabel}). Higher usage costs apply.`, "info");
		if (mode === "ultrafast") {
			ctx.ui.notify(
				"Ultrafast requires OpenAI API access (GPT-5.6 Sol: limited preview). ChatGPT-subscription access is unconfirmed. Pi (through 1.0.0) prices Ultrafast at the standard rate; its displayed cost is too low.",
				"warning",
			);
		}
	}

	pi.registerFlag("fast", { description: "Start with OpenAI Fast mode enabled", type: "boolean", default: false });
	pi.registerFlag("ultrafast", { description: "Start with OpenAI Ultrafast mode enabled", type: "boolean", default: false });
	pi.registerCommand("openai-fast", {
		description: "Set OpenAI speed: off, fast, ultrafast, or status (no argument toggles fast/off)",
		handler: async (args, ctx) => {
			const next = commandMode(args, mode);
			if (next !== "status") {
				mode = next;
				settingsWriteQueue = settingsWriteQueue.catch(() => undefined).then(() => persistMode(next));
				try {
					await settingsWriteQueue;
				} catch (error) {
					if (ctx.hasUI) ctx.ui.notify(`openai-fast: failed to write settings: ${String(error)}`, "warning");
					else throw error;
				}
			}
			notifyState(ctx);
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		mode = "off";
		let persisted: SpeedMode | undefined;
		try {
			persisted = await loadPersistedMode(ctx.cwd);
		} catch (error) {
			if (ctx.hasUI) ctx.ui.notify(`openai-fast: failed to load settings: ${String(error)}`, "warning");
			else throw error;
		}
		mode = startupMode(persisted, pi.getFlag("fast") === true, pi.getFlag("ultrafast") === true);
		if (ctx.mode === "tui") {
			await patchFooterRender((model) => {
				const tier = serviceTier(model, mode);
				return tier === "ultrafast" ? "⚡⚡" : tier === "fast" ? "⚡" : undefined;
			});
		}
		if (mode !== "off") notifyState(ctx);
	});
	pi.on("session_shutdown", async () => {
		await settingsWriteQueue.catch(() => undefined);
		unpatchFooterRender();
	});
	pi.on("before_provider_request", (event, ctx) => applyServiceTier(event.payload, ctx.model, mode));
}

export const _test = {
	FAST_MODELS,
	ULTRAFAST_MODELS,
	serviceTier,
	applyServiceTier,
	commandMode,
	startupMode,
	injectFastIntoFooterLine,
	loadPersistedMode,
	persistMode,
};
