import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const SETTINGS_KEY = "pi-codex-fast";
const PRIORITY_MODELS = [
	"openai-codex/gpt-5.4",
	"openai-codex/gpt-5.5",
	"openai-codex/gpt-5.6-sol",
	"openai-codex/gpt-5.6-terra",
	"openai-codex/gpt-5.6-luna",
];

type FooterModel = NonNullable<ExtensionContext["model"]> & {
	reasoning?: boolean;
};

type FooterComponentLike = {
	prototype: {
		render(width: number): string[];
	};
};

let originalFooterRender: ((width: number) => string[]) | undefined;
let patchedFooterComponent: FooterComponentLike | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function currentModelName(ctx: Pick<ExtensionContext, "model">): string | undefined {
	return ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined;
}

function supportsPriorityServiceTier(ctx: Pick<ExtensionContext, "model">): boolean {
	const modelName = currentModelName(ctx);
	return modelName !== undefined && PRIORITY_MODELS.includes(modelName);
}

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
	const candidates = buildFooterRightSideCandidates(model, thinkingLevel);
	const suffix = ` • ${indicator}`;

	for (const candidate of candidates) {
		const candidateStart = line.lastIndexOf(candidate);
		if (candidateStart === -1) continue;

		let paddingStart = candidateStart;
		while (paddingStart > 0 && line[paddingStart - 1] === " ") paddingStart -= 1;

		const availableWidth = candidateStart - paddingStart + candidate.length;
		const indicatorWidth = indicator === "⚡" ? 2 : [...indicator].length;
		const desiredWidth = candidate.length + 3 + indicatorWidth;
		if (desiredWidth > availableWidth) return line;

		const prefix = line.slice(0, paddingStart);
		const suffixAnsi = line.slice(candidateStart + candidate.length);
		const nextPadding = " ".repeat(availableWidth - desiredWidth);
		return `${prefix}${nextPadding}${candidate}${suffix}${suffixAnsi}`;
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

function asObject(value: unknown): Record<string, unknown> | null {
	if (!isRecord(value)) return null;
	return value;
}

function globalSettingsPath(): string {
	return join(process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ".pi", "agent"), "settings.json");
}

function projectSettingsPath(cwd: string): string {
	return join(cwd, ".pi", "settings.json");
}

async function readSettings(path: string): Promise<Record<string, unknown>> {
	try {
		const content = await readFile(path, "utf8");
		const settings = JSON.parse(content) as unknown;
		return isRecord(settings) ? settings : {};
	} catch (error) {
		if (isRecord(error) && error.code === "ENOENT") return {};
		throw error;
	}
}

function mergeSettings(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
	const merged: Record<string, unknown> = { ...base };
	for (const [key, overrideValue] of Object.entries(overrides)) {
		const baseValue = merged[key];
		if (isRecord(baseValue) && isRecord(overrideValue)) {
			merged[key] = mergeSettings(baseValue, overrideValue);
			continue;
		}
		merged[key] = overrideValue;
	}
	return merged;
}

async function loadPersistedFastMode(cwd: string): Promise<boolean | undefined> {
	const settings = mergeSettings(
		await readSettings(globalSettingsPath()),
		await readSettings(projectSettingsPath(cwd)),
	);
	const extensionSettings = asObject(settings[SETTINGS_KEY]);
	return typeof extensionSettings?.enabled === "boolean" ? extensionSettings.enabled : undefined;
}

async function persistFastMode(enabled: boolean): Promise<void> {
	const path = globalSettingsPath();
	const globalSettings = await readSettings(path);
	const extensionSettings = asObject(globalSettings[SETTINGS_KEY]) ?? {};
	globalSettings[SETTINGS_KEY] = {
		...extensionSettings,
		enabled,
	};
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, `${JSON.stringify(globalSettings, null, 2)}\n`);
}

export default function codexFastExtension(pi: ExtensionAPI): void {
	let fastModeEnabled = false;
	let settingsWriteQueue: Promise<void> = Promise.resolve();

	function persistState(enabled: boolean, ctx: ExtensionContext): void {
		settingsWriteQueue = settingsWriteQueue
			.catch(() => undefined)
			.then(() => persistFastMode(enabled));

		void settingsWriteQueue.catch((error) => {
			if (!ctx.hasUI) return;
			const message = error instanceof Error ? error.message : String(error);
			ctx.ui.notify(`pi-codex-fast: failed to write settings: ${message}`, "warning");
		});
	}

	function notifyState(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		if (!fastModeEnabled) {
			ctx.ui.notify("Fast mode disabled. Requests will use the default service tier.", "info");
			return;
		}

		const modelLabel = currentModelName(ctx) ?? "no active model";
		if (supportsPriorityServiceTier(ctx)) {
			ctx.ui.notify(`Fast mode enabled (${modelLabel}).`, "info");
			return;
		}

		ctx.ui.notify(`Fast mode enabled but inactive (${modelLabel}).`, "info");
	}

	function setFastMode(enabled: boolean, ctx: ExtensionContext, options?: { persist?: boolean; notify?: boolean }): void {
		fastModeEnabled = enabled;
		if (options?.persist !== false) persistState(enabled, ctx);
		if (options?.notify !== false) notifyState(ctx);
	}

	async function reloadFastModeState(ctx: ExtensionContext, options?: { includeStartupFlag?: boolean }): Promise<void> {
		fastModeEnabled = false;

		try {
			const persistedEnabled = await loadPersistedFastMode(ctx.cwd);
			if (typeof persistedEnabled === "boolean") {
				fastModeEnabled = persistedEnabled;
			}
		} catch (error) {
			if (ctx.hasUI) {
				const message = error instanceof Error ? error.message : String(error);
				ctx.ui.notify(`pi-codex-fast: failed to load settings: ${message}`, "warning");
			}
		}

		if (options?.includeStartupFlag && pi.getFlag("fast") === true) {
			fastModeEnabled = true;
		}
	}

	pi.registerFlag("fast", {
		description: "Start with fast mode enabled",
		type: "boolean",
		default: false,
	});

	pi.registerCommand("codex-fast", {
		description: "Toggle fast mode",
		handler: async (_args, ctx) => {
			setFastMode(!fastModeEnabled, ctx);
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		await reloadFastModeState(ctx, { includeStartupFlag: true });
		await patchFooterRender((model) => {
			if (!fastModeEnabled || !supportsPriorityServiceTier({ model })) return;
			return "⚡";
		});
	});

	pi.on("session_shutdown", async () => {
		unpatchFooterRender();
	});

	pi.on("before_provider_request", (event, ctx) => {
		if (!fastModeEnabled || !supportsPriorityServiceTier(ctx) || !isRecord(event.payload)) {
			return;
		}

		return {
			...event.payload,
			service_tier: "priority",
		};
	});
}

export const _test = {
	PRIORITY_MODELS,
	SETTINGS_KEY,
	buildFooterRightSideCandidates,
	injectFastIntoFooterLine,
	currentModelName,
	supportsPriorityServiceTier,
	mergeSettings,
	loadPersistedFastMode,
	persistFastMode,
};
