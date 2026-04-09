// Repo-native local version of:
// https://github.com/ben-vargas/pi-packages/tree/main/packages/pi-openai-fast
import { FooterComponent, type ExtensionAPI, type ExtensionContext } from "@mariozechner/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@mariozechner/pi-tui";
import {
	DEFAULT_CONFIG_FILE,
	DEFAULT_SUPPORTED_MODEL_KEYS,
	FAST_CONFIG_BASENAME,
	getConfigPaths,
	parseSupportedModelKey,
	parseSupportedModels,
	readConfigFile,
	resolveFastConfig,
	writeConfigFile,
	type FastConfigFile,
	type FastSupportedModel,
	type ResolvedFastConfig,
} from "./config.js";

const FAST_COMMAND = "fast";
const FAST_FLAG = "fast";
const FAST_COMMAND_ARGS = ["on", "off", "status"] as const;
const FAST_SERVICE_TIER = "priority";

interface FastModeState {
	active: boolean;
}

type FastPayload = Record<string, unknown> & {
	service_tier?: string;
};

type FooterModel = NonNullable<ExtensionContext["model"]> & {
	reasoning?: boolean;
};

let originalFooterRender: ((this: FooterComponent, width: number) => string[]) | undefined;
let footerPatched = false;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getConfigCwd(ctx: ExtensionContext): string {
	return ctx.cwd || process.cwd();
}

function getCurrentModelKey(model: ExtensionContext["model"]): string | undefined {
	if (!model) {
		return undefined;
	}

	return `${model.provider}/${model.id}`;
}

function isFastSupportedModel(model: ExtensionContext["model"], supportedModels: FastSupportedModel[]): boolean {
	if (!model) {
		return false;
	}

	return supportedModels.some((supported) => supported.provider === model.provider && supported.id === model.id);
}

function describeSupportedModels(supportedModels: FastSupportedModel[]): string {
	if (supportedModels.length === 0) {
		return "none configured";
	}

	return supportedModels.map((model) => `${model.provider}/${model.id}`).join(", ");
}

function describeCurrentState(
	ctx: Pick<ExtensionContext, "model">,
	active: boolean,
	supportedModels: FastSupportedModel[],
): string {
	const model = getCurrentModelKey(ctx.model) ?? "none";

	if (!active) {
		return `Fast mode is off. Current model: ${model}.`;
	}
	if (!ctx.model) {
		return `Fast mode is on. No model is selected. Supported models: ${describeSupportedModels(supportedModels)}.`;
	}
	if (isFastSupportedModel(ctx.model, supportedModels)) {
		return `Fast mode is on for ${model}.`;
	}

	return `Fast mode is on, but ${model} does not support it. Supported models: ${describeSupportedModels(supportedModels)}.`;
}

function getFastIndicator(
	ctx: Pick<ExtensionContext, "model" | "ui">,
	active: boolean,
	supportedModels: FastSupportedModel[],
): string | undefined {
	if (!active) {
		return undefined;
	}

	const color = isFastSupportedModel(ctx.model, supportedModels) ? "success" : "warning";
	return ctx.ui.theme.fg(color, "⚡");
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
		if (candidateStart === -1) {
			continue;
		}

		let paddingStart = candidateStart;
		while (paddingStart > 0 && line[paddingStart - 1] === " ") {
			paddingStart -= 1;
		}

		const prefix = line.slice(0, paddingStart);
		const suffixAnsi = line.slice(candidateStart + candidate.length);
		const availableWidth = candidateStart - paddingStart + visibleWidth(candidate);
		const desiredRightSide = `${candidate}${suffix}`;
		const fittedRightSide = truncateToWidth(desiredRightSide, availableWidth, "");
		const fittedWidth = visibleWidth(fittedRightSide);
		const nextPadding = " ".repeat(Math.max(0, availableWidth - fittedWidth));
		return `${prefix}${nextPadding}${fittedRightSide}${suffixAnsi}`;
	}

	return line;
}

function patchFooterRender(getIndicator: (ctx: { model?: FooterModel; thinkingLevel?: string }) => string | undefined): void {
	if (footerPatched) {
		return;
	}

	originalFooterRender = FooterComponent.prototype.render;
	FooterComponent.prototype.render = function renderWithFast(width: number): string[] {
		const lines = originalFooterRender?.call(this, width) ?? [];
		if (lines.length < 2) {
			return lines;
		}

		const session = (this as unknown as { session?: { state?: { model?: FooterModel; thinkingLevel?: string } } }).session;
		const model = session?.state?.model;
		if (!model) {
			return lines;
		}

		const indicator = getIndicator({ model, thinkingLevel: session?.state?.thinkingLevel });
		if (!indicator) {
			return lines;
		}

		const nextLines = [...lines];
		nextLines[1] = injectFastIntoFooterLine(lines[1] ?? "", model, session?.state?.thinkingLevel, indicator);
		return nextLines;
	};
	footerPatched = true;
}

function unpatchFooterRender(): void {
	if (!footerPatched || !originalFooterRender) {
		return;
	}

	FooterComponent.prototype.render = originalFooterRender;
	footerPatched = false;
	originalFooterRender = undefined;
}

function applyFastServiceTier(payload: unknown): unknown {
	if (!isRecord(payload)) {
		return payload;
	}

	const nextPayload: FastPayload = { ...payload };
	nextPayload.service_tier = FAST_SERVICE_TIER;
	return nextPayload;
}

export default function openaiFast(pi: ExtensionAPI): void {
	let state: FastModeState = { active: false };
	let cachedConfig: ResolvedFastConfig | undefined;

	patchFooterRender(({ model, thinkingLevel }) => {
		if (!model) {
			return undefined;
		}

		const supportedModels = cachedConfig?.supportedModels ?? parseSupportedModels(DEFAULT_SUPPORTED_MODEL_KEYS) ?? [];
		return getFastIndicator(
			{ model, ui: { theme: { fg: (_color: string, text: string) => text } } as ExtensionContext["ui"] },
			state.active,
			supportedModels,
		);
	});

	function refreshConfig(ctx: ExtensionContext): ResolvedFastConfig {
		cachedConfig = resolveFastConfig(getConfigCwd(ctx));
		return cachedConfig;
	}

	function getConfig(ctx: ExtensionContext): ResolvedFastConfig {
		return cachedConfig ?? refreshConfig(ctx);
	}

	function persistState(_ctx: ExtensionContext, config: ResolvedFastConfig): void {
		cachedConfig = { ...config, active: state.active };
		if (!config.persistState) {
			return;
		}

		const nextConfig = { ...(readConfigFile(config.configPath) ?? {}), active: state.active };
		writeConfigFile(config.configPath, nextConfig);
	}

	async function enableFastMode(ctx: ExtensionContext, notify: boolean = true): Promise<void> {
		const config = refreshConfig(ctx);
		if (state.active) {
			if (notify) {
				ctx.ui.notify("Fast mode is already on.", "info");
			}
			return;
		}

		state = { active: true };
		persistState(ctx, config);
		if (notify) {
			ctx.ui.notify(describeCurrentState(ctx, state.active, config.supportedModels), "info");
		}
	}

	async function disableFastMode(ctx: ExtensionContext, notify: boolean = true): Promise<void> {
		const config = refreshConfig(ctx);
		if (!state.active) {
			if (notify) {
				ctx.ui.notify("Fast mode is already off.", "info");
			}
			return;
		}

		state = { active: false };
		persistState(ctx, config);
		if (notify) {
			ctx.ui.notify("Fast mode disabled.", "info");
		}
	}

	async function toggleFastMode(ctx: ExtensionContext): Promise<void> {
		if (state.active) {
			await disableFastMode(ctx);
			return;
		}

		await enableFastMode(ctx);
	}

	pi.registerFlag(FAST_FLAG, {
		description: "Start with OpenAI fast mode enabled",
		type: "boolean",
		default: false,
	});

	pi.registerCommand(FAST_COMMAND, {
		description: "Toggle fast mode (priority service tier for configured models)",
		getArgumentCompletions: (prefix) => {
			const items = FAST_COMMAND_ARGS.filter((value) => value.startsWith(prefix)).map((value) => ({
				value,
				label: value,
			}));
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const command = args.trim().toLowerCase();
			if (!command) {
				await toggleFastMode(ctx);
				return;
			}

			switch (command) {
				case "on":
					await enableFastMode(ctx);
					return;
				case "off":
					await disableFastMode(ctx);
					return;
				case "status":
					ctx.ui.notify(describeCurrentState(ctx, state.active, refreshConfig(ctx).supportedModels), "info");
					return;
				default:
					ctx.ui.notify("Usage: /fast [on|off|status]", "error");
			}
		},
	});

	pi.on("before_provider_request", (event, ctx) => {
		const config = getConfig(ctx);
		if (!state.active || !isFastSupportedModel(ctx.model, config.supportedModels)) {
			return;
		}

		return applyFastServiceTier(event.payload);
	});

	pi.on("session_start", async (_event, ctx) => {
		const config = refreshConfig(ctx);
		state = config.persistState && typeof config.active === "boolean" ? { active: config.active } : { active: false };

		if (pi.getFlag(FAST_FLAG) === true) {
			state = { active: true };
			persistState(ctx, config);
			ctx.ui.notify(describeCurrentState(ctx, state.active, config.supportedModels), "info");
			return;
		}

		if (state.active) {
			ctx.ui.notify(describeCurrentState(ctx, state.active, config.supportedModels), "info");
		}
	});

	pi.on("model_select", async (_event, ctx) => {
		refreshConfig(ctx);
	});

	pi.on("session_shutdown", async () => {
		unpatchFooterRender();
	});
}

export const _test = {
	FAST_COMMAND,
	FAST_FLAG,
	FAST_CONFIG_BASENAME,
	FAST_COMMAND_ARGS,
	FAST_SERVICE_TIER,
	DEFAULT_SUPPORTED_MODEL_KEYS,
	DEFAULT_CONFIG_FILE,
	getConfigPaths,
	parseSupportedModelKey,
	parseSupportedModels,
	readConfigFile,
	resolveFastConfig,
	isFastSupportedModel,
	describeSupportedModels,
	describeCurrentState,
	buildFooterRightSideCandidates,
	injectFastIntoFooterLine,
	getFastIndicator,
	applyFastServiceTier,
};
