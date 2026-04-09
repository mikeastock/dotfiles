import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const FAST_CONFIG_BASENAME = "openai-fast.json";
export const DEFAULT_SUPPORTED_MODEL_KEYS = ["openai/gpt-5.4", "openai-codex/gpt-5.4"] as const;

export interface FastSupportedModel {
	provider: string;
	id: string;
}

export interface FastConfigFile {
	persistState?: boolean;
	active?: boolean;
	supportedModels?: string[];
}

export interface ResolvedFastConfig {
	configPath: string;
	persistState: boolean;
	active: boolean | undefined;
	supportedModels: FastSupportedModel[];
}

export const DEFAULT_CONFIG_FILE: FastConfigFile = {
	persistState: true,
	active: false,
	supportedModels: [...DEFAULT_SUPPORTED_MODEL_KEYS],
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function getConfigPaths(cwd: string, homeDir: string = homedir()) {
	return {
		projectConfigPath: join(cwd, ".pi", "extensions", FAST_CONFIG_BASENAME),
		globalConfigPath: join(homeDir, ".pi", "agent", "extensions", FAST_CONFIG_BASENAME),
	};
}

export function parseSupportedModelKey(value: string): FastSupportedModel | undefined {
	const trimmed = value.trim();
	if (!trimmed) {
		return undefined;
	}

	const slashIndex = trimmed.indexOf("/");
	if (slashIndex <= 0 || slashIndex >= trimmed.length - 1) {
		return undefined;
	}

	const provider = trimmed.slice(0, slashIndex).trim();
	const id = trimmed.slice(slashIndex + 1).trim();
	if (!provider || !id) {
		return undefined;
	}

	return { provider, id };
}

function normalizeSupportedModelKeys(value: unknown): string[] | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (!Array.isArray(value)) {
		return undefined;
	}

	const models: string[] = [];
	for (const entry of value) {
		if (typeof entry !== "string") {
			continue;
		}
		const parsed = parseSupportedModelKey(entry);
		if (!parsed) {
			continue;
		}
		models.push(`${parsed.provider}/${parsed.id}`);
	}
	return models;
}

export function parseSupportedModels(value: readonly string[]): FastSupportedModel[];
export function parseSupportedModels(value: unknown): FastSupportedModel[] | undefined;
export function parseSupportedModels(value: unknown): FastSupportedModel[] | undefined {
	const normalized = normalizeSupportedModelKeys(value);
	if (normalized === undefined) {
		return undefined;
	}

	return normalized
		.map((entry) => parseSupportedModelKey(entry))
		.filter((entry): entry is FastSupportedModel => entry !== undefined);
}

export function readConfigFile(filePath: string): FastConfigFile | null {
	if (!existsSync(filePath)) {
		return null;
	}

	try {
		const parsed = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
		if (!isRecord(parsed)) {
			console.warn(`[openai-fast] Ignoring invalid config object in ${filePath}`);
			return {};
		}

		const config: FastConfigFile = {};
		if (typeof parsed.persistState === "boolean") {
			config.persistState = parsed.persistState;
		}
		if (typeof parsed.active === "boolean") {
			config.active = parsed.active;
		}
		const supportedModels = normalizeSupportedModelKeys(parsed.supportedModels);
		if (supportedModels !== undefined) {
			config.supportedModels = supportedModels;
		}
		return config;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn(`[openai-fast] Failed to read ${filePath}: ${message}`);
		return null;
	}
}

export function writeConfigFile(filePath: string, config: FastConfigFile): void {
	try {
		mkdirSync(dirname(filePath), { recursive: true });
		writeFileSync(filePath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn(`[openai-fast] Failed to write ${filePath}: ${message}`);
	}
}

function ensureGlobalConfigFile(globalConfigPath: string): void {
	if (existsSync(globalConfigPath)) {
		return;
	}

	writeConfigFile(globalConfigPath, DEFAULT_CONFIG_FILE);
}

export function resolveFastConfig(cwd: string, homeDir: string = homedir()): ResolvedFastConfig {
	const { projectConfigPath, globalConfigPath } = getConfigPaths(cwd, homeDir);
	ensureGlobalConfigFile(globalConfigPath);

	const globalConfig = readConfigFile(globalConfigPath) ?? {};
	const projectConfig = readConfigFile(projectConfigPath) ?? {};
	const supportedModels =
		parseSupportedModels(projectConfig.supportedModels) ??
		parseSupportedModels(globalConfig.supportedModels) ??
		parseSupportedModels(DEFAULT_SUPPORTED_MODEL_KEYS) ??
		[];

	return {
		configPath: globalConfigPath,
		persistState: globalConfig.persistState ?? DEFAULT_CONFIG_FILE.persistState ?? true,
		active: typeof globalConfig.active === "boolean" ? globalConfig.active : undefined,
		supportedModels,
	};
}
