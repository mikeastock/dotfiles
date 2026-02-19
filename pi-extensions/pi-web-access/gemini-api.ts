import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const API_BASE = "https://generativelanguage.googleapis.com/v1beta";
export const DEFAULT_MODEL = "gemini-3-flash-preview";

const CONFIG_PATH = join(homedir(), ".pi", "web-search.json");

interface GeminiApiConfig {
	geminiApiKey?: string;
}

let cachedConfig: GeminiApiConfig | null = null;

function loadConfig(): GeminiApiConfig {
	if (cachedConfig) return cachedConfig;
	if (existsSync(CONFIG_PATH)) {
		try {
			cachedConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf-8")) as GeminiApiConfig;
			return cachedConfig;
		} catch {
			// ignore parse errors and fall back to empty config
		}
	}
	cachedConfig = {};
	return cachedConfig;
}

export function getApiKey(): string | null {
	const envKey = process.env.GEMINI_API_KEY;
	if (envKey) return envKey;
	return loadConfig().geminiApiKey ?? null;
}
