import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

type ModelLike = {
	provider: string;
	id: string;
};

function findNearestProjectSettingsPath(cwd: string): string | null {
	let currentDir = cwd;
	while (true) {
		const candidate = path.join(currentDir, ".pi", "settings.json");
		if (fs.existsSync(candidate)) return candidate;

		const parentDir = path.dirname(currentDir);
		if (parentDir === currentDir) return null;
		currentDir = parentDir;
	}
}

function readEnabledModels(settingsPath: string): string[] {
	try {
		const raw = fs.readFileSync(settingsPath, "utf8");
		const parsed = JSON.parse(raw) as { enabledModels?: unknown };
		return Array.isArray(parsed.enabledModels)
			? parsed.enabledModels.filter((value): value is string => typeof value === "string" && value.trim().length > 0)
			: [];
	} catch {
		return [];
	}
}

export function formatAvailableModelId(model: ModelLike): string {
	return `${model.provider}/${model.id}`;
}

export function getSavedScopedModelIds(cwd: string, homeDir: string = os.homedir()): string[] {
	const projectSettingsPath = findNearestProjectSettingsPath(cwd);
	if (projectSettingsPath) {
		const projectModels = readEnabledModels(projectSettingsPath);
		if (projectModels.length > 0) return projectModels;
	}

	const globalSettingsPath = path.join(homeDir, ".pi", "agent", "settings.json");
	return readEnabledModels(globalSettingsPath);
}

export function resolveModelOverride(
	scopedModelIds: string[],
	modelOverride: string | undefined,
	agentModel: string | undefined,
): { model?: string; error?: string } {
	if (!modelOverride) {
		return { model: agentModel };
	}

	const scopedModels = new Set(scopedModelIds);
	if (!scopedModels.has(modelOverride)) {
		const availableList = Array.from(scopedModels).sort().join(", ") || "none";
		return {
			error: `Unknown model override: "${modelOverride}". Scoped models: ${availableList}`,
		};
	}

	return { model: modelOverride };
}
