import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const SESSION_QUERY_SKILL_COMMAND = "/skill:session-query";

type SessionHeaderLike = {
	type?: unknown;
	parentSession?: unknown;
};

function readParentSessionPath(sessionPath: string): string | null {
	if (!existsSync(sessionPath)) return null;

	try {
		const firstLine = readFileSync(sessionPath, "utf8").split(/\r?\n/, 1)[0];
		if (!firstLine?.trim()) return null;

		const header = JSON.parse(firstLine) as SessionHeaderLike;
		if (
			header.type !== "session" ||
			typeof header.parentSession !== "string" ||
			!header.parentSession.trim()
		) {
			return null;
		}

		return resolve(dirname(sessionPath), header.parentSession);
	} catch {
		return null;
	}
}

export function buildSessionLineage(
	startSessionPath: string | undefined,
	maxDepth = 50,
): string[] {
	if (!startSessionPath) return [];

	const lineage: string[] = [];
	const seen = new Set<string>();
	let current: string | null = resolve(startSessionPath);

	while (current && lineage.length < maxDepth && !seen.has(current)) {
		lineage.push(current);
		seen.add(current);
		current = readParentSessionPath(current);
	}

	return lineage;
}

function formatSessionReferenceSection(sessionLineage: string[]): string {
	if (sessionLineage.length === 0) return "";
	if (sessionLineage.length === 1) {
		return `${SESSION_QUERY_SKILL_COMMAND}\n\n**Parent session:** \`${sessionLineage[0]}\`\n\n`;
	}

	const lineageList = sessionLineage
		.map((sessionPath, index) => `${index + 1}. \`${sessionPath}\``)
		.join("\n");
	return `${SESSION_QUERY_SKILL_COMMAND}\n\n**Session lineage (newest to oldest):**\n${lineageList}\n\n`;
}

export function buildFinalPrompt(params: {
	goal: string;
	summary: string;
	currentSessionFile?: string;
}): string {
	const sessionReferenceSection = formatSessionReferenceSection(
		buildSessionLineage(params.currentSessionFile),
	);
	return `${params.goal}\n\n${sessionReferenceSection}${params.summary}`;
}
