import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { resolve } from "node:path";

type ReadInput = {
	path: string;
	offset?: number;
	limit?: number;
};

const FULL_READ_PATH_PATTERNS: RegExp[] = [
	/\/AGENTS\.md$/,
	/\/AGENTS\.MD$/,
	/\/CLAUDE\.md$/,
	/\/CLAUDE\.MD$/,
	/\/README\.md$/,
	/\/README\.MD$/,
	/\/SKILL\.md$/,
];

function isPartialRead(input: ReadInput): boolean {
	return input.offset !== undefined || input.limit !== undefined;
}

function matchesFullReadPath(path: string, cwd: string, patterns: RegExp[]): boolean {
	const absolutePath = resolve(cwd, path);
	return patterns.some((pattern) => pattern.test(absolutePath));
}

export function normalizeReadInputForFullReadPaths(input: ReadInput, cwd: string, patterns = FULL_READ_PATH_PATTERNS): boolean {
	if (!isPartialRead(input)) return false;
	if (!matchesFullReadPath(input.path, cwd, patterns)) return false;

	delete input.offset;
	delete input.limit;
	return true;
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "read") return undefined;

		const input = event.input as Partial<ReadInput>;
		if (typeof input.path !== "string") return undefined;

		const changed = normalizeReadInputForFullReadPaths(input as ReadInput, ctx.cwd);
		if (changed && ctx.hasUI) {
			ctx.ui.notify(`Upgraded partial read to full read: ${input.path}`, "info");
		}

		return undefined;
	});
}
