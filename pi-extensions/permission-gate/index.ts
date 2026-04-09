/**
 * Permission Gate Extension
 *
 * Prompts for confirmation before running potentially dangerous bash commands.
 * Patterns checked: rm -rf, chmod/chown 777, heroku sensitive commands
 *
 * SSH commands are excluded since they run on remote machines.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const SAFE_TMP_PREFIXES = ["/tmp", "tmp/", ".tmp"];
const RECURSIVE_RM_PATTERN = /\brm\s+(-rf?|--recursive)/i;

function tokenizeCommand(command: string): string[] {
	return command.match(/'[^']*'|"(?:\\.|[^"\\])*"|[^\s]+/g) ?? [];
}

function stripWrappingQuotes(token: string): string {
	if (token.length < 2) return token;

	const first = token[0];
	const last = token[token.length - 1];
	if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
		return token.slice(1, -1);
	}

	return token;
}

function getRecursiveRmTargets(command: string): string[] | null {
	const tokens = tokenizeCommand(command.trim());
	if (tokens[0] !== "rm") return null;

	let isRecursive = false;
	let parsingOptions = true;
	const targets: string[] = [];

	for (const rawToken of tokens.slice(1)) {
		const token = stripWrappingQuotes(rawToken);

		if (parsingOptions && token === "--") {
			parsingOptions = false;
			continue;
		}

		if (parsingOptions && token.startsWith("-") && token !== "-") {
			if (token.startsWith("--")) {
				if (token === "--recursive") {
					isRecursive = true;
				}
			} else if (/[rR]/.test(token.slice(1))) {
				isRecursive = true;
			}
			continue;
		}

		parsingOptions = false;
		targets.push(token);
	}

	if (!isRecursive || targets.length === 0) return null;
	return targets;
}

export function isSafeTmpRmCommand(command: string): boolean {
	const targets = getRecursiveRmTargets(command);
	if (!targets) return false;

	return targets.every((target) => SAFE_TMP_PREFIXES.some((prefix) => target.startsWith(prefix)));
}

export default function (pi: ExtensionAPI) {
	const dangerousPatterns = [
		// File system destructive operations
		RECURSIVE_RM_PATTERN,
		/\b(chmod|chown)\b.*777/i,

		// Heroku database commands (direct access, resets, data movement)
		/\bheroku\s+pg:psql\b/i,
		/\bheroku\s+pg:reset\b/i,
		/\bheroku\s+pg:push\b/i,
		/\bheroku\s+pg:pull\b/i,
		/\bheroku\s+pg:copy\b/i,
		/\bheroku\s+pg:kill\b/i,
		/\bheroku\s+pg:killall\b/i,

		// Heroku destructive app operations
		/\bheroku\s+apps:destroy\b/i,
		/\bheroku\s+addons:destroy\b/i,
		/\bheroku\s+domains:clear\b/i,

		// Heroku config and release operations
		/\bheroku\s+config:set\b/i,
		/\bheroku\s+config:unset\b/i,
		/\bheroku\s+releases:rollback\b/i,

		// Heroku run (can execute arbitrary code on dyno)
		/\bheroku\s+run\b/i,
	];

	// Pattern to detect SSH commands (ssh user@host ... or ssh host ...)
	const sshPattern = /^\s*ssh\s+/i;

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = event.input.command as string;

		// Skip SSH commands - they run on remote machines
		if (sshPattern.test(command)) {
			return undefined;
		}

		if (isSafeTmpRmCommand(command)) {
			return undefined;
		}

		const isDangerous = dangerousPatterns.some((p) => p.test(command));

		if (isDangerous) {
			if (!ctx.hasUI) {
				// In non-interactive mode, block by default
				return { block: true, reason: "Dangerous command blocked (no UI for confirmation)" };
			}

			const choice = await ctx.ui.select(`⚠️ Dangerous command:\n\n ${command}\n\nAllow?`, ["Yes", "No"]);

			if (choice !== "Yes") {
				return { block: true, reason: "Blocked by user" };
			}
		}

		return undefined;
	});
}
