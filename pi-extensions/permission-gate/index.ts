/**
 * Permission Gate Extension
 *
 * Prompts for confirmation only when a recursive `rm` targets a known unsafe
 * directory prefix. Everything else is allowed through without prompting.
 *
 * The gate is intentionally a growing deny list: pad `UNSAFE_RM_PREFIXES` with
 * directories whose recursive deletion would be catastrophic. Deleting anything
 * that does not sit under one of those prefixes (project files, /tmp, build
 * output, etc.) is allowed silently.
 *
 * SSH commands are excluded since they run on remote machines.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/**
 * Directories we never want to recursively delete (or delete anything inside).
 * Matching is prefix-based: a target is unsafe when it equals a prefix or sits
 * beneath it. Keep this list small and focused on genuine catastrophe.
 */
export const UNSAFE_RM_PREFIXES = [
	// Root filesystem itself. Matched exactly only, otherwise every absolute
	// path would sit "under" it and prompt.
	"/",

	// Linux system directories
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/lib64",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/sys",
	"/usr",
	"/var",

	// macOS system directories
	"/System",
	"/Library",
	"/Applications",
	"/Volumes",

	// Home directories
	"/home",
	"/Users",
	"~",
	"$HOME",
	"${HOME}",

	// Shared / mounted software roots
	"/opt",
	"/srv",
	"/mnt",
	"/media",
];

const PROMPT_TITLE = "⚠️ Unsafe rm — allow?";
const PROMPT_MESSAGE_MAX_LENGTH = 8000;

// Keep the dialog title short and put the command in the message body.
// RPC hosts such as BB cap dialog titles (160 chars) and cancel longer ones,
// which silently turned long commands into "Blocked by user".
export function buildUnsafeRmPrompt(command: string): { title: string; message: string } {
	const message =
		command.length > PROMPT_MESSAGE_MAX_LENGTH
			? `${command.slice(0, PROMPT_MESSAGE_MAX_LENGTH)}\n… (truncated, ${command.length} chars total)`
			: command;
	return { title: PROMPT_TITLE, message };
}

const SSH_PATTERN = /^\s*ssh\s+/i;

// Shell control operators that terminate an `rm` argument list. Tokenized as
// standalone tokens (including newlines) so we never read the next command's
// arguments as rm targets.
const SHELL_SEPARATORS = new Set([
	"\n",
	"&&",
	"||",
	";",
	"|",
	"&",
	"(",
	")",
	"{",
	"}",
	">",
	">>",
	"<",
]);

function tokenizeCommand(command: string): string[] {
	return command.match(/'[^']*'|"(?:\\.|[^"\\])*"|\n|[^\s]+/g) ?? [];
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

function isRecursiveOption(token: string): boolean {
	if (token.startsWith("--")) return token === "--recursive";
	return /[rR]/.test(token.slice(1));
}

/**
 * Collect every target of a recursive `rm` anywhere in the command, including
 * through wrappers such as `sudo` or `xargs`.
 */
export function collectRecursiveRmTargets(command: string): string[] {
	const tokens = tokenizeCommand(command);
	const targets: string[] = [];

	for (let i = 0; i < tokens.length; i++) {
		if (stripWrappingQuotes(tokens[i]) !== "rm") continue;

		let isRecursive = false;
		let parsingOptions = true;

		for (let j = i + 1; j < tokens.length; j++) {
			const token = stripWrappingQuotes(tokens[j]);
			if (SHELL_SEPARATORS.has(token)) break;

			if (parsingOptions && token === "--") {
				parsingOptions = false;
				continue;
			}

			if (parsingOptions && token.startsWith("-") && token !== "-") {
				if (isRecursiveOption(token)) isRecursive = true;
				continue;
			}

			parsingOptions = false;
			if (isRecursive) targets.push(token);
		}
	}

	return targets;
}

function normalizeTarget(target: string): string {
	if (target === "") return "";
	const stripped = target.replace(/\/+$/, "");
	return stripped === "" ? "/" : stripped;
}

export function isUnsafeRmTarget(target: string): boolean {
	const normalized = normalizeTarget(target);

	return UNSAFE_RM_PREFIXES.some((prefix) => {
		// The root prefix only matches the root itself.
		if (prefix === "/") return normalized === "/";
		return normalized === prefix || normalized.startsWith(`${prefix}/`);
	});
}

export function isUnsafeRmCommand(command: string): boolean {
	return collectRecursiveRmTargets(command).some(isUnsafeRmTarget);
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = event.input.command as string;

		// Remote machines are not our filesystem; the gate does not apply.
		if (SSH_PATTERN.test(command)) return undefined;

		if (!isUnsafeRmCommand(command)) return undefined;

		if (!ctx.hasUI) {
			// In non-interactive mode, block by default.
			return { block: true, reason: "Unsafe rm blocked (no UI for confirmation)" };
		}

		const prompt = buildUnsafeRmPrompt(command);
		const allowed = await ctx.ui.confirm(prompt.title, prompt.message);

		if (!allowed) {
			return { block: true, reason: "Blocked by user" };
		}

		return undefined;
	});
}
