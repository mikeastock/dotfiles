/**
 * Permission Gate Extension
 *
 * Prompts for confirmation only when a recursive `rm` hits the deny list below.
 * Everything else runs without prompting.
 *
 * The deny list has three parts:
 * - UNSAFE_RM_TREES: never delete these or anything inside them.
 * - UNSAFE_RM_ROOTS: never delete or empty these directories, but deleting
 *   things inside them is fine (e.g. a project's node_modules under /home).
 * - UNSAFE_RM_NAMES: never delete a directory with this name, wherever it is.
 *
 * Patterns may start with `~` (the current user's home) and use `*` to match
 * exactly one path segment.
 *
 * SSH commands are excluded since they run on remote machines.
 */

import { homedir } from "node:os";
import { posix } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/** Deleting any of these, or anything beneath them, prompts. */
export const UNSAFE_RM_TREES = [
	// Linux system directories
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/lib32",
	"/lib64",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/snap",
	"/sys",
	"/usr",
	"/var/lib",

	// macOS system directories
	"/Applications",
	"/Library",
	"/System",
	"/private/etc",

	// Credentials
	"~/.gnupg",
	"~/.ssh",
	"/data/workspace/1password-service-tokens",
];

/**
 * Deleting or emptying (`dir/*`) any of these prompts. Deleting a path inside
 * them does not, because that is where normal work happens.
 */
export const UNSAFE_RM_ROOTS = [
	"/",

	// Shared system roots whose subdirectories are routinely cleaned up
	"/opt",
	"/private",
	"/private/var",
	"/srv",
	"/tmp",
	"/var",

	// Mounted drives
	"/media",
	"/media/*",
	"/mnt",
	"/mnt/*",
	"/Volumes",
	"/Volumes/*",

	// Home directories
	"/home",
	"/home/*",
	"/Users",
	"/Users/*",
	"~",
	"~/.config",
	"~/.local",
	"~/Desktop",
	"~/Documents",
	"~/Library",

	// Workspace volume that holds the main checkouts
	"/data",
	"/data/workspace",
	"/data/workspace/*",
	"/data/workspace/code/*",
];

/** Deleting a directory with one of these names prompts, wherever it lives. */
export const UNSAFE_RM_NAMES = [".git"];

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

// Shell control operators that end an `rm` argument list. Newlines are kept as
// tokens so a following command's arguments are never read as rm targets.
const SHELL_SEPARATORS = new Set(["\n", "&&", "||", ";", "|", "&", "(", ")", "{", "}", ">", ">>", "<"]);

// A last segment made only of wildcards (`*`, `.*`, `**`, `.[!.]*`) empties its
// directory. Globs with literal text (`build-*`, `*.log`) only remove matches.
const EMPTYING_GLOB = /^[.*?[\]!{},]*\*[.*?[\]!{},]*$/;

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

export type RecursiveRm = { targets: string[]; noPreserveRoot: boolean };

/**
 * Find every recursive `rm` in the command, including behind wrappers such as
 * `sudo` or `xargs`. Options may appear after operands, as GNU rm allows.
 */
export function collectRecursiveRms(command: string): RecursiveRm[] {
	const tokens = tokenizeCommand(command);
	const invocations: RecursiveRm[] = [];

	for (let i = 0; i < tokens.length; i++) {
		if (stripWrappingQuotes(tokens[i]) !== "rm") continue;

		let isRecursive = false;
		let noPreserveRoot = false;
		let parsingOptions = true;
		const targets: string[] = [];

		for (let j = i + 1; j < tokens.length; j++) {
			const token = stripWrappingQuotes(tokens[j]);
			if (SHELL_SEPARATORS.has(token)) break;

			if (parsingOptions && token === "--") {
				parsingOptions = false;
			} else if (parsingOptions && token.startsWith("-") && token !== "-") {
				if (isRecursiveOption(token)) isRecursive = true;
				if (token === "--no-preserve-root") noPreserveRoot = true;
			} else {
				targets.push(token);
			}
		}

		if (isRecursive) invocations.push({ targets, noPreserveRoot });
	}

	return invocations;
}

function expandHome(path: string, home: string): string {
	const match = path.match(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/);
	return match ? home + path.slice(match[0].length) : path;
}

function normalizePath(path: string, home: string): string {
	const normalized = posix.normalize(expandHome(path, home));
	return normalized.length > 1 ? normalized.replace(/\/+$/, "") : normalized;
}

function splitSegments(path: string): string[] {
	// "/etc/nginx" -> ["", "etc", "nginx"]; "/" -> [""]
	return path === "/" ? [""] : path.split("/");
}

function segmentsMatch(pathSegments: string[], patternSegments: string[]): boolean {
	return patternSegments.every((pattern, index) => pattern === "*" || pattern === pathSegments[index]);
}

function isSameOrInside(path: string[], pattern: string[]): boolean {
	return path.length >= pattern.length && segmentsMatch(path, pattern);
}

function isSame(path: string[], pattern: string[]): boolean {
	return path.length === pattern.length && segmentsMatch(path, pattern);
}

export function isUnsafeRmTarget(target: string, home: string = homedir()): boolean {
	if (target === "") return false;

	let path = normalizePath(target, home);

	// `dir/*` empties dir, so judge dir itself.
	if (EMPTYING_GLOB.test(posix.basename(path))) {
		path = posix.dirname(path);
	}

	const segments = splitSegments(path);
	const patternSegments = (pattern: string) => splitSegments(normalizePath(pattern, home));

	return (
		UNSAFE_RM_TREES.some((tree) => isSameOrInside(segments, patternSegments(tree))) ||
		UNSAFE_RM_ROOTS.some((root) => isSame(segments, patternSegments(root))) ||
		UNSAFE_RM_NAMES.includes(posix.basename(path))
	);
}

export function isUnsafeRmCommand(command: string, home: string = homedir()): boolean {
	return collectRecursiveRms(command).some(
		(rm) => rm.noPreserveRoot || rm.targets.some((target) => isUnsafeRmTarget(target, home)),
	);
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
