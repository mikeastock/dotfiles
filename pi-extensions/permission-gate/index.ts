/**
 * Permission Gate Extension
 *
 * Prompts for confirmation only when an `rm` hits the deny list below.
 * Everything else runs without prompting.
 *
 * The deny list has three parts:
 * - UNSAFE_RM_TREES: never delete these or anything inside them, recursive or
 *   not (system and credential directories).
 * - UNSAFE_RM_ROOTS: never recursively delete or empty these directories, but
 *   deleting things inside them is fine (e.g. node_modules under /home).
 * - UNSAFE_RM_NAMES: never recursively delete a directory with this name.
 *
 * Patterns may start with `~` (the current user's home) and use `*` to match
 * exactly one path segment.
 *
 * Relative targets resolve against the agent's working directory and any
 * `cd <dir>` earlier in the same command. `sh -c` / `bash -c` payloads and
 * `$(...)` / backtick substitutions are scanned too.
 *
 * Known gaps: variables other than $HOME and command substitutions are not
 * expanded, so targets like "$DIR/" are judged as written. SSH commands are
 * skipped since they run on remote machines.
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
	"~/.aws",
	"~/.config/gh",
	"~/.config/op",
	"~/.docker",
	"~/.gnupg",
	"~/.kube",
	"~/.ssh",
	"/data/workspace/1password-service-tokens",
];

/**
 * Recursively deleting or emptying (`dir/*`) any of these prompts. Deleting a
 * path inside them does not, because that is where normal work happens.
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
	"~/.bb",
	"~/.bb/*",
	"~/.config",
	"~/.local",
	"~/.local/*",
	"~/Desktop",
	"~/Documents",
	"~/Library",

	// Workspace volume. Main checkouts live one level below each code group;
	// /data/workspace/code/worktrees/* is left out so worktree cleanup is quiet.
	"/data",
	"/data/workspace",
	"/data/workspace/*",
	"/data/workspace/code/*",
	"/data/workspace/code/buildr/*",
	"/data/workspace/code/exo/*",
	"/data/workspace/code/oss/*",
	"/data/workspace/code/personal/*",
];

/** Recursively deleting a directory with one of these names prompts. */
export const UNSAFE_RM_NAMES = [".git"];

export type GateContext = {
	/** Working directory the command runs in; null when unknown. */
	cwd: string | null;
	home: string;
};

export type RmInvocation = {
	recursive: boolean;
	noPreserveRoot: boolean;
	/** Targets resolved to absolute paths where the working directory is known. */
	targets: string[];
};

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
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
const SHELL_COMMAND_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/;
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const HOME_PREFIX = /^(~|\$HOME|\$\{HOME\})(?=\/|$)/;
// Paths that still contain a variable or command substitution can't be resolved.
const UNRESOLVED = /[$`]/;
const GLOB_CHARS = /[*?[{]/;
// A last segment made only of wildcards (`*`, `.*`, `**`, `{*,.*}`) empties its
// directory. Globs with literal text (`build-*`, `*.log`) only remove matches.
const EMPTYING_GLOB = /^[.*?[\]!{},]*\*[.*?[\]!{},]*$/;

const OPERATOR_CHARS = new Set([";", "&", "|", "(", ")", "<", ">"]);
// Inside double quotes, a backslash only escapes these characters.
const DOUBLE_QUOTE_ESCAPES = new Set(["$", "`", '"', "\\", "\n"]);

/** A shell word with quotes removed, or null for an operator that ends a command. */
type Token = string | null;

/** Index of the `)` closing a `$(` whose body starts at `start`. */
function closingParen(command: string, start: number): number {
	let depth = 1;
	for (let i = start; i < command.length; i++) {
		if (command[i] === "(") depth++;
		if (command[i] === ")" && --depth === 0) return i;
	}
	return command.length;
}

/**
 * Split a command into words and operators the way the shell would: quotes
 * and backslashes are removed, `\`-newline continues a line, unquoted
 * newlines and `;&|()<>` end a command, and `#` starts a comment.
 * Substitutions stay in the word as written; their bodies are returned
 * separately so they can be scanned too.
 */
export function tokenize(command: string): { tokens: Token[]; substitutions: string[] } {
	const tokens: Token[] = [];
	const substitutions: string[] = [];
	let word = "";
	let inWord = false;

	const endWord = () => {
		if (inWord) tokens.push(word);
		word = "";
		inWord = false;
	};

	// Append a `$(...)` or backtick substitution starting at `i`; return its last index.
	const readSubstitution = (i: number): number => {
		const backtick = command[i] === "`";
		const bodyStart = backtick ? i + 1 : i + 2;
		const end = backtick ? command.indexOf("`", bodyStart) : closingParen(command, bodyStart);
		const stop = end === -1 ? command.length : end;
		substitutions.push(command.slice(bodyStart, stop));
		word += command.slice(i, stop + 1);
		inWord = true;
		return stop;
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		const next = command[i + 1];

		if (char === "\\") {
			i++;
			if (next !== undefined && next !== "\n") {
				word += next;
				inWord = true;
			}
		} else if (char === "'") {
			const end = command.indexOf("'", i + 1);
			const stop = end === -1 ? command.length : end;
			word += command.slice(i + 1, stop);
			inWord = true;
			i = stop;
		} else if (char === '"') {
			inWord = true;
			for (i++; i < command.length && command[i] !== '"'; i++) {
				const inner = command[i];
				if (inner === "\\" && DOUBLE_QUOTE_ESCAPES.has(command[i + 1])) {
					i++;
					if (command[i] !== "\n") word += command[i];
				} else if (inner === "`" || (inner === "$" && command[i + 1] === "(")) {
					i = readSubstitution(i);
				} else {
					word += inner;
				}
			}
		} else if (char === "`" || (char === "$" && next === "(")) {
			i = readSubstitution(i);
		} else if (char === "#" && !inWord) {
			const end = command.indexOf("\n", i);
			i = (end === -1 ? command.length : end) - 1;
		} else if (char === "\n" || OPERATOR_CHARS.has(char)) {
			endWord();
			if (tokens.at(-1) !== null) tokens.push(null);
		} else if (char === " " || char === "\t") {
			endWord();
		} else {
			word += char;
			inWord = true;
		}
	}

	endWord();
	return { tokens, substitutions };
}

function wordsUntilSeparator(tokens: Token[], start: number): string[] {
	const words: string[] = [];
	for (let i = start; i < tokens.length; i++) {
		const word = tokens[i];
		if (word === null) break;
		words.push(word);
	}
	return words;
}

function resolvePath(path: string, context: GateContext): string {
	const expanded = path.replace(HOME_PREFIX, context.home);
	const resolvable = !expanded.startsWith("/") && context.cwd !== null && !UNRESOLVED.test(expanded);
	const normalized = posix.normalize(resolvable ? posix.join(context.cwd as string, expanded) : expanded);
	return normalized.length > 1 ? normalized.replace(/\/+$/, "") : normalized;
}

function changeDirectory(arg: string | undefined, context: GateContext): string | null {
	if (arg === undefined) return context.home;
	if (arg === "-") return null;
	const next = resolvePath(arg, context);
	return next.startsWith("/") && !UNRESOLVED.test(next) ? next : null;
}

function parseRmArgs(args: string[], context: GateContext): RmInvocation {
	let recursive = false;
	let noPreserveRoot = false;
	let parsingOptions = true;
	const targets: string[] = [];

	// GNU rm accepts options after operands, so keep reading options until `--`.
	for (const arg of args) {
		if (parsingOptions && arg === "--") {
			parsingOptions = false;
		} else if (parsingOptions && arg.startsWith("-") && arg !== "-") {
			if (arg === "--recursive" || (!arg.startsWith("--") && /[rR]/.test(arg))) recursive = true;
			if (arg === "--no-preserve-root") noPreserveRoot = true;
		} else if (arg !== "") {
			targets.push(resolvePath(arg, context));
		}
	}

	return { recursive, noPreserveRoot, targets };
}

/** Return the command string passed to `sh -c` and friends, if any. */
function shellPayload(args: string[]): string | null {
	for (let i = 0; i < args.length && args[i].startsWith("-"); i++) {
		if (SHELL_COMMAND_FLAG.test(args[i])) return args[i + 1] ?? null;
	}
	return null;
}

function scanCommand(command: string, context: GateContext, found: RmInvocation[]): void {
	const { tokens, substitutions } = tokenize(command);
	for (const body of substitutions) scanCommand(body, context, found);

	let current = context;
	let atCommandStart = true;

	for (let i = 0; i < tokens.length; i++) {
		const word = tokens[i];
		if (word === null) {
			atCommandStart = true;
			continue;
		}

		const args = wordsUntilSeparator(tokens, i + 1);
		// Matches `rm`, `\rm` (the tokenizer drops the backslash), and `/bin/rm`.
		// Every word is checked, so `sudo rm` and `xargs rm` are covered too.
		const program = posix.basename(word);

		if (atCommandStart && word === "cd") {
			current = { ...current, cwd: changeDirectory(args[0], current) };
		}
		if (program === "rm") {
			found.push(parseRmArgs(args, current));
		}
		if (SHELLS.has(program)) {
			const payload = shellPayload(args);
			if (payload !== null) scanCommand(payload, current, found);
		}

		atCommandStart = atCommandStart && ENV_ASSIGNMENT.test(word);
	}
}

/** Find every `rm` in the command, with targets resolved against the context. */
export function collectRmInvocations(command: string, context: GateContext): RmInvocation[] {
	const found: RmInvocation[] = [];
	scanCommand(command, context, found);
	return found;
}

function segmentsOf(path: string): string[] {
	// "/etc/nginx" -> ["", "etc", "nginx"]; "/" -> [""]
	return path === "/" ? [""] : path.split("/");
}

const escapeRegExp = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Regex source for one path segment of a shell glob: `*`, `?`, `[...]`, `{a,b}`. */
function globSource(glob: string): string {
	let source = "";

	for (let i = 0; i < glob.length; i++) {
		const char = glob[i];
		const close = char === "[" ? glob.indexOf("]", i + 2) : char === "{" ? glob.indexOf("}", i + 1) : -1;

		if (char === "*") {
			source += ".*";
		} else if (char === "?") {
			source += ".";
		} else if (char === "[" && close !== -1) {
			const body = glob.slice(i + 1, close).replace(/^!/, "^").replaceAll("\\", "\\\\");
			source += `[${body}]`;
			i = close;
		} else if (char === "{" && close !== -1) {
			source += `(?:${glob.slice(i + 1, close).split(",").map(globSource).join("|")})`;
			i = close;
		} else {
			source += escapeRegExp(char);
		}
	}

	return source;
}

function segmentMatches(pathSegment: string | undefined, patternSegment: string): boolean {
	if (pathSegment === undefined) return false;
	if (patternSegment === "*" || pathSegment === patternSegment) return true;
	if (!GLOB_CHARS.test(pathSegment)) return false;
	// Like the shell, a glob only matches a dot entry when it starts with a dot.
	if (patternSegment.startsWith(".") && !pathSegment.startsWith(".")) return false;
	// A glob in the target (`/home/*/.ssh`) matches any directory it could expand to.
	return new RegExp(`^${globSource(pathSegment)}$`).test(patternSegment);
}

function startsWithPattern(path: string[], pattern: string[]): boolean {
	return pattern.every((segment, index) => segmentMatches(path[index], segment));
}

function patternSegments(pattern: string, home: string): string[] {
	return segmentsOf(resolvePath(pattern, { cwd: null, home }));
}

/**
 * Check one resolved target. Relative targets (unknown working directory) can
 * only match UNSAFE_RM_NAMES.
 */
export function isUnsafeRmTarget(target: string, recursive: boolean, home: string): boolean {
	let path = target;
	// `dir/*` (or `dir/*/*`) empties dir, so judge dir itself.
	while (path !== "/" && EMPTYING_GLOB.test(posix.basename(path))) {
		path = posix.dirname(path);
	}

	const segments = segmentsOf(path);
	const inTree = UNSAFE_RM_TREES.some((tree) => startsWithPattern(segments, patternSegments(tree, home)));
	if (inTree || !recursive) return inTree;

	return (
		UNSAFE_RM_ROOTS.some((root) => {
			const pattern = patternSegments(root, home);
			return segments.length === pattern.length && startsWithPattern(segments, pattern);
		}) || UNSAFE_RM_NAMES.includes(posix.basename(path))
	);
}

export function isUnsafeRmCommand(command: string, context: GateContext): boolean {
	return collectRmInvocations(command, context).some(
		(rm) =>
			(rm.recursive && rm.noPreserveRoot) ||
			rm.targets.some((target) => isUnsafeRmTarget(target, rm.recursive, context.home)),
	);
}

/** Decide whether a bash tool call needs confirmation. */
export function evaluateBashCommand(command: string, context: GateContext): "allow" | "confirm" {
	// Remote machines are not our filesystem; the gate does not apply.
	if (SSH_PATTERN.test(command)) return "allow";
	return isUnsafeRmCommand(command, context) ? "confirm" : "allow";
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = event.input.command as string;
		if (evaluateBashCommand(command, { cwd: ctx.cwd, home: homedir() }) === "allow") return undefined;

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
