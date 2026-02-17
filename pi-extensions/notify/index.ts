/**
 * Desktop Notification Extension
 *
 * Sends a native desktop notification when the agent finishes and is waiting for input.
 * Uses OSC 777 escape sequence - no external dependencies.
 *
 * Supported terminals: Ghostty, iTerm2, WezTerm, rxvt-unicode
 * Not supported: Kitty (uses OSC 99), Terminal.app, Windows Terminal, Alacritty
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Markdown, type MarkdownTheme } from "@mariozechner/pi-tui";

/**
 * Send a desktop notification via OSC 777 escape sequence.
 */
const notify = (title: string, body: string): void => {
	// OSC 777 format: ESC ] 777 ; notify ; title ; body BEL
	process.stdout.write(`\x1b]777;notify;${title};${body}\x07`);
};

const isTextPart = (part: unknown): part is { type: "text"; text: string } =>
	Boolean(part && typeof part === "object" && "type" in part && part.type === "text" && "text" in part);

const extractLastAssistantText = (messages: Array<{ role?: string; content?: unknown }>): string | null => {
	for (let i = messages.length - 1; i >= 0; i--) {
		const message = messages[i];
		if (message?.role !== "assistant") {
			continue;
		}

		const content = message.content;
		if (typeof content === "string") {
			return content.trim() || null;
		}

		if (Array.isArray(content)) {
			const text = content.filter(isTextPart).map((part) => part.text).join("\n").trim();
			return text || null;
		}

		return null;
	}

	return null;
};

const plainMarkdownTheme: MarkdownTheme = {
	heading: (text) => text,
	link: (text) => text,
	linkUrl: () => "",
	code: (text) => text,
	codeBlock: (text) => text,
	codeBlockBorder: () => "",
	quote: (text) => text,
	quoteBorder: () => "",
	hr: () => "",
	listBullet: () => "",
	bold: (text) => text,
	italic: (text) => text,
	strikethrough: (text) => text,
	underline: (text) => text,
};

const simpleMarkdown = (text: string, width = 80): string => {
	const markdown = new Markdown(text, 0, 0, plainMarkdownTheme);
	return markdown.render(width).join("\n");
};

const formatNotification = (text: string | null): { title: string; body: string } => {
	const simplified = text ? simpleMarkdown(text) : "";
	const normalized = simplified.replace(/\s+/g, " ").trim();
	if (!normalized) {
		return { title: "Ready for input", body: "" };
	}

	const maxBody = 200;
	const body = normalized.length > maxBody ? `${normalized.slice(0, maxBody - 1)}…` : normalized;
	return { title: "π", body };
};

type AgentState = "waiting" | "working";

type StatusEntry = {
	pid: number;
	terminal: string;
	state: AgentState;
	updatedAt: number;
};

const STATUS_DIR = join(tmpdir(), "pi-notify-status");
const STALE_MS = 1000 * 60 * 60 * 12;

const isProcessAlive = (pid: number): boolean => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};

const terminalSlug = (terminal: string): string => Buffer.from(terminal, "utf8").toString("base64url");

const entryPath = (terminal: string, pid: number): string => join(STATUS_DIR, `${terminalSlug(terminal)}.${pid}.json`);

const writeSelfEntry = async (terminal: string, state: AgentState): Promise<void> => {
	await mkdir(STATUS_DIR, { recursive: true });
	const entry: StatusEntry = {
		pid: process.pid,
		terminal,
		state,
		updatedAt: Date.now(),
	};

	const finalPath = entryPath(terminal, process.pid);
	const tempPath = `${finalPath}.tmp-${Date.now()}-${Math.random().toString(36).slice(2)}`;
	try {
		await writeFile(tempPath, `${JSON.stringify(entry)}\n`, "utf8");
		await rename(tempPath, finalPath);
	} catch (error) {
		await unlink(tempPath).catch(() => undefined);
		throw error;
	}
};

const removeSelfEntry = async (terminal: string): Promise<void> => {
	try {
		await unlink(entryPath(terminal, process.pid));
	} catch {
		// Ignore if already removed.
	}
};

const deleteIfOld = async (path: string, now: number): Promise<void> => {
	try {
		const info = await stat(path);
		if (now - info.mtimeMs > STALE_MS) {
			await unlink(path).catch(() => undefined);
		}
	} catch {
		// Ignore stat/unlink failures.
	}
};

const countWaiting = async (terminal: string): Promise<number> => {
	await mkdir(STATUS_DIR, { recursive: true });
	const now = Date.now();
	const files = await readdir(STATUS_DIR);
	let waiting = 0;

	for (const file of files) {
		if (!file.endsWith(".json")) {
			continue;
		}

		const path = join(STATUS_DIR, file);
		try {
			const raw = await readFile(path, "utf8");
			const entry = JSON.parse(raw) as Partial<StatusEntry>;
			if (typeof entry.pid !== "number" || typeof entry.terminal !== "string") {
				await deleteIfOld(path, now);
				continue;
			}
			if (!isProcessAlive(entry.pid)) {
				await unlink(path).catch(() => undefined);
				continue;
			}
			if (entry.terminal === terminal && entry.state === "waiting") {
				waiting++;
			}
		} catch {
			await deleteIfOld(path, now);
		}
	}

	return waiting;
};

export default function (pi: ExtensionAPI) {
	let terminalKeyPromise: Promise<string> | undefined;

	const getTerminalKey = (): Promise<string> => {
		if (terminalKeyPromise) {
			return terminalKeyPromise;
		}

		terminalKeyPromise = (async () => {
			const byEnv = process.env.TERM_SESSION_ID ?? process.env.ZELLIJ_SESSION_NAME ?? process.env.ZMX_SESSION;
			if (byEnv) {
				return byEnv;
			}

			try {
				const result = await pi.exec("tty", [], { timeout: 1000 });
				const tty = result.stdout.trim();
				if (result.code === 0 && tty.startsWith("/")) {
					return tty;
				}
			} catch {
				// Fall through.
			}

			return `pty-${process.ppid}`;
		})();

		return terminalKeyPromise;
	};

	const updateStateAndRenderTitle = async (ctx: { hasUI: boolean; ui: { setTitle: (title: string) => void } }, state: AgentState) => {
		const terminal = await getTerminalKey();
		await writeSelfEntry(terminal, state);
		const waitingCount = await countWaiting(terminal);
		if (ctx.hasUI) {
			const symbol = state === "waiting" ? "⏸" : "▶";
			ctx.ui.setTitle(`pi ${symbol} [${waitingCount} waiting]`);
		}
	};

	const removeSelf = async (): Promise<void> => {
		const terminal = await getTerminalKey();
		await removeSelfEntry(terminal);
	};

	pi.on("session_start", async (_event, ctx) => {
		await updateStateAndRenderTitle(ctx, "waiting");
	});

	pi.on("agent_start", async (_event, ctx) => {
		await updateStateAndRenderTitle(ctx, "working");
	});

	pi.on("agent_end", async (event, ctx) => {
		await updateStateAndRenderTitle(ctx, "waiting");

		const lastText = extractLastAssistantText(event.messages ?? []);
		const { title, body } = formatNotification(lastText);
		notify(title, body);
	});

	pi.on("session_shutdown", async () => {
		await removeSelf();
	});
}
