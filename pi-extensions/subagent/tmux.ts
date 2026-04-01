import { execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

const execFileAsync = promisify(execFile);

export function isTmuxAvailable(): boolean {
	return !!process.env.TMUX;
}

export function shellEscape(s: string): string {
	return "'" + s.replace(/'/g, "'\\''") + "'";
}

/**
 * Get the pane ID of the current pi session.
 * Falls back to undefined if not available (split will target focused pane).
 */
export function getParentPane(): string | undefined {
	return process.env.TMUX_PANE || undefined;
}

export function getParentSession(): string | undefined {
	const parentPane = getParentPane();
	if (!parentPane) return undefined;
	try {
		return execFileSync("tmux", ["display-message", "-p", "-t", parentPane, "#{session_id}"], {
			encoding: "utf8",
		}).trim();
	} catch {
		return undefined;
	}
}

/**
 * Create a horizontal split pane that runs a bash command directly.
 * Targets the parent pi pane (via TMUX_PANE) so the split always opens
 * next to pi regardless of which pane the user has focused.
 * Uses `remain-on-exit on` so the pane stays alive after the command finishes,
 * giving the watcher time to read the sentinel. closePane() kills it after.
 * Returns the pane ID (e.g. "%12").
 */
export function getSourceWindowToken(): string {
	const parentPane = getParentPane();
	if (!parentPane) return "unknown";
	try {
		return execFileSync(
			"tmux",
			["display-message", "-p", "-t", parentPane, "#{window_index}"],
			{ encoding: "utf8" },
		).trim();
	} catch {
		return "unknown";
	}
}

export function makeBatchWindowName(batchId: string): string {
	return `subagents-${getSourceWindowToken()}-${batchId}`;
}

export function createWindow(name: string): string {
	const parentSession = getParentSession();
	const args = ["new-window", "-d", "-P", "-F", "#{window_id}", "-n", name];
	if (parentSession) args.push("-t", parentSession);
	return execFileSync("tmux", args, { encoding: "utf8" }).trim();
}

export function createPaneWithCommand(name: string, command: string): string {
	const parentPane = getParentPane();
	const args = ["split-window", "-h", "-d", "-P", "-F", "#{pane_id}"];
	if (parentPane) args.push("-t", parentPane);
	args.push("bash", "-c", command);

	const pane = execFileSync("tmux", args, {
		encoding: "utf8",
	}).trim();
	try {
		execFileSync("tmux", ["set-option", "-t", pane, "remain-on-exit", "on"]);
	} catch {}
	try {
		execFileSync("tmux", ["select-pane", "-t", pane, "-T", name]);
	} catch {}
	return pane;
}

export function getWindowPanes(windowId: string): string[] {
	try {
		return execFileSync("tmux", ["list-panes", "-t", windowId, "-F", "#{pane_id}"], {
			encoding: "utf8",
		})
			.split("\n")
			.map((line) => line.trim())
			.filter(Boolean);
	} catch {
		return [];
	}
}

export function runCommandInPane(pane: string, name: string, command: string): void {
	execFileSync("tmux", ["respawn-pane", "-k", "-t", pane, "bash", "-c", command]);
	try {
		execFileSync("tmux", ["set-option", "-t", pane, "remain-on-exit", "on"]);
	} catch {}
	try {
		execFileSync("tmux", ["select-pane", "-t", pane, "-T", name]);
	} catch {}
}

export function createPaneInWindow(windowId: string, name: string, command: string): string {
	const pane = execFileSync(
		"tmux",
		["split-window", "-t", windowId, "-d", "-P", "-F", "#{pane_id}", "bash", "-c", command],
		{ encoding: "utf8" },
	).trim();
	try {
		execFileSync("tmux", ["set-option", "-t", pane, "remain-on-exit", "on"]);
	} catch {}
	try {
		execFileSync("tmux", ["select-pane", "-t", pane, "-T", name]);
	} catch {}
	return pane;
}

export function tileWindow(windowId: string): void {
	try {
		execFileSync("tmux", ["select-layout", "-t", windowId, "tiled"]);
	} catch {}
}

export function closeWindow(windowId: string): void {
	try {
		execFileSync("tmux", ["kill-window", "-t", windowId]);
	} catch {}
}

/**
 * Close a pane.
 */
export function closePane(pane: string): void {
	try {
		execFileSync("tmux", ["kill-pane", "-t", pane]);
	} catch {}
}

/**
 * Read the last N lines from a pane's screen buffer.
 */
export async function readScreen(pane: string, lines = 5): Promise<string> {
	const { stdout } = await execFileAsync(
		"tmux",
		["capture-pane", "-p", "-t", pane, "-S", `-${Math.max(1, lines)}`],
		{ encoding: "utf8" },
	);
	return stdout;
}

/**
 * Poll a pane until the sentinel __SUBAGENT_DONE_N__ appears.
 * Returns the exit code embedded in the sentinel.
 */
export async function pollForExit(
	pane: string,
	signal: AbortSignal,
	opts: { interval: number; onTick?: () => void },
): Promise<number> {
	while (true) {
		if (signal.aborted) throw new Error("Aborted");

		const screen = await readScreen(pane, 5);
		const match = screen.match(/__SUBAGENT_DONE_(\d+)__/);
		if (match) return parseInt(match[1], 10);

		opts.onTick?.();

		await new Promise<void>((resolve, reject) => {
			if (signal.aborted) return reject(new Error("Aborted"));
			const timer = setTimeout(() => {
				signal.removeEventListener("abort", onAbort);
				resolve();
			}, opts.interval);
			function onAbort() {
				clearTimeout(timer);
				reject(new Error("Aborted"));
			}
			signal.addEventListener("abort", onAbort, { once: true });
		});
	}
}
