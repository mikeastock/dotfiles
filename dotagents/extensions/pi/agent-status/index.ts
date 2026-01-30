/**
 * Agent Status Extension
 *
 * Writes Pi agent state to ~/.config/agents/state.json for tmux status integration.
 * Uses PID-based keying to support multiple agents per tmux session.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

type AgentState = "idle" | "working" | "waiting";

interface AgentEntry {
	session: string;
	pane: string | null;
	agent: "pi";
	state: AgentState;
	timestamp: number;
}

interface StateFile {
	agents: Record<string, AgentEntry>;
}

const STATE_FILE = path.join(os.homedir(), ".config", "agents", "state.json");

const WAIT_EVENT = "agent-status:wait";

interface WaitEvent {
	active: boolean;
	source?: string;
}

function getTmuxInfo(): { session: string; pane: string | null } | null {
	const tmuxPane = process.env.TMUX_PANE;
	if (!tmuxPane) return null;

	try {
		const result = execSync("tmux display-message -p '#S\n#{pane_id}'", {
			encoding: "utf-8",
			timeout: 1000,
		}).trim();
		const lines = result.split("\n");
		const session = lines[0] || null;
		const pane = lines[1] || null;
		if (!session) return null;
		return { session, pane };
	} catch {
		return null;
	}
}

function isWaitEvent(payload: unknown): payload is WaitEvent {
	return (
		typeof payload === "object" &&
		payload !== null &&
		typeof (payload as WaitEvent).active === "boolean"
	);
}

function readStateFile(): StateFile {
	try {
		const content = fs.readFileSync(STATE_FILE, "utf-8");
		const parsed = JSON.parse(content);
		// Handle migration from old format
		if (parsed?.sessions && !parsed?.agents) {
			return { agents: {} };
		}
		if (!parsed?.agents) return { agents: {} };
		return parsed as StateFile;
	} catch {
		return { agents: {} };
	}
}

function writeStateFile(state: StateFile): void {
	const dir = path.dirname(STATE_FILE);
	fs.mkdirSync(dir, { recursive: true });

	const tempFile = `${STATE_FILE}.${process.pid}.tmp`;
	fs.writeFileSync(tempFile, JSON.stringify(state, null, 2));
	fs.renameSync(tempFile, STATE_FILE);
}

function updateState(
	session: string,
	pane: string | null,
	newState: AgentState,
): void {
	const stateFile = readStateFile();
	const pid = process.pid.toString();
	stateFile.agents[pid] = {
		session,
		pane,
		agent: "pi",
		state: newState,
		timestamp: Date.now(),
	};
	writeStateFile(stateFile);
}

function removeAgent(): void {
	const stateFile = readStateFile();
	const pid = process.pid.toString();
	delete stateFile.agents[pid];
	writeStateFile(stateFile);
}

export default function (pi: ExtensionAPI) {
	const tmuxInfo = getTmuxInfo();
	if (!tmuxInfo) return;

	const { session, pane } = tmuxInfo;

	updateState(session, pane, "idle");

	pi.on("agent_start", async () => {
		updateState(session, pane, "working");
	});

	pi.events.on(WAIT_EVENT, (payload) => {
		if (!isWaitEvent(payload)) return;
		updateState(session, pane, payload.active ? "waiting" : "working");
	});

	pi.on("agent_end", async () => {
		updateState(session, pane, "waiting");
	});

	pi.on("session_shutdown", async () => {
		removeAgent();
	});

	const cleanup = () => {
		try {
			removeAgent();
		} catch {
			// Ignore cleanup errors
		}
	};

	process.on("SIGINT", cleanup);
	process.on("SIGTERM", cleanup);
	process.on("exit", cleanup);
}
