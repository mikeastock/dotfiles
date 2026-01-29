/**
 * Agent Status Extension
 *
 * Writes Pi agent state to ~/.config/agents/state.json for tmux status integration.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

type AgentState = "idle" | "working" | "waiting";

interface SessionState {
	agent: "pi";
	state: AgentState;
	pid: number;
	timestamp: number;
}

interface StateFile {
	sessions: Record<string, SessionState>;
}

const STATE_FILE = path.join(os.homedir(), ".config", "agents", "state.json");

function getTmuxSessionName(): string | null {
	const tmuxPane = process.env.TMUX_PANE;
	if (!tmuxPane) return null;

	try {
		const result = execSync("tmux display-message -p '#S'", {
			encoding: "utf-8",
			timeout: 1000,
		}).trim();
		return result || null;
	} catch {
		return null;
	}
}

function readStateFile(): StateFile {
	try {
		const content = fs.readFileSync(STATE_FILE, "utf-8");
		const parsed = JSON.parse(content) as StateFile;
		if (!parsed?.sessions) return { sessions: {} };
		return parsed;
	} catch {
		return { sessions: {} };
	}
}

function writeStateFile(state: StateFile): void {
	const dir = path.dirname(STATE_FILE);
	fs.mkdirSync(dir, { recursive: true });

	const tempFile = `${STATE_FILE}.${process.pid}.tmp`;
	fs.writeFileSync(tempFile, JSON.stringify(state, null, 2));
	fs.renameSync(tempFile, STATE_FILE);
}

function updateState(sessionName: string, newState: AgentState): void {
	const stateFile = readStateFile();
	stateFile.sessions[sessionName] = {
		agent: "pi",
		state: newState,
		pid: process.pid,
		timestamp: Date.now(),
	};
	writeStateFile(stateFile);
}

function removeSession(sessionName: string): void {
	const stateFile = readStateFile();
	delete stateFile.sessions[sessionName];
	writeStateFile(stateFile);
}

export default function (pi: ExtensionAPI) {
	const sessionName = getTmuxSessionName();
	if (!sessionName) return;

	updateState(sessionName, "idle");

	pi.on("agent_start", async () => {
		updateState(sessionName, "working");
	});

	pi.on("agent_end", async () => {
		updateState(sessionName, "waiting");
	});

	pi.on("session_shutdown", async () => {
		removeSession(sessionName);
	});

	const cleanup = () => {
		try {
			removeSession(sessionName);
		} catch {
			// Ignore cleanup errors
		}
	};

	process.on("SIGINT", cleanup);
	process.on("SIGTERM", cleanup);
	process.on("exit", cleanup);
}
