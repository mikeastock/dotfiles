/**
 * Agent Status Extension
 *
 * Connects to the agent-status daemon via Unix socket for tmux status integration.
 * Connection lifecycle = agent liveness (no PID tracking needed).
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { execFileSync } from "node:child_process";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

type AgentState = "idle" | "working" | "waiting";

const SOCKET_PATH = path.join(
	os.homedir(),
	".config",
	"agents",
	"agent-status.sock",
);
const WAIT_EVENT = "agent-status:wait";

interface WaitEvent {
	active: boolean;
	source?: string;
}

interface JsonRpcRequest {
	id?: number;
	method: string;
	params?: Record<string, unknown>;
}

interface JsonRpcResponse {
	id?: number;
	result?: unknown;
	error?: { code: number; message: string };
}

function getTmuxInfo(): { session: string; pane: string | null } | null {
	const tmuxPane = process.env.TMUX_PANE;
	if (!tmuxPane) return null;

	try {
		const result = execFileSync(
			"tmux",
			["display-message", "-p", "-t", tmuxPane, "#S\n#{pane_id}"],
			{
			encoding: "utf-8",
			timeout: 1000,
			},
		).trim();
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

export default function (pi: ExtensionAPI) {
	const tmuxInfo = getTmuxInfo();
	if (!tmuxInfo) return;

	const { session, pane } = tmuxInfo;

	let socket: net.Socket | null = null;
	let nextRequestId = 0;
	let connected = false;

	function sendRequest(method: string, params?: Record<string, unknown>): void {
		if (!socket || !connected) return;

		const req: JsonRpcRequest = {
			method,
			params,
		};

		try {
			socket.write(JSON.stringify(req) + "\n");
		} catch {
			// Ignore write errors
		}
	}

	function sendRequestWithResponse(
		method: string,
		params?: Record<string, unknown>,
	): Promise<JsonRpcResponse> {
		return new Promise((resolve) => {
			if (!socket || !connected) {
				resolve({ error: { code: -1, message: "not connected" } });
				return;
				}

				const id = ++nextRequestId;
			const req: JsonRpcRequest = { id, method, params };

			const handleData = (data: Buffer) => {
				const lines = data.toString().split("\n").filter(Boolean);
				for (const line of lines) {
					try {
						const resp: JsonRpcResponse = JSON.parse(line);
						if (resp.id === id) {
							socket?.off("data", handleData);
							resolve(resp);
							return;
						}
					} catch {
						// Ignore parse errors
					}
				}
			};

			socket.on("data", handleData);

			try {
				socket.write(JSON.stringify(req) + "\n");
			} catch (err) {
				socket.off("data", handleData);
				resolve({ error: { code: -1, message: String(err) } });
			}

			setTimeout(() => {
				socket?.off("data", handleData);
				resolve({ error: { code: -1, message: "timeout" } });
			}, 5000);
		});
	}

	function updateState(newState: AgentState): void {
		sendRequest("update", { state: newState });
	}

	function connect(): void {
		socket = net.createConnection(SOCKET_PATH);

		socket.on("connect", async () => {
			connected = true;

			await sendRequestWithResponse("register", {
				session,
				pane,
				agent: "pi",
				state: "idle",
			});
		});

		socket.on("error", () => {
			connected = false;
			socket?.destroy();
		});

		socket.on("close", () => {
			connected = false;
			setTimeout(() => {
				if (!connected) connect();
			}, 5000);
		});
	}

	connect();

	pi.on("agent_start", async () => {
		updateState("working");
	});

	pi.events.on(WAIT_EVENT, (payload) => {
		if (!isWaitEvent(payload)) return;
		updateState(payload.active ? "waiting" : "working");
	});

	pi.on("agent_end", async () => {
		updateState("idle");
	});

	pi.on("session_shutdown", async () => {
		if (socket) {
			sendRequest("unregister");
			socket.end();
		}
	});

	const cleanup = () => {
		try {
			if (socket) {
				socket.destroy();
			}
		} catch {
			// Ignore cleanup errors
		}
	};

	process.on("SIGINT", cleanup);
	process.on("SIGTERM", cleanup);
	process.on("exit", cleanup);
}
