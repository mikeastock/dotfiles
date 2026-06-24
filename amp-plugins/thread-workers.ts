import type { BuiltinAgentMode, PluginAPI, ThreadID } from "@ampcode/plugin";

type BuildWorkerPromptOptions = {
	prompt: string;
	parentThreadID: ThreadID;
	label?: string;
};

const BUILTIN_MODES = new Set<BuiltinAgentMode>(["smart", "deep", "rush"]);

export function buildWorkerPrompt({ prompt, parentThreadID, label }: BuildWorkerPromptOptions): string {
	const labelSection = label ? `\nContext label: ${label}\n` : "";

	return `You are a worker agent spawned from parent thread ${parentThreadID}.${labelSection}
Your task:
${prompt}

Work independently, keep the implementation aligned with the parent thread's design intent, and avoid adding abstractions that are not needed for this task.

When you are done, use the send_to_thread tool to report back to ${parentThreadID}. Include:
- what you changed
- how you verified it
- any follow-up questions or blockers

If the parent thread sends follow-up feedback, address it in this worker thread and report back again.`;
}

function requiredString(input: Record<string, unknown>, key: string): string {
	const value = input[key];
	if (typeof value !== "string" || value.trim() === "") {
		throw new Error(`${key} must be a non-empty string`);
	}
	return value;
}

function optionalString(input: Record<string, unknown>, key: string): string | undefined {
	const value = input[key];
	if (value === undefined) {
		return undefined;
	}
	if (typeof value !== "string") {
		throw new Error(`${key} must be a string when provided`);
	}
	return value.trim() || undefined;
}

function optionalBoolean(input: Record<string, unknown>, key: string, fallback: boolean): boolean {
	const value = input[key];
	if (value === undefined) {
		return fallback;
	}
	if (typeof value !== "boolean") {
		throw new Error(`${key} must be a boolean when provided`);
	}
	return value;
}

function builtinMode(input: Record<string, unknown>): BuiltinAgentMode {
	const value = input.mode;
	if (value === undefined) {
		return "smart";
	}
	if (typeof value !== "string" || !BUILTIN_MODES.has(value as BuiltinAgentMode)) {
		throw new Error("mode must be one of: smart, deep, rush");
	}
	return value as BuiltinAgentMode;
}

function threadID(input: Record<string, unknown>): ThreadID {
	const value = requiredString(input, "threadID");
	if (!value.startsWith("T-")) {
		throw new Error("threadID must start with T-");
	}
	return value as ThreadID;
}

export default function registerThreadWorkers(amp: PluginAPI) {
	amp.registerTool({
		name: "spawn_worker",
		description:
			"Spawn a builtin Amp agent in a new thread to work on a task and report back to the current thread.",
		inputSchema: {
			type: "object",
			properties: {
				prompt: {
					type: "string",
					description: "The worker's task and any context it needs.",
				},
				mode: {
					type: "string",
					enum: ["smart", "deep", "rush"],
					description: "Builtin Amp agent mode to use. Defaults to smart.",
				},
				label: {
					type: "string",
					description: "Optional short context label for the worker task.",
				},
			},
			required: ["prompt"],
		},
		async execute(input, ctx) {
			const mode = builtinMode(input);
			const prompt = requiredString(input, "prompt");
			const label = optionalString(input, "label");

			const agent = amp.getBuiltinAgent(mode);
			const workerThread = await agent.createThread({
				parentThreadID: ctx.thread.id,
				show: false,
			});

			await workerThread.appendUserMessage({
				type: "user-message",
				content: buildWorkerPrompt({ prompt, parentThreadID: ctx.thread.id, label }),
			});

			return `Spawned ${mode} worker thread ${workerThread.id}. Continue your design work; the worker has been instructed to report back to this thread when done.`;
		},
	});

	amp.registerTool({
		name: "send_to_thread",
		description: "Send a user message to an existing Amp thread, usually to report worker progress.",
		inputSchema: {
			type: "object",
			properties: {
				threadID: {
					type: "string",
					description: "Target Amp thread ID, for example T-...",
				},
				message: {
					type: "string",
					description: "Message to append to the target thread.",
				},
				steer: {
					type: "boolean",
					description: "Queue as a steering message when the target thread is busy. Defaults to true.",
				},
			},
			required: ["threadID", "message"],
		},
		async execute(input) {
			const targetThreadID = threadID(input);
			const message = requiredString(input, "message");
			const steer = optionalBoolean(input, "steer", true);

			const targetThread = amp.threads.get(targetThreadID);
			await targetThread.appendUserMessage(
				{
					type: "user-message",
					content: message,
				},
				{ steer },
			);

			return `Sent message to thread ${targetThreadID}.`;
		},
	});
}
