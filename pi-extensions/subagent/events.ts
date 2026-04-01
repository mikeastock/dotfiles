export const SUBAGENT_RUN_START_EVENT = "subagent:run_start";
export const SUBAGENT_RUN_END_EVENT = "subagent:run_end";

export type SubagentExecutionMode = "sync" | "async";
export type SubagentRunStatus = "completed" | "failed";
export type SubagentAgentSource = "bundled" | "user" | "project" | "unknown";

export interface SubagentRunStartEvent {
	id: string;
	agent: string;
	agentSource: SubagentAgentSource;
	task: string;
	execution: SubagentExecutionMode;
	startedAt: number;
	batchId?: string;
}

export interface SubagentRunEndEvent extends SubagentRunStartEvent {
	finishedAt: number;
	status: SubagentRunStatus;
	exitCode: number;
	stopReason?: string;
	errorMessage?: string;
}

export function buildSubagentRunStartEvent(event: SubagentRunStartEvent): SubagentRunStartEvent {
	return event;
}

export function buildSubagentRunEndEvent(event: SubagentRunEndEvent): SubagentRunEndEvent {
	return event;
}
