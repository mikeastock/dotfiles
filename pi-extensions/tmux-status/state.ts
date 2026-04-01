export type StatusState = "new" | "running" | "waitingInput" | "stalled" | "done" | "failed";
export type AsyncSubagentStatus = "completed" | "failed";

type TerminalState = Extract<StatusState, "new" | "done" | "failed">;

export class TmuxStatusState {
	private readonly activeAsyncRunIds = new Set<string>();
	private terminalState: TerminalState = "new";
	private asyncFailureOccurred = false;

	reset(next: TerminalState): StatusState {
		this.activeAsyncRunIds.clear();
		this.terminalState = next;
		this.asyncFailureOccurred = false;
		return next;
	}

	setTerminalState(next: Extract<StatusState, "done" | "failed">): void {
		this.terminalState = next;
	}

	handleAsyncStart(runId: string): StatusState | null {
		if (this.activeAsyncRunIds.has(runId)) return null;
		this.activeAsyncRunIds.add(runId);
		return "running";
	}

	handleAsyncEnd(runId: string, status: AsyncSubagentStatus): StatusState | null {
		if (!this.activeAsyncRunIds.has(runId)) return null;
		this.activeAsyncRunIds.delete(runId);
		if (status === "failed") this.asyncFailureOccurred = true;
		return this.getIdleState();
	}

	getIdleState(): StatusState {
		if (this.activeAsyncRunIds.size > 0) return "running";
		if (this.asyncFailureOccurred) return "failed";
		return this.terminalState;
	}

	hasActiveAsyncRuns(): boolean {
		return this.activeAsyncRunIds.size > 0;
	}
}
