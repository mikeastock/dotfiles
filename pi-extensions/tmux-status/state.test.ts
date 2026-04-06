import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { TmuxStatusState } from "./state.js";

describe("TmuxStatusState", () => {
	it("stays running while async subagents remain active after agent end", () => {
		const state = new TmuxStatusState();

		state.reset("new");
		state.setTerminalState("done");
		assert.equal(state.handleAsyncStart("run-1"), "running");
		assert.equal(state.getIdleState(), "running");
		assert.equal(state.handleAsyncEnd("run-1", "completed"), "done");
	});

	it("becomes failed when the last async subagent fails", () => {
		const state = new TmuxStatusState();

		state.reset("new");
		state.setTerminalState("done");
		state.handleAsyncStart("run-1");
		state.handleAsyncStart("run-2");
		assert.equal(state.handleAsyncEnd("run-1", "completed"), "running");
		assert.equal(state.handleAsyncEnd("run-2", "failed"), "failed");
	});

	it("ignores duplicate or unknown async end events", () => {
		const state = new TmuxStatusState();

		state.reset("done");
		assert.equal(state.handleAsyncEnd("missing", "completed"), null);
		state.handleAsyncStart("run-1");
		state.handleAsyncEnd("run-1", "completed");
		assert.equal(state.handleAsyncEnd("run-1", "completed"), null);
	});

	it("treats handoff activity as running until it ends", () => {
		const state = new TmuxStatusState();

		state.reset("new");
		assert.equal(state.startExternalActivity("handoff"), "running");
		assert.equal(state.getIdleState(), "running");
		assert.equal(state.endExternalActivity("handoff"), "new");
	});

	it("keeps running while handoff activity overlaps async subagent work", () => {
		const state = new TmuxStatusState();

		state.reset("done");
		state.startExternalActivity("handoff");
		state.handleAsyncStart("run-1");
		assert.equal(state.endExternalActivity("handoff"), "running");
		assert.equal(state.handleAsyncEnd("run-1", "completed"), "done");
	});
});
