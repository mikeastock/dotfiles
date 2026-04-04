import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createPendingHandoffStore } from "./pending.js";
import { completePendingHandoff, finalizeGeneratedHandoff, queueToolHandoff } from "./flow.js";

describe("queueToolHandoff", () => {
  it("stores the pending handoff and queues /__handoff-complete as a follow-up command", () => {
    const store = createPendingHandoffStore();
    const sent: Array<{ message: string; options: unknown }> = [];

    const result = queueToolHandoff(store, {
      finalPrompt: "Prompt",
      parentSession: "/tmp/parent.jsonl",
    }, (message, options) => {
      sent.push({ message, options });
    });

    assert.equal(result.ok, true);
    assert.deepEqual(store.consume(), { finalPrompt: "Prompt", parentSession: "/tmp/parent.jsonl" });
    assert.deepEqual(sent, [{ message: "/__handoff-complete", options: { deliverAs: "followUp" } }]);
  });

  it("returns an error when command queueing throws", () => {
    const store = createPendingHandoffStore();

    const result = queueToolHandoff(store, {
      finalPrompt: "Prompt",
      parentSession: undefined,
    }, () => {
      throw new Error("queue failed");
    });

    assert.equal(result.ok, false);
    assert.match(result.error!, /queue failed/);
  });
});

describe("completePendingHandoff", () => {
  it("returns an error when no pending handoff exists", async () => {
    const store = createPendingHandoffStore();
    const result = await completePendingHandoff(store, async () => ({ cancelled: false }));
    assert.equal(result.ok, false);
    assert.match(result.error!, /No pending handoff/);
  });

  it("surfaces cancellation from session creation", async () => {
    const store = createPendingHandoffStore();
    store.set({ finalPrompt: "Prompt", parentSession: undefined });
    const result = await completePendingHandoff(store, async () => ({ cancelled: true }));
    assert.deepEqual(result, { ok: true, cancelled: true });
  });
});

describe("handoff bridge", () => {
  it("passes the queued pending payload into the shared session creator", async () => {
    const store = createPendingHandoffStore();
    const sent: Array<{ message: string; options: unknown }> = [];
    const received: Array<{ finalPrompt: string; parentSession: string | undefined }> = [];

    const queued = queueToolHandoff(store, {
      finalPrompt: "Prompt",
      parentSession: "/tmp/parent.jsonl",
    }, (message, options) => {
      sent.push({ message, options });
    });

    assert.deepEqual(queued, { ok: true });
    assert.deepEqual(sent, [{ message: "/__handoff-complete", options: { deliverAs: "followUp" } }]);

    const completed = await completePendingHandoff(store, async (pending) => {
      received.push(pending);
      return { cancelled: false };
    });

    assert.deepEqual(completed, { ok: true, cancelled: false });
    assert.deepEqual(received, [{ finalPrompt: "Prompt", parentSession: "/tmp/parent.jsonl" }]);
  });

  it("returns cancelled when prompt generation is cancelled and does not create a session", () => {
    let created = false;

    const result = finalizeGeneratedHandoff({
      generatedPrompt: null,
      finalPrompt: "unused",
    });

    if (result.ok) {
      created = true;
    }

    assert.deepEqual(result, { ok: false, cancelled: true });
    assert.equal(created, false);
  });
});
