import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createPendingHandoffStore } from "./pending.js";

describe("createPendingHandoffStore", () => {
  it("returns the pending handoff once and then clears it", () => {
    const store = createPendingHandoffStore();
    store.set({ finalPrompt: "Prompt", parentSession: "/tmp/parent.jsonl" });

    assert.deepEqual(store.consume(), { finalPrompt: "Prompt", parentSession: "/tmp/parent.jsonl" });
    assert.equal(store.consume(), null);
  });

  it("replaces the previous pending handoff when set twice", () => {
    const store = createPendingHandoffStore();
    store.set({ finalPrompt: "Old", parentSession: undefined });
    store.set({ finalPrompt: "New", parentSession: "/tmp/parent.jsonl" });

    assert.deepEqual(store.consume(), { finalPrompt: "New", parentSession: "/tmp/parent.jsonl" });
  });
});
