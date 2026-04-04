import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildFinalPrompt, buildInitialUserMessage } from "./prompt.js";

describe("buildFinalPrompt", () => {
  it("includes the goal and parent session block when a parent session exists", () => {
    const result = buildFinalPrompt({
      goal: "Continue the refactor",
      generatedPrompt: "## Context\nDone work",
      parentSession: "/tmp/parent.jsonl",
    });

    assert.match(result, /^Continue the refactor\n\n\/skill:session-query\n\n\*\*Parent session:\*\* `\/tmp\/parent\.jsonl`/);
    assert.match(result, /## Context\nDone work/);
  });

  it("omits the parent session block when there is no parent session", () => {
    const result = buildFinalPrompt({
      goal: "Continue the refactor",
      generatedPrompt: "## Context\nDone work",
      parentSession: undefined,
    });

    assert.equal(result, "Continue the refactor\n\n## Context\nDone work");
  });
});

describe("buildInitialUserMessage", () => {
  it("creates a user message containing the final prompt", () => {
    const message = buildInitialUserMessage("Final prompt text", 123);

    assert.equal(message.role, "user");
    assert.equal(message.timestamp, 123);
    assert.deepEqual(message.content, [{ type: "text", text: "Final prompt text" }]);
  });
});
