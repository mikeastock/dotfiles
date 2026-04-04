import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { afterEach, describe, it } from "node:test";
import { SessionManager } from "@mariozechner/pi-coding-agent";
import { buildInitialUserMessage } from "./prompt.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("handoff session seeding", () => {
  it("appends the initial user handoff prompt into a fresh session", () => {
    const cwd = mkdtempSync(path.join(os.tmpdir(), "handoff-cwd-"));
    const sessionDir = mkdtempSync(path.join(os.tmpdir(), "handoff-sessions-"));
    tempDirs.push(cwd, sessionDir);

    const sm = SessionManager.create(cwd, sessionDir);
    sm.newSession();
    sm.appendMessage(buildInitialUserMessage("Carry this context forward", 123));

    const entries = sm.getEntries();
    const messageEntries = entries.filter((entry: any) => entry.type === "message");
    assert.equal(messageEntries.length, 1);
    assert.equal(messageEntries[0].message.role, "user");
    assert.deepEqual(messageEntries[0].message.content, [{ type: "text", text: "Carry this context forward" }]);
  });
});
