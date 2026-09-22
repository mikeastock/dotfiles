import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildDangerousCommandPrompt, isSafeTmpRmCommand } from "./index.js";

const RPC_TITLE_MAX_LENGTH = 160;
const RPC_MESSAGE_MAX_LENGTH = 8192;

describe("isSafeTmpRmCommand", () => {
	it("allows recursive removals under approved temporary prefixes", () => {
		assert.equal(isSafeTmpRmCommand("rm -rf /tmp"), true);
		assert.equal(isSafeTmpRmCommand("rm -rf /tmp/cache"), true);
		assert.equal(isSafeTmpRmCommand("rm -rf tmp/cache"), true);
		assert.equal(isSafeTmpRmCommand("rm -rf .tmp/cache"), true);
		assert.equal(isSafeTmpRmCommand("rm -rf '/tmp/cache dir'"), true);
	});

	it("does not allow other paths or compound commands", () => {
		assert.equal(isSafeTmpRmCommand("rm -rf ./tmp"), false);
		assert.equal(isSafeTmpRmCommand("rm -rf /var/tmp"), false);
		assert.equal(isSafeTmpRmCommand("rm -rf /tmp foo"), false);
		assert.equal(isSafeTmpRmCommand("echo hi && rm -rf /tmp"), false);
	});
});

describe("buildDangerousCommandPrompt", () => {
	it("keeps the title within RPC host limits and shows the full command in the message", () => {
		const command = `cd /some/long/worktree/path && rm -rf ${"scratchpad/dir ".repeat(40)}`;
		const prompt = buildDangerousCommandPrompt(command);

		assert.ok(prompt.title.length <= RPC_TITLE_MAX_LENGTH);
		assert.ok(!prompt.title.includes("\n"));
		assert.equal(prompt.message, command);
	});

	it("truncates huge commands so the message stays within RPC host limits", () => {
		const command = `rm -rf ${"x".repeat(20_000)}`;
		const prompt = buildDangerousCommandPrompt(command);

		assert.ok(prompt.message.length <= RPC_MESSAGE_MAX_LENGTH);
		assert.ok(prompt.message.startsWith("rm -rf xxx"));
		assert.match(prompt.message, /truncated, 20007 chars total/);
	});
});
