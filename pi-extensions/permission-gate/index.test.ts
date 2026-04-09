import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isSafeTmpRmCommand } from "./index.js";

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
