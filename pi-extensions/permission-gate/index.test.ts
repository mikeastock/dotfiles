import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	buildUnsafeRmPrompt,
	collectRecursiveRmTargets,
	isUnsafeRmCommand,
	isUnsafeRmTarget,
} from "./index.js";

const RPC_TITLE_MAX_LENGTH = 160;
const RPC_MESSAGE_MAX_LENGTH = 8192;

describe("collectRecursiveRmTargets", () => {
	it("returns targets only for recursive rm invocations", () => {
		assert.deepEqual(collectRecursiveRmTargets("rm -rf /etc"), ["/etc"]);
		assert.deepEqual(collectRecursiveRmTargets("rm -r a b"), ["a", "b"]);
		assert.deepEqual(collectRecursiveRmTargets("rm --recursive x"), ["x"]);
		assert.deepEqual(collectRecursiveRmTargets("rm file"), []);
	});

	it("finds rm behind wrappers and separators", () => {
		assert.deepEqual(collectRecursiveRmTargets("sudo rm -rf /"), ["/"]);
		assert.deepEqual(collectRecursiveRmTargets("xargs rm -rf /etc"), ["/etc"]);
		assert.deepEqual(collectRecursiveRmTargets("echo hi && rm -rf /etc"), ["/etc"]);
		assert.deepEqual(collectRecursiveRmTargets("echo hi\nrm -rf /var"), ["/var"]);
	});

	it("stops at shell separators so later args are not misread", () => {
		assert.deepEqual(collectRecursiveRmTargets("rm -rf build && ls /etc"), ["build"]);
	});
});

describe("isUnsafeRmTarget", () => {
	it("matches unsafe prefixes exactly and beneath them", () => {
		assert.equal(isUnsafeRmTarget("/"), true);
		assert.equal(isUnsafeRmTarget("/etc"), true);
		assert.equal(isUnsafeRmTarget("/etc/"), true);
		assert.equal(isUnsafeRmTarget("/etc/nginx"), true);
		assert.equal(isUnsafeRmTarget("/usr/local/bin"), true);
		assert.equal(isUnsafeRmTarget("/home"), true);
		assert.equal(isUnsafeRmTarget("/home/mike/project"), true);
		assert.equal(isUnsafeRmTarget("~"), true);
		assert.equal(isUnsafeRmTarget("~/scratch"), true);
		assert.equal(isUnsafeRmTarget("$HOME/work"), true);
	});

	it("allows ordinary project and temporary paths", () => {
		assert.equal(isUnsafeRmTarget("./build"), false);
		assert.equal(isUnsafeRmTarget("node_modules"), false);
		assert.equal(isUnsafeRmTarget("/tmp/scratch"), false);
		assert.equal(isUnsafeRmTarget("/var/tmp"), true); // still under /var
		assert.equal(isUnsafeRmTarget(""), false);
		assert.equal(isUnsafeRmTarget("/etcetera"), false);
	});
});

describe("isUnsafeRmCommand", () => {
	it("flags recursive removals of unsafe directories", () => {
		assert.equal(isUnsafeRmCommand("rm -rf /"), true);
		assert.equal(isUnsafeRmCommand("rm -rf /etc"), true);
		assert.equal(isUnsafeRmCommand("rm -rf '/etc/nginx'"), true);
		assert.equal(isUnsafeRmCommand("echo hi && rm -rf /usr"), true);
		assert.equal(isUnsafeRmCommand("sudo rm -rf /"), true);
	});

	it("allows safe, non-recursive, or unrelated commands", () => {
		assert.equal(isUnsafeRmCommand("rm -rf ./build"), false);
		assert.equal(isUnsafeRmCommand("rm -rf /tmp/cache"), false);
		assert.equal(isUnsafeRmCommand("rm file.txt"), false);
		assert.equal(isUnsafeRmCommand("echo hello"), false);
		assert.equal(isUnsafeRmCommand("git commit -m 'rm -rf /etc handling'"), false);
	});

	it("stays conservative when rm appears as an argument", () => {
		// Not a real exec, but flagging it is cheap and keeps the scanner simple.
		assert.equal(isUnsafeRmCommand("echo rm -rf /etc"), true);
	});
});

describe("buildUnsafeRmPrompt", () => {
	it("keeps the title within RPC host limits and shows the full command in the message", () => {
		const command = `cd /some/long/worktree/path && rm -rf ${"scratchpad/dir ".repeat(40)}`;
		const prompt = buildUnsafeRmPrompt(command);

		assert.ok(prompt.title.length <= RPC_TITLE_MAX_LENGTH);
		assert.ok(!prompt.title.includes("\n"));
		assert.equal(prompt.message, command);
	});

	it("truncates huge commands so the message stays within RPC host limits", () => {
		const command = `rm -rf ${"x".repeat(20_000)}`;
		const prompt = buildUnsafeRmPrompt(command);

		assert.ok(prompt.message.length <= RPC_MESSAGE_MAX_LENGTH);
		assert.ok(prompt.message.startsWith("rm -rf xxx"));
		assert.match(prompt.message, /truncated, 20007 chars total/);
	});
});
