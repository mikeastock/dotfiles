import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildUnsafeRmPrompt, collectRecursiveRms, isUnsafeRmCommand, isUnsafeRmTarget } from "./index.js";

const RPC_TITLE_MAX_LENGTH = 160;
const RPC_MESSAGE_MAX_LENGTH = 8192;
const HOME = "/home/mike";

const unsafe = (target: string) => isUnsafeRmTarget(target, HOME);
const unsafeCommand = (command: string) => isUnsafeRmCommand(command, HOME);

describe("collectRecursiveRms", () => {
	it("returns targets only for recursive rm invocations", () => {
		assert.deepEqual(collectRecursiveRms("rm -rf /etc"), [{ targets: ["/etc"], noPreserveRoot: false }]);
		assert.deepEqual(collectRecursiveRms("rm -r a b")[0].targets, ["a", "b"]);
		assert.deepEqual(collectRecursiveRms("rm --recursive x")[0].targets, ["x"]);
		assert.deepEqual(collectRecursiveRms("rm file"), []);
	});

	it("accepts options after operands, as GNU rm does", () => {
		assert.deepEqual(collectRecursiveRms("rm /etc -rf")[0].targets, ["/etc"]);
	});

	it("treats everything after -- as a target", () => {
		assert.deepEqual(collectRecursiveRms("rm -rf -- -weird /etc")[0].targets, ["-weird", "/etc"]);
	});

	it("records --no-preserve-root", () => {
		assert.equal(collectRecursiveRms("rm -rf --no-preserve-root x")[0].noPreserveRoot, true);
	});

	it("finds rm behind wrappers and separators", () => {
		assert.deepEqual(collectRecursiveRms("sudo rm -rf /")[0].targets, ["/"]);
		assert.deepEqual(collectRecursiveRms("xargs rm -rf /etc")[0].targets, ["/etc"]);
		assert.deepEqual(collectRecursiveRms("echo hi && rm -rf /etc")[0].targets, ["/etc"]);
		assert.deepEqual(collectRecursiveRms("echo hi\nrm -rf /var")[0].targets, ["/var"]);
	});

	it("stops at shell separators so later args are not misread", () => {
		assert.deepEqual(collectRecursiveRms("rm -rf build && ls /etc")[0].targets, ["build"]);
		assert.deepEqual(collectRecursiveRms("rm -rf build\nls -r /etc")[0].targets, ["build"]);
	});
});

describe("isUnsafeRmTarget: trees (the directory and everything inside)", () => {
	it("prompts for system directories and anything beneath them", () => {
		for (const target of ["/etc", "/etc/", "/etc/nginx", "/usr/local/bin", "/var/lib/dpkg", "/System/Library"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("prompts for credential directories under home", () => {
		assert.equal(unsafe("~/.ssh"), true);
		assert.equal(unsafe("/home/mike/.ssh/id_ed25519"), true);
		assert.equal(unsafe("$HOME/.gnupg"), true);
	});

	it("does not match directories that merely share a name prefix", () => {
		assert.equal(unsafe("/etcetera"), false);
		assert.equal(unsafe("/usrdata"), false);
	});
});

describe("isUnsafeRmTarget: roots (the directory itself, not its contents)", () => {
	it("prompts when deleting a root directory", () => {
		for (const target of ["/", "/home", "/home/mike", "/Users/mike", "~", "$HOME", "${HOME}", "/var", "/tmp", "/data/workspace/code/personal"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("prompts when emptying a root directory with a trailing glob", () => {
		for (const target of ["/*", "/.*", "~/*", "/home/*", "/home/mike/*", "/tmp/*", "/data/workspace/*"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("judges globs with literal text by the matched path, not the parent", () => {
		assert.equal(unsafe("/tmp/build-*"), false);
		assert.equal(unsafe("~/*.bak"), false);
		assert.equal(unsafe("/etc/*.conf"), true);
	});

	it("allows deleting paths inside a root directory", () => {
		for (const target of [
			"/home/mike/code/app/node_modules",
			"~/.cache/pnpm",
			"~/.config/some-tool",
			"/tmp/scratch",
			"/tmp/build-*",
			"/var/folders/ab/xyz/T/tmp.123",
			"/opt/homebrew/Cellar/foo",
			"/data/workspace/worktrees/feature/app",
			"/data/workspace/code/personal/app/dist",
		]) {
			assert.equal(unsafe(target), false, target);
		}
	});
});

describe("isUnsafeRmTarget: names", () => {
	it("prompts when deleting a .git directory anywhere", () => {
		for (const target of [".git", "./.git", "app/.git", "/home/mike/code/app/.git", ".git/*"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("allows other dot directories", () => {
		assert.equal(unsafe(".github"), false);
		assert.equal(unsafe(".gitignore"), false);
	});
});

describe("isUnsafeRmTarget: normalization", () => {
	it("resolves redundant slashes, dot segments, and parent segments", () => {
		for (const target of ["//etc", "/./etc", "/tmp/../etc", "///"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("allows ordinary relative paths", () => {
		for (const target of ["./build", "node_modules", "dist/", "..", "*"]) {
			assert.equal(unsafe(target), false, target);
		}
	});
});

describe("isUnsafeRmCommand", () => {
	it("prompts for recursive removals that hit the deny list", () => {
		for (const command of [
			"rm -rf /",
			"rm -rf /*",
			"rm -rf '/etc/nginx'",
			"echo hi && rm -rf /usr",
			"sudo rm -rf /",
			"rm -rf build .git",
			"rm -rf --no-preserve-root ./anything",
		]) {
			assert.equal(unsafeCommand(command), true, command);
		}
	});

	it("allows safe, non-recursive, or unrelated commands", () => {
		for (const command of [
			"rm -rf ./build",
			"rm -rf /tmp/cache",
			"rm -rf /home/mike/code/app/node_modules",
			"rm file.txt",
			"rm /etc/hosts",
			"echo hello",
			"git commit -m 'rm -rf /etc handling'",
		]) {
			assert.equal(unsafeCommand(command), false, command);
		}
	});

	it("stays conservative when rm appears as an argument", () => {
		// Not a real exec, but flagging it is cheap and keeps the scanner simple.
		assert.equal(unsafeCommand("echo rm -rf /etc"), true);
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
