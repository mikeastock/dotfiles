import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	buildUnsafeRmPrompt,
	collectRmInvocations,
	evaluateBashCommand,
	type GateContext,
	isUnsafeRmCommand,
	isUnsafeRmTarget,
	tokenize,
	UNSAFE_RM_NAMES,
	UNSAFE_RM_ROOTS,
	UNSAFE_RM_TREES,
} from "./index.js";

const RPC_TITLE_MAX_LENGTH = 160;
const RPC_MESSAGE_MAX_LENGTH = 8192;
const HOME = "/home/mike";
const PROJECT: GateContext = { cwd: "/home/mike/code/app", home: HOME };

const targetsOf = (command: string, context: GateContext = PROJECT) =>
	collectRmInvocations(command, context).flatMap((rm) => rm.targets);
const unsafe = (target: string) => isUnsafeRmTarget(target, true, HOME);
const unsafeCommand = (command: string, context: GateContext = PROJECT) => isUnsafeRmCommand(command, context);

function assertPrompts(commands: string[], context: GateContext = PROJECT) {
	for (const command of commands) assert.equal(unsafeCommand(command, context), true, JSON.stringify(command));
}

function assertAllows(commands: string[], context: GateContext = PROJECT) {
	for (const command of commands) assert.equal(unsafeCommand(command, context), false, JSON.stringify(command));
}

describe("tokenize", () => {
	const tokens = (command: string) => tokenize(command).tokens;

	it("splits words on whitespace and removes quotes", () => {
		assert.deepEqual(tokens(`a 'b c' "d e" f\\ g`), ["a", "b c", "d e", "f g"]);
		assert.deepEqual(tokens(`"$HOME"/x '~'/y`), ["$HOME/x", "~/y"]);
		assert.deepEqual(tokens(`"" x`), ["", "x"]);
	});

	it("handles backslashes inside double quotes like the shell", () => {
		assert.deepEqual(tokens(`"a\\"b" "c\\d"`), ['a"b', "c\\d"]);
	});

	it("turns operators and unquoted newlines into separators", () => {
		assert.deepEqual(tokens("a;b&&c || d|e 2>&1\nf"), ["a", null, "b", null, "c", null, "d", null, "e", "2", null, "1", null, "f"]);
	});

	it("skips comments and line continuations", () => {
		assert.deepEqual(tokens("a # b c\nd"), ["a", null, "d"]);
		assert.deepEqual(tokens("a#b"), ["a#b"]);
		assert.deepEqual(tokens("a \\\n b"), ["a", "b"]);
	});

	it("keeps substitutions in the word and returns their bodies", () => {
		assert.deepEqual(tokenize("rm -rf $(pwd)/x `echo y` \"$(a (b))\""), {
			tokens: ["rm", "-rf", "$(pwd)/x", "`echo y`", "$(a (b))"],
			substitutions: ["pwd", "echo y", "a (b)"],
		});
	});
});

describe("collectRmInvocations: parsing", () => {
	it("reads flags, targets, and --no-preserve-root", () => {
		assert.deepEqual(collectRmInvocations("rm -rf /etc", PROJECT), [
			{ recursive: true, noPreserveRoot: false, targets: ["/etc"] },
		]);
		assert.equal(collectRmInvocations("rm --recursive x", PROJECT)[0].recursive, true);
		assert.equal(collectRmInvocations("rm file", PROJECT)[0].recursive, false);
		assert.equal(collectRmInvocations("rm -rf --no-preserve-root x", PROJECT)[0].noPreserveRoot, true);
	});

	it("accepts options after operands, as GNU rm does", () => {
		assert.equal(collectRmInvocations("rm /etc -rf", PROJECT)[0].recursive, true);
	});

	it("treats everything after -- as a target", () => {
		assert.deepEqual(targetsOf("rm -rf -- -weird /etc"), ["/home/mike/code/app/-weird", "/etc"]);
	});

	it("splits operators glued to words", () => {
		assert.deepEqual(targetsOf("rm -rf /etc;"), ["/etc"]);
		assert.deepEqual(targetsOf("rm -rf /etc&&echo done"), ["/etc"]);
		assert.deepEqual(targetsOf("rm -rf dist; cat /etc/hosts"), ["/home/mike/code/app/dist"]);
	});

	it("joins partially quoted words", () => {
		assert.deepEqual(targetsOf('rm -rf "$HOME"/code/app/node_modules'), ["/home/mike/code/app/node_modules"]);
		assert.deepEqual(targetsOf('rm -rf "${HOME}"/.cache'), ["/home/mike/.cache"]);
		assert.deepEqual(targetsOf("rm -rf ~/'.ssh'"), ["/home/mike/.ssh"]);
	});

	it("treats newlines as separators and follows line continuations", () => {
		assert.deepEqual(targetsOf("rm -rf build\nls -r /etc"), ["/home/mike/code/app/build"]);
		assert.deepEqual(targetsOf("rm -rf \\\n  build \\\n  /etc"), ["/home/mike/code/app/build", "/etc"]);
	});

	it("keeps newlines inside quotes", () => {
		assert.deepEqual(targetsOf('rm -rf "a\nb"'), ["/home/mike/code/app/a\nb"]);
	});

	it("recognizes rm by any spelling", () => {
		for (const command of ["\\rm -rf /etc", "/bin/rm -rf /etc", "/usr/bin/rm -rf /etc", "sudo rm -rf /etc", "xargs rm -rf /etc", "FOO=1 rm -rf /etc"]) {
			assert.deepEqual(targetsOf(command), ["/etc"], command);
		}
	});

	it("scans sh -c and bash -c payloads", () => {
		for (const command of ["sh -c 'rm -rf /etc'", 'bash -lc "rm -rf /etc"', "sudo bash -e -c 'cd / && rm -rf etc'"]) {
			assert.deepEqual(targetsOf(command), ["/etc"], command);
		}
	});

	it("resolves relative targets against cwd and earlier cd commands", () => {
		assert.deepEqual(targetsOf("rm -rf build"), ["/home/mike/code/app/build"]);
		assert.deepEqual(targetsOf("rm -rf .."), ["/home/mike/code"]);
		assert.deepEqual(targetsOf("cd / && rm -rf etc"), ["/etc"]);
		assert.deepEqual(targetsOf("cd /tmp; cd work && rm -rf out"), ["/tmp/work/out"]);
		assert.deepEqual(targetsOf("cd && rm -rf x"), ["/home/mike/x"]);
	});

	it("leaves targets relative when the directory is unknown", () => {
		assert.deepEqual(targetsOf("cd - && rm -rf x"), ["x"]);
		assert.deepEqual(targetsOf('cd "$DIR" && rm -rf x'), ["x"]);
		assert.deepEqual(targetsOf("rm -rf x", { cwd: null, home: HOME }), ["x"]);
		assert.deepEqual(targetsOf('rm -rf "$DIR/"'), ["$DIR"]);
		assert.deepEqual(targetsOf("rm -rf $(pwd)/x"), ["$(pwd)/x"]);
	});

	it("scans command substitutions", () => {
		assert.deepEqual(targetsOf("echo $(rm -rf /etc)"), ["/etc"]);
		assert.deepEqual(targetsOf('x="`rm -rf /etc`"'), ["/etc"]);
	});

	it("ignores rm in comments", () => {
		assert.deepEqual(targetsOf("rm -rf build # not /etc"), ["/home/mike/code/app/build"]);
	});
});

describe("isUnsafeRmTarget: trees (the directory and everything inside)", () => {
	it("matches system and credential directories and anything beneath them", () => {
		for (const target of ["/etc", "/etc/nginx", "/usr/local/bin", "/var/lib/dpkg", "/System/Library", "/home/mike/.ssh/id_ed25519", "/home/mike/.aws", "/home/mike/.config/gh"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("also applies to non-recursive rm", () => {
		assert.equal(isUnsafeRmTarget("/home/mike/.ssh/id_ed25519", false, HOME), true);
		assert.equal(isUnsafeRmTarget("/etc/hosts", false, HOME), true);
	});

	it("does not match directories that merely share a name prefix", () => {
		assert.equal(unsafe("/etcetera"), false);
		assert.equal(unsafe("/usrdata"), false);
		assert.equal(unsafe("/home/mike/.sshx"), false);
	});

	it("matches globs anywhere in the path", () => {
		assert.equal(unsafe("/home/*/.ssh"), true);
		assert.equal(unsafe("/e*"), true);
		assert.equal(unsafe("/e?c"), true);
		assert.equal(unsafe("/[ef]tc"), true);
		assert.equal(unsafe("/{etc,opt}"), true);
		assert.equal(unsafe("/home/mike/code/app/[id]"), false);
		assert.equal(unsafe("/home/mike/*/id_ed25519"), false); // `*` skips dot directories like .ssh
		assert.equal(unsafe("/etc/*.conf"), true);
	});
});

describe("isUnsafeRmTarget: roots (the directory itself, not its contents)", () => {
	it("matches the root directory itself", () => {
		for (const target of ["/", "/home", "/home/mike", "/Users/mike", "/var", "/tmp", "/home/mike/.local/share", "/home/mike/.bb", "/data/workspace/code/personal/dotfiles"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("matches emptying a root with pure-wildcard globs", () => {
		for (const target of ["/*", "/.*", "/home/mike/*", "/home/mike/*/*", "/home/*", "/tmp/*", "/data/workspace/*"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("ignores roots for non-recursive rm", () => {
		assert.equal(isUnsafeRmTarget("/home/mike/*", false, HOME), false);
	});

	it("allows paths inside a root", () => {
		for (const target of [
			"/home/mike/code/app/node_modules",
			"/home/mike/.cache/pnpm",
			"/home/mike/.config/some-tool",
			"/home/mike/.local/share/pnpm",
			"/home/mike/.bb/plugins/environment-git-worktree/host-data/worktrees/thr_x/app",
			"/tmp/scratch",
			"/tmp/build-*",
			"/home/mike/*.bak",
			"/var/folders/ab/xyz/T/tmp.123",
			"/opt/homebrew/Cellar/foo",
			"/data/workspace/worktrees/feature/app",
			"/data/workspace/code/worktrees/feature",
			"/data/workspace/code/personal/app/dist",
		]) {
			assert.equal(unsafe(target), false, target);
		}
	});
});

describe("isUnsafeRmTarget: names", () => {
	it("matches a .git directory anywhere", () => {
		for (const target of [".git", "/home/mike/code/app/.git", "/tmp/clone/.git/*"]) {
			assert.equal(unsafe(target), true, target);
		}
	});

	it("allows similar names", () => {
		assert.equal(unsafe("/home/mike/code/app/.github"), false);
		assert.equal(unsafe("/home/mike/code/app/.gitignore"), false);
	});
});

describe("deny list self-consistency", () => {
	// A typo like a missing leading slash would silently disable an entry.
	const concrete = (pattern: string) => pattern.replaceAll("*", "x");

	for (const tree of UNSAFE_RM_TREES) {
		it(`tree ${tree} matches itself and its contents, recursive or not`, () => {
			assert.equal(isUnsafeRmTarget(concrete(tree).replace(/^~/, HOME), true, HOME), true);
			assert.equal(isUnsafeRmTarget(`${concrete(tree).replace(/^~/, HOME)}/child`, false, HOME), true);
		});
	}

	for (const root of UNSAFE_RM_ROOTS) {
		it(`root ${root} matches itself and being emptied`, () => {
			const path = concrete(root).replace(/^~/, HOME);
			assert.equal(unsafe(path), true);
			assert.equal(unsafe(path === "/" ? "/*" : `${path}/*`), true);
		});
	}

	for (const name of UNSAFE_RM_NAMES) {
		it(`name ${name} matches anywhere`, () => {
			assert.equal(unsafe(`/tmp/a/${name}`), true);
		});
	}
});

describe("isUnsafeRmCommand", () => {
	it("prompts for the reviewed bypasses", () => {
		assertPrompts([
			"rm -rf /etc;",
			"rm -rf ~/'.ssh'",
			"\\rm -rf /etc",
			"sh -c 'rm -rf /etc'",
			"rm -rf \\\n build \\\n /etc",
			"rm -rf /home/*/.ssh",
			"cd / && rm -rf *",
			"rm -rf /data/workspace/code/personal/dotfiles",
			"rm -rf ~/.local/share",
			"rm -rf ~/.aws",
			"rm ~/.ssh/id_ed25519",
			"rm -f ~/.ssh/*",
		]);
	});

	it("prompts for classic disasters", () => {
		assertPrompts(["rm -rf /", "rm -rf /*", "sudo rm -rf /usr", "rm -rf build .git", "rm -rf --no-preserve-root ./x", "rm -rf ~"]);
	});

	it("prompts for relative targets that resolve to unsafe paths", () => {
		assertPrompts(["rm -rf *", "rm -rf ."], { cwd: HOME, home: HOME });
		assertPrompts(["rm -rf ../.."], { cwd: "/home/mike/code", home: HOME });
	});

	it("allows normal cleanup", () => {
		assertAllows([
			"rm -rf ./build",
			"rm -rf node_modules dist",
			"rm -rf *",
			"rm -rf dist; cat /etc/hosts",
			'rm -rf "$HOME"/code/app/node_modules',
			"rm -rf /tmp/cache",
			"cd /tmp && rm -rf *.log work",
			"rm -rf ~/.cache/pnpm",
			"rm file.txt",
			"rm -f /tmp/*",
			"echo hello",
			"git commit -m 'rm -rf /etc handling'",
		]);
	});

	it("stays conservative when rm appears as an argument", () => {
		// Not a real exec, but flagging it is cheap and keeps the scanner simple.
		assertPrompts(["echo rm -rf /etc"]);
	});
});

describe("evaluateBashCommand", () => {
	it("confirms unsafe rm and allows everything else", () => {
		assert.equal(evaluateBashCommand("rm -rf /etc", PROJECT), "confirm");
		assert.equal(evaluateBashCommand("rm -rf build", PROJECT), "allow");
		assert.equal(evaluateBashCommand("chmod -R 777 .", PROJECT), "allow");
	});

	it("skips SSH commands, which run on a remote machine", () => {
		assert.equal(evaluateBashCommand("ssh host rm -rf /etc", PROJECT), "allow");
		assert.equal(evaluateBashCommand("  SSH host 'rm -rf /'", PROJECT), "allow");
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
