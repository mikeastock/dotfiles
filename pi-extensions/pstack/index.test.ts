import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, it } from "node:test";
import { MODE_ENTRY_TYPE, modeReminder, potetoSkillInvocation, restoreModeState } from "./mode.ts";
import {
	type TaskResult,
	applyChildEvent,
	buildChildArgs,
	capOutput,
	childSystemPrompt,
	currentDepth,
	emptyUsage,
	formatBackgroundStatus,
	formatFinal,
	mapWithConcurrency,
	pendingResult,
	findTranscript,
	validateTasks,
} from "./task.ts";
import { renderTodos, restoreTodos } from "./todo.ts";

const parent = { model: "openai/gpt-5.6-luna", thinkingLevel: "high" };
const session = { dir: "/s", id: "abc" };

function freshResult(): TaskResult {
	return { description: "d", agent: "general", status: "running", output: "", turns: 0, usage: emptyUsage() };
}

describe("buildChildArgs", () => {
	it("runs an explicit model without the parent thinking level", () => {
		assert.deepEqual(buildChildArgs({ description: "d", prompt: "do it", model: "xai/grok-4.7:xhigh" }, parent, session), [
			"--mode",
			"json",
			"-p",
			"--session-dir",
			"/s",
			"--session-id",
			"abc",
			"--model",
			"xai/grok-4.7:xhigh",
			"--",
			"do it",
		]);
	});

	it("inherits the parent model and thinking level for inherit-parent, auto, and omitted models", () => {
		for (const model of ["inherit-parent", "auto", undefined]) {
			assert.deepEqual(buildChildArgs({ description: "d", prompt: "p", model }, parent, session).slice(7, 11), [
				"--model",
				"openai/gpt-5.6-luna",
				"--thinking",
				"high",
			]);
		}
	});

	it("drops edit and write tools for read-only tasks and appends the system prompt file", () => {
		const args = buildChildArgs({ description: "d", prompt: "-starts-with-dash", readonly: true }, {}, session, "/tmp/sp.md");
		assert.deepEqual(args, [
			"--mode",
			"json",
			"-p",
			"--session-dir",
			"/s",
			"--session-id",
			"abc",
			"--exclude-tools",
			"edit,write",
			"--append-system-prompt",
			"/tmp/sp.md",
			"--",
			"-starts-with-dash",
		]);
	});
});

describe("findTranscript", () => {
	it("finds the session file Pi wrote for the child's session id", async () => {
		const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pstack-test-"));
		await fs.promises.writeFile(path.join(dir, "2026-10-04T03-09-06-194Z_other.jsonl"), "");
		await fs.promises.writeFile(path.join(dir, "2026-10-04T03-09-07-001Z_abc.jsonl"), "");
		assert.equal(await findTranscript({ dir, id: "abc" }), path.join(dir, "2026-10-04T03-09-07-001Z_abc.jsonl"));
		assert.equal(await findTranscript({ dir, id: "missing" }), undefined);
		assert.equal(await findTranscript({ dir: path.join(dir, "nope"), id: "abc" }), undefined);
		await fs.promises.rm(dir, { recursive: true });
	});
});

describe("childSystemPrompt", () => {
	it("is empty for a writable general task", () => {
		assert.equal(childSystemPrompt({ description: "d", prompt: "p" }), undefined);
	});

	it("loads the bundled agent prompt and adds the read-only notice", () => {
		const prompt = childSystemPrompt({ description: "d", prompt: "p", agent: "comment-sicko", readonly: true });
		assert.ok(prompt?.startsWith("# Comment Sicko"));
		assert.match(prompt ?? "", /This is a read-only task\./);
		assert.doesNotMatch(prompt ?? "", /^---/);
	});

	it("points poteto-agent at the installed poteto-mode skill", () => {
		assert.match(childSystemPrompt({ description: "d", prompt: "p", agent: "poteto-agent" }) ?? "", /~\/\.agents\/skills\/poteto-mode\/SKILL\.md/);
	});
});

describe("validateTasks", () => {
	it("refuses to nest past the depth limit", () => {
		assert.throws(() => validateTasks([{ description: "d", prompt: "p" }], 2), /nesting limit/);
	});

	it("refuses empty, oversized, and over-long batches", () => {
		assert.throws(() => validateTasks([], 0), /at least one task/);
		assert.throws(() => validateTasks(Array.from({ length: 13 }, () => ({ description: "d", prompt: "p" })), 0), /at most 12/);
		assert.throws(() => validateTasks([{ description: "big", prompt: "x".repeat(101 * 1024) }], 0), /exceeds 100 KB/);
	});

	it("reads depth from the environment", () => {
		assert.equal(currentDepth({ PSTACK_TASK_DEPTH: "1" }), 1);
		assert.equal(currentDepth({}), 0);
		assert.equal(currentDepth({ PSTACK_TASK_DEPTH: "junk" }), 0);
	});
});

describe("applyChildEvent", () => {
	const assistantEnd = (content: unknown[], extra: Record<string, unknown> = {}) =>
		JSON.stringify({
			type: "message_end",
			message: {
				role: "assistant",
				provider: "xai",
				model: "grok-4.7",
				content,
				usage: { input: 10, output: 5, cacheRead: 1, cacheWrite: 0, totalTokens: 16, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0.25 } },
				stopReason: "stop",
				...extra,
			},
		});

	it("keeps the latest assistant text as output and sums usage across turns", () => {
		const result = freshResult();
		assert.equal(applyChildEvent(result, assistantEnd([{ type: "toolCall", name: "bash", arguments: { command: "git log -1" } }])), true);
		assert.equal(result.lastActivity, "bash git log -1");
		applyChildEvent(result, assistantEnd([{ type: "text", text: "final report" }]));
		assert.equal(result.output, "final report");
		assert.equal(result.turns, 2);
		assert.equal(result.usage.input, 20);
		assert.equal(result.usage.cost.total, 0.5);
		assert.equal(result.model, "xai/grok-4.7");
	});

	it("records child errors and ignores non-assistant and malformed lines", () => {
		const result = freshResult();
		assert.equal(applyChildEvent(result, "not json"), false);
		assert.equal(applyChildEvent(result, JSON.stringify({ type: "message_end", message: { role: "user", content: [] } })), false);
		applyChildEvent(result, assistantEnd([], { stopReason: "error", errorMessage: "rate limited" }));
		assert.equal(result.error, "rate limited");
	});
});

describe("formatting", () => {
	it("caps long output and reports failures with their error", () => {
		assert.match(capOutput("x".repeat(60 * 1024)), /\[output truncated: 10240 bytes omitted\]$/);
		const failed = { ...freshResult(), status: "failed" as const, error: "boom", description: "probe" };
		assert.match(formatFinal([failed]), /## \[1\] probe[\s\S]*status: failed[\s\S]*Error: boom/);
	});
});

describe("formatBackgroundStatus", () => {
	it("lists running tasks with elapsed minutes and last activity, and names stopped ids", () => {
		const progress = { ...pendingResult({ description: "owner #12", prompt: "p", agent: "poteto-agent" }), turns: 4, lastActivity: "bash gh pr checks" };
		assert.equal(
			formatBackgroundStatus([{ id: "bg-2", startedAt: 0, progress }], ["bg-1"], 125_000),
			"Stopped: bg-1\nRunning background tasks:\nbg-2: owner #12 (poteto-agent, 2m, 4 turns) \u00b7 last: bash gh pr checks",
		);
		assert.equal(formatBackgroundStatus([], [], 0), "No background tasks running.");
	});
});

describe("mapWithConcurrency", () => {
	it("preserves input order and never exceeds the limit", async () => {
		let running = 0;
		let peak = 0;
		const results = await mapWithConcurrency([30, 10, 20, 5, 15], 2, async (ms, index) => {
			running++;
			peak = Math.max(peak, running);
			await new Promise((resolve) => setTimeout(resolve, ms));
			running--;
			return index;
		});
		assert.deepEqual(results, [0, 1, 2, 3, 4]);
		assert.equal(peak, 2);
	});
});

describe("todos", () => {
	it("renders status marks and a done count that includes cancelled items", () => {
		assert.deepEqual(
			renderTodos([
				{ content: "repro", status: "completed" },
				{ content: "fix", status: "in_progress" },
				{ content: "bench", status: "cancelled" },
				{ content: "pr", status: "pending" },
			]),
			["2/4 done", "[x] 1. repro", "[~] 2. fix", "[-] 3. bench", "[ ] 4. pr"],
		);
		assert.deepEqual(renderTodos([]), ["(no todos)"]);
	});

	it("restores the list from the last todo_write result on the branch", () => {
		const result = (toolName: string, content: string) => ({
			type: "message",
			message: { role: "toolResult", toolName, details: { todos: [{ content, status: "pending" }] } },
		});
		assert.deepEqual(restoreTodos([result("todo_write", "old"), result("bash", "noise"), result("todo_write", "new")]), [
			{ content: "new", status: "pending" },
		]);
	});
});

describe("poteto mode state", () => {
	it("detects the expanded poteto-mode skill block and its location", () => {
		const prompt = '<skill name="poteto-mode" location="/home/u/.agents/skills/poteto-mode/SKILL.md">\nbody\n</skill>\n\nfix the bug';
		assert.equal(potetoSkillInvocation(prompt), "/home/u/.agents/skills/poteto-mode/SKILL.md");
		assert.equal(potetoSkillInvocation('<skill name="how" location="/x">'), undefined);
	});

	it("restores the last mode entry on the branch", () => {
		const entries = [
			{ type: "custom", customType: MODE_ENTRY_TYPE, data: { enabled: true, skillPath: "/a" } },
			{ type: "message" },
			{ type: "custom", customType: "other", data: { enabled: true } },
			{ type: "custom", customType: MODE_ENTRY_TYPE, data: { enabled: false, skillPath: "/a" } },
		];
		assert.deepEqual(restoreModeState(entries), { enabled: false, skillPath: "/a" });
		assert.deepEqual(restoreModeState([]), { enabled: false });
	});

	it("names the skill path and the off switch in the reminder", () => {
		const reminder = modeReminder({ enabled: true, skillPath: "/a/SKILL.md" });
		assert.match(reminder, /`\/a\/SKILL\.md`/);
		assert.match(reminder, /\/poteto-mode off/);
	});
});
