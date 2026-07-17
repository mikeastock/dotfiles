import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { getEffectiveHandoffOptions } from "./lib/effective-options.js";
import { buildFinalPrompt, buildSessionLineage } from "./lib/session-lineage.js";
import { prepareToolHandoff } from "./lib/tool-path.js";

describe("handoff model preservation", () => {
	it("preserves the current model when no explicit mode or model is provided", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions(undefined, "anthropic/claude-sonnet-4-6"),
			{ model: "anthropic/claude-sonnet-4-6" },
		);
	});

	it("does not override an explicit mode with the current model", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions({ mode: "rush" }, "anthropic/claude-sonnet-4-6"),
			{ mode: "rush" },
		);
	});

	it("does not override an explicit model", () => {
		assert.deepEqual(
			getEffectiveHandoffOptions({ model: "anthropic/claude-haiku-4-5" }, "anthropic/claude-sonnet-4-6"),
			{ model: "anthropic/claude-haiku-4-5" },
		);
	});
});

describe("handoff session lineage", () => {
	it("includes the parent session when no ancestors are recorded", () => {
		const dir = mkdtempSync(join(tmpdir(), "handoff-lineage-"));
		try {
			const current = join(dir, "current.jsonl");
			writeFileSync(current, `${JSON.stringify({ type: "session", version: 3, id: "current" })}\n`);

			assert.deepEqual(buildSessionLineage(current), [current]);
			assert.equal(
				buildFinalPrompt({
					goal: "continue the work",
					summary: "## Context\nExisting summary",
					currentSessionFile: current,
				}),
				`continue the work\n\n/skill:session-query\n\n**Parent session:** \`${current}\`\n\n## Context\nExisting summary`,
			);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("includes the full session lineage from newest to oldest", () => {
		const dir = mkdtempSync(join(tmpdir(), "handoff-lineage-"));
		try {
			const root = join(dir, "root.jsonl");
			const parent = join(dir, "parent.jsonl");
			const current = join(dir, "current.jsonl");
			const timestamp = "2026-05-21T00:00:00.000Z";
			writeFileSync(root, `${JSON.stringify({ type: "session", version: 3, id: "root", timestamp })}\n`);
			writeFileSync(
				parent,
				`${JSON.stringify({ type: "session", version: 3, id: "parent", timestamp, parentSession: root })}\n`,
			);
			writeFileSync(
				current,
				`${JSON.stringify({ type: "session", version: 3, id: "current", timestamp, parentSession: parent })}\n`,
			);

			assert.deepEqual(buildSessionLineage(current), [current, parent, root]);
			assert.equal(
				buildFinalPrompt({
					goal: "continue the work",
					summary: "## Context\nExisting summary",
					currentSessionFile: current,
				}),
				`continue the work\n\n/skill:session-query\n\n**Session lineage (newest to oldest):**\n1. \`${current}\`\n2. \`${parent}\`\n3. \`${root}\`\n\n## Context\nExisting summary`,
			);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("stops lineage traversal at cycles", () => {
		const dir = mkdtempSync(join(tmpdir(), "handoff-lineage-"));
		try {
			const first = join(dir, "first.jsonl");
			const second = join(dir, "second.jsonl");
			writeFileSync(first, `${JSON.stringify({ type: "session", parentSession: second })}\n`);
			writeFileSync(second, `${JSON.stringify({ type: "session", parentSession: first })}\n`);

			assert.deepEqual(buildSessionLineage(first), [first, second]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("handoff tool", () => {
	it("prepares a /handoff command instead of switching sessions from the tool path", () => {
		let editorText = "";
		let notifications = 0;

		const result = prepareToolHandoff(
			{
				hasUI: true,
				ui: {
					setEditorText(text: string) {
						editorText = text;
					},
					notify() {
						notifications += 1;
					},
				},
			},
			{
				goal: "investigate the next bug",
				mode: "rush",
				model: "anthropic/claude-haiku-4-5",
			},
		);

		assert.equal(editorText, "/handoff -mode rush -model anthropic/claude-haiku-4-5 investigate the next bug");
		assert.equal(notifications, 1);
		assert.equal(result.details.ok, true);
		assert.match(result.content[0].text, /Submit it to create the new session safely\./);
	});
});
