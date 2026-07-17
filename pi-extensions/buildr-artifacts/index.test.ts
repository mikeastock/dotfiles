import assert from "node:assert/strict";
import { describe, it } from "node:test";

import buildrArtifacts, { _test } from "./index.js";

describe("share_artifact input validation", () => {
	it("rejects both path and html", () => {
		assert.throws(
			() => _test.normalizeShareArtifactInput({ path: "report.html", html: "<h1>Report</h1>" }),
			/exactly one/,
		);
	});

	it("rejects neither path nor html", () => {
		assert.throws(() => _test.normalizeShareArtifactInput({}), /exactly one/);
	});

	it("normalizes a leading @ in path inputs", () => {
		assert.deepEqual(_test.normalizeShareArtifactInput({ path: "@dist/index.html" }), {
			kind: "path",
			path: "dist/index.html",
		});
	});

	it("accepts inline html", () => {
		assert.deepEqual(_test.normalizeShareArtifactInput({ html: "<h1>Hi</h1>" }), {
			html: "<h1>Hi</h1>",
			kind: "html",
		});
	});
});

describe("buildr-artifacts extension registration", () => {
	it("registers the share_artifact tool and command", () => {
		const tools: string[] = [];
		const commands: string[] = [];

		buildrArtifacts({
			registerTool(tool: { name: string }) {
				tools.push(tool.name);
			},
			registerCommand(name: string) {
				commands.push(name);
			},
		} as any);

		assert.deepEqual(tools, ["share_artifact"]);
		assert.deepEqual(commands, ["share_artifact"]);
	});
});
