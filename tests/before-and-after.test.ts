import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// @ts-ignore — plain .mjs module, no types on purpose (skill-internal interface)
import {
	MARKER_END,
	MARKER_START,
	attachList,
	buildPairs,
	formatMarkdown,
	formatVideoTables,
	localRef,
	mediaKind,
	replaceMarkedBlock,
} from "../skills/before-and-after/scripts/format.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(__dirname, "..");
const skillDir = join(projectRoot, "skills", "before-and-after");
const formatScript = join(skillDir, "scripts", "format.mjs");

const pair = (before: string | null, after: string, label: string | null = null) => ({
	before,
	after,
	label,
});

describe("mediaKind", () => {
	it("classifies by extension, case-insensitively", () => {
		assert.deepEqual(
			["capture.PNG", "capture.jpeg", "capture.gif", "capture.webp"].map(mediaKind),
			["image", "image", "image", "image"],
		);
		assert.deepEqual(["capture.MP4", "capture.mov", "capture.webm"].map(mediaKind), [
			"video",
			"video",
			"video",
		]);
	});

	it("rejects unsupported files", () => {
		assert.throws(() => mediaKind("capture.svg"), /Unsupported media/);
	});
});

describe("localRef", () => {
	it("produces gh-compatible relative references", () => {
		assert.equal(localRef("/repo/captures/after.png", "/repo"), "./captures/after.png");
	});

	it("rejects whitespace because attachment refs must match exactly", () => {
		assert.throws(() => localRef("/repo/captures/after image.png", "/repo"), /whitespace/);
	});

	it("rejects media outside the working directory", () => {
		assert.throws(() => localRef("/tmp/after.png", "/repo"), /inside the working directory/);
	});
});

describe("buildPairs", () => {
	it("pairs corresponding before and after files", () => {
		assert.deepEqual(
			buildPairs({
				before: ["b1.png", "b2.png"],
				after: ["a1.png", "a2.png"],
				labels: ["Desktop"],
			}),
			[pair("b1.png", "a1.png", "Desktop"), pair("b2.png", "a2.png")],
		);
	});

	it("builds after-only preview pairs", () => {
		assert.deepEqual(buildPairs({ after: ["a.png"] }), [pair(null, "a.png")]);
	});

	it("requires at least one after file", () => {
		assert.throws(() => buildPairs({}), /At least one --after/);
	});

	it("rejects mismatched pair counts", () => {
		assert.throws(
			() => buildPairs({ before: ["b.png"], after: ["a1.png", "a2.png"] }),
			/one --before file/,
		);
	});

	it("rejects excess labels", () => {
		assert.throws(
			() => buildPairs({ after: ["a.png"], labels: ["One", "Two"] }),
			/at most one --label/,
		);
	});
});

describe("formatMarkdown", () => {
	it("wraps image pairs in stable markers and a table", () => {
		const markdown = formatMarkdown([pair("/repo/captures/b.png", "/repo/captures/a.png")], {
			cwd: "/repo",
		});
		assert.equal(
			markdown,
			[
				MARKER_START,
				"| Before | After |",
				"|:---:|:---:|",
				"| ![Before](./captures/b.png) | ![After](./captures/a.png) |",
				"",
				MARKER_END,
				"",
			].join("\n"),
		);
	});

	it("renders after-only images as Preview", () => {
		const markdown = formatMarkdown([pair(null, "/repo/captures/a.png")], { cwd: "/repo" });
		assert.ok(markdown.includes("| Preview |"));
		assert.ok(markdown.includes("![Preview](./captures/a.png)"));
		assert.ok(!markdown.includes("Before"));
	});

	it("labels multiple pairs", () => {
		const markdown = formatMarkdown(
			[
				pair("/repo/b1.png", "/repo/a1.png", "Desktop"),
				pair("/repo/b2.png", "/repo/a2.png", "Mobile"),
			],
			{ cwd: "/repo" },
		);
		assert.ok(markdown.includes("| Before (Desktop) | After (Desktop) |"));
		assert.ok(markdown.includes("| Before (Mobile) | After (Mobile) |"));
	});

	it("adds attribution inside the marker block", () => {
		const markdown = formatMarkdown([pair(null, "/repo/a.png")], {
			attribution: "@agent",
			cwd: "/repo",
		});
		assert.ok(markdown.includes(`${MARKER_START}\n> Before/after by @agent`));
	});

	it("puts videos on their own lines instead of table cells", () => {
		const markdown = formatMarkdown([pair("/repo/b.webm", "/repo/a.webm")], { cwd: "/repo" });
		assert.ok(markdown.includes("**Before**\n\n![Before](./b.webm)"));
		assert.ok(markdown.includes("**After**\n\n![After](./a.webm)"));
		assert.ok(!markdown.includes("|"));
	});

	it("renders after-only videos as Preview", () => {
		const markdown = formatMarkdown([pair(null, "/repo/a.mp4", "Checkout")], { cwd: "/repo" });
		assert.ok(markdown.includes("**Preview (Checkout)**"));
		assert.ok(markdown.includes("![Preview](./a.mp4)"));
	});

	it("rejects mixed media within a pair", () => {
		assert.throws(
			() => formatMarkdown([pair("/repo/b.png", "/repo/a.mp4")], { cwd: "/repo" }),
			/same media type/,
		);
	});
});

describe("formatVideoTables", () => {
	it("renders final GitHub attachment URLs as playable table videos", () => {
		const markdown = formatVideoTables([
			pair(
				"https://github.com/user-attachments/assets/before-id",
				"https://github.com/user-attachments/assets/after-id",
				"Desktop hero",
			),
		]);
		assert.ok(markdown.includes("<th>Before (Desktop hero)</th>"));
		assert.ok(markdown.includes("<th>After (Desktop hero)</th>"));
		assert.ok(
			markdown.includes(
				'<video src="https://github.com/user-attachments/assets/before-id" width="100%" controls></video>',
			),
		);
		assert.ok(
			markdown.includes(
				'<video src="https://github.com/user-attachments/assets/after-id" width="100%" controls></video>',
			),
		);
	});

	it("renders an after-only video table as Preview", () => {
		const markdown = formatVideoTables([
			pair(null, "https://github.com/user-attachments/assets/preview-id"),
		]);
		assert.ok(markdown.includes("<th>Preview</th>"));
		assert.ok(!markdown.includes("<th>Before</th>"));
	});

	it("rejects non-attachment URLs", () => {
		assert.throws(
			() => formatVideoTables([pair(null, "https://example.com/video.mp4")]),
			/github\.com\/user-attachments/,
		);
	});
});

describe("attachList", () => {
	it("returns every file once in publish order", () => {
		assert.deepEqual(
			attachList(
				[
					pair("/repo/b.png", "/repo/a.png"),
					pair(null, "/repo/a.png"),
					pair(null, "/repo/preview.webm"),
				],
				{ cwd: "/repo" },
			),
			["./b.png", "./a.png", "./preview.webm"],
		);
	});
});

describe("replaceMarkedBlock", () => {
	const block = `${MARKER_START}\nnew media\n${MARKER_END}\n`;

	it("appends to a body without markers", () => {
		assert.equal(replaceMarkedBlock("Intro\n", block), `Intro\n\n${block}`);
	});

	it("returns only the block for an empty body", () => {
		assert.equal(replaceMarkedBlock("", block), block);
	});

	it("replaces only the existing marked section", () => {
		const body = `Intro\n\n${MARKER_START}\nold media\n${MARKER_END}\n\nFooter\n`;
		assert.equal(replaceMarkedBlock(body, block), `Intro\n\n${block.trim()}\n\nFooter\n`);
	});

	it("is idempotent", () => {
		const once = replaceMarkedBlock("Intro", block);
		assert.equal(replaceMarkedBlock(once, block), once);
	});

	it("rejects incomplete markers", () => {
		assert.throws(() => replaceMarkedBlock(`${MARKER_START}\nold`, block), /incomplete/);
		assert.throws(() => replaceMarkedBlock(`old\n${MARKER_END}`, block), /incomplete/);
	});

	it("rejects multiple marked sections", () => {
		const body = `${block}\n${block}`;
		assert.throws(() => replaceMarkedBlock(body, block), /multiple/);
	});

	it("rejects duplicate end markers", () => {
		const body = `${block}${MARKER_END}\n`;
		assert.throws(() => replaceMarkedBlock(body, block), /multiple/);
	});
});

describe("format.mjs CLI", () => {
	function fixture() {
		const cwd = mkdtempSync(join(tmpdir(), "before-and-after-"));
		mkdirSync(join(cwd, "captures"));
		for (const file of ["before.png", "after.png", "preview.webm"]) {
			writeFileSync(join(cwd, "captures", file), file);
		}
		return cwd;
	}

	it("rejects mixing local files with final video URLs", () => {
		const cwd = fixture();
		const result = spawnSync(
			"node",
			[
				formatScript,
				"--after",
				"captures/preview.webm",
				"--after-video-url",
				"https://github.com/user-attachments/assets/after-id",
			],
			{ cwd, encoding: "utf8" },
		);
		assert.equal(result.status, 1);
		assert.ok(result.stderr.includes("but not both"));
	});

	it("fails for missing files", () => {
		const cwd = fixture();
		const result = spawnSync("node", [formatScript, "--after", "captures/missing.png"], {
			cwd,
			encoding: "utf8",
		});
		assert.equal(result.status, 1);
		assert.ok(result.stderr.includes("Media file does not exist"));
	});

	it("fails for unsupported files", () => {
		const cwd = fixture();
		writeFileSync(join(cwd, "captures", "after.svg"), "<svg/>");
		const result = spawnSync("node", [formatScript, "--after", "captures/after.svg"], {
			cwd,
			encoding: "utf8",
		});
		assert.equal(result.status, 1);
		assert.ok(result.stderr.includes("Unsupported media file"));
	});

	it("emits formatted markdown for local image pairs", () => {
		const cwd = fixture();
		const result = spawnSync(
			"node",
			[
				formatScript,
				"--before",
				"captures/before.png",
				"--after",
				"captures/after.png",
				"--label",
				"Desktop",
			],
			{ cwd, encoding: "utf8" },
		);
		assert.equal(result.status, 0);
		assert.ok(result.stdout.includes(MARKER_START));
		assert.ok(result.stdout.includes("| Before (Desktop) | After (Desktop) |"));
		assert.ok(result.stdout.includes(MARKER_END));
	});

	it("emits attach list for gh --attach", () => {
		const cwd = fixture();
		const result = spawnSync(
			"node",
			[
				formatScript,
				"--attach-list",
				"--before",
				"captures/before.png",
				"--after",
				"captures/after.png",
			],
			{ cwd, encoding: "utf8" },
		);
		assert.equal(result.status, 0);
		assert.equal(result.stdout.trim(), "./captures/before.png\n./captures/after.png");
	});

	it("updates a body file with replaceMarkedBlock", () => {
		const cwd = fixture();
		const bodyPath = join(cwd, "pr-body.md");
		writeFileSync(bodyPath, "## Summary\nInitial body\n");

		const result = spawnSync(
			"node",
			[
				formatScript,
				"--body-file",
				bodyPath,
				"--before",
				"captures/before.png",
				"--after",
				"captures/after.png",
			],
			{ cwd, encoding: "utf8" },
		);
		assert.equal(result.status, 0);
		assert.ok(result.stdout.startsWith("## Summary\nInitial body\n\n<!-- before-and-after:start -->"));
	});
});

describe("before-and-after skill contract", () => {
	const skill = readFileSync(join(skillDir, "SKILL.md"), "utf8");
	const formatter = readFileSync(formatScript, "utf8");
	const scripts = readdirSync(join(skillDir, "scripts")).sort();

	it("contains only format.mjs in scripts/", () => {
		assert.deepEqual(scripts, ["format.mjs"]);
	});

	it("delegates browser navigation and capture to agent-browser", () => {
		assert.ok(skill.includes("agent-browser skills get core --full"));
		assert.ok(skill.includes("agent-browser skills get protected-vercel-deployments --full"));
		assert.ok(!skill.includes("x-vercel-protection-bypass"));
		assert.ok(!skill.includes("x-vercel-trusted-oidc-idp-token"));
	});

	it("documents all format.mjs CLI options in SKILL.md", () => {
		const optionsBlock = formatter.match(/options:\s*\{([\s\S]*?)\n\s*\},/)?.[1] ?? "";
		const cliFlags = new Set(
			[...optionsBlock.matchAll(/^\s*"?([a-z-]+)"?:\s*\{/gm)].map((match) => match[1]),
		);
		assert.ok(cliFlags.size > 0);

		const formatterInvocations = [
			...skill.matchAll(/format\.mjs[\s\S]*?(?=\n\s*\n|```)/g),
		].map((match) => match[0]);
		const documentedFlags = new Set(
			formatterInvocations.flatMap((block) =>
				[...block.matchAll(/--([a-z-]+)/g)].map((match) => match[1]),
			),
		);

		for (const flag of documentedFlags) {
			assert.ok(cliFlags.has(flag), `SKILL.md documents --${flag}, which format.mjs does not accept`);
		}
		for (const flag of cliFlags) {
			assert.ok(
				documentedFlags.has(flag) || skill.includes(`--${flag}`),
				`format.mjs accepts --${flag}, which SKILL.md never documents`,
			);
		}
	});

	it("agrees on marker block contract", () => {
		assert.ok(formatter.includes("<!-- before-and-after:start -->"));
		assert.ok(formatter.includes("<!-- before-and-after:end -->"));
		assert.ok(skill.includes("before-and-after:start/end"));
	});

	it("includes evidence placement and reading order rules", () => {
		const placement = skill.match(/## Place the evidence\n([\s\S]*?)\n## Publish/)?.[1] ?? "";
		assert.ok(placement, "SKILL.md must include a Place the evidence section before Publish");

		const requiredPhrases = [
			"existing Preview or deployment-link section",
			"before implementation-heavy sections",
			"proves the PR first",
			"supplemental formats",
			"as a demo",
			"10 fps",
			"preserve every byte of unrelated prose",
			"open the rendered PR",
		];
		for (const phrase of requiredPhrases) {
			assert.ok(placement.includes(phrase), `Placement guidance missing required phrase: ${phrase}`);
		}
	});
});
