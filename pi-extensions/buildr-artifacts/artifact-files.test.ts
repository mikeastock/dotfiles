import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
	artifactContentTypeForExtension,
	collectArtifactFiles,
	readArtifactFileSafely,
} from "./artifact-files.js";

function tempDir(): string {
	return mkdtempSync(join(tmpdir(), "buildr-artifacts-files-"));
}

describe("artifactContentTypeForExtension", () => {
	it("returns exact content types for supported extensions", () => {
		assert.equal(artifactContentTypeForExtension(".html"), "text/html");
		assert.equal(artifactContentTypeForExtension(".css"), "text/css");
		assert.equal(artifactContentTypeForExtension(".js"), "application/javascript");
		assert.equal(artifactContentTypeForExtension(".png"), "image/png");
		assert.equal(artifactContentTypeForExtension(".woff2"), "font/woff2");
	});
});

describe("collectArtifactFiles", () => {
	it("collects a single html file as index.html", async () => {
		const root = tempDir();
		const file = join(root, "report.html");
		await writeFile(file, "<h1>Report</h1>");

		const files = collectArtifactFiles(file);

		assert.equal(files.length, 1);
		assert.equal(files[0].relativePath, "index.html");
		assert.equal(readArtifactFileSafely(files[0]).toString("utf8"), "<h1>Report</h1>");
	});

	it("rejects a non-html single file", async () => {
		const root = tempDir();
		const file = join(root, "report.txt");
		await writeFile(file, "not html");

		assert.throws(() => collectArtifactFiles(file), /Single file must be an \.html file/);
	});

	it("collects a directory with root index.html and assets", async () => {
		const root = tempDir();
		await mkdir(join(root, "assets"));
		await writeFile(join(root, "index.html"), '<script src="assets/app.js"></script>');
		await writeFile(join(root, "assets", "app.js"), "console.log('ok');");

		const files = collectArtifactFiles(root);

		assert.deepEqual(
			files.map((file) => file.relativePath),
			["assets/app.js", "index.html"],
		);
	});

	it("rejects a directory without root index.html", async () => {
		const root = tempDir();
		await writeFile(join(root, "page.html"), "<h1>Missing index</h1>");

		assert.throws(() => collectArtifactFiles(root), /Directory must contain an index\.html/);
	});

	it("rejects unsupported extensions in directory uploads", async () => {
		const root = tempDir();
		await writeFile(join(root, "index.html"), "<h1>OK</h1>");
		await writeFile(join(root, "secret.env"), "TOKEN=abc");

		assert.throws(() => collectArtifactFiles(root), /Unsupported file extension/);
	});

	it("rejects symlinks", async () => {
		const root = tempDir();
		await writeFile(join(root, "index.html"), "<h1>OK</h1>");
		await writeFile(join(root, "target.js"), "console.log('target');");
		await symlink(join(root, "target.js"), join(root, "linked.js"));

		assert.throws(() => collectArtifactFiles(root), /symlink paths are not allowed/);
	});

	it("rejects files whose parent directory resolves outside the artifact root after collection", async () => {
		const root = tempDir();
		const outside = tempDir();
		await mkdir(join(root, "assets"));
		await writeFile(join(root, "index.html"), "<h1>OK</h1>");
		await writeFile(join(root, "assets", "app.js"), "console.log('inside');");
		await writeFile(join(outside, "app.js"), "console.log('outside');");
		const files = collectArtifactFiles(root);
		const appFile = files.find((file) => file.relativePath === "assets/app.js");
		assert.ok(appFile);

		await rm(join(root, "assets"), { recursive: true });
		await symlink(outside, join(root, "assets"));

		assert.throws(() => readArtifactFileSafely(appFile), /outside artifact root/);
	});
});
