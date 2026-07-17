import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import Module from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { GetObjectCommand, HeadObjectCommand, S3Client } from "@aws-sdk/client-s3";
import type S3rverType from "@20minutes/s3rver";

import {
	createS3ArtifactUpload,
	shareArtifactFromHostPath,
	shareArtifactFromHtml,
} from "./artifact-share.js";

const BUCKET = "test-artifacts";
const require = createRequire(import.meta.url);
const S3rver = requireS3rver();
let servers: S3rverType[] = [];
let clients: S3Client[] = [];
let serverDirectories: string[] = [];

function requireS3rver(): typeof S3rverType {
	const loader = Module as unknown as {
		_load(request: string, parent: unknown, isMain: boolean): unknown;
	};
	const originalLoad = loader._load;
	loader._load = function patchedLoad(request: string, parent: unknown, isMain: boolean): unknown {
		const result = originalLoad.call(this, request, parent, isMain);
		if (
			request === "generator-function" &&
			typeof result === "object" &&
			result !== null &&
			"default" in result &&
			typeof result.default === "function"
		) {
			return result.default;
		}
		return result;
	};

	try {
		return require("@20minutes/s3rver") as typeof S3rverType;
	} finally {
		loader._load = originalLoad;
	}
}

async function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = createServer();
		server.on("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => {
				if (address && typeof address === "object") {
					resolve(address.port);
					return;
				}
				reject(new Error("Could not allocate test port"));
			});
		});
	});
}

async function startFakeS3(): Promise<{ endpoint: string; client: S3Client }> {
	const directory = mkdtempSync(join(tmpdir(), "buildr-artifacts-s3-"));
	serverDirectories.push(directory);
	const port = await getFreePort();
	const server = new S3rver({
		address: "127.0.0.1",
		allowMismatchedSignatures: true,
		configureBuckets: [{ name: BUCKET }],
		directory,
		port,
		resetOnClose: false,
		silent: true,
	});
	await server.run();
	servers.push(server);

	const endpoint = `http://127.0.0.1:${port}`;
	const client = new S3Client({
		credentials: { accessKeyId: "S3RVER", secretAccessKey: "S3RVER" },
		endpoint,
		forcePathStyle: true,
		region: "us-east-1",
	});
	clients.push(client);
	return { endpoint, client };
}

async function objectBody(client: S3Client, key: string): Promise<string> {
	const result = await client.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
	return result.Body?.transformToString() ?? "";
}

async function objectContentType(client: S3Client, key: string): Promise<string | undefined> {
	const result = await client.send(new HeadObjectCommand({ Bucket: BUCKET, Key: key }));
	return result.ContentType;
}

afterEach(async () => {
	for (const client of clients) {
		client.destroy();
	}
	clients = [];
	await Promise.all(servers.map((server) => server.close()));
	servers = [];
	await Promise.all(serverDirectories.map((directory) => rm(directory, { force: true, recursive: true })));
	serverDirectories = [];
});

describe("shareArtifactFromHtml", () => {
	it("uploads inline HTML as index.html and returns the artifact URL", async () => {
		const { client } = await startFakeS3();
		const upload = createS3ArtifactUpload(BUCKET, client);

		const result = await shareArtifactFromHtml({
			baseUrl: "https://artifacts.example.test",
			html: "<h1>Hello</h1>",
			slug: "fixed-slug",
			upload,
		});

		assert.equal(result.url, "https://artifacts.example.test/fixed-slug/");
		assert.equal(await objectBody(client, "fixed-slug/index.html"), "<h1>Hello</h1>");
	});
});

describe("shareArtifactFromHostPath", () => {
	it("uploads a single HTML file as index.html", async () => {
		const { client } = await startFakeS3();
		const upload = createS3ArtifactUpload(BUCKET, client);
		const root = mkdtempSync(join(tmpdir(), "buildr-artifacts-html-"));
		const htmlPath = join(root, "report.html");
		await writeFile(htmlPath, "<h1>Report</h1>");

		const result = await shareArtifactFromHostPath({
			baseUrl: "https://artifacts.example.test",
			hostPath: htmlPath,
			slug: "file-slug",
			upload,
		});

		assert.equal(result.url, "https://artifacts.example.test/file-slug/");
		assert.equal(await objectBody(client, "file-slug/index.html"), "<h1>Report</h1>");
	});

	it("uploads a directory bundle with content types", async () => {
		const { client } = await startFakeS3();
		const upload = createS3ArtifactUpload(BUCKET, client);
		const root = mkdtempSync(join(tmpdir(), "buildr-artifacts-dir-"));
		await mkdir(join(root, "assets"));
		await writeFile(join(root, "index.html"), '<script src="assets/app.js"></script>');
		await writeFile(join(root, "assets", "app.js"), "console.log('ok');");

		await shareArtifactFromHostPath({
			baseUrl: "https://artifacts.example.test",
			hostPath: root,
			slug: "dir-slug",
			upload,
		});

		assert.equal(await objectBody(client, "dir-slug/index.html"), '<script src="assets/app.js"></script>');
		assert.equal(await objectBody(client, "dir-slug/assets/app.js"), "console.log('ok');");
		assert.equal(await objectContentType(client, "dir-slug/index.html"), "text/html");
		assert.equal(await objectContentType(client, "dir-slug/assets/app.js"), "application/javascript");
	});

	it("returns explicit index.html for localhost:9000 base URLs", async () => {
		const { client } = await startFakeS3();
		const upload = createS3ArtifactUpload(BUCKET, client);

		const result = await shareArtifactFromHtml({
			baseUrl: "http://localhost:9000/test-artifacts",
			html: "<h1>Local</h1>",
			slug: "local-slug",
			upload,
		});

		assert.equal(result.url, "http://localhost:9000/test-artifacts/local-slug/index.html");
	});

	it("returns explicit index.html for IPv6 localhost port 9000 base URLs", async () => {
		const { client } = await startFakeS3();
		const upload = createS3ArtifactUpload(BUCKET, client);

		const result = await shareArtifactFromHtml({
			baseUrl: "http://[::1]:9000/test-artifacts",
			html: "<h1>Local</h1>",
			slug: "ipv6-slug",
			upload,
		});

		assert.equal(result.url, "http://[::1]:9000/test-artifacts/ipv6-slug/index.html");
	});
});
