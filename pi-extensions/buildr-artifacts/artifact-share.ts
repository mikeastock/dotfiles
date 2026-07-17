import { randomBytes } from "node:crypto";
import { extname } from "node:path";

import { PutObjectCommand, type S3Client } from "@aws-sdk/client-s3";

import {
	artifactContentTypeForExtension,
	assertArtifactFilesWithinSizeLimit,
	collectArtifactFiles,
	readArtifactFileSafely,
	type ArtifactShareLimitOverrides,
} from "./artifact-files.js";

const ADJECTIVES = [
	"agile",
	"amber",
	"bold",
	"brave",
	"bright",
	"calm",
	"clear",
	"clever",
	"cobalt",
	"crisp",
	"daring",
	"deep",
	"eager",
	"fast",
	"fresh",
	"golden",
	"green",
	"happy",
	"ivory",
	"keen",
	"lively",
	"lucid",
	"maple",
	"merry",
	"noble",
	"onyx",
	"opal",
	"quick",
	"quiet",
	"rapid",
	"silver",
	"solar",
	"steady",
	"swift",
	"tidy",
	"vivid",
];

const NOUNS = [
	"anchor",
	"badge",
	"beacon",
	"brook",
	"canvas",
	"cedar",
	"comet",
	"ember",
	"field",
	"forge",
	"garden",
	"harbor",
	"kernel",
	"lantern",
	"meadow",
	"orbit",
	"panda",
	"pixel",
	"river",
	"rocket",
	"signal",
	"summit",
	"thicket",
	"tiger",
	"valley",
	"window",
];

export type ArtifactUploadFn = (
	key: string,
	body: Buffer,
	contentType: string,
	signal?: AbortSignal,
) => Promise<void>;

export interface ShareArtifactFromHostPathInput {
	hostPath: string;
	baseUrl: string;
	upload: ArtifactUploadFn;
	signal?: AbortSignal;
	slug?: string;
	limits?: ArtifactShareLimitOverrides;
}

export interface ShareArtifactFromHtmlInput {
	html: string;
	baseUrl: string;
	upload: ArtifactUploadFn;
	signal?: AbortSignal;
	slug?: string;
}

export interface ShareArtifactResult {
	slug: string;
	url: string;
}

export function createS3ArtifactUpload(bucketName: string, client: S3Client): ArtifactUploadFn {
	return async (key, body, contentType, signal) => {
		await client.send(
			new PutObjectCommand({
				Body: body,
				Bucket: bucketName,
				CacheControl: "public, max-age=31536000, immutable",
				ContentType: contentType,
				Key: key,
			}),
			{ abortSignal: signal },
		);
	};
}

export function generateArtifactSlug(): string {
	const adjective = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
	const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
	return `${adjective}-${noun}-${randomBytes(2).toString("hex")}`;
}

export async function shareArtifactFromHtml(
	input: ShareArtifactFromHtmlInput,
): Promise<ShareArtifactResult> {
	throwIfAborted(input.signal);
	const baseUrl = input.baseUrl.replace(/\/+$/, "");
	const slug = input.slug ?? generateArtifactSlug();
	await input.upload(`${slug}/index.html`, Buffer.from(input.html, "utf8"), "text/html", input.signal);
	return { slug, url: buildArtifactUrl(baseUrl, slug) };
}

export async function shareArtifactFromHostPath(
	input: ShareArtifactFromHostPathInput,
): Promise<ShareArtifactResult> {
	throwIfAborted(input.signal);
	const baseUrl = input.baseUrl.replace(/\/+$/, "");
	const files = collectArtifactFiles(input.hostPath, input.limits);
	assertArtifactFilesWithinSizeLimit(files);
	const slug = input.slug ?? generateArtifactSlug();

	for (const file of files) {
		throwIfAborted(input.signal);
		const key = `${slug}/${file.relativePath}`;
		const body = readArtifactFileSafely(file);
		const contentType = artifactContentTypeForExtension(extname(file.relativePath));
		await input.upload(key, body, contentType, input.signal);
	}

	return { slug, url: buildArtifactUrl(baseUrl, slug) };
}

function throwIfAborted(signal: AbortSignal | undefined): void {
	if (signal?.aborted) {
		throw new Error("Operation aborted");
	}
}

function buildArtifactUrl(baseUrl: string, slug: string): string {
	return `${baseUrl}/${slug}${shouldUseExplicitIndexHtml(baseUrl) ? "/index.html" : "/"}`;
}

function shouldUseExplicitIndexHtml(baseUrl: string): boolean {
	try {
		const parsed = new URL(baseUrl);
		const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
		return ["localhost", "127.0.0.1", "::1"].includes(hostname) && parsed.port === "9000";
	} catch {
		return false;
	}
}
