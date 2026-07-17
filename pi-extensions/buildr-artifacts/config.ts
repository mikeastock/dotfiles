import { S3Client, type S3ClientConfig } from "@aws-sdk/client-s3";

import { createS3ArtifactUpload, type ArtifactUploadFn } from "./artifact-share.js";

export interface ArtifactConfig {
	bucketName: string;
	baseUrl: string;
}

export interface ArtifactRuntimeConfig extends ArtifactConfig {
	upload: ArtifactUploadFn;
}

const DEFAULT_BUCKET = "buildr-bizops-artifacts";
const DEFAULT_BASE_URL = "https://artifacts.buildrtools.com";

export function resolveArtifactConfig(env: NodeJS.ProcessEnv): ArtifactConfig {
	return {
		baseUrl: (env.ARTIFACTS_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, ""),
		bucketName: env.ARTIFACTS_S3_BUCKET ?? DEFAULT_BUCKET,
	};
}

export function resolveS3ClientConfig(env: NodeJS.ProcessEnv): S3ClientConfig {
	const endpoint = env.ARTIFACTS_S3_ENDPOINT ?? env.AWS_ENDPOINT_URL_S3;
	const forcePathStyle = parseBooleanEnv(env.ARTIFACTS_S3_FORCE_PATH_STYLE) ?? Boolean(endpoint);
	const credentials = resolveArtifactCredentials(env);
	return {
		...(credentials ? { credentials } : {}),
		endpoint,
		forcePathStyle,
		region: env.ARTIFACTS_AWS_REGION ?? env.AWS_REGION,
	};
}

function resolveArtifactCredentials(env: NodeJS.ProcessEnv): S3ClientConfig["credentials"] {
	const accessKeyId = nonEmptyEnv(env.ARTIFACTS_AWS_ACCESS_KEY_ID);
	const secretAccessKey = nonEmptyEnv(env.ARTIFACTS_AWS_SECRET_ACCESS_KEY);
	const sessionToken = nonEmptyEnv(env.ARTIFACTS_AWS_SESSION_TOKEN);

	if (!accessKeyId && !secretAccessKey && !sessionToken) {
		return undefined;
	}

	if (!accessKeyId || !secretAccessKey) {
		throw new Error(
			"ARTIFACTS_AWS_ACCESS_KEY_ID and ARTIFACTS_AWS_SECRET_ACCESS_KEY must be set together.",
		);
	}

	return { accessKeyId, secretAccessKey, sessionToken };
}

function nonEmptyEnv(value: string | undefined): string | undefined {
	if (value?.trim()) {
		return value;
	}
	return undefined;
}

export function createArtifactRuntimeConfig(
	env: NodeJS.ProcessEnv = process.env,
): ArtifactRuntimeConfig {
	const artifactConfig = resolveArtifactConfig(env);
	const client = new S3Client(resolveS3ClientConfig(env));
	return {
		...artifactConfig,
		upload: createS3ArtifactUpload(artifactConfig.bucketName, client),
	};
}

function parseBooleanEnv(value: string | undefined): boolean | undefined {
	if (value === undefined) {
		return undefined;
	}

	const normalized = value.trim().toLowerCase();
	if (["1", "true", "yes", "on"].includes(normalized)) {
		return true;
	}
	if (["0", "false", "no", "off"].includes(normalized)) {
		return false;
	}
	return undefined;
}
