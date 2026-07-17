import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	lstatSync,
	openSync,
	readdirSync,
	readFileSync,
	realpathSync,
	type Stats,
} from "node:fs";
import { extname, isAbsolute, join, relative, resolve } from "node:path";

const CONTENT_TYPES: Record<string, string> = {
	".css": "text/css",
	".gif": "image/gif",
	".html": "text/html",
	".ico": "image/x-icon",
	".jpeg": "image/jpeg",
	".jpg": "image/jpeg",
	".js": "application/javascript",
	".json": "application/json",
	".pdf": "application/pdf",
	".png": "image/png",
	".svg": "image/svg+xml",
	".ttf": "font/ttf",
	".txt": "text/plain",
	".webp": "image/webp",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".xml": "application/xml",
};

const ALLOWED_ARTIFACT_EXTENSIONS = new Set(Object.keys(CONTENT_TYPES));
const DEFAULT_MAX_ARTIFACT_FILES = 2000;
const DEFAULT_MAX_ARTIFACT_DEPTH = 20;
const MAX_ARTIFACT_FILE_BYTES = 1_073_741_824;

export interface ArtifactShareLimitOverrides {
	maxFiles?: number;
	maxDepth?: number;
}

export interface CollectedArtifactFile {
	relativePath: string;
	absolutePath: string;
	expectedDev: number;
	expectedIno: number;
	expectedSizeBytes: number;
	rootRealPath: string;
}

interface ArtifactCollectionLimits {
	maxFiles: number;
	maxDepth: number;
}

interface ArtifactCollectionState {
	fileCount: number;
}

export function artifactContentTypeForExtension(ext: string): string {
	return CONTENT_TYPES[ext.toLowerCase()] ?? "application/octet-stream";
}

export function collectArtifactFiles(
	hostPath: string,
	limitOverrides: ArtifactShareLimitOverrides = {},
): CollectedArtifactFile[] {
	const resolvedHostPath = resolve(hostPath);
	const limits = resolveArtifactCollectionLimits(limitOverrides);
	const state: ArtifactCollectionState = { fileCount: 0 };
	const stat = lstatNoSymlink(resolvedHostPath, `Path does not exist: ${resolvedHostPath}`);

	if (stat.isFile()) {
		if (extname(resolvedHostPath).toLowerCase() !== ".html") {
			throw new Error(`Single file must be an .html file: ${resolvedHostPath}`);
		}

		const files: CollectedArtifactFile[] = [];
		const rootRealPath = realpathSync(resolvedHostPath);
		pushCollectedArtifactFile(files, "index.html", resolvedHostPath, stat, state, limits, rootRealPath);
		assertArtifactFilesWithinSizeLimit(files);
		return files;
	}

	if (!stat.isDirectory()) {
		throw new Error(`Path is neither a file nor a directory: ${resolvedHostPath}`);
	}

	const rootRealPath = realpathSync(resolvedHostPath);
	const indexPath = join(resolvedHostPath, "index.html");
	const indexStat = lstatNoSymlink(
		indexPath,
		`Directory must contain an index.html at its root: ${resolvedHostPath}`,
		rootRealPath,
	);

	if (!indexStat.isFile()) {
		throw new Error(`index.html must be a regular file: ${indexPath}`);
	}

	const files: CollectedArtifactFile[] = [];
	walkDir(resolvedHostPath, resolvedHostPath, 0, files, state, limits, rootRealPath);
	assertArtifactFilesWithinSizeLimit(files);
	return files;
}

function resolveArtifactCollectionLimits(
	overrides: ArtifactShareLimitOverrides = {},
): ArtifactCollectionLimits {
	return {
		maxDepth: resolvePositiveInteger(overrides.maxDepth, DEFAULT_MAX_ARTIFACT_DEPTH, "maxDepth"),
		maxFiles: resolvePositiveInteger(overrides.maxFiles, DEFAULT_MAX_ARTIFACT_FILES, "maxFiles"),
	};
}

function resolvePositiveInteger(value: number | undefined, fallback: number, name: string): number {
	const resolved = value ?? fallback;
	if (!Number.isInteger(resolved) || resolved <= 0) {
		throw new Error(`${name} must be a positive integer`);
	}
	return resolved;
}

function lstatNoSymlink(path: string, missingError: string, rootRealPath?: string): Stats {
	let stat: Stats;
	try {
		stat = lstatSync(path);
	} catch (error) {
		const nodeError = error as NodeJS.ErrnoException;
		if (nodeError.code === "ENOENT" || nodeError.code === "ENOTDIR") {
			throw new Error(missingError, { cause: error });
		}
		if (nodeError.code === "ELOOP") {
			throw new Error(`symlink paths are not allowed: ${path}`, { cause: error });
		}
		throw error;
	}

	if (stat.isSymbolicLink()) {
		throw new Error(`symlink paths are not allowed: ${path}`);
	}

	if (rootRealPath) {
		assertRealPathWithinRoot(rootRealPath, path);
	}

	return stat;
}

function walkDir(
	baseDir: string,
	currentDir: string,
	depth: number,
	files: CollectedArtifactFile[],
	state: ArtifactCollectionState,
	limits: ArtifactCollectionLimits,
	rootRealPath: string,
): void {
	for (const entryName of readdirSync(currentDir).sort()) {
		const fullPath = join(currentDir, entryName);
		const entryStat = lstatNoSymlink(fullPath, `Path does not exist: ${fullPath}`, rootRealPath);

		if (entryStat.isDirectory()) {
			if (depth + 1 > limits.maxDepth) {
				throw new Error(`Artifact depth limit exceeded (${limits.maxDepth}): ${fullPath}`);
			}
			walkDir(baseDir, fullPath, depth + 1, files, state, limits, rootRealPath);
			continue;
		}

		if (entryStat.isFile()) {
			assertAllowedArtifactExtension(fullPath);
			pushCollectedArtifactFile(
				files,
				relative(baseDir, fullPath),
				fullPath,
				entryStat,
				state,
				limits,
				rootRealPath,
			);
			continue;
		}

		throw new Error(`Only regular files and directories are allowed: ${fullPath}`);
	}
}

function assertAllowedArtifactExtension(filePath: string): void {
	const extension = extname(filePath).toLowerCase();
	if (ALLOWED_ARTIFACT_EXTENSIONS.has(extension)) {
		return;
	}

	throw new Error(
		`Unsupported file extension for artifact sharing: ${filePath} (${extension || "none"})`,
	);
}

function pushCollectedArtifactFile(
	files: CollectedArtifactFile[],
	relativePath: string,
	absolutePath: string,
	stat: Stats,
	state: ArtifactCollectionState,
	limits: ArtifactCollectionLimits,
	rootRealPath: string,
): void {
	state.fileCount += 1;
	if (state.fileCount > limits.maxFiles) {
		throw new Error(`Artifact file count limit exceeded (${limits.maxFiles} files): ${absolutePath}`);
	}

	files.push({
		absolutePath,
		expectedDev: stat.dev,
		expectedIno: stat.ino,
		expectedSizeBytes: stat.size,
		relativePath,
		rootRealPath,
	});
}

function openReadonlyNoFollow(path: string): number {
	const noFollowFlag = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;

	try {
		return openSync(path, fsConstants.O_RDONLY | noFollowFlag);
	} catch (error) {
		const nodeError = error as NodeJS.ErrnoException;
		if (nodeError.code === "ELOOP") {
			throw new Error(`symlink paths are not allowed: ${path}`, { cause: error });
		}
		if (nodeError.code === "ENOENT") {
			throw new Error(`Path does not exist: ${path}`, { cause: error });
		}
		throw error;
	}
}

export function readArtifactFileSafely(file: CollectedArtifactFile): Buffer {
	assertRealPathWithinRoot(file.rootRealPath, file.absolutePath);
	const fd = openReadonlyNoFollow(file.absolutePath);
	try {
		const openedStat = fstatSync(fd);

		if (!openedStat.isFile()) {
			throw new Error(`Path is not a regular file: ${file.absolutePath}`);
		}

		if (
			openedStat.dev !== file.expectedDev ||
			openedStat.ino !== file.expectedIno ||
			openedStat.size !== file.expectedSizeBytes
		) {
			throw new Error(`Path changed while sharing artifact: ${file.absolutePath}`);
		}

		return readFileSync(fd);
	} finally {
		closeSync(fd);
	}
}

function assertRealPathWithinRoot(rootRealPath: string, path: string): void {
	const fileRealPath = realpathSync(path);
	const relativePath = relative(rootRealPath, fileRealPath);
	if (relativePath && (relativePath.startsWith("..") || isAbsolute(relativePath))) {
		throw new Error(`Path resolves outside artifact root: ${path}`);
	}
}

export function assertArtifactFilesWithinSizeLimit(files: CollectedArtifactFile[]): void {
	for (const file of files) {
		if (file.expectedSizeBytes > MAX_ARTIFACT_FILE_BYTES) {
			throw new Error(`Artifact file too large (>1 GiB): ${file.absolutePath}`);
		}
	}
}
