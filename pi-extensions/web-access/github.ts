import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Page } from "./exa.ts";

const run = promisify(execFile);

const CLONE_TIMEOUT_MS = 60_000;
const MAX_LISTED_FILES = 300;
const README_NAMES = ["README.md", "readme.md", "README", "README.rst", "README.txt"];

interface RepoRef {
	owner: string;
	repo: string;
	ref?: string;
	path: string;
	kind: "root" | "tree" | "blob";
}

let cloneRoot: string | undefined;
const clones = new Map<string, Promise<string>>();

/** Match repository, tree, and blob URLs; issues, PRs, and other pages are left to Exa. */
function parseRepoUrl(url: string): RepoRef | undefined {
	const parsed = new URL(url);
	if (parsed.hostname !== "github.com") return undefined;

	const [owner, rawRepo, kind, ref, ...rest] = parsed.pathname.split("/").filter(Boolean);
	if (!owner || !rawRepo) return undefined;
	const repo = rawRepo.replace(/\.git$/, "");

	if (!kind) return { owner, repo, path: "", kind: "root" };
	if ((kind === "tree" || kind === "blob") && ref) return { owner, repo, ref, path: rest.join("/"), kind };
	return undefined;
}

async function clone({ owner, repo, ref }: RepoRef, signal?: AbortSignal): Promise<string> {
	cloneRoot ??= mkdtempSync(join(tmpdir(), "pi-github-"));
	const dir = join(cloneRoot, owner, ref ? `${repo}@${ref.replaceAll("/", "_")}` : repo);
	const gitArgs = ["--depth", "1", "--single-branch", ...(ref ? ["--branch", ref] : [])];
	const options = { timeout: CLONE_TIMEOUT_MS, signal };

	try {
		// gh handles private-repo auth; fall back to plain git when gh is not installed.
		await run("gh", ["repo", "clone", `${owner}/${repo}`, dir, "--", ...gitArgs], options);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		await run("git", ["clone", ...gitArgs, `https://github.com/${owner}/${repo}.git`, dir], options);
	}
	return dir;
}

function cachedClone(target: RepoRef, signal?: AbortSignal): Promise<string> {
	const key = `${target.owner}/${target.repo}@${target.ref ?? ""}`;
	let pending = clones.get(key);
	if (!pending) {
		pending = clone(target, signal);
		pending.catch(() => clones.delete(key));
		clones.set(key, pending);
	}
	return pending;
}

async function listFiles(dir: string, path: string): Promise<string> {
	const { stdout } = await run("git", ["-C", dir, "ls-files", "--", path || "."], { maxBuffer: 64 * 1024 * 1024 });
	const files = stdout.split("\n").filter(Boolean);
	const shown = files.slice(0, MAX_LISTED_FILES).join("\n");
	return files.length > MAX_LISTED_FILES ? `${shown}\n… ${files.length - MAX_LISTED_FILES} more files` : shown;
}

function readText(file: string): string | undefined {
	const content = readFileSync(file);
	return content.subarray(0, 8_192).includes(0) ? undefined : content.toString("utf-8");
}

/**
 * Shallow-clone GitHub repository URLs so the agent can explore them with its file tools.
 * Returns undefined for non-repository URLs or when cloning fails, so the caller can use Exa instead.
 */
export async function fetchGitHub(url: string, signal?: AbortSignal): Promise<Page | undefined> {
	const target = parseRepoUrl(url);
	if (!target) return undefined;

	let dir: string;
	try {
		dir = await cachedClone(target, signal);
	} catch {
		return undefined;
	}

	const fullPath = join(dir, target.path);
	if (!existsSync(fullPath)) return undefined;

	const title = target.path ? `${target.owner}/${target.repo}: ${target.path}` : `${target.owner}/${target.repo}`;
	const sections = [`Shallow clone: ${dir}\nPath: ${fullPath}\nExplore it with read, rg, and other file tools.`];

	if (statSync(fullPath).isFile()) {
		const text = readText(fullPath);
		sections.push(text === undefined ? "Binary file; inspect it from the clone." : `## ${target.path}\n\n${text}`);
	} else {
		sections.push(`## Files\n\n${await listFiles(dir, target.path)}`);
		const readme = README_NAMES.find((name) => readdirSync(fullPath).includes(name));
		if (readme) sections.push(`## ${readme}\n\n${readText(join(fullPath, readme)) ?? ""}`);
	}

	return { url, title, text: sections.join("\n\n") };
}

export function removeClones(): void {
	if (cloneRoot) rmSync(cloneRoot, { recursive: true, force: true });
	cloneRoot = undefined;
	clones.clear();
}
