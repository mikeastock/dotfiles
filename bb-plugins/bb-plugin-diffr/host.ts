// bb-plugin-diffr host entry: runs diffr on the machine that holds the
// thread's workspace, which may not be the bb server's machine.
import { spawn } from "node:child_process";
import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { experimental_defineHostEntry } from "@get-bb/plugin-sdk/host";
import { hostContract, type DiffMode } from "./src/contract";

/** Host RPC output is capped at 8 MiB of JSON; stay under it with room for escaping. */
const MAX_OUTPUT_BYTES = 6 * 1024 * 1024;
const MAX_STDERR_CHARS = 16 * 1024;
/** diffr's subcommands. Custom arguments name revisions and paths only. */
const SUBCOMMANDS = new Set(["pprint", "config", "upgrade", "uninstall", "help"]);
const INSTALL_HINT =
  "Install diffr on this machine with: curl -fsSL https://install.dev.fast/diffr | sh";

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

class OutputTooLarge extends Error {}

function run(
  argv: string[],
  options: { cwd: string; env?: NodeJS.ProcessEnv; signal: AbortSignal; maxBytes?: number },
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const [command, ...args] = argv;
    const child = spawn(command!, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      signal: options.signal,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let stderr = "";
    let tooLarge = false;
    child.stdout.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (options.maxBytes !== undefined && bytes > options.maxBytes) {
        tooLarge = true;
        child.kill("SIGTERM");
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-MAX_STDERR_CHARS);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (tooLarge) {
        reject(new OutputTooLarge());
        return;
      }
      resolve({ code, stdout: Buffer.concat(chunks).toString("utf8"), stderr });
    });
  });
}

async function git(cwd: string, args: string[], signal: AbortSignal, env?: NodeJS.ProcessEnv) {
  const result = await run(["git", ...args], { cwd, env, signal });
  if (result.code !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr.trim() || `exit ${result.code}`}`);
  }
  return result.stdout.trim();
}

/** The first candidate that names a commit, trying each as given and then on origin. */
async function resolveBase(cwd: string, bases: string[], signal: AbortSignal): Promise<string> {
  const candidates = [...bases.flatMap((base) => [base, `origin/${base}`]), "origin/HEAD"];
  for (const candidate of candidates) {
    const result = await run(["git", "rev-parse", "--verify", "--quiet", `${candidate}^{commit}`], {
      cwd,
      signal,
    });
    if (result.code === 0) return candidate;
  }
  throw new Error(
    `No base branch found. Tried ${candidates.join(", ")}. Use Custom with an explicit revision instead.`,
  );
}

function presetArgs(mode: DiffMode, base: string | null): string[] {
  switch (mode.kind) {
    case "changes":
      return ["HEAD"];
    case "branch":
      return ["--merge-base", base!];
    case "custom": {
      const first = mode.args[0];
      if (first !== undefined && SUBCOMMANDS.has(first)) {
        throw new Error(`"${first}" is a diffr subcommand; pass revisions and paths only.`);
      }
      return mode.args;
    }
  }
}

/**
 * A throwaway copy of the index with every untracked file added as
 * intent-to-add, so diffr shows new files as additions. The real index is
 * never touched.
 */
async function untrackedIndex(cwd: string, dir: string, signal: AbortSignal): Promise<string> {
  const indexPath = await git(cwd, ["rev-parse", "--git-path", "index"], signal);
  const source = isAbsolute(indexPath) ? indexPath : join(cwd, indexPath);
  const target = join(dir, "index");
  try {
    await copyFile(source, target);
  } catch (error) {
    // A repository with nothing staged yet has no index file.
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await git(cwd, ["add", "--intent-to-add", "--all"], signal, {
    ...process.env,
    GIT_INDEX_FILE: target,
  });
  return target;
}

/** The configured binary, falling back to the install script's default location. */
function binaryCandidates(binary: string): string[] {
  return binary === "diffr" ? ["diffr", join(homedir(), ".local", "bin", "diffr")] : [binary];
}

async function runDiffr(
  binary: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  signal: AbortSignal,
): Promise<string> {
  const argv = ["--format", "ndjson", "--syntax", ...args];
  for (const candidate of binaryCandidates(binary)) {
    let result: RunResult;
    try {
      result = await run([candidate, ...argv], { cwd, env, signal, maxBytes: MAX_OUTPUT_BYTES });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      if (error instanceof OutputTooLarge) {
        throw new Error(
          `This diff is larger than ${MAX_OUTPUT_BYTES / 1024 / 1024} MB. Use Custom with paths to narrow it, e.g. HEAD -- src/`,
        );
      }
      throw error;
    }
    if (result.code !== 0) {
      throw new Error(`diffr ${args.join(" ")} failed: ${result.stderr.trim() || `exit ${result.code}`}`);
    }
    return result.stdout;
  }
  throw new Error(`Could not find the diffr binary (${binaryCandidates(binary).join(", ")}). ${INSTALL_HINT}`);
}

export default experimental_defineHostEntry({
  contract: hostContract,
  handlers: {
    diff: async ({ cwd, binary, mode, bases }, context) => {
      const { signal } = context;
      const base = mode.kind === "branch" ? await resolveBase(cwd, bases, signal) : null;
      const args = presetArgs(mode, base);
      const dir = await mkdtemp(join(tmpdir(), "bb-diffr-"));
      try {
        const index = await untrackedIndex(cwd, dir, signal);
        const ndjson = await runDiffr(binary, args, cwd, { ...process.env, GIT_INDEX_FILE: index }, signal);
        return { ndjson, args };
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  },
});
