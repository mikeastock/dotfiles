// bb-plugin-diffr host entry: runs diffr on the machine that holds the
// thread's workspace, which may not be the bb server's machine.
//
// A run's NDJSON is written to this plugin's data directory and indexed by
// file, so the panel can read any record in compressed byte ranges. That keeps
// every RPC response small however large the diff is.
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createWriteStream } from "node:fs";
import { copyFile, mkdir, mkdtemp, open, readdir, rm, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { createInterface } from "node:readline";
import { gzipSync } from "node:zlib";
import { experimental_defineHostEntry } from "@get-bb/plugin-sdk/host";
import { hostContract, type DiffMode, type DiffRun, type FileRecord, type FileSummary } from "./src/contract";

const MAX_STDERR_CHARS = 16 * 1024;
/** Refuse a run whose NDJSON would not fit in a browser tab anyway. */
const MAX_RUN_BYTES = 512 * 1024 * 1024;
/** Runs older than this, or beyond the newest MAX_RUNS, are deleted when diffr runs again. */
const RUN_TTL_MS = 60 * 60 * 1000;
const MAX_RUNS = 10;
/** diffr can spend minutes on one large file; stop it before the server's call deadline. */
const DIFF_BUDGET_MS = 100_000;
/** diffr's subcommands. Custom arguments name revisions and paths only. */
const SUBCOMMANDS = new Set(["pprint", "config", "upgrade", "uninstall", "help"]);
const INSTALL_HINT =
  "Install diffr on this machine with: curl -fsSL https://install.dev.fast/diffr | sh";

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function run(argv: string[], options: { cwd: string; env?: NodeJS.ProcessEnv; signal: AbortSignal }): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const [command, ...args] = argv;
    const child = spawn(command!, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      signal: options.signal,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-MAX_STDERR_CHARS);
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
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
    const result = await run(["git", "rev-parse", "--verify", "--quiet", `${candidate}^{commit}`], { cwd, signal });
    if (result.code === 0) return candidate;
  }
  throw new Error(`No base branch found. Tried ${candidates.join(", ")}. Use Custom with an explicit revision instead.`);
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
  await git(cwd, ["add", "--intent-to-add", "--all"], signal, { ...process.env, GIT_INDEX_FILE: target });
  return target;
}

/** The configured binary, falling back to the install script's default location. */
function binaryCandidates(binary: string): string[] {
  return binary === "diffr" ? ["diffr", join(homedir(), ".local", "bin", "diffr")] : [binary];
}

/** Matches the viewer's fileIdentity, so records find their manifest entry. */
type Pairing = { lhs?: { path: string }; rhs?: { path: string } };
const fileIdentity = (file: Pairing) => JSON.stringify([file.lhs?.path ?? null, file.rhs?.path ?? null]);

interface WireSide {
  root: { visibility?: { collapsed?: boolean; label?: string } };
}
interface WireFileEvent {
  type: "file";
  file: Pairing;
  diff?:
    | { type: "text"; lhs?: WireSide; rhs?: WireSide; stats: { textual: { added: number; removed: number }; fallback?: { message: string } } }
    | { type: "binary" };
  error?: { message: string };
}

function summarize(event: WireFileEvent): FileSummary {
  if (event.error || !event.diff) return { kind: "error", message: event.error?.message ?? "diffr sent neither a diff nor an error" };
  if (event.diff.type === "binary") return { kind: "binary" };
  const visibility = (event.diff.rhs ?? event.diff.lhs)?.root.visibility;
  return {
    kind: "text",
    stats: event.diff.stats.textual,
    fallback: event.diff.stats.fallback?.message ?? null,
    hidden: { collapsed: visibility?.collapsed ?? false, label: visibility?.label ?? "" },
  };
}

class BinaryMissing extends Error {}

/** Run diffr, write its NDJSON to `path`, and index each file record. */
async function recordRun(
  binary: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  path: string,
  signal: AbortSignal,
): Promise<Omit<DiffRun, "runId" | "args">> {
  const child = spawn(binary, ["--format", "ndjson", "--syntax", ...args], { cwd, env, signal, stdio: ["ignore", "pipe", "pipe"] });
  const spawned = new Promise<void>((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", (error) => reject((error as NodeJS.ErrnoException).code === "ENOENT" ? new BinaryMissing() : error));
  });
  const closed = new Promise<number | null>((resolve) => child.once("close", resolve));
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = (stderr + chunk.toString("utf8")).slice(-MAX_STDERR_CHARS);
  });
  await spawned;

  const out = createWriteStream(path);
  let start: string | null = null;
  let complete: string | null = null;
  let manifest = new Map<string, number>();
  let files: (FileRecord | null)[] = [];
  let offset = 0;
  try {
    for await (const line of createInterface({ input: child.stdout, crlfDelay: Infinity })) {
      const length = Buffer.byteLength(line, "utf8");
      if (offset + length + 1 > MAX_RUN_BYTES) {
        throw new Error(`This diff is larger than ${MAX_RUN_BYTES / 1024 / 1024} MB. Use Custom with paths to narrow it, e.g. HEAD -- src/`);
      }
      if (!out.write(`${line}\n`)) await once(out, "drain");
      if (line.trim() !== "") {
        const event = JSON.parse(line) as { type: string };
        if (event.type === "start") {
          start = line;
          const entries = (event as unknown as { files: { file: Pairing }[] }).files;
          manifest = new Map(entries.map((entry, index) => [fileIdentity(entry.file), index]));
          files = entries.map(() => null);
        } else if (event.type === "file") {
          const fileEvent = event as WireFileEvent;
          const slot = manifest.get(fileIdentity(fileEvent.file));
          if (slot !== undefined) files[slot] = { offset, length, summary: summarize(fileEvent) };
        } else if (event.type === "complete") {
          complete = line;
        }
      }
      offset += length + 1;
    }
  } catch (error) {
    child.kill("SIGTERM");
    out.destroy();
    throw error;
  }
  out.end();
  await once(out, "close");
  const code = await closed;
  // diffr exits 2 when some files failed or the run aborted, but still writes
  // its complete record; the panel shows those per-file errors itself.
  if (code !== 0 && complete === null) throw new Error(`diffr ${args.join(" ")} failed: ${stderr.trim() || `exit ${code}`}`);
  if (start === null) throw new Error(`diffr ${args.join(" ")} printed no start record${stderr ? `: ${stderr.trim()}` : ""}`);
  return { start, complete, files };
}

/** Delete runs past their lifetime and all but the newest MAX_RUNS. */
async function pruneRuns(dir: string) {
  const entries = await Promise.all(
    (await readdir(dir)).map(async (name) => ({ name, mtime: (await stat(join(dir, name))).mtimeMs })),
  );
  entries.sort((a, b) => b.mtime - a.mtime);
  const now = Date.now();
  await Promise.all(
    entries
      .filter((entry, index) => index >= MAX_RUNS || now - entry.mtime > RUN_TTL_MS)
      .map((entry) => rm(join(dir, entry.name), { force: true })),
  );
}

const runsDir = (dataDir: string) => join(dataDir, "runs");

export default experimental_defineHostEntry({
  contract: hostContract,
  handlers: {
    diff: async ({ cwd, binary, mode, bases, byteLimit }, context) => {
      const budget = AbortSignal.timeout(DIFF_BUDGET_MS);
      const signal = AbortSignal.any([context.signal, budget]);
      const dir = runsDir(context.experimental_paths.dataDir);
      await mkdir(dir, { recursive: true });
      await pruneRuns(dir);
      const base = mode.kind === "branch" ? await resolveBase(cwd, bases, signal) : null;
      const args = [...(byteLimit === null ? [] : ["--byte-limit", String(byteLimit)]), ...presetArgs(mode, base)];
      const runId = randomUUID();
      const path = join(dir, `${runId}.ndjson`);
      const scratch = await mkdtemp(join(tmpdir(), "bb-diffr-"));
      try {
        const index = await untrackedIndex(cwd, scratch, signal);
        const env = { ...process.env, GIT_INDEX_FILE: index };
        for (const candidate of binaryCandidates(binary)) {
          try {
            return { runId, args, ...(await recordRun(candidate, args, cwd, env, path, signal)) };
          } catch (error) {
            await rm(path, { force: true });
            if (budget.aborted) {
              throw new Error(
                `diffr did not finish within ${DIFF_BUDGET_MS / 1000} seconds. A large file can take minutes to diff structurally: lower the plugin's structural diff size limit, or narrow the diff with Custom paths.`,
              );
            }
            if (!(error instanceof BinaryMissing)) throw error;
          }
        }
        throw new Error(`Could not find the diffr binary (${binaryCandidates(binary).join(", ")}). ${INSTALL_HINT}`);
      } finally {
        await rm(scratch, { recursive: true, force: true });
      }
    },
    read: async ({ runId, offset, length }, context) => {
      const path = join(runsDir(context.experimental_paths.dataDir), `${runId}.ndjson`);
      let handle;
      try {
        handle = await open(path, "r");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("This diff has expired. Run diffr again.");
        throw error;
      }
      try {
        const buffer = Buffer.alloc(length);
        const { bytesRead } = await handle.read(buffer, 0, length, offset);
        return { gzip: gzipSync(buffer.subarray(0, bytesRead)).toString("base64") };
      } finally {
        await handle.close();
      }
    },
  },
});
