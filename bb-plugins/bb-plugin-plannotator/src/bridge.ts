import { createHash, randomUUID } from "node:crypto";
import {
  accessSync,
  constants,
  createReadStream,
  createWriteStream,
} from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { spawn, type ChildProcess } from "node:child_process";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

export const UPSTREAM_REPOSITORY = "https://github.com/backnotprop/plannotator";
export const DEFAULT_BINARY = "plannotator";
export const BUNDLED_BINARY = "bundled";
export const BUNDLED_RELEASE_VERSION = "0.27.1";
export const BUNDLED_DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;
export const READY_TIMEOUT_MS = 15_000;
export const INTERACTION_SETTLE_TIMEOUT_MS = 10_000;
/** Remote mode accepts a range so multiple simultaneous reviews can coexist. */
export const REMOTE_PORT_RANGE = "19432-19441";

const BUNDLED_RELEASE_BASE_URL = `${UPSTREAM_REPOSITORY}/releases/download/v${BUNDLED_RELEASE_VERSION}`;

export type BundledTarget =
  | "darwin-arm64"
  | "darwin-x64"
  | "linux-arm64"
  | "linux-x64"
  | "win32-arm64"
  | "win32-x64";

export type BundledAsset = {
  target: BundledTarget;
  name: string;
  sha256: string;
  sizeBytes: number;
};

/** Pinned official release assets; update this table with each plugin release. */
export const BUNDLED_ASSETS: Record<BundledTarget, BundledAsset> = {
  "darwin-arm64": {
    target: "darwin-arm64",
    name: "plannotator-darwin-arm64",
    sha256: "5d08f591e6ee34d070913b36fa133494047b1565adeaf8192d366840192815d8",
    sizeBytes: 119_388_770,
  },
  "darwin-x64": {
    target: "darwin-x64",
    name: "plannotator-darwin-x64",
    sha256: "ac2f55494c4bf18f1d963b61a543323b2dacb92d13d067875eecb412defc2d67",
    sizeBytes: 124_682_320,
  },
  "linux-arm64": {
    target: "linux-arm64",
    name: "plannotator-linux-arm64",
    sha256: "e10e6e73bd5f087380c1ba0c8eed22a86578be49687059ba224afed78d4429b3",
    sizeBytes: 149_203_088,
  },
  "linux-x64": {
    target: "linux-x64",
    name: "plannotator-linux-x64",
    sha256: "e7a3cec5676cc7f842a8fb74b71ccb98f1014fe9c3633c3cffec28d0b1815451",
    sizeBytes: 150_096_000,
  },
  "win32-arm64": {
    target: "win32-arm64",
    name: "plannotator-win32-arm64.exe",
    sha256: "9dbb76a01ea50d3d2282adf5475df03a8478fc232f2ed661c822dc36b4c4b778",
    sizeBytes: 150_089_216,
  },
  "win32-x64": {
    target: "win32-x64",
    name: "plannotator-win32-x64.exe",
    sha256: "83417fe66b8ebb4b19256921ea530216d81d733a6f90f61439c6d327eeb54eab",
    sizeBytes: 153_985_536,
  },
};

type FetchLike = typeof fetch;
const bundledDownloadLocks = new Map<string, Promise<string>>();

export type UpstreamReadyMetadata = {
  url: string;
  isRemote: boolean;
  port: number;
};

export type UpstreamDecision = {
  approved: boolean;
  feedback?: string;
  savedPath?: string;
  agentSwitch?: string;
};

/** Agent identity understood by Plannotator's upstream result screen. */
export type UpstreamOrigin =
  | "claude-code"
  | "opencode"
  | "codex"
  | "copilot-cli"
  | "gemini-cli"
  | "pi";

type BridgeOptions = {
  binaryPath: string;
  /** The upstream entrypoint and the JSON request it reads from stdin. */
  request: UpstreamRequest;
  timeoutSeconds: number | null;
  signal: AbortSignal;
  /** Do not let the child infer an agent from unrelated host environment. */
  origin?: UpstreamOrigin;
  /** Persistent upstream state, including plan history and configuration. */
  dataDir?: string;
  /** Host used by BB's loopback server, so embedded cookies share one host. */
  embedHost?: string;
  /** Bind beyond loopback when BB itself is configured for remote access. */
  remote?: boolean;
  cwd?: string;
  readyTimeoutMs?: number;
};

export type RunningUpstreamReview = {
  url: string;
  result: Promise<UpstreamDecision>;
  stop(): Promise<void>;
};

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function bundledTargetFor(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): BundledTarget | null {
  if (platform !== "darwin" && platform !== "linux" && platform !== "win32") {
    return null;
  }
  if (arch !== "arm64" && arch !== "x64") return null;
  return `${platform}-${arch}` as BundledTarget;
}

export function bundledAssetFor(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): BundledAsset | null {
  const target = bundledTargetFor(platform, arch);
  return target ? BUNDLED_ASSETS[target] : null;
}

function bundledBinaryPath(runtimeDir: string, asset: BundledAsset): string {
  return join(runtimeDir, `v${BUNDLED_RELEASE_VERSION}`, asset.name);
}

function bundledMetadataPath(binaryPath: string): string {
  return `${binaryPath}.json`;
}

function isMatchingBundledMetadata(value: unknown, asset: BundledAsset): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    record.version === BUNDLED_RELEASE_VERSION &&
    record.name === asset.name &&
    record.sha256 === asset.sha256 &&
    record.sizeBytes === asset.sizeBytes
  );
}

async function findCachedBundledBinary(
  binaryPath: string,
  asset: BundledAsset,
): Promise<string | null> {
  try {
    const [metadata, binary] = await Promise.all([
      readFile(bundledMetadataPath(binaryPath), "utf8"),
      stat(binaryPath),
    ]);
    if (!binary.isFile() || binary.size !== asset.sizeBytes) return null;
    if (!isMatchingBundledMetadata(JSON.parse(metadata) as unknown, asset)) return null;
    const digest = createHash("sha256");
    for await (const chunk of createReadStream(binaryPath)) digest.update(chunk);
    if (digest.digest("hex") !== asset.sha256) return null;
    if (!isExecutable(binaryPath)) await chmod(binaryPath, 0o700);
    return isExecutable(binaryPath) ? binaryPath : null;
  } catch {
    return null;
  }
}

async function downloadBundledBinary(
  binaryPath: string,
  asset: BundledAsset,
  signal: AbortSignal | undefined,
  fetchImpl: FetchLike,
): Promise<string> {
  const metadataPath = bundledMetadataPath(binaryPath);
  const temporaryPath = `${binaryPath}.${randomUUID()}.download`;
  await mkdir(dirname(binaryPath), { recursive: true });

  const downloadController = new AbortController();
  let timedOut = false;
  const forwardAbort = () => downloadController.abort();
  if (signal?.aborted) {
    downloadController.abort();
  } else {
    signal?.addEventListener("abort", forwardAbort, { once: true });
  }
  const timeout = setTimeout(() => {
    timedOut = true;
    downloadController.abort();
  }, BUNDLED_DOWNLOAD_TIMEOUT_MS);
  timeout.unref?.();

  try {
    const response = await fetchImpl(
      `${BUNDLED_RELEASE_BASE_URL}/${asset.name}`,
      { signal: downloadController.signal },
    );
    if (!response.ok) {
      throw new Error(
        `Bundled Plannotator download failed with HTTP ${response.status}.`,
      );
    }
    if (!response.body) throw new Error("Bundled Plannotator download returned no body.");

    const digest = createHash("sha256");
    let sizeBytes = 0;
    const hashingTransform = new Transform({
      transform(chunk, _encoding, callback) {
        digest.update(chunk);
        sizeBytes += chunk.byteLength;
        callback(null, chunk);
      },
    });

    await pipeline(
      Readable.fromWeb(response.body as never),
      hashingTransform,
      createWriteStream(temporaryPath, { mode: 0o700 }),
    );

    const sha256 = digest.digest("hex");
    if (sizeBytes !== asset.sizeBytes || sha256 !== asset.sha256) {
      throw new Error(
        `Bundled Plannotator checksum mismatch (expected ${asset.sha256}, got ${sha256}).`,
      );
    }

    await chmod(temporaryPath, 0o700);
    // fs.rename replaces the destination on POSIX but fails when the
    // destination exists on Windows. The cache is disposable, so remove an
    // invalid/stale copy before the atomic replacement.
    await rm(binaryPath, { force: true });
    await rename(temporaryPath, binaryPath);
    await writeFile(
      metadataPath,
      JSON.stringify({
        version: BUNDLED_RELEASE_VERSION,
        name: asset.name,
        sha256: asset.sha256,
        sizeBytes: asset.sizeBytes,
      }),
      { encoding: "utf8", mode: 0o600 },
    );
    return binaryPath;
  } catch (error) {
    if (timedOut) {
      throw new Error(
        `Bundled Plannotator download timed out after ${BUNDLED_DOWNLOAD_TIMEOUT_MS / 1000} seconds.`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", forwardAbort);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
  }
}

async function provisionBundledBinary(
  runtimeDir: string,
  asset: BundledAsset,
  signal: AbortSignal | undefined,
  fetchImpl: FetchLike,
): Promise<string> {
  const binaryPath = bundledBinaryPath(runtimeDir, asset);
  const cached = await findCachedBundledBinary(binaryPath, asset);
  if (cached) return cached;

  return downloadBundledBinary(binaryPath, asset, signal, fetchImpl);
}

/**
 * Provision the pinned official release into BB's writable plugin data area.
 * The repository does not carry six 120–154 MB Bun executables; the first
 * review downloads exactly the host target and verifies its release digest.
 */
export async function ensureBundledPlannotatorBinary(options: {
  runtimeDir: string;
  platform?: NodeJS.Platform;
  arch?: string;
  asset?: BundledAsset;
  signal?: AbortSignal;
  fetchImpl?: FetchLike;
}): Promise<string> {
  const asset = options.asset ?? bundledAssetFor(options.platform, options.arch);
  if (!asset) {
    throw new Error(
      `Bundled Plannotator does not support ${options.platform ?? process.platform}/${options.arch ?? process.arch}. Set PLANNOTATOR_BIN to a compatible executable.`,
    );
  }

  const runtimeDir = resolve(options.runtimeDir);
  const key = `${runtimeDir}:${asset.name}`;
  const existing = bundledDownloadLocks.get(key);
  if (existing) return existing;

  const pending = provisionBundledBinary(
    runtimeDir,
    asset,
    options.signal,
    options.fetchImpl ?? fetch,
  ).finally(() => {
    bundledDownloadLocks.delete(key);
  });
  bundledDownloadLocks.set(key, pending);
  return pending;
}

/**
 * Resolve the standalone binary without invoking a shell. The official
 * installer puts it in ~/.local/bin, while a package manager may put it on
 * PATH. An explicit setting or PLANNOTATOR_BIN wins.
 */
export function resolvePlannotatorBinary(
  configuredPath = DEFAULT_BINARY,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const configured = (env.PLANNOTATOR_BIN?.trim() || configuredPath.trim() || DEFAULT_BINARY);
  const candidates: string[] = [];

  if (isAbsolute(configured)) {
    candidates.push(configured);
  } else if (configured.includes("/")) {
    candidates.push(resolve(configured));
  } else {
    for (const directory of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
      candidates.push(join(directory, configured));
    }
    candidates.push(join(homedir(), ".local", "bin", configured));
  }

  return candidates.find(isExecutable) ?? null;
}

function parseJsonLines(value: string): unknown[] {
  const parsed: unknown[] = [];
  for (const line of value.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)) {
    try {
      parsed.push(JSON.parse(line) as unknown);
    } catch {
      // Upstream writes diagnostics to stderr. Ignore non-JSON stdout lines so
      // a future informational line does not hide the final decision record.
    }
  }
  return parsed;
}

function isHttpUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function parseReadyMetadata(value: string): UpstreamReadyMetadata | null {
  const records = parseJsonLines(value).reverse();
  for (const record of records) {
    if (typeof record !== "object" || record === null || Array.isArray(record)) continue;
    const candidate = record as Record<string, unknown>;
    if (!isHttpUrl(candidate.url)) continue;
    if (typeof candidate.port !== "number" || !Number.isInteger(candidate.port)) continue;
    if (candidate.port < 1 || candidate.port > 65_535) continue;
    return {
      url: candidate.url,
      port: candidate.port,
      isRemote: candidate.isRemote === true,
    };
  }
  return null;
}

export function parseUpstreamDecision(stdout: string, stderr = ""): UpstreamDecision {
  const records = parseJsonLines(stdout).reverse();
  for (const record of records) {
    if (typeof record !== "object" || record === null || Array.isArray(record)) continue;
    const candidate = record as Record<string, unknown>;
    if (typeof candidate.approved !== "boolean") continue;
    const decision: UpstreamDecision = { approved: candidate.approved };
    if (typeof candidate.feedback === "string" && candidate.feedback.trim()) {
      decision.feedback = candidate.feedback;
    }
    if (typeof candidate.savedPath === "string" && candidate.savedPath.trim()) {
      decision.savedPath = candidate.savedPath;
    }
    if (typeof candidate.agentSwitch === "string" && candidate.agentSwitch.trim()) {
      decision.agentSwitch = candidate.agentSwitch;
    }
    return decision;
  }

  // The official generic hook entrypoint returns the host's native hook
  // envelope rather than the OpenCode bridge's `{ approved }` record. BB uses
  // this entrypoint so PLANNOTATOR_ORIGIN remains authoritative instead of
  // inheriting the OpenCode-only label from `opencode-plan`.
  for (const record of records) {
    if (typeof record !== "object" || record === null || Array.isArray(record)) continue;
    const hookOutput = (record as Record<string, unknown>).hookSpecificOutput;
    if (typeof hookOutput !== "object" || hookOutput === null || Array.isArray(hookOutput)) continue;
    const decision = (hookOutput as Record<string, unknown>).decision;
    if (typeof decision !== "object" || decision === null || Array.isArray(decision)) continue;
    const behavior = (decision as Record<string, unknown>).behavior;
    if (behavior === "allow") return { approved: true };
    if (behavior === "deny") {
      const message = (decision as Record<string, unknown>).message;
      return {
        approved: false,
        ...(typeof message === "string" && message.trim() ? { feedback: message } : {}),
      };
    }
  }

  const diagnostic = stderr.trim().split(/\r?\n/u).filter(Boolean).slice(-4).join(" ");
  throw new Error(
    diagnostic
      ? `Plannotator exited without a decision: ${diagnostic}`
      : "Plannotator exited without a decision",
  );
}

export type UpstreamRequest = {
  args: string[];
  stdin: string;
  /** Extra environment for the child, such as the directory to diff. */
  env?: Record<string, string>;
};

export function planReviewRequest(planMarkdown: string): UpstreamRequest {
  // Feed the official generic plan-review hook. Unlike the OpenCode-specific
  // bridge, this path uses PLANNOTATOR_ORIGIN when constructing /api/plan.
  return {
    args: [],
    stdin: JSON.stringify({
      hook_event_name: "PermissionRequest",
      permission_mode: "default",
      tool_input: { plan: planMarkdown },
    }),
  };
}

/**
 * Upstream's structured code-review entry. Unlike `plannotator review`, it
 * prints one JSON decision record (`{ decision, approved, feedback? }`) that
 * parseUpstreamDecision reads, and reviews a PR from the platform diff alone
 * instead of checking it out into a background git worktree.
 */
export function codeReviewRequest(cwd: string, prUrl?: string): UpstreamRequest {
  return {
    args: ["opencode-review"],
    stdin: JSON.stringify({ arguments: prUrl ?? "" }),
    env: { PLANNOTATOR_CWD: cwd },
  };
}

export function rehostUpstreamUrl(url: string, host: string | undefined): string {
  if (!host) return url;
  const parsed = new URL(url);
  parsed.hostname = host;
  return parsed.toString().replace(/\/$/u, "");
}

function wait(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function readReadyFile(path: string): Promise<UpstreamReadyMetadata | null> {
  try {
    return parseReadyMetadata(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

function childExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

async function terminateChild(
  child: ChildProcess,
  exited: Promise<void>,
): Promise<void> {
  if (!childExited(child)) {
    child.kill("SIGTERM");
    await Promise.race([exited, wait(750)]);
  }
  if (!childExited(child)) child.kill("SIGKILL");
  await exited.catch(() => undefined);
}

async function waitForReady(
  readyFile: string,
  child: ChildProcess,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<UpstreamReadyMetadata> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (signal.aborted) throw new Error("Plannotator review was cancelled");
    const metadata = await readReadyFile(readyFile);
    if (metadata) return metadata;
    if (childExited(child)) throw new Error("Plannotator exited before its review UI was ready");
    await wait(25);
  }
  throw new Error(`Plannotator did not start its review UI within ${timeoutMs}ms`);
}

/** Start an upstream review process and expose its real browser session. */
export async function startUpstreamReview(
  options: BridgeOptions,
): Promise<RunningUpstreamReview> {
  if (options.signal.aborted) throw new Error("Plannotator review was cancelled");

  const tempDir = await mkdtemp(join(tmpdir(), "bb-plannotator-"));
  const readyFile = join(tempDir, "ready.jsonl");
  let stdout = "";
  let stderr = "";
  let spawnError: Error | null = null;
  let resolveExit!: () => void;
  const exited = new Promise<void>((resolvePromise) => {
    resolveExit = resolvePromise;
  });

  let child: ChildProcess;
  try {
    child = spawn(options.binaryPath, options.request.args, {
      cwd: options.cwd ?? process.cwd(),
      env: {
        ...process.env,
        ...options.request.env,
        PLANNOTATOR_REMOTE: options.remote ? "1" : "0",
        PLANNOTATOR_SKIP_BROWSER_OPEN: "1",
        PLANNOTATOR_READY_FILE: readyFile,
        ...(options.remote ? { PLANNOTATOR_PORT: REMOTE_PORT_RANGE } : {}),
        ...(options.origin ? { PLANNOTATOR_ORIGIN: options.origin } : {}),
        ...(options.dataDir ? { PLANNOTATOR_DATA_DIR: options.dataDir } : {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (error) {
    await rm(tempDir, { recursive: true, force: true });
    throw error;
  }

  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    stdout = `${stdout}${chunk}`.slice(-256 * 1024);
  });
  child.stderr?.on("data", (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-256 * 1024);
  });
  child.once("error", (error) => {
    spawnError = error instanceof Error ? error : new Error(String(error));
    resolveExit();
  });
  child.once("exit", () => resolveExit());
  child.stdin?.once("error", (error) => {
    spawnError ??= error instanceof Error ? error : new Error(String(error));
  });

  const onAbort = () => {
    if (!childExited(child)) child.kill("SIGTERM");
  };
  options.signal.addEventListener("abort", onAbort, { once: true });

  try {
    child.stdin?.end(options.request.stdin);
    const ready = await waitForReady(
      readyFile,
      child,
      options.readyTimeoutMs ?? READY_TIMEOUT_MS,
      options.signal,
    );

    const decision = exited.then(() => {
      if (spawnError) throw spawnError;
      if (child.exitCode !== 0) {
        throw new Error(
          `Plannotator exited with code ${child.exitCode ?? "unknown"}${stderr.trim() ? `: ${stderr.trim()}` : ""}`,
        );
      }
      return parseUpstreamDecision(stdout, stderr);
    });

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    const timeoutMs =
      options.timeoutSeconds !== null &&
      Number.isFinite(options.timeoutSeconds) &&
      options.timeoutSeconds > 0
        ? options.timeoutSeconds * 1000
        : null;
    const result =
      timeoutMs === null
        ? decision
        : new Promise<UpstreamDecision>((resolveResult, rejectResult) => {
            timeoutHandle = setTimeout(() => {
              timedOut = true;
              void terminateChild(child, exited).then(
                () =>
                  resolveResult({
                    approved: false,
                    feedback: `[Plannotator] No response within ${options.timeoutSeconds} seconds. Port released automatically. Please start the review again.`,
                  }),
                rejectResult,
              );
            }, timeoutMs);
            void decision.then(
              (value) => {
                if (!timedOut) resolveResult(value);
              },
              (error) => {
                if (!timedOut) rejectResult(error);
              },
            );
          }).finally(() => {
            if (timeoutHandle) clearTimeout(timeoutHandle);
          });

    return {
      url: rehostUpstreamUrl(ready.url, options.embedHost),
      result,
      async stop() {
        options.signal.removeEventListener("abort", onAbort);
        await terminateChild(child, exited);
        await rm(tempDir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    options.signal.removeEventListener("abort", onAbort);
    await terminateChild(child, exited);
    await rm(tempDir, { recursive: true, force: true });
    throw error;
  }
}

export function missingBinaryMessage(configuredPath: string): string {
  if (configuredPath === BUNDLED_BINARY) {
    return [
      `The bundled Plannotator runtime could not be prepared for ${process.platform}/${process.arch}.`,
      "The plugin downloads the official release on first use and verifies its SHA-256 checksum.",
      `Set PLANNOTATOR_BIN to a compatible executable or see ${UPSTREAM_REPOSITORY} for supported targets.`,
    ].join(" ");
  }
  return [
    `Could not find the Plannotator binary (${configuredPath || DEFAULT_BINARY}).`,
    `Use the bundled runtime by setting the binary option to \"${BUNDLED_BINARY}\", or set PLANNOTATOR_BIN to a compatible executable.`,
  ].join(" ");
}
