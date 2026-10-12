import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";

/**
 * Muse's durable session log is the only local record of what a subscription
 * has spent: Meta ships no usage endpoint, and the CLI keeps its account token
 * in the OS keychain. Every model completion writes one `model_completed`
 * record carrying verbatim provider counters, so a rolling window over those
 * records is a measurement rather than an estimate.
 */

export interface MuseUsageSample {
  atMs: number;
  model: string | null;
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  reasoningTokens: number;
}

export interface MuseRateLimitEvent {
  atMs: number;
  resetsAtMs: number | null;
}

export interface MuseUsageScan {
  samples: MuseUsageSample[];
  windowTokens: number;
  windowStartMs: number;
  oldestSampleMs: number | null;
  latestSampleMs: number | null;
  scannedFiles: number;
  truncated: boolean;
  /** The most recent provider rate-limit refusal inside the window, if any. */
  rateLimit: MuseRateLimitEvent | null;
}

export interface ScanMuseUsageArgs {
  sessionsDir: string;
  nowMs: number;
  windowMs: number;
  maxFiles?: number;
}

const DEFAULT_MAX_FILES = 400;
const DAY_MS = 24 * 60 * 60 * 1_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/**
 * Muse records `recorded_at` in microseconds since the epoch. Older records and
 * hand-authored fixtures use milliseconds, so the magnitude decides rather than
 * a schema version that the log does not carry.
 */
export function recordedAtToMs(recordedAt: unknown): number | null {
  if (typeof recordedAt !== "number" || !Number.isFinite(recordedAt)) {
    return null;
  }
  if (recordedAt > 1e14) {
    return Math.round(recordedAt / 1_000);
  }
  if (recordedAt > 1e11) {
    return Math.round(recordedAt);
  }
  return Math.round(recordedAt * 1_000);
}

export function usageSampleFromRecord(line: string): MuseUsageSample | null {
  if (!line.includes("model_completed")) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) {
    return null;
  }
  const payload = parsed.payload;
  if (!isRecord(payload)) {
    return null;
  }
  const event = payload.event;
  if (!isRecord(event) || event.kind !== "model_completed") {
    return null;
  }
  const usage = event.usage;
  if (!isRecord(usage)) {
    return null;
  }
  const atMs = recordedAtToMs(parsed.recorded_at);
  if (atMs === null) {
    return null;
  }
  return {
    atMs,
    model: typeof event.model === "string" ? event.model : null,
    inputTokens: readNumber(usage.input_tokens),
    outputTokens: readNumber(usage.output_tokens),
    cachedTokens: readNumber(usage.cached_tokens),
    reasoningTokens: readNumber(usage.reasoning_tokens),
  };
}

/**
 * When Muse's provider refuses a call for quota, the durable record carries the
 * provider's own `resets_at`. That beats any local estimate: it is the plan's
 * own answer to "when does this open again".
 */
export function rateLimitFromRecord(line: string): MuseRateLimitEvent | null {
  if (!line.includes("resets_at") && !line.includes("rate_limit")) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) {
    return null;
  }
  const atMs = recordedAtToMs(parsed.recorded_at);
  if (atMs === null) {
    return null;
  }
  const found = findRateLimit(parsed.payload);
  return found === undefined ? null : { atMs, resetsAtMs: found };
}

function findRateLimit(value: unknown, depth = 0): number | null | undefined {
  if (depth > 8 || !isRecord(value)) {
    return undefined;
  }
  const kind = value.error_kind ?? value.kind ?? value.code;
  const limited =
    typeof kind === "string" &&
    (kind === "rate_limited" || kind === "RateLimit" || kind === "quota");
  if (limited || "resets_at" in value) {
    const resets = value.resets_at;
    if (typeof resets === "number" && Number.isFinite(resets)) {
      return recordedAtToMs(resets);
    }
    if (typeof resets === "string") {
      const parsed = Date.parse(resets);
      return Number.isNaN(parsed) ? null : parsed;
    }
    if (limited) {
      return null;
    }
  }
  for (const nested of Object.values(value)) {
    const found = findRateLimit(nested, depth + 1);
    if (found !== undefined) {
      return found;
    }
  }
  return undefined;
}

export function sampleTotalTokens(sample: MuseUsageSample): number {
  return sample.inputTokens + sample.outputTokens;
}

/**
 * Muse buckets sessions by date, and nothing in the log says whether that date
 * is local or UTC, so a scan covers both readings of every day it spans.
 */
export function sessionDayPaths(fromMs: number, toMs: number): string[] {
  const days = new Set<string>();
  for (let at = fromMs - DAY_MS; at <= toMs + DAY_MS; at += DAY_MS) {
    const day = new Date(at);
    days.add(
      join(
        String(day.getUTCFullYear()),
        String(day.getUTCMonth() + 1).padStart(2, "0"),
        String(day.getUTCDate()).padStart(2, "0"),
      ),
    );
    days.add(
      join(
        String(day.getFullYear()),
        String(day.getMonth() + 1).padStart(2, "0"),
        String(day.getDate()).padStart(2, "0"),
      ),
    );
  }
  return [...days];
}

async function listSessionLogs(
  sessionsDir: string,
  sinceMs: number,
  untilMs: number,
): Promise<string[]> {
  const logs: string[] = [];
  const days = sessionDayPaths(sinceMs, untilMs);

  for (const day of days) {
    const dayDir = join(sessionsDir, day);
    let sessionDirs: string[];
    try {
      sessionDirs = await readdir(dayDir);
    } catch {
      continue;
    }
    for (const sessionDir of sessionDirs) {
      logs.push(join(dayDir, sessionDir, "session.jsonl"));
    }
  }
  return logs;
}

export async function scanMuseUsage(
  args: ScanMuseUsageArgs,
): Promise<MuseUsageScan> {
  const windowStartMs = args.nowMs - args.windowMs;
  const maxFiles = args.maxFiles ?? DEFAULT_MAX_FILES;
  const candidates = await listSessionLogs(
    args.sessionsDir,
    windowStartMs,
    args.nowMs,
  );

  const fresh: string[] = [];
  for (const candidate of candidates) {
    try {
      const stats = await stat(candidate);
      if (stats.mtimeMs >= windowStartMs) {
        fresh.push(candidate);
      }
    } catch {
      continue;
    }
  }
  fresh.sort();
  const truncated = fresh.length > maxFiles;
  const files = truncated ? fresh.slice(-maxFiles) : fresh;

  const samples: MuseUsageSample[] = [];
  let rateLimit: MuseRateLimitEvent | null = null;
  for (const file of files) {
    const reader = createInterface({
      input: createReadStream(file, { encoding: "utf8" }),
      crlfDelay: Number.POSITIVE_INFINITY,
    });
    try {
      for await (const line of reader) {
        const sample = usageSampleFromRecord(line);
        if (sample !== null && sample.atMs >= windowStartMs) {
          samples.push(sample);
          continue;
        }
        const limited = rateLimitFromRecord(line);
        if (
          limited !== null &&
          limited.atMs >= windowStartMs &&
          (rateLimit === null || limited.atMs > rateLimit.atMs)
        ) {
          rateLimit = limited;
        }
      }
    } catch {
      continue;
    } finally {
      reader.close();
    }
  }

  samples.sort((left, right) => left.atMs - right.atMs);
  const windowTokens = samples.reduce(
    (total, sample) => total + sampleTotalTokens(sample),
    0,
  );

  return {
    samples,
    windowTokens,
    windowStartMs,
    oldestSampleMs: samples[0]?.atMs ?? null,
    latestSampleMs: samples[samples.length - 1]?.atMs ?? null,
    scannedFiles: files.length,
    truncated,
    rateLimit,
  };
}

/**
 * A rolling window frees capacity as its oldest tokens age out, so the honest
 * reset instant is when the earliest counted completion leaves the window.
 */
export function rollingWindowResetsAt(
  scan: MuseUsageScan,
  windowMs: number,
): string | null {
  if (scan.oldestSampleMs === null) {
    return null;
  }
  return new Date(scan.oldestSampleMs + windowMs).toISOString();
}
