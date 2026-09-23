// Output speed for Pi threads, read from the Pi session file BB writes.
//
// BB prunes its event log: it keeps only the newest `thread/tokenUsage/updated`
// snapshot per thread and drops streaming deltas once an item resolves. For Pi
// threads the event log therefore cannot yield per-turn throughput. The Pi
// bridge, however, runs `pi --session <file>` and Pi appends one JSONL entry
// per message, never pruned. Each assistant entry carries:
//
//   - `message.timestamp`: when the provider request started (ms epoch)
//   - the entry `timestamp`: when the message finished (ISO string)
//   - `message.usage.output`: output tokens for that response
//
// The rate is pooled per BB turn: summed output tokens over summed response
// time. Response time runs from request start, so it includes time to first
// token and thinking; output tokens include thinking tokens to match.

import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { EventRow, TurnRate } from "./rate";

/** One finished Pi assistant response. */
export interface PiResponseSample {
  startedAt: number;
  completedAt: number;
  outputTokens: number;
}

/** A BB turn's wall-clock bounds, from its `turn/started`/`turn/completed`. */
export interface PiTurnWindow {
  turnId: string;
  startedAt: number;
  /** Null while the turn is still running. */
  completedAt: number | null;
}

/** Mirrors the Pi provider's `resolvePiBridgeSessionDir`. */
export const PI_BRIDGE_SESSION_DIR_ENV = "BB_PI_BRIDGE_SESSION_DIR";

/**
 * Pi's first response in a turn starts a few milliseconds before BB records
 * `turn/started` (BB writes that event after Pi's `agent_start`). Accept
 * responses that start this much earlier than the recorded turn start.
 */
const TURN_START_SLACK_MS = 1_000;
const DEFAULT_MIN_RESPONSE_MS = 50;
const DEFAULT_MAX_RESPONSE_MS = 30 * 60 * 1000;
const SKIPPED_STOP_REASONS = new Set(["aborted", "error"]);

export function piSessionFilePath(args: {
  providerThreadId: string;
  env: NodeJS.ProcessEnv;
  homeDir?: string;
}): string {
  const configured = args.env[PI_BRIDGE_SESSION_DIR_ENV]?.trim();
  const dir = configured
    ? resolve(configured)
    : join(args.homeDir ?? homedir(), ".bb", "pi-bridge-sessions");
  const key = args.providerThreadId.replace(/[^A-Za-z0-9._-]/g, "_");
  return join(dir, `${key}.jsonl`);
}

/**
 * Extract finished assistant responses from a Pi session file. Lines that do
 * not parse are skipped: Pi appends to the file while a turn runs, so the last
 * line can be partial. Aborted and errored responses are skipped because their
 * usage does not describe a completed stream.
 */
export function parsePiSessionSamples(jsonl: string): PiResponseSample[] {
  const samples: PiResponseSample[] = [];
  for (const line of jsonl.split("\n")) {
    if (line.trim() === "") continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const sample = sampleFromEntry(entry);
    if (sample) samples.push(sample);
  }
  return samples;
}

function sampleFromEntry(entry: unknown): PiResponseSample | null {
  if (!isRecord(entry) || entry.type !== "message") return null;
  const message = entry.message;
  if (!isRecord(message) || message.role !== "assistant") return null;
  if (
    typeof message.stopReason === "string" &&
    SKIPPED_STOP_REASONS.has(message.stopReason)
  ) {
    return null;
  }

  const startedAt = message.timestamp;
  const completedAt =
    typeof entry.timestamp === "string" ? Date.parse(entry.timestamp) : NaN;
  const usage = message.usage;
  const outputTokens = isRecord(usage) ? usage.output : undefined;
  if (
    typeof startedAt !== "number" ||
    !Number.isFinite(startedAt) ||
    !Number.isFinite(completedAt) ||
    typeof outputTokens !== "number" ||
    !Number.isFinite(outputTokens) ||
    outputTokens < 0
  ) {
    return null;
  }
  return { startedAt, completedAt, outputTokens };
}

/**
 * Group BB turn windows by the Pi session that ran them. `turn/started`
 * carries the Pi `providerThreadId`, which names the session file.
 */
export function piTurnWindowsFromEvents(
  events: readonly EventRow[],
): Map<string, PiTurnWindow[]> {
  const byTurnId = new Map<string, PiTurnWindow>();
  const providerThreadIdByTurnId = new Map<string, string>();
  for (const event of events) {
    const turnId =
      event.scope?.kind === "turn" ? event.scope.turnId : undefined;
    if (!turnId) continue;
    if (event.type === "turn/started") {
      const providerThreadId = event.data?.providerThreadId;
      if (!providerThreadId) continue;
      byTurnId.set(turnId, {
        turnId,
        startedAt: event.createdAt,
        completedAt: byTurnId.get(turnId)?.completedAt ?? null,
      });
      providerThreadIdByTurnId.set(turnId, providerThreadId);
    } else if (event.type === "turn/completed") {
      const window = byTurnId.get(turnId);
      if (window) window.completedAt = event.createdAt;
    }
  }

  const result = new Map<string, PiTurnWindow[]>();
  for (const [turnId, window] of byTurnId) {
    const providerThreadId = providerThreadIdByTurnId.get(turnId)!;
    let windows = result.get(providerThreadId);
    if (!windows) {
      windows = [];
      result.set(providerThreadId, windows);
    }
    windows.push(window);
  }
  for (const windows of result.values()) {
    windows.sort((left, right) => left.startedAt - right.startedAt);
  }
  return result;
}

/**
 * Assign each response to the turn it started in, then pool per turn. A
 * response belongs to a turn when it starts after the previous turn finished,
 * no earlier than {@link TURN_START_SLACK_MS} before the turn's recorded start,
 * and not after the turn's end. Responses outside every window (for example,
 * history copied into a forked session) are ignored.
 */
export function computePiTurnRates(args: {
  turns: readonly PiTurnWindow[];
  samples: readonly PiResponseSample[];
  minResponseMs?: number;
  maxResponseMs?: number;
}): TurnRate[] {
  const minResponseMs = args.minResponseMs ?? DEFAULT_MIN_RESPONSE_MS;
  const maxResponseMs = args.maxResponseMs ?? DEFAULT_MAX_RESPONSE_MS;
  const turns = [...args.turns].sort(
    (left, right) => left.startedAt - right.startedAt,
  );

  const rates: TurnRate[] = [];
  for (const [index, turn] of turns.entries()) {
    const previousEnd = turns[index - 1]?.completedAt ?? -Infinity;
    const lowerBound = Math.max(
      previousEnd,
      turn.startedAt - TURN_START_SLACK_MS,
    );
    const upperBound = turn.completedAt ?? Infinity;

    let totalOutputTokens = 0;
    let totalDurationMs = 0;
    let responseCount = 0;
    for (const sample of args.samples) {
      if (sample.startedAt <= lowerBound || sample.startedAt > upperBound) {
        continue;
      }
      const durationMs = sample.completedAt - sample.startedAt;
      if (durationMs < minResponseMs || durationMs > maxResponseMs) continue;
      totalOutputTokens += sample.outputTokens;
      totalDurationMs += durationMs;
      responseCount += 1;
    }
    if (responseCount === 0 || totalOutputTokens === 0) continue;

    rates.push({
      turnId: turn.turnId,
      rate: totalOutputTokens / (totalDurationMs / 1000),
      totalOutputTokens,
      responseCount,
    });
  }
  return rates;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
