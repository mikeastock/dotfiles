// bb-plugin-tok-speed — backend entry.
//
// Answers the app content script's `turnRates` RPC: for the requested threads,
// compute each turn's pooled provider-output speed. The app paints the result
// in each assistant message's hover menu.
//
// Two sources, chosen by the thread's provider:
//   - Pi threads read the Pi session file BB's Pi bridge writes, because BB's
//     event pruning removes the per-turn usage and stream timing Pi reports
//     (see src/pi-session.ts).
//   - Every other provider pages through the event log
//     (`bb.sdk.threads.events.list`); see src/rate.ts.
// The computations are pure and unit-tested; this file only does I/O.

import { readFile, stat } from "node:fs/promises";
import { defineRpcContract, type BbPluginApi } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { computeTurnRates, type EventRow } from "./src/rate";
import {
  computePiTurnRates,
  parsePiSessionSamples,
  piSessionFilePath,
  piTurnWindowsFromEvents,
  type PiResponseSample,
} from "./src/pi-session";

const MAX_THREAD_IDS = 8;
/** BB rejects `threads.events.list` pages larger than 100 events. */
const EVENTS_PAGE_LIMIT = 100;
const MAX_EVENTS_PER_THREAD = 20_000;
const MAX_EVENTS_PAGES = MAX_EVENTS_PER_THREAD / EVENTS_PAGE_LIMIT;
/** Re-fetch a thread's events at most this often. Events only grow at the tail
 *  while a turn is live, so once a turn's last response is closed its value is
 *  stable; the TTL bounds how quickly a *new* turn's figure appears. */
const EVENT_CACHE_TTL_MS = 10_000;

type EventTypes = NonNullable<
  Parameters<BbPluginApi["sdk"]["threads"]["events"]["list"]>[0]["types"]
>;

const EVENT_LOG_TYPES: EventTypes = [
  "client/turn/requested",
  "item/started",
  "item/agentMessage/delta",
  "item/completed",
  "thread/tokenUsage/updated",
];
const PI_TURN_TYPES: EventTypes = ["turn/started", "turn/completed"];

const measurementSchema = z.enum(["visible-stream", "pi-session"]);
export type Measurement = z.infer<typeof measurementSchema>;

export const rpcContract = defineRpcContract({
  turnRates: {
    input: z
      .object({
        threadIds: z.array(z.string().min(1)).min(1).max(MAX_THREAD_IDS),
      })
      .strict(),
    output: z.object({
      turns: z.array(
        z.object({
          threadId: z.string(),
          turnId: z.string(),
          rate: z.number().nullable(),
          totalOutputTokens: z.number(),
          responseCount: z.number(),
          measurement: measurementSchema,
        }),
      ),
    }),
  },
});

export interface ThreadRateResult {
  threadId: string;
  turnId: string;
  rate: number | null;
  totalOutputTokens: number;
  responseCount: number;
  measurement: Measurement;
}

interface CachedEvents {
  fetchedAt: number;
  events: readonly EventRow[];
}

interface CachedPiSession {
  mtimeMs: number;
  size: number;
  samples: readonly PiResponseSample[];
}

/**
 * Page through the thread's events of the given types, newest first (the SDK
 * pages backward from the newest sequence), then reverse into ascending order.
 */
async function fetchThreadEvents(
  bb: BbPluginApi,
  threadId: string,
  types: EventTypes,
): Promise<readonly EventRow[]> {
  const collected: EventRow[] = [];
  let beforeSeq: string | undefined;
  let pages = 0;
  for (;;) {
    const page = (await bb.sdk.threads.events.list({
      threadId,
      order: "desc",
      limit: String(EVENTS_PAGE_LIMIT),
      types,
      ...(beforeSeq ? { beforeSeq } : {}),
    })) as unknown as EventRow[];
    collected.push(...page);
    pages += 1;
    const oldest = page[page.length - 1];
    if (
      page.length < EVENTS_PAGE_LIMIT ||
      pages >= MAX_EVENTS_PAGES ||
      !oldest
    ) {
      break;
    }
    beforeSeq = String(oldest.seq);
  }
  return collected.reverse();
}

/** Convert one thread's event stream into the RPC's thread-qualified rows. */
export function computeThreadRates(
  threadId: string,
  events: readonly EventRow[],
): ThreadRateResult[] {
  // A turn is the scope carried by its tokenUsage events; asking the
  // computation for every turn that reports usage yields exactly the turns
  // that can produce a rate (no pre-filter needed).
  const turnIds = new Set<string>();
  for (const event of events) {
    if (
      event.type === "thread/tokenUsage/updated" &&
      event.scope?.kind === "turn" &&
      event.scope.turnId
    ) {
      turnIds.add(event.scope.turnId);
    }
  }
  if (turnIds.size === 0) return [];

  return Array.from(
    computeTurnRates({ turnIds, events }).values(),
    (turnRate) => ({
      threadId,
      ...turnRate,
      measurement: "visible-stream" as const,
    }),
  );
}

/**
 * Read and parse a Pi session file, reusing the parsed samples while the
 * file's mtime and size are unchanged. A missing file yields no samples.
 */
export function createPiSessionReader(): (
  path: string,
) => Promise<readonly PiResponseSample[]> {
  const cache = new Map<string, CachedPiSession>();
  return async (path) => {
    let info;
    try {
      info = await stat(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        cache.delete(path);
        return [];
      }
      throw error;
    }
    const cached = cache.get(path);
    if (cached && cached.mtimeMs === info.mtimeMs && cached.size === info.size) {
      return cached.samples;
    }
    const samples = parsePiSessionSamples(await readFile(path, "utf8"));
    cache.set(path, { mtimeMs: info.mtimeMs, size: info.size, samples });
    return samples;
  };
}

/** Pi turn rates for one thread, from its turn events and session files. */
export async function computePiThreadRates(args: {
  threadId: string;
  turnEvents: readonly EventRow[];
  readSamples: (path: string) => Promise<readonly PiResponseSample[]>;
  env: NodeJS.ProcessEnv;
  homeDir?: string;
}): Promise<ThreadRateResult[]> {
  const results: ThreadRateResult[] = [];
  const windowsBySession = piTurnWindowsFromEvents(args.turnEvents);
  for (const [providerThreadId, turns] of windowsBySession) {
    const path = piSessionFilePath({
      providerThreadId,
      env: args.env,
      homeDir: args.homeDir,
    });
    const samples = await args.readSamples(path);
    for (const turnRate of computePiTurnRates({ turns, samples })) {
      results.push({
        threadId: args.threadId,
        ...turnRate,
        measurement: "pi-session",
      });
    }
  }
  return results;
}

export default function plugin(bb: BbPluginApi): void {
  const eventCache = new Map<string, CachedEvents>();
  const providerIdByThreadId = new Map<string, string>();
  const readPiSamples = createPiSessionReader();

  async function providerIdFor(threadId: string): Promise<string> {
    const known = providerIdByThreadId.get(threadId);
    if (known) return known;
    const thread = await bb.sdk.threads.get({ threadId });
    providerIdByThreadId.set(threadId, thread.providerId);
    return thread.providerId;
  }

  async function loadEvents(
    threadId: string,
    types: EventTypes,
    now: number,
  ): Promise<readonly EventRow[]> {
    const key = `${threadId}\u0000${types.join(",")}`;
    const cached = eventCache.get(key);
    if (cached && now - cached.fetchedAt < EVENT_CACHE_TTL_MS) {
      return cached.events;
    }
    const events = await fetchThreadEvents(bb, threadId, types);
    eventCache.set(key, { fetchedAt: now, events });
    return events;
  }

  async function threadRates(
    threadId: string,
    now: number,
  ): Promise<ThreadRateResult[]> {
    if ((await providerIdFor(threadId)) === "pi") {
      return computePiThreadRates({
        threadId,
        turnEvents: await loadEvents(threadId, PI_TURN_TYPES, now),
        readSamples: readPiSamples,
        env: process.env,
      });
    }
    return computeThreadRates(
      threadId,
      await loadEvents(threadId, EVENT_LOG_TYPES, now),
    );
  }

  bb.rpc.register(rpcContract, {
    async turnRates({ threadIds }) {
      const now = Date.now();
      const turns: ThreadRateResult[] = [];

      for (const threadId of threadIds) {
        try {
          turns.push(...(await threadRates(threadId, now)));
        } catch (error) {
          const detail = error instanceof Error ? `: ${error.message}` : "";
          bb.log.warn(`turnRates: could not compute rates for ${threadId}${detail}`);
        }
      }

      return { turns };
    },
  });

  bb.onDispose(() => {
    eventCache.clear();
    providerIdByThreadId.clear();
  });
}
