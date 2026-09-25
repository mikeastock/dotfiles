import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { describeReclaim } from "./reclaim";
import { promptToCloseSettledPorts } from "./settled-port-prompt";
import {
  canPark,
  formatSnoozeWakeTime,
  isThreadWorking,
  nextWakeDelayMs,
  resolveShelf,
  resolveWakeReason,
  type ThreadLifecycleRow,
  type ThreadShelf,
} from "./lifecycle";
import {
  MAX_CACHED_LIFECYCLE_ROWS,
  pruneLifecycleRows,
  safeSetItem,
} from "./lib/safe-storage";

/** Any live work at all, which blocks parking and wakes a parked thread. */
export function isWorking(thread: PluginSidebarThread): boolean {
  return isThreadWorking(thread);
}

export interface LifecycleApi {
  shelfFor(thread: PluginSidebarThread): ThreadShelf;
  canPark(thread: PluginSidebarThread): boolean;
  wakeAtFor(thread: PluginSidebarThread): number | null;
  settledAtFor(thread: PluginSidebarThread): number | null;
  wokeFor(thread: PluginSidebarThread): boolean;
  acknowledgeWake(threadId: string): Promise<boolean>;
  parkedAtFor(thread: PluginSidebarThread): number | null;
  park(threadId: string): Promise<boolean>;
  resume(threadId: string): Promise<boolean>;
  settle(threadId: string): Promise<boolean>;
  unsettle(threadId: string): Promise<boolean>;
  snooze(threadId: string, snoozedUntil: number): Promise<boolean>;
  unsnooze(threadId: string): Promise<boolean>;
}

type LifecycleMutation =
  | "park"
  | "resume"
  | "settle"
  | "unsettle"
  | "snooze"
  | "unsnooze"
  | "acknowledgeWake";
type LifecycleMutationRequest =
  | { method: "snooze"; threadId: string; snoozedUntil: number }
  | {
      method: Exclude<LifecycleMutation, "snooze">;
      threadId: string;
    };

const lifecycleRowsByRpcClient = new WeakMap<
  object,
  ReadonlyMap<string, ThreadLifecycleRow>
>();
const LIFECYCLE_ROWS_CACHE_KEY = "bb-sidebar:lifecycle-cache:v1";

function isNullableNumber(value: unknown): value is number | null {
  return (
    value === null || (typeof value === "number" && Number.isFinite(value))
  );
}

function readStoredLifecycleRows(): ReadonlyMap<
  string,
  ThreadLifecycleRow
> | null {
  try {
    const stored = window.localStorage.getItem(LIFECYCLE_ROWS_CACHE_KEY);
    if (!stored) return null;
    const values = JSON.parse(stored) as unknown;
    if (!Array.isArray(values)) return null;
    const rows = new Map<string, ThreadLifecycleRow>();
    for (const value of values) {
      if (typeof value !== "object" || value === null) return null;
      const row = value as Partial<ThreadLifecycleRow>;
      if (
        typeof row.threadId !== "string" ||
        (row.parkedAt !== undefined && !isNullableNumber(row.parkedAt)) ||
        !isNullableNumber(row.settledAt) ||
        !isNullableNumber(row.snoozedUntil) ||
        !isNullableNumber(row.snoozedAt) ||
        (row.settledOverride !== undefined &&
          row.settledOverride !== null &&
          row.settledOverride !== "active" &&
          row.settledOverride !== "settled")
      ) {
        return null;
      }
      rows.set(row.threadId, row as ThreadLifecycleRow);
    }
    if (rows.size > MAX_CACHED_LIFECYCLE_ROWS) {
      const pruned = pruneLifecycleRows([...rows.values()]);
      return new Map(pruned.map((row) => [row.threadId, row] as const));
    }
    return rows;
  } catch {
    return null;
  }
}

function cacheLifecycleRows(
  rpcClient: object,
  rows: ReadonlyMap<string, ThreadLifecycleRow>,
): void {
  lifecycleRowsByRpcClient.set(rpcClient, rows);
  const pruned = pruneLifecycleRows([...rows.values()]);
  safeSetItem(LIFECYCLE_ROWS_CACHE_KEY, JSON.stringify(pruned));
}

const SUCCESS_MESSAGE: Record<
  Exclude<LifecycleMutation, "snooze" | "acknowledgeWake">,
  string
> = {
  park: "Thread parked",
  resume: "Thread returned to the inbox",
  settle: "Thread settled",
  unsettle: "Thread returned to the inbox",
  unsnooze: "Thread woke up",
};

/**
 * How long a parking toast that carries a reclaim reminder stays up.
 *
 * Sonner's four-second default is sized for a confirmation nobody needs to
 * read. "2 terminals left running" is the opposite: it is the one line worth
 * acting on, and it can sit behind a wake time and a session clause. Toasts
 * without a reminder keep the default, so a bare confirmation still gets out
 * of the way.
 */
const PARK_REMINDER_TOAST_MS = 10_000;

const ERROR_MESSAGE: Record<LifecycleMutation, string> = {
  park: "Could not park thread",
  resume: "Could not resume thread",
  settle: "Could not settle thread",
  unsettle: "Could not un-settle thread",
  snooze: "Could not snooze thread",
  unsnooze: "Could not wake thread",
  acknowledgeWake: "Could not dismiss Woke marker",
};

function errorDescription(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const message = error.message.trim();
  return message.length > 0 ? message : undefined;
}

/**
 * Reads the plugin's own lifecycle store and classifies threads onto shelves.
 *
 * `now` is state, not a render-time clock read: a snooze that elapses must
 * move its row without waiting for an unrelated re-render, and re-reading the
 * clock during render would make the classification unstable.
 */
export function useLifecycle(
  threads: readonly PluginSidebarThread[],
): LifecycleApi {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const [rows, setRows] = useState<ReadonlyMap<string, ThreadLifecycleRow>>(
    () =>
      lifecycleRowsByRpcClient.get(rpc) ??
      readStoredLifecycleRows() ??
      new Map(),
  );
  const [now, setNow] = useState(() => Date.now());

  // Responses can land out of order (a mutation's refresh racing a realtime
  // one), and an older list would silently restore state the user just
  // changed. Only the newest request may write.
  const requestSeq = useRef(0);
  const inFlightThreadIds = useRef(new Set<string>());
  const portPromptVersions = useRef(new Map<string, number>());
  const refresh = useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const result = await rpc.call("listLifecycle", {});
      if (seq !== requestSeq.current) return;
      const nextRows = new Map(
        result.rows.map((row) => [row.threadId, row] as const),
      );
      cacheLifecycleRows(rpc, nextRows);
      setRows(nextRows);
    } catch {
      void 0; // Keep the last known rows during a backend reload or transient RPC
      // failure. The next realtime signal or mount retries the refresh.
    }
  }, [rpc]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // One policy pass per mounted sidebar gives a freshly opened client current
  // state immediately. The backend coalesces concurrent clients and does the
  // thread and PR work in one batch.
  useEffect(() => {
    void rpc
      .call("evaluateAutoSettle", {})
      .then(({ changedThreadIds }) => {
        if (changedThreadIds.length > 0) void refresh();
      })
      .catch(() => {
        void 0; // A backend generation can briefly lag the app bundle during reload.
        // The scheduled evaluator and realtime refresh will reconcile later.
      });
  }, [refresh, rpc]);

  useRealtime("lifecycle", () => {
    void refresh();
  });

  // Arm one timer for the soonest wake instead of polling: the shelf empties
  // the moment a snooze expires, and nothing ticks while nothing is snoozed.
  useEffect(() => {
    // Read a fresh clock here rather than trusting `now`: `now` is only
    // updated when a timer fires, so arming from it after a long idle period
    // would schedule a new snooze far too late.
    const armedAt = Date.now();
    const delay = nextWakeDelayMs(
      [...rows.values()].flatMap((row) =>
        row.snoozedUntil === null ? [] : [row.snoozedUntil],
      ),
      armedAt,
    );
    if (delay === null) return;
    const timer = setTimeout(() => setNow(Date.now()), delay);
    return () => clearTimeout(timer);
  }, [now, rows]);

  return useMemo<LifecycleApi>(() => {
    const signalsFor = (thread: PluginSidebarThread) => ({
      hasPendingInteraction: thread.hasPendingInteraction,
      isWorking: isWorking(thread),
      isUnread: thread.isUnread,
      latestAttentionAt: thread.latestAttentionAt,
    });
    // One mutation per thread at a time. The write publishes on the realtime
    // channel, and that subscription refreshes every client after success.
    const mutate = async (
      request: LifecycleMutationRequest,
    ): Promise<boolean> => {
      const { method, threadId } = request;
      if (inFlightThreadIds.current.has(threadId)) return false;
      inFlightThreadIds.current.add(threadId);
      const portPromptVersion = (portPromptVersions.current.get(threadId) ?? 0) + 1;
      portPromptVersions.current.set(threadId, portPromptVersion);
      toast.dismiss(`settled-ports:${threadId}`);
      let parkReminder: string | undefined;
      // An unsnooze clears the row server-side, so its wake time has to be
      // captured before the RPC; Undo re-snoozes with this absolute time to
      // restore the exact schedule that was cancelled.
      const unsnoozeWakeAt =
        method === "unsnooze"
          ? (rows.get(threadId)?.snoozedUntil ?? null)
          : null;
      try {
        if (method === "snooze") {
          const { reclaim } = await rpc.call("snooze", {
            threadId,
            snoozedUntil: request.snoozedUntil,
          });
          parkReminder = describeReclaim(reclaim);
        } else if (method === "settle" || method === "park") {
          const { reclaim } = await rpc.call(method, { threadId });
          parkReminder = describeReclaim(reclaim);
        } else {
          await rpc.call(method, { threadId });
        }
      } catch (error) {
        toast.error(ERROR_MESSAGE[method], {
          description: errorDescription(error),
        });
        return false;
      } finally {
        inFlightThreadIds.current.delete(threadId);
      }

      if (method === "park" || method === "resume") {
        toast.success(SUCCESS_MESSAGE[method], {
          description: parkReminder,
          duration: parkReminder === undefined ? undefined : PARK_REMINDER_TOAST_MS,
          action: {
            label: "Undo",
            onClick: () => void mutate({
              method: method === "park" ? "resume" : "park",
              threadId,
            }),
          },
        });
      } else if (method === "snooze") {
        // The wake time is the headline; the reminder follows it, because a
        // snooze releases the same resources a settle does.
        const wakes = `Wakes ${formatSnoozeWakeTime(request.snoozedUntil)}`;
        toast.success("Thread snoozed", {
          description:
            parkReminder === undefined ? wakes : `${wakes} · ${parkReminder}`,
          duration:
            parkReminder === undefined ? undefined : PARK_REMINDER_TOAST_MS,
          action: {
            label: "Undo",
            onClick: () => void mutate({ method: "unsnooze", threadId }),
          },
        });
      } else if (method === "settle") {
        void promptToCloseSettledPorts(
          threadId,
          () => rpc.call("getThreadPorts", { threadId }),
          (ports) => rpc.call("closeThreadPorts", { threadId, ports }),
          () => portPromptVersions.current.get(threadId) === portPromptVersion,
        );
        // The reminder is the point of this toast: parking releases the agent
        // session but leaves any terminal the user typed in alone, and that is
        // only obvious if it is said out loud. Undo returns the thread to the
        // inbox; it does not re-pin, because settle never records the pin it
        // removed.
        toast.success(SUCCESS_MESSAGE.settle, {
          description: parkReminder,
          duration:
            parkReminder === undefined ? undefined : PARK_REMINDER_TOAST_MS,
          action: {
            label: "Undo",
            onClick: () => void mutate({ method: "unsettle", threadId }),
          },
        });
      } else if (method === "unsettle") {
        // Undo re-settles, which re-runs the reclaim a settle always does:
        // restoring the previous shelf means releasing what a wake restored.
        toast.success(SUCCESS_MESSAGE.unsettle, {
          action: {
            label: "Undo",
            onClick: () => void mutate({ method: "settle", threadId }),
          },
        });
      } else if (method === "unsnooze") {
        // Undo is only offered while the captured wake time is still ahead;
        // a row whose snooze already elapsed has no schedule left to restore.
        const undoWakeAt =
          unsnoozeWakeAt !== null && unsnoozeWakeAt > Date.now()
            ? unsnoozeWakeAt
            : null;
        toast.success(SUCCESS_MESSAGE.unsnooze, {
          action:
            undoWakeAt === null
              ? undefined
              : {
                  label: "Undo",
                  onClick: () =>
                    void mutate({
                      method: "snooze",
                      threadId,
                      snoozedUntil: undoWakeAt,
                    }),
                },
        });
      }
      return true;
    };
    return {
      shelfFor: (thread) => {
        const row = rows.get(thread.id);
        // Keep explicit shelf changes visible while the host's unpin update
        // propagates. The pin RPC clears these rows when pinning succeeds.
        if (
          thread.isPinned &&
          row?.settledOverride !== "settled" &&
          row?.snoozedUntil == null &&
          row?.parkedAt == null
        ) {
          return "active";
        }
        return resolveShelf(row, signalsFor(thread), now);
      },
      canPark: (thread) => canPark(signalsFor(thread)),
      wakeAtFor: (thread) => rows.get(thread.id)?.snoozedUntil ?? null,
      parkedAtFor: (thread) => rows.get(thread.id)?.parkedAt ?? null,
      park: (threadId) => mutate({ method: "park", threadId }),
      resume: (threadId) => mutate({ method: "resume", threadId }),
      settledAtFor: (thread) => rows.get(thread.id)?.settledAt ?? null,
      wokeFor: (thread) =>
        resolveWakeReason(rows.get(thread.id), signalsFor(thread), now) !== null,
      acknowledgeWake: (threadId) =>
        mutate({ method: "acknowledgeWake", threadId }),
      settle: (threadId) => mutate({ method: "settle", threadId }),
      unsettle: (threadId) => mutate({ method: "unsettle", threadId }),
      unsnooze: (threadId) => mutate({ method: "unsnooze", threadId }),
      snooze: (threadId, snoozedUntil) =>
        mutate({ method: "snooze", threadId, snoozedUntil }),
    };
  }, [now, rows, rpc]);
}
