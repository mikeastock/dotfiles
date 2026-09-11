import { useCallback, useEffect, useRef, useState } from "react";
import {
  useRealtime,
  useRealtimeConnectionState,
  useRpc,
} from "@get-bb/plugin-sdk/app";
import type { bbSidebarRpcContract } from "./server";
import { BOTS_CHANNEL, type BotsSnapshot } from "./bots";

/**
 * How often to re-ask while nothing else prompts a read.
 *
 * The bots plugin publishes its changes on ITS realtime channel, which this
 * plugin cannot hear: a plugin's `useRealtime` only receives its own
 * signals. So the sources of freshness are this plugin's own `bots` signal
 * (published after a thread is created, once the bots plugin has had a
 * moment to bind it, and after every write this sidebar makes), a change in
 * the thread list itself, a reconnect, and this slow tick for everything
 * else — a bot renamed or hidden over there.
 */
const REFRESH_INTERVAL_MS = 60_000;

export interface BotsState {
  /** The bots snapshot, or null before the first answer. */
  snapshot: BotsSnapshot | null;
  /** Re-read now; resolves once the newest answer has landed. */
  refresh: () => Promise<void>;
}

/**
 * `threadIdsKey` is the thread list reduced to its ids: a new id means a new
 * thread the bots plugin may have just bound, so the list re-reads. Nothing
 * is read while `enabled` is false — the user turned the shelf off, and an
 * off switch that still costs a request would not be off.
 */
export function useBots(threadIdsKey: string, enabled: boolean): BotsState {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const [snapshot, setSnapshot] = useState<BotsSnapshot | null>(null);

  // Only the newest request may write, the same rule the lifecycle read
  // follows: an older answer landing late would resurrect a stale list.
  const requestSeq = useRef(0);
  const refresh = useCallback(async () => {
    if (!enabled) return;
    const seq = ++requestSeq.current;
    try {
      const result = await rpc.call("listBots", {});
      if (seq !== requestSeq.current) return;
      setSnapshot(result);
    } catch (error) {
      if (seq !== requestSeq.current) return;
      // A failed read is "no bots", never a broken sidebar: the list stays
      // exactly what it was before this shelf existed.
      setSnapshot({
        available: false,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }, [enabled, rpc]);

  useEffect(() => {
    void refresh();
  }, [refresh, threadIdsKey]);

  useRealtime(BOTS_CHANNEL, () => {
    void refresh();
  });

  // Signals are not replayed across a reconnect, so a fresh connection
  // re-reads to pick up anything published while the socket was down.
  const connection = useRealtimeConnectionState();
  const previousConnection = useRef(connection);
  useEffect(() => {
    if (
      connection === "connected" &&
      previousConnection.current !== "connected"
    ) {
      void refresh();
    }
    previousConnection.current = connection;
  }, [connection, refresh]);

  useEffect(() => {
    if (!enabled) return;
    const timer = setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [enabled, refresh]);

  return { snapshot, refresh };
}
