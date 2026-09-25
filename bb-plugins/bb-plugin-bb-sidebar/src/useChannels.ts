import { useCallback, useEffect, useRef, useState } from "react";
import {
  useRealtime,
  useRealtimeConnectionState,
  useRpc,
} from "@get-bb/plugin-sdk/app";
import type { bbSidebarRpcContract } from "./server";
import { CHANNELS_CHANNEL, type ChannelsSnapshot } from "./channels";

/**
 * How often to re-read while nothing else prompts it.
 *
 * Bot Teams publishes its changes on ITS realtime channel, which this plugin
 * cannot hear: a plugin's `useRealtime` only receives its own signals. So
 * freshness comes from this plugin's `channels` signal (after every write the
 * sidebar makes), a change in thread activity (bots work in threads), a
 * reconnect, and this tick for everything else — a new message, a rename.
 */
export const CHANNELS_REFRESH_INTERVAL_MS = 10_000;

export interface ChannelsState {
  /** The channels snapshot, or null before the first answer. */
  snapshot: ChannelsSnapshot | null;
  refresh: () => Promise<void>;
}

/**
 * `activityKey` changes whenever any thread changes; bot work in a channel
 * runs in threads, so that is the earliest hint a channel moved.
 */
export function useChannels(activityKey: string): ChannelsState {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const [snapshot, setSnapshot] = useState<ChannelsSnapshot | null>(null);

  // Only the newest request may write: an older answer landing late would
  // resurrect a stale list.
  const requestSeq = useRef(0);
  const refresh = useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const result = await rpc.call("listChannels", {});
      if (seq === requestSeq.current) setSnapshot(result);
    } catch (error) {
      if (seq !== requestSeq.current) return;
      // A failed read means "no channels", never a broken sidebar.
      setSnapshot({
        available: false,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }, [rpc]);

  useEffect(() => {
    void refresh();
  }, [refresh, activityKey]);

  useRealtime(CHANNELS_CHANNEL, () => {
    void refresh();
  });

  // Signals are not replayed across a reconnect.
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
    const timer = setInterval(
      () => void refresh(),
      CHANNELS_REFRESH_INTERVAL_MS,
    );
    return () => clearInterval(timer);
  }, [refresh]);

  return { snapshot, refresh };
}

interface NavigationLike {
  addEventListener(type: "currententrychange", listener: () => void): void;
  removeEventListener(type: "currententrychange", listener: () => void): void;
}

/**
 * The browser pathname, kept current across bb's in-app navigation. bb routes
 * with the History API, which fires no event of its own; the Navigation API's
 * `currententrychange` covers it where available, and `popstate` covers
 * back/forward everywhere.
 */
export function usePathname(): string {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  useEffect(() => {
    const update = () => setPathname(window.location.pathname);
    const navigation = (window as { navigation?: NavigationLike }).navigation;
    navigation?.addEventListener("currententrychange", update);
    window.addEventListener("popstate", update);
    return () => {
      navigation?.removeEventListener("currententrychange", update);
      window.removeEventListener("popstate", update);
    };
  }, []);
  return pathname;
}
