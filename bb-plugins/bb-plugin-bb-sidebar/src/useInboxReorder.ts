import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type PluginSidebarThread,
  useRealtime,
  useRpc,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { orderInboxThreads } from "./pinned-order";
import { safeSetItem } from "./lib/safe-storage";

const ORDER_CACHE_KEY = "bb-sidebar:inbox-order-cache:v1";
const ordersByRpcClient = new WeakMap<object, readonly string[]>();

function cachedOrder(rpc: object): readonly string[] | null {
  const cached = ordersByRpcClient.get(rpc);
  if (cached) return cached;
  try {
    const value: unknown = JSON.parse(
      window.localStorage.getItem(ORDER_CACHE_KEY) ?? "null",
    );
    if (Array.isArray(value) && value.every((id) => typeof id === "string")) {
      return [...new Set(value)];
    }
  } catch {
    // A missing or unavailable cache falls back to creation order.
  }
  return null;
}

function cacheOrder(rpc: object, ids: readonly string[]): readonly string[] {
  const order = [...ids];
  ordersByRpcClient.set(rpc, order);
  safeSetItem(ORDER_CACHE_KEY, JSON.stringify(order));
  return order;
}

export interface InboxReorderApi {
  threads: PluginSidebarThread[];
  ids: string[];
  isReordering: boolean;
  reorder(nextIds: readonly string[]): Promise<boolean>;
}

function orderKey(ids: readonly string[]): string {
  return ids.join("\0");
}

/** Durable, optimistic inbox ordering backed by the plugin database. */
export function useInboxReorder(
  inboxThreads: readonly PluginSidebarThread[],
): InboxReorderApi {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const [storedIds, setStoredIds] = useState<readonly string[] | null>(
    () => cachedOrder(rpc),
  );
  const [optimisticIds, setOptimisticIds] = useState<
    readonly string[] | null
  >(null);
  const [isReordering, setIsReordering] = useState(false);
  const inFlight = useRef(false);
  const requestSeq = useRef(0);

  const refresh = useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const result = await rpc.call("listInboxOrder", {});
      if (seq === requestSeq.current) {
        setStoredIds(cacheOrder(rpc, result.inboxThreadIds));
      }
    } catch {
      // Keep the cached order if a backend reload briefly races this frontend.
    }
  }, [rpc]);

  useEffect(() => {
    void refresh();
    return () => {
      requestSeq.current += 1;
    };
  }, [refresh]);

  useRealtime("inbox-order", () => {
    void refresh();
  });

  const threads = useMemo(
    () => orderInboxThreads(inboxThreads, optimisticIds ?? storedIds),
    [inboxThreads, optimisticIds, storedIds],
  );
  const ids = threads.map((thread) => thread.id);

  const reorder = useCallback(
    async (nextIds: readonly string[]): Promise<boolean> => {
      if (inFlight.current || orderKey(nextIds) === orderKey(ids)) return false;
      inFlight.current = true;
      // Any list read that started before this write is stale by definition.
      requestSeq.current += 1;
      setIsReordering(true);
      setOptimisticIds([...nextIds]);

      try {
        const result = await rpc.call("reorderInbox", {
          inboxThreadIds: [...nextIds],
        });
        // Ignore refreshes that raced the write. The mutation response is the
        // authoritative order for this client.
        requestSeq.current += 1;
        setStoredIds(cacheOrder(rpc, result.inboxThreadIds));
        setOptimisticIds(null);
        return true;
      } catch (error) {
        requestSeq.current += 1;
        setOptimisticIds(null);
        void refresh();
        toast.error("Could not reorder inbox thread", {
          description: error instanceof Error ? error.message : undefined,
        });
        return false;
      } finally {
        inFlight.current = false;
        setIsReordering(false);
      }
    },
    [ids, refresh, rpc],
  );

  return { threads, ids, isReordering, reorder };
}
