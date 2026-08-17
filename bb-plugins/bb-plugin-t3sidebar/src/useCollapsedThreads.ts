import { useCallback, useState } from "react";

/**
 * Which parents are collapsed, remembered per browser.
 *
 * bb keeps its own sidebar's collapse state in localStorage under
 * `bb.sidebar.collapsedThreads`, so this matches: collapsing is a per-screen
 * preference, not something to sync to every client through the plugin's
 * database the way settled and snoozed are.
 *
 * Every access is guarded. localStorage throws outright in some privacy modes,
 * and a sidebar that cannot render because it could not read a preference
 * would be a poor trade.
 */
const STORAGE_KEY = "t3sidebar.collapsed-threads";

function readStored(): Set<string> {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === null) return new Set();
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((id): id is string => typeof id === "string"));
  } catch {
    return new Set();
  }
}

function writeStored(ids: ReadonlySet<string>): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify([...ids]));
  } catch {
    // A preference that cannot be saved is still worth honouring this session.
  }
}

export interface CollapsedThreads {
  collapsed: ReadonlySet<string>;
  toggle: (threadId: string) => void;
}

export function useCollapsedThreads(): CollapsedThreads {
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(readStored);

  const toggle = useCallback((threadId: string) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(threadId)) next.delete(threadId);
      else next.add(threadId);
      writeStored(next);
      return next;
    });
  }, []);

  return { collapsed, toggle };
}
