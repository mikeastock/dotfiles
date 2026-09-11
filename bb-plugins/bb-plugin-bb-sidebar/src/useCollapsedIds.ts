import { useCallback, useState } from "react";

/**
 * A remembered set of folded ids under one localStorage key, per browser —
 * the same choice the shelves and child lists make for their own expansion.
 *
 * Every access is guarded. localStorage throws outright in some privacy
 * modes, and a sidebar that cannot render because it could not read a
 * preference would be a poor trade.
 */
export const BOT_EXPANSION_STORAGE_KEY = "bb-sidebar:bot-expansion:v1";

function readStored(storageKey: string): Set<string> {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (raw === null) return new Set();
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((id): id is string => typeof id === "string"));
  } catch {
    return new Set();
  }
}

function writeStored(storageKey: string, ids: ReadonlySet<string>): void {
  try {
    window.localStorage.setItem(storageKey, JSON.stringify([...ids].sort()));
  } catch {
    // A preference that cannot be saved is still worth honouring this session.
  }
}

export interface CollapsedIds {
  collapsed: ReadonlySet<string>;
  toggle: (id: string) => void;
}

export function useCollapsedIds(storageKey: string): CollapsedIds {
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() =>
    readStored(storageKey),
  );

  const toggle = useCallback(
    (id: string) => {
      setCollapsed((current) => {
        const next = new Set(current);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        writeStored(storageKey, next);
        return next;
      });
    },
    [storageKey],
  );

  return { collapsed, toggle };
}
