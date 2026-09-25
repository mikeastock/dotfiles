import { useSyncExternalStore } from "react";

// Keep progress outside individual rows so it survives shelf/search changes
// and is shared by every visible copy of a thread in this window.
const pending = new Set<string>();
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function beginTitleGeneration(threadId: string): boolean {
  if (pending.has(threadId)) return false;
  pending.add(threadId);
  for (const listener of listeners) listener();
  return true;
}

export function finishTitleGeneration(threadId: string) {
  pending.delete(threadId);
  for (const listener of listeners) listener();
}

export function useTitleGenerating(threadId: string) {
  return useSyncExternalStore(
    subscribe,
    () => pending.has(threadId),
    () => false,
  );
}
