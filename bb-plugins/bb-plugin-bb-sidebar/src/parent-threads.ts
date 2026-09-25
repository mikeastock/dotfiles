interface ParentThread {
  id: string;
  parentThreadId: string | null;
  isArchived: boolean;
}

/** Exclude the entire descendant tree, even when its rows are collapsed. */
export function parentCandidates<T extends ParentThread>(
  threads: readonly T[],
  thread: ParentThread,
): T[] {
  const children = new Map<string, string[]>();
  for (const candidate of threads) {
    if (candidate.parentThreadId === null) continue;
    const siblings = children.get(candidate.parentThreadId) ?? [];
    siblings.push(candidate.id);
    children.set(candidate.parentThreadId, siblings);
  }
  const excluded = new Set<string>();
  const pending = [thread.id];
  while (pending.length > 0) {
    const id = pending.pop()!;
    if (excluded.has(id)) continue;
    excluded.add(id);
    pending.push(...(children.get(id) ?? []));
  }
  return threads.filter((candidate) =>
    (!candidate.isArchived || candidate.id === thread.parentThreadId) &&
    !excluded.has(candidate.id),
  );
}
