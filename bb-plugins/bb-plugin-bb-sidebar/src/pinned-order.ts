export type DropPlacement = "before" | "after";

/** Move one pinned id relative to another without mutating the source order. */
export function movePinnedId(
  ids: readonly string[],
  movingId: string,
  targetId: string,
  placement: DropPlacement,
): string[] {
  if (
    movingId === targetId ||
    !ids.includes(movingId) ||
    !ids.includes(targetId)
  ) {
    return [...ids];
  }

  const withoutMoving = ids.filter((id) => id !== movingId);
  const targetIndex = withoutMoving.indexOf(targetId);
  const insertionIndex = placement === "after" ? targetIndex + 1 : targetIndex;
  return [
    ...withoutMoving.slice(0, insertionIndex),
    movingId,
    ...withoutMoving.slice(insertionIndex),
  ];
}

/** Move one id by a keyboard-sized step. */
export function movePinnedIdByOffset(
  ids: readonly string[],
  movingId: string,
  offset: -1 | 1,
): string[] {
  const currentIndex = ids.indexOf(movingId);
  const targetIndex = currentIndex + offset;
  if (currentIndex < 0 || targetIndex < 0 || targetIndex >= ids.length) {
    return [...ids];
  }
  return movePinnedId(
    ids,
    movingId,
    ids[targetIndex]!,
    offset < 0 ? "before" : "after",
  );
}

/** The neighboring ids expected by bb's threads.reorderPinned operation. */
export function pinnedNeighbors(
  ids: readonly string[],
  movingId: string,
): { previousThreadId: string | null; nextThreadId: string | null } {
  const index = ids.indexOf(movingId);
  if (index < 0) {
    return { previousThreadId: null, nextThreadId: null };
  }
  return {
    previousThreadId: ids[index - 1] ?? null,
    nextThreadId: ids[index + 1] ?? null,
  };
}

/** Apply an optimistic or server-confirmed id order to the visible rows. */
export function orderPinnedThreads<T extends { readonly id: string }>(
  threads: readonly T[],
  orderedIds: readonly string[] | null,
): T[] {
  if (orderedIds === null) return [...threads];
  const rank = new Map(orderedIds.map((id, index) => [id, index]));
  return [...threads].sort((left, right) => {
    const leftRank = rank.get(left.id);
    const rightRank = rank.get(right.id);
    if (leftRank === undefined && rightRank === undefined) return 0;
    if (leftRank === undefined) return 1;
    if (rightRank === undefined) return -1;
    return leftRank - rightRank;
  });
}

/**
 * Apply plugin-owned inbox order while keeping newly created rows at the top.
 * Rows absent from the durable order retain their incoming (newest-first)
 * order; known rows follow in the saved order.
 */
export function orderInboxThreads<T extends { readonly id: string }>(
  threads: readonly T[],
  orderedIds: readonly string[] | null,
): T[] {
  if (orderedIds === null) return [...threads];
  const rank = new Map(orderedIds.map((id, index) => [id, index]));
  return [...threads].sort((left, right) => {
    const leftRank = rank.get(left.id);
    const rightRank = rank.get(right.id);
    if (leftRank === undefined && rightRank === undefined) return 0;
    if (leftRank === undefined) return -1;
    if (rightRank === undefined) return 1;
    return leftRank - rightRank;
  });
}

/**
 * Re-apply a finished move to the order as it stands now, expressed as a move
 * relative to the nearest row that outlived the gesture.
 *
 * Replaying the preview wholesale is not safe. It was built when the drag
 * began, so by the time it lands it can reinstate rows that have since
 * disappeared, ignore rows that have since arrived, and revert reorders made
 * elsewhere while the pointer was down. Only the moved row's position relative
 * to its neighbours is what the user actually asked for; everything else in
 * the preview is incidental.
 */
export function rebaseMovedId(
  currentIds: readonly string[],
  previewIds: readonly string[],
  movingId: string,
): string[] {
  const index = previewIds.indexOf(movingId);
  if (index < 0 || !currentIds.includes(movingId)) return [...currentIds];
  const survives = new Set(currentIds);
  // The row above is what the drop was aimed past, so prefer it; fall forward
  // only when everything above the moved row is gone.
  for (let above = index - 1; above >= 0; above--) {
    const anchor = previewIds[above]!;
    if (anchor !== movingId && survives.has(anchor)) {
      return movePinnedId(currentIds, movingId, anchor, "after");
    }
  }
  for (let below = index + 1; below < previewIds.length; below++) {
    const anchor = previewIds[below]!;
    if (anchor !== movingId && survives.has(anchor)) {
      return movePinnedId(currentIds, movingId, anchor, "before");
    }
  }
  return [...currentIds];
}

