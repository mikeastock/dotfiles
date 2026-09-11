export interface ThreadSelectionState {
  selectedIds: ReadonlySet<string>;
  anchorId: string | null;
}

export const EMPTY_THREAD_SELECTION: ThreadSelectionState = {
  selectedIds: new Set(),
  anchorId: null,
};

export interface SelectionModifiers {
  shiftKey: boolean;
  toggleKey: boolean;
}

export function updateThreadSelection(
  current: ThreadSelectionState,
  visibleIds: readonly string[],
  targetId: string,
  modifiers: SelectionModifiers,
): ThreadSelectionState {
  const targetIndex = visibleIds.indexOf(targetId);
  if (targetIndex < 0) return current;

  if (modifiers.shiftKey) {
    const anchorIndex =
      current.anchorId === null ? -1 : visibleIds.indexOf(current.anchorId);
    const effectiveAnchorIndex = anchorIndex < 0 ? targetIndex : anchorIndex;
    const start = Math.min(effectiveAnchorIndex, targetIndex);
    const end = Math.max(effectiveAnchorIndex, targetIndex);
    const selectedIds = modifiers.toggleKey
      ? new Set(current.selectedIds)
      : new Set<string>();
    for (const threadId of visibleIds.slice(start, end + 1)) {
      selectedIds.add(threadId);
    }
    return {
      selectedIds,
      anchorId: anchorIndex < 0 ? targetId : current.anchorId,
    };
  }

  const selectedIds = new Set(current.selectedIds);
  if (modifiers.toggleKey) {
    if (selectedIds.has(targetId)) selectedIds.delete(targetId);
    else selectedIds.add(targetId);
  } else {
    selectedIds.clear();
    selectedIds.add(targetId);
  }
  return { selectedIds, anchorId: targetId };
}

export function reconcileThreadSelection(
  current: ThreadSelectionState,
  visibleIds: readonly string[],
): ThreadSelectionState {
  const visible = new Set(visibleIds);
  const selectedIds = new Set(
    [...current.selectedIds].filter((threadId) => visible.has(threadId)),
  );
  const anchorId =
    current.anchorId !== null && visible.has(current.anchorId)
      ? current.anchorId
      : null;

  if (
    anchorId === current.anchorId &&
    selectedIds.size === current.selectedIds.size &&
    [...selectedIds].every((threadId) => current.selectedIds.has(threadId))
  ) {
    return current;
  }
  return { selectedIds, anchorId };
}

export function keepFailedSelection(
  failedThreadIds: readonly string[],
  visibleIds: readonly string[],
): ThreadSelectionState {
  const visible = new Set(visibleIds);
  const retained = failedThreadIds.filter((threadId) => visible.has(threadId));
  return {
    selectedIds: new Set(retained),
    anchorId: retained[0] ?? null,
  };
}
