import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreads as useSidebarThreads,
  experimental_useProviders as useProviders,
  type PluginSidebarThread,
  type PluginThreadListProps,
  useRealtime,
  useRpc,
  useSettings,
} from "@get-bb/plugin-sdk/app";
import { autoAnimate } from "@formkit/auto-animate";
import { toast } from "sonner";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./components/Select";
import { ThreadCard, type ThreadReorderControls } from "./ThreadCard";
import { SlimRow } from "./SlimRow";
import { SearchResults } from "./SearchResults";
import { BulkSelectionBar } from "./BulkSelectionBar";
import { childThreadsByParent } from "./ChildThreadList";
import { runBulkAction, type BulkActionResult } from "./bulk-actions";
import { useLifecycle } from "./useLifecycle";
import { usePinnedReorder } from "./usePinnedReorder";
import { useInboxReorder } from "./useInboxReorder";
import { TRAILING_GLYPH_BOX_CLASS } from "./StatusSlot";
import {
  ALL_PROJECTS,
  filterByProject,
  hideChildrenOfVisibleParents,
  nextThreadAfterParking,
  partitionPinned,
  reconcileProjectScope,
  searchThreadsByTitle,
  sortByCreatedAtDescending,
  sortSettledThreads,
  visibleInboxThreads,
} from "./inbox";
import {
  movePinnedId,
  movePinnedIdByOffset,
  mergeVisibleOrder,
  orderPinnedThreads,
} from "./pinned-order";
import {
  DEFAULT_SNOOZE_PRESET_CONFIG,
  parseConfiguredSnoozePresets,
  type ConfiguredSnoozePreset,
} from "./lifecycle";
import {
  DEFAULT_INACTIVE_AFTER_HOURS,
  isInactiveThread,
  parseInactiveAfterHours,
} from "./inactive";
import {
  EMPTY_THREAD_SELECTION,
  keepFailedSelection,
  reconcileThreadSelection,
  updateThreadSelection,
  type ThreadSelectionState,
} from "./selection";
import {
  PROJECT_ICONS_CHANNEL,
  projectIconUrl,
} from "./project-icons";
import { ProjectFavicon } from "./ProjectFavicon";
import type { bbSidebarRpcContract } from "./server";
import {
  cachedSidebarSettings,
  cacheSidebarSettings,
  SIDEBAR_SETTINGS_CHANNEL,
  type SidebarSettingsValues,
} from "./sidebar-settings";

const ACTIVE_GROUPING_STORAGE_KEY = "bb-sidebar:active-grouping:v1";
const ACTIVE_SORT_STORAGE_KEY = "bb-sidebar:active-sort:v1";
const SHELF_EXPANSION_STORAGE_KEY = "bb-sidebar:shelf-expansion:v1";
const CHILD_EXPANSION_STORAGE_KEY = "bb-sidebar:child-expansion:v1";
const SETTLED_INITIAL_LIMIT = 10;
const SETTLED_PAGE_SIZE = 25;

function readChildExpansion(): Set<string> {
  try {
    const stored = window.localStorage.getItem(CHILD_EXPANSION_STORAGE_KEY);
    if (!stored) return new Set();
    const parsed = JSON.parse(stored) as unknown;
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((value): value is string => typeof value === "string"));
  } catch {
    return new Set();
  }
}

function useListAutoAnimate<T extends HTMLElement>() {
  return useCallback((node: T | null) => {
    if (!node || typeof window.matchMedia !== "function") return;
    autoAnimate(node, { duration: 150, easing: "ease-out" });
  }, []);
}

function suppressNextClick(threadId: string): void {
  let timeout = 0;
  const suppress = (event: MouseEvent) => {
    const clickedThreadId =
      event.target instanceof Element
        ? event.target
            .closest("[data-sidebar-thread-id]")
            ?.getAttribute("data-sidebar-thread-id")
        : null;
    if (clickedThreadId !== threadId) return;
    event.preventDefault();
    event.stopPropagation();
    window.removeEventListener("click", suppress, true);
    window.clearTimeout(timeout);
  };
  window.addEventListener("click", suppress, true);
  timeout = window.setTimeout(
    () => window.removeEventListener("click", suppress, true),
    300,
  );
}

interface ShelfExpansionState {
  active: boolean;
  pinned: boolean;
  inactive: boolean;
  snoozed: boolean;
  settled: boolean;
}

const DEFAULT_SHELF_EXPANSION: ShelfExpansionState = {
  active: true,
  pinned: true,
  inactive: false,
  snoozed: false,
  settled: false,
};

function readShelfExpansion(): ShelfExpansionState {
  try {
    const stored = window.localStorage.getItem(SHELF_EXPANSION_STORAGE_KEY);
    if (!stored) return DEFAULT_SHELF_EXPANSION;
    const parsed = JSON.parse(stored) as Partial<ShelfExpansionState>;
    return {
      // Keep Active expanded for people with the older stored shape.
      active: parsed.active !== false,
      // Pinned became independently collapsible after the first stored shape.
      pinned: parsed.pinned !== false,
      inactive: parsed.inactive === true,
      snoozed: parsed.snoozed === true,
      settled: parsed.settled === true,
    };
  } catch {
    return DEFAULT_SHELF_EXPANSION;
  }
}

const ACTIVE_SORT_MODES = ["manual", "activity", "created", "project"] as const;
type ActiveSortMode = (typeof ACTIVE_SORT_MODES)[number];

const ACTIVE_SORT_LABELS: Record<ActiveSortMode, string> = {
  manual: "Manual order",
  activity: "Recent activity",
  created: "Date created",
  project: "Project",
};

function isActiveSortMode(value: string): value is ActiveSortMode {
  return ACTIVE_SORT_MODES.some((mode) => mode === value);
}

function readActiveSort(): ActiveSortMode {
  try {
    const stored = window.localStorage.getItem(ACTIVE_SORT_STORAGE_KEY);
    if (stored && isActiveSortMode(stored)) return stored;
    return window.localStorage.getItem(ACTIVE_GROUPING_STORAGE_KEY) === "true"
      ? "project"
      : "manual";
  } catch {
    return "manual";
  }
}

type ActiveShelfKind = "pinned" | "inbox";

interface ActiveThreadGroup {
  projectId: string;
  entries: Array<{
    thread: PluginSidebarThread;
    shelf: ActiveShelfKind;
  }>;
}

function groupActiveThreadsByProject(
  pinned: readonly PluginSidebarThread[],
  inbox: readonly PluginSidebarThread[],
  projectNameById: ReadonlyMap<string, string>,
): ActiveThreadGroup[] {
  const groups = new Map<string, ActiveThreadGroup>();
  for (const [threads, shelf] of [
    [pinned, "pinned"],
    [inbox, "inbox"],
  ] as const) {
    for (const thread of threads) {
      let group = groups.get(thread.projectId);
      if (!group) {
        group = { projectId: thread.projectId, entries: [] };
        groups.set(thread.projectId, group);
      }
      group.entries.push({ thread, shelf });
    }
  }
  return [...groups.values()].sort((left, right) =>
    (projectNameById.get(left.projectId) ?? left.projectId).localeCompare(
      projectNameById.get(right.projectId) ?? right.projectId,
    ),
  );
}

function sortActiveThreads(
  threads: readonly PluginSidebarThread[],
  mode: ActiveSortMode,
): PluginSidebarThread[] {
  if (mode !== "activity" && mode !== "created") return [...threads];
  const primaryKey = mode === "activity" ? "updatedAt" : "createdAt";
  return [...threads].sort(
    (left, right) =>
      right[primaryKey] - left[primaryKey] ||
      right.updatedAt - left.updatedAt ||
      right.createdAt - left.createdAt,
  );
}

function visibleShelfThreads(
  threads: readonly PluginSidebarThread[],
  expanded: boolean,
  activeThreadId: string | null,
  limit = threads.length,
): PluginSidebarThread[] {
  const activeThread = threads.find((thread) => thread.id === activeThreadId);
  if (!expanded) return activeThread ? [activeThread] : [];
  return threads.filter(
    (thread, index) => index < limit || thread.id === activeThreadId,
  );
}

function childListContainsThread(
  children: readonly PluginSidebarThread[],
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>,
  threadId: string | null,
): boolean {
  if (threadId === null) return false;
  return children.some(
    (child) =>
      child.id === threadId ||
      childrenByParent
        .get(child.id)
        ?.some((grandchild) => grandchild.id === threadId) === true,
  );
}

function rootVisibleThreadId(
  threads: readonly PluginSidebarThread[],
  threadId: string | null,
): string | null {
  if (threadId === null) return null;
  const visibleById = new Map(
    visibleInboxThreads(threads).map((thread) => [thread.id, thread] as const),
  );
  let current = visibleById.get(threadId);
  if (!current) return threadId;
  const visited = new Set([current.id]);
  while (current.parentThreadId) {
    const parent = visibleById.get(current.parentThreadId);
    if (!parent || visited.has(parent.id)) break;
    visited.add(parent.id);
    current = parent;
  }
  return current.id;
}

/**
 * The sidebar's scrolling list: one flat, statically ordered stack of cards.
 *
 * The host owns the New-thread button and the search field above it, so this
 * ships neither. It filters by the `searchQuery` prop and keeps only the one
 * control the host has no equivalent for: the project scope picker.
 */
export function ThreadInbox({
  activeThreadId,
  onNavigate,
  searchQuery,
}: PluginThreadListProps) {
  const { status, threads, projects } = useSidebarThreads();
  const { providers } = useProviders();
  const actions = useSidebarThreadActions();
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const { values: legacySettings } = useSettings();
  const [sidebarSettings, setSidebarSettings] =
    useState<SidebarSettingsValues | null>(() => cachedSidebarSettings(rpc));
  const loadSidebarSettings = useCallback(async () => {
    try {
      const result = await rpc.call("getSidebarSettings", {});
      setSidebarSettings(cacheSidebarSettings(rpc, result));
    } catch {
      // Older test harnesses and a backend still reloading have no method yet.
    }
  }, [rpc]);
  useEffect(() => {
    void loadSidebarSettings();
  }, [loadSidebarSettings]);
  useRealtime(SIDEBAR_SETTINGS_CHANNEL, () => {
    void loadSidebarSettings();
  });
  const lifecycle = useLifecycle(threads);
  const [projectIconRevision, setProjectIconRevision] = useState(0);
  useRealtime(PROJECT_ICONS_CHANNEL, () => {
    setProjectIconRevision((revision) => revision + 1);
  });
  const attachShelvesAutoAnimateRef = useListAutoAnimate<HTMLDivElement>();
  const activeThreadIdRef = useRef(activeThreadId);
  activeThreadIdRef.current = activeThreadId;
  const configuredSnoozePresets =
    sidebarSettings?.snoozePresets ??
    (typeof legacySettings?.snoozePresets === "string"
      ? legacySettings.snoozePresets
      : DEFAULT_SNOOZE_PRESET_CONFIG);
  const snoozePresets = useMemo(
    () => parseConfiguredSnoozePresets(configuredSnoozePresets),
    [configuredSnoozePresets],
  );
  const inactiveAfterHours = parseInactiveAfterHours(
    sidebarSettings?.inactiveThreadsEnabled === true ||
      legacySettings?.inactiveThreadsEnabled === true,
    sidebarSettings
      ? String(sidebarSettings.inactiveAfterHours)
      : typeof legacySettings?.inactiveAfterHours === "string"
        ? legacySettings.inactiveAfterHours
        : String(DEFAULT_INACTIVE_AFTER_HOURS),
  );
  const [scope, setScope] = useState<string>(ALL_PROJECTS);
  useEffect(() => {
    setScope((current) => reconcileProjectScope(current, projects));
  }, [projects]);
  // One clock for every card in a render, quantized to the minute so the
  // labels do not disagree and do not churn on unrelated re-renders.
  const [nowMinute, setNowMinute] = useState(() =>
    Math.floor(Date.now() / 60_000),
  );
  useEffect(() => {
    const timer = setInterval(
      () => setNowMinute(Math.floor(Date.now() / 60_000)),
      60_000,
    );
    return () => clearInterval(timer);
  }, []);
  const now = nowMinute * 60_000;
  const [expandedShelves, setExpandedShelves] =
    useState<ShelfExpansionState>(readShelfExpansion);
  const [expandedChildParentIds, setExpandedChildParentIds] =
    useState<Set<string>>(readChildExpansion);
  const [activeSortMode, setActiveSortMode] =
    useState<ActiveSortMode>(readActiveSort);
  const [settledLimit, setSettledLimit] = useState(SETTLED_INITIAL_LIMIT);
  const [selection, setSelection] = useState<ThreadSelectionState>(
    EMPTY_THREAD_SELECTION,
  );
  const [bulkBusy, setBulkBusy] = useState(false);
  useEffect(() => {
    try {
      window.localStorage.setItem(
        CHILD_EXPANSION_STORAGE_KEY,
        JSON.stringify([...expandedChildParentIds].sort()),
      );
    } catch {
      // Expansion remains usable for this mount when storage is unavailable.
    }
  }, [expandedChildParentIds]);
  useEffect(() => {
    try {
      window.localStorage.setItem(
        SHELF_EXPANSION_STORAGE_KEY,
        JSON.stringify(expandedShelves),
      );
    } catch {
      // Storage may be unavailable in a hardened browser. The shelves still
      // work for this mount; only the preference becomes non-durable.
    }
  }, [expandedShelves]);
  useEffect(() => {
    try {
      window.localStorage.setItem(
        ACTIVE_SORT_STORAGE_KEY,
        activeSortMode,
      );
    } catch {
      // Keep the view usable when browser storage is unavailable.
    }
  }, [activeSortMode]);

  const projectNameById = useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects],
  );
  const providerById = useMemo(
    () => new Map(providers.map((provider) => [provider.id, provider])),
    [providers],
  );
  const childrenByParentId = useMemo(
    () => childThreadsByParent(threads),
    [threads],
  );
  useEffect(() => {
    setExpandedChildParentIds((current) => {
      const next = new Set(
        [...current].filter((threadId) => childrenByParentId.has(threadId)),
      );
      return next.size === current.size ? current : next;
    });
  }, [childrenByParentId]);
  const activeListThreadId = useMemo(
    () => rootVisibleThreadId(threads, activeThreadId),
    [activeThreadId, threads],
  );
  const toggleChildExpansion = useCallback((parentThreadId: string) => {
    setExpandedChildParentIds((current) => {
      const next = new Set(current);
      if (next.has(parentThreadId)) next.delete(parentThreadId);
      else next.add(parentThreadId);
      return next;
    });
  }, []);

  const {
    pinnedBase,
    inboxBase,
    inactiveBase,
    allPinnedBase,
    allInboxBase,
    snoozed,
    settled,
  } = useMemo(() => {
    const allVisible = visibleInboxThreads(threads);
    const scoped = filterByProject(
      allVisible,
      scope === ALL_PROJECTS ? null : scope,
    );
    // Children live in their parent's header chip instead of the flat list;
    // an orphan whose parent is not on screen stays here.
    const visible = hideChildrenOfVisibleParents(scoped);
    const active: typeof visible = [];
    const onSnoozeShelf: typeof visible = [];
    const onSettledShelf: typeof visible = [];
    for (const thread of visible) {
      const shelf = lifecycle.shelfFor(thread);
      if (shelf === "snoozed") onSnoozeShelf.push(thread);
      else if (shelf === "settled") onSettledShelf.push(thread);
      else active.push(thread);
    }
    const split = partitionPinned(active);
    const activeUnpinned: typeof split.inbox = [];
    const inactive: typeof split.inbox = [];
    for (const thread of split.inbox) {
      if (isInactiveThread(thread, now, inactiveAfterHours)) {
        inactive.push(thread);
      } else {
        activeUnpinned.push(thread);
      }
    }
    const allSplit = partitionPinned(allVisible);
    return {
      // BB supplies pinned rows in the user's persisted pin order.
      pinnedBase: split.pinned,
      inboxBase: sortByCreatedAtDescending(activeUnpinned),
      inactiveBase: sortByCreatedAtDescending(inactive),
      // Keep a global order behind project-scoped and parked views. Child and
      // parked rows are included because they can become visible later; a
      // reorder elsewhere must not silently discard their old slot.
      allPinnedBase: allSplit.pinned,
      allInboxBase: sortByCreatedAtDescending(allSplit.inbox),
      // Soonest wake first: "what comes back next" is the shelf's question.
      snoozed: [...onSnoozeShelf].sort(
        (left, right) =>
          (lifecycle.wakeAtFor(left) ?? 0) - (lifecycle.wakeAtFor(right) ?? 0),
      ),
      settled: sortSettledThreads(onSettledShelf, lifecycle.settledAtFor),
    };
  }, [inactiveAfterHours, lifecycle, now, scope, threads]);

  const pinnedReorder = usePinnedReorder(allPinnedBase);
  const inboxReorder = useInboxReorder(allInboxBase);
  const [dragOrder, setDragOrder] = useState<{
    shelf: "pinned" | "inbox";
    movingId: string;
    ids: string[];
  } | null>(null);
  const dragOrderRef = useRef(dragOrder);
  dragOrderRef.current = dragOrder;
  const activeReorderCancelRef = useRef<(() => void) | null>(null);
  useEffect(
    () => () => {
      activeReorderCancelRef.current?.();
    },
    [],
  );
  const pinned = useMemo(() => {
    const ordered = orderPinnedThreads(pinnedBase, pinnedReorder.ids);
    return orderPinnedThreads(
      ordered,
      dragOrder?.shelf === "pinned" ? dragOrder.ids : null,
    );
  }, [dragOrder, pinnedBase, pinnedReorder.ids]);
  const inbox = useMemo(() => {
    const ordered = orderPinnedThreads(inboxBase, inboxReorder.ids);
    return orderPinnedThreads(
      ordered,
      dragOrder?.shelf === "inbox" ? dragOrder.ids : null,
    );
  }, [dragOrder, inboxBase, inboxReorder.ids]);
  const inactive = useMemo(
    () => orderPinnedThreads(inactiveBase, inboxReorder.ids),
    [inactiveBase, inboxReorder.ids],
  );
  const visiblePinned = useMemo(
    () =>
      visibleShelfThreads(
        pinned,
        expandedShelves.pinned,
        activeListThreadId,
      ),
    [activeListThreadId, expandedShelves.pinned, pinned],
  );
  const visibleInbox = useMemo(
    () => visibleShelfThreads(inbox, expandedShelves.active, activeListThreadId),
    [activeListThreadId, expandedShelves.active, inbox],
  );
  const visibleInactive = useMemo(
    () =>
      visibleShelfThreads(
        inactive,
        expandedShelves.inactive,
        activeListThreadId,
      ),
    [activeListThreadId, expandedShelves.inactive, inactive],
  );
  const sortedVisibleInbox = useMemo(
    () => sortActiveThreads(visibleInbox, activeSortMode),
    [activeSortMode, visibleInbox],
  );
  const inboxProjectGroups = useMemo(
    () =>
      groupActiveThreadsByProject(
        [],
        visibleInbox,
        projectNameById,
      ),
    [projectNameById, visibleInbox],
  );

  const threadReorderControls = (
    thread: PluginSidebarThread,
    shelf: "pinned" | "inbox",
  ): ThreadReorderControls => {
    const target = shelf === "pinned" ? pinnedReorder : inboxReorder;
    const visibleIds = (shelf === "pinned" ? visiblePinned : visibleInbox)
      .filter(
        (candidate) =>
          activeSortMode !== "project" ||
          candidate.projectId === thread.projectId,
      )
      .map((candidate) => candidate.id);
    return {
      disabled: target.isReordering,
      isDragging:
        dragOrder?.shelf === shelf && dragOrder.movingId === thread.id,
      onPointerDown: (event) => {
        if (target.isReordering || event.button !== 0) return;

        activeReorderCancelRef.current?.();
        const pointerId = event.pointerId;
        const startX = event.clientX;
        const startY = event.clientY;
        const movingId = thread.id;
        let engaged = false;
        let finished = false;
        let previousUserSelect = "";
        let previousCursor = "";

        function cleanup() {
          window.removeEventListener("pointermove", onPointerMove);
          window.removeEventListener("pointerup", onPointerUp);
          window.removeEventListener("pointercancel", onPointerCancel);
          window.removeEventListener("keydown", onKeyDown);
          if (engaged) {
            document.body.style.userSelect = previousUserSelect;
            document.body.style.cursor = previousCursor;
          }
          if (activeReorderCancelRef.current === cancel) {
            activeReorderCancelRef.current = null;
          }
        }

        function cancel() {
          if (finished) return;
          finished = true;
          cleanup();
          if (engaged) {
            dragOrderRef.current = null;
            setDragOrder(null);
          }
        }

        function engage() {
          engaged = true;
          previousUserSelect = document.body.style.userSelect;
          previousCursor = document.body.style.cursor;
          document.body.style.userSelect = "none";
          document.body.style.cursor = "grabbing";
          const next = { shelf, movingId, ids: visibleIds };
          dragOrderRef.current = next;
          setDragOrder(next);
        }

        function reorderAt(clientX: number, clientY: number) {
          const hit = document.elementFromPoint(clientX, clientY);
          const row = hit instanceof Element ? hit.closest("li") : null;
          const targetId = row
            ?.querySelector<HTMLAnchorElement>("[data-sidebar-thread-id]")
            ?.getAttribute("data-sidebar-thread-id");
          const current = dragOrderRef.current;
          if (
            !row ||
            !targetId ||
            !visibleIds.includes(targetId) ||
            !current ||
            current.shelf !== shelf ||
            current.movingId === targetId
          ) {
            return;
          }
          const rect = row.getBoundingClientRect();
          const placement =
            clientY < rect.top + rect.height / 2 ? "before" : "after";
          const ids = movePinnedId(
            current.ids,
            current.movingId,
            targetId,
            placement,
          );
          const next = { ...current, ids };
          dragOrderRef.current = next;
          setDragOrder(next);
        }

        function onPointerMove(moveEvent: PointerEvent) {
          if (finished || moveEvent.pointerId !== pointerId) return;
          if (!engaged) {
            const deltaX = moveEvent.clientX - startX;
            const deltaY = moveEvent.clientY - startY;
            if (Math.abs(deltaY) < 6 || Math.abs(deltaY) <= Math.abs(deltaX)) {
              return;
            }
            engage();
          }
          moveEvent.preventDefault();
          reorderAt(moveEvent.clientX, moveEvent.clientY);
        }

        function onPointerUp(upEvent: PointerEvent) {
          if (finished || upEvent.pointerId !== pointerId) return;
          const current = dragOrderRef.current;
          finished = true;
          cleanup();
          if (!engaged || !current || current.shelf !== shelf) return;

          dragOrderRef.current = null;
          setDragOrder(null);
          suppressNextClick(current.movingId);
          const globalIds = mergeVisibleOrder(target.ids, current.ids);
          if (shelf === "pinned") {
            void pinnedReorder.reorder(globalIds, current.movingId);
          } else {
            void inboxReorder.reorder(globalIds);
          }
        }

        function onPointerCancel(cancelEvent: PointerEvent) {
          if (cancelEvent.pointerId === pointerId) cancel();
        }

        function onKeyDown(keyEvent: KeyboardEvent) {
          if (keyEvent.key === "Escape") cancel();
        }

        window.addEventListener("pointermove", onPointerMove, {
          passive: false,
        });
        window.addEventListener("pointerup", onPointerUp);
        window.addEventListener("pointercancel", onPointerCancel);
        window.addEventListener("keydown", onKeyDown);
        activeReorderCancelRef.current = cancel;
      },
      onKeyDown: (event) => {
        if (
          !event.altKey ||
          target.isReordering ||
          (event.key !== "ArrowUp" && event.key !== "ArrowDown")
        ) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        const ids = movePinnedIdByOffset(
          visibleIds,
          thread.id,
          event.key === "ArrowUp" ? -1 : 1,
        );
        const globalIds = mergeVisibleOrder(target.ids, ids);
        if (shelf === "pinned") {
          void pinnedReorder.reorder(globalIds, thread.id);
        } else {
          void inboxReorder.reorder(globalIds);
        }
      },
    };
  };

  const isSearching = searchQuery.trim().length > 0;
  const searchCandidates = useMemo(
    () =>
      filterByProject(
        visibleInboxThreads(threads),
        scope === ALL_PROJECTS ? null : scope,
      ),
    [scope, threads],
  );
  const searchResults = useMemo(
    () => searchThreadsByTitle(searchCandidates, searchQuery),
    [searchCandidates, searchQuery],
  );
  const visibleSnoozed = useMemo(
    () =>
      visibleShelfThreads(
        snoozed,
        expandedShelves.snoozed,
        activeListThreadId,
      ),
    [activeListThreadId, expandedShelves.snoozed, snoozed],
  );
  const visibleSettled = useMemo(
    () =>
      visibleShelfThreads(
        settled,
        expandedShelves.settled,
        activeListThreadId,
        settledLimit,
      ),
    [activeListThreadId, expandedShelves.settled, settled, settledLimit],
  );
  const selectableThreads = useMemo(
    () =>
      isSearching
        ? searchResults
        : [
            ...visiblePinned,
            ...visibleInbox,
            ...visibleInactive,
            ...visibleSnoozed,
            ...visibleSettled,
          ],
    [
      isSearching,
      searchResults,
      visibleInbox,
      visibleInactive,
      visiblePinned,
      visibleSettled,
      visibleSnoozed,
    ],
  );
  const selectableThreadIds = useMemo(
    () => selectableThreads.map((thread) => thread.id),
    [selectableThreads],
  );
  const selectableThreadIdsKey = selectableThreadIds.join("\0");
  useEffect(() => {
    setSelection((current) =>
      reconcileThreadSelection(current, selectableThreadIds),
    );
  }, [selectableThreadIds, selectableThreadIdsKey]);
  const selectedThreads = useMemo(
    () =>
      selectableThreads.filter((thread) =>
        selection.selectedIds.has(thread.id),
      ),
    [selectableThreads, selection.selectedIds],
  );
  const wokeThreadIds = useMemo(
    () =>
      new Set(
        [...pinned, ...inbox, ...inactive]
          .filter((thread) => lifecycle.wokeFor(thread))
          .map((thread) => thread.id),
      ),
    [inactive, inbox, lifecycle, pinned],
  );

  const scopeLabel =
    scope === ALL_PROJECTS
      ? "All projects"
      : (projectNameById.get(scope) ?? "All projects");

  const handleSelectionClick = (
    threadId: string,
    event: ReactMouseEvent<HTMLAnchorElement>,
  ): boolean => {
    const toggleKey = event.metaKey || event.ctrlKey;
    if (!toggleKey && !event.shiftKey) {
      if (selection.selectedIds.size > 0) {
        setSelection(EMPTY_THREAD_SELECTION);
      }
      return false;
    }
    setSelection((current) =>
      updateThreadSelection(current, selectableThreadIds, threadId, {
        shiftKey: event.shiftKey,
        toggleKey,
      }),
    );
    return true;
  };

  const finishBulkAction = (
    actionLabel: string,
    successLabel: string,
    total: number,
    result: BulkActionResult,
  ) => {
    if (result.failures.length === 0) {
      toast.success(
        `${total} ${total === 1 ? "thread" : "threads"} ${successLabel}`,
      );
    } else {
      toast.error(
        `${result.failures.length} of ${total} ${actionLabel} actions failed`,
        { description: result.failures[0]?.error },
      );
    }
    setSelection(
      keepFailedSelection(
        result.failures.map((failure) => failure.threadId),
        selectableThreadIds,
      ),
    );
  };

  const runSelectedAction = async (
    actionLabel: string,
    successLabel: string,
    action: (
      threads: readonly PluginSidebarThread[],
    ) => Promise<BulkActionResult>,
    parksThreads = false,
  ) => {
    if (bulkBusy || selectedThreads.length === 0) return;
    const targets = [...selectedThreads];
    setBulkBusy(true);
    try {
      const result = await action(targets);
      finishBulkAction(actionLabel, successLabel, targets.length, result);
      if (
        parksThreads &&
        activeThreadIdRef.current !== null &&
        result.succeededThreadIds.includes(activeThreadIdRef.current)
      ) {
        const parkedIds = new Set(result.succeededThreadIds);
        const activeRows = [...pinned, ...inbox, ...inactive];
        const activeIndex = activeRows.findIndex(
          (thread) => thread.id === activeThreadIdRef.current,
        );
        const nextThread =
          activeRows
            .slice(activeIndex + 1)
            .find((thread) => !parkedIds.has(thread.id)) ??
          activeRows
            .slice(0, Math.max(0, activeIndex))
            .reverse()
            .find((thread) => !parkedIds.has(thread.id)) ??
          null;
        if (nextThread) actions.open(nextThread.id);
        else {
          actions.openNewThread({
            projectId: targets[0]?.projectId,
            focusPrompt: true,
          });
        }
        onNavigate();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      const failures = targets.map((thread) => ({
        threadId: thread.id,
        error: message,
      }));
      finishBulkAction(actionLabel, successLabel, targets.length, {
        succeededThreadIds: [],
        failures,
      });
    } finally {
      setBulkBusy(false);
    }
  };

  const runBulkParkAction = (
    actionLabel: "settle" | "snooze",
    snoozedUntil?: number,
  ) =>
    runSelectedAction(
      actionLabel,
      actionLabel === "settle" ? "settled" : "snoozed",
      async (targets) => {
        const eligible = targets.filter(lifecycle.canPark);
        const blocked = targets
          .filter((thread) => !lifecycle.canPark(thread))
          .map((thread) => ({
            threadId: thread.id,
            error: "Thread is working or needs input",
          }));
        const result =
          eligible.length === 0
            ? { succeededThreadIds: [], failures: [] }
            : actionLabel === "settle"
              ? await lifecycle.bulkSettle(eligible.map((thread) => thread.id))
              : await lifecycle.bulkSnooze(
                  eligible.map((thread) => thread.id),
                  snoozedUntil!,
                );
        return { ...result, failures: [...result.failures, ...blocked] };
      },
      true,
    );

  const parkActiveThread = async (
    thread: PluginSidebarThread,
    mutation: () => Promise<boolean>,
  ) => {
    const parked = await mutation();
    if (!parked || activeThreadIdRef.current !== thread.id) return;

    const nextThread = nextThreadAfterParking(
      [...pinned, ...inbox, ...inactive],
      thread.id,
    );
    if (nextThread) {
      actions.open(nextThread.id);
    } else {
      actions.openNewThread({
        projectId: thread.projectId,
        focusPrompt: true,
      });
    }
    onNavigate();
  };

  const renderActiveThread = (
    thread: PluginSidebarThread,
    shelf: ActiveShelfKind,
    reorderable = true,
  ) => (
    <ThreadCard
      key={thread.id}
      thread={thread}
      provider={providerById.get(thread.providerId) ?? null}
      projectName={projectNameById.get(thread.projectId) ?? null}
      projectIconUrl={projectIconUrl(thread.projectId, projectIconRevision)}
      isActive={thread.id === activeThreadId}
      isSelected={selection.selectedIds.has(thread.id)}
      isWoke={wokeThreadIds.has(thread.id)}
      canPark={lifecycle.canPark(thread)}
      snoozePresets={snoozePresets}
      onNavigate={onNavigate}
      onSettle={() =>
        void parkActiveThread(thread, () => lifecycle.settle(thread.id))
      }
      onSnooze={(until) =>
        void parkActiveThread(thread, () => lifecycle.snooze(thread.id, until))
      }
      onAcknowledgeWake={() => void lifecycle.acknowledgeWake(thread.id)}
      onSelectionClick={(event) => handleSelectionClick(thread.id, event)}
      childThreads={childrenByParentId.get(thread.id) ?? []}
      childrenByParent={childrenByParentId}
      activeThreadId={activeThreadId}
      childrenExpanded={
        expandedChildParentIds.has(thread.id) ||
        childListContainsThread(
          childrenByParentId.get(thread.id) ?? [],
          childrenByParentId,
          activeThreadId,
        )
      }
      onToggleChildren={() => toggleChildExpansion(thread.id)}
      reorder={
        !reorderable ||
        (shelf === "inbox" &&
          (activeSortMode === "activity" || activeSortMode === "created"))
          ? undefined
          : threadReorderControls(thread, shelf)
      }
      now={now}
    />
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* The one control the host has no equivalent for. Everything else in
          the chrome above — New thread, search — is bb's and stays bb's. */}
      <div className="flex shrink-0 items-center gap-1 px-2 pb-1">
        {selectedThreads.length > 0 ? (
          <BulkSelectionBar
            count={selectedThreads.length}
            busy={bulkBusy}
            snoozePresets={snoozePresets}
            onSettle={() => void runBulkParkAction("settle")}
            onSnooze={(snoozedUntil) =>
              void runBulkParkAction("snooze", snoozedUntil)
            }
            onMarkRead={() =>
              void runSelectedAction("mark read", "marked read", (targets) =>
                runBulkAction(
                  targets.map((thread) => thread.id),
                  (threadId) => actions.setRead(threadId, true),
                ),
              )
            }
            onMarkUnread={() =>
              void runSelectedAction(
                "mark unread",
                "marked unread",
                (targets) =>
                  runBulkAction(
                    targets.map((thread) => thread.id),
                    (threadId) => actions.setRead(threadId, false),
                  ),
              )
            }
            onClear={() => setSelection(EMPTY_THREAD_SELECTION)}
          />
        ) : (
          <Select value={scope} onValueChange={setScope}>
            {/* Ghost trigger: no border, no filled track — it reads as a label
                until you hover it. */}
            <SelectTrigger
              className="h-7 min-w-0 flex-1 border-0 px-1.5 py-1 text-xs font-medium text-muted-foreground shadow-none hover:bg-sidebar-accent focus:ring-0"
              aria-label={`Project scope: ${scopeLabel}`}
            >
              <SelectValue>
                <span className="flex min-w-0 items-center gap-1.5">
                  {scope !== ALL_PROJECTS ? (
                    <ProjectFavicon
                      src={projectIconUrl(
                        scope,
                        projectIconRevision,
                      )}
                      className="size-3"
                    />
                  ) : null}
                  <span className="truncate">{scopeLabel}</span>
                </span>
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_PROJECTS} className="text-xs">
                All projects
              </SelectItem>
              {projects.map((project) => (
                <SelectItem
                  key={project.id}
                  value={project.id}
                  className="text-xs"
                >
                  <span className="flex min-w-0 items-center gap-1.5">
                    <ProjectFavicon
                      src={projectIconUrl(
                        project.id,
                        projectIconRevision,
                      )}
                      className="size-3"
                    />
                    <span className="truncate">{project.name}</span>
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-2">
        {status === "loading" ? null : status === "error" ? (
          <p
            role="status"
            className="px-2 py-6 text-center text-xs text-muted-foreground"
          >
            Could not load threads.
          </p>
        ) : isSearching && searchResults.length === 0 ? (
          <p
            role="status"
            className="px-2 py-6 text-center text-xs text-muted-foreground"
          >
            No threads found
          </p>
        ) : isSearching ? (
          <SearchResults
            threads={searchResults}
            projectNameById={projectNameById}
            projectIconRevision={projectIconRevision}
            activeThreadId={activeThreadId}
            now={now}
            wokeThreadIds={wokeThreadIds}
            onAcknowledgeWake={(threadId) =>
              void lifecycle.acknowledgeWake(threadId)
            }
            selectedThreadIds={selection.selectedIds}
            onSelectionClick={handleSelectionClick}
            onNavigate={onNavigate}
          />
        ) : (
          <div ref={attachShelvesAutoAnimateRef} className="flex flex-col">
            {pinned.length > 0 ? (
              <CollapsibleShelf
                label="Pinned"
                count={pinned.length}
                expanded={expandedShelves.pinned}
                onToggle={() =>
                  setExpandedShelves((current) => ({
                    ...current,
                    pinned: !current.pinned,
                  }))
                }
              >
                <Shelf label={null}>
                  {visiblePinned.map((thread) =>
                    renderActiveThread(thread, "pinned"),
                  )}
                </Shelf>
              </CollapsibleShelf>
            ) : null}
            {inbox.length > 0 ? (
              <CollapsibleShelf
                label="Active"
                count={inbox.length}
                expanded={expandedShelves.active}
                onToggle={() =>
                  setExpandedShelves((current) => ({
                    ...current,
                    active: !current.active,
                  }))
                }
                action={
                  <Select
                    value={activeSortMode}
                    onValueChange={(value) => {
                      if (isActiveSortMode(value)) setActiveSortMode(value);
                    }}
                  >
                    <SelectTrigger
                      aria-label={`Sort active threads: ${ACTIVE_SORT_LABELS[activeSortMode]}`}
                      title={`Sort active threads: ${ACTIVE_SORT_LABELS[activeSortMode]}`}
                      className={cn(
                        "absolute bottom-1 right-[1.875rem] z-10 size-4 h-4 w-4 border-0 p-0 text-muted-foreground/40 shadow-none hover:bg-sidebar-accent hover:text-muted-foreground focus:ring-0 focus-visible:ring-1 focus-visible:ring-ring [&>svg:last-child]:hidden",
                        activeSortMode !== "manual" &&
                          "bg-sidebar-accent/60 text-muted-foreground/80",
                      )}
                    >
                      <Icon name="ArrowUpDown" className="size-3" />
                    </SelectTrigger>
                    <SelectContent align="end" className="min-w-40">
                      {ACTIVE_SORT_MODES.map((mode) => (
                        <SelectItem key={mode} value={mode} className="text-xs">
                          {ACTIVE_SORT_LABELS[mode]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                }
              >
                {activeSortMode === "project" ? (
                  <ProjectGroups
                    groups={inboxProjectGroups}
                    projectNameById={projectNameById}
                    renderThread={renderActiveThread}
                  />
                ) : visibleInbox.length > 0 ? (
                  <Shelf label={null}>
                    {sortedVisibleInbox.map((thread) =>
                      renderActiveThread(thread, "inbox"),
                    )}
                  </Shelf>
                ) : null}
              </CollapsibleShelf>
            ) : null}
            {inactive.length > 0 ? (
              <CollapsibleShelf
                label="Inactive"
                count={inactive.length}
                expanded={expandedShelves.inactive}
                onToggle={() =>
                  setExpandedShelves((current) => ({
                    ...current,
                    inactive: !current.inactive,
                  }))
                }
              >
                <Shelf label={null}>
                  {visibleInactive.map((thread) =>
                    renderActiveThread(thread, "inbox", false),
                  )}
                </Shelf>
              </CollapsibleShelf>
            ) : null}
            {pinned.length === 0 &&
            inbox.length === 0 &&
            inactive.length === 0 ? (
              <ActiveEmptyState />
            ) : null}
            <ParkedShelf
              label="Snoozed"
              threads={snoozed}
              projectNameById={projectNameById}
              expanded={expandedShelves.snoozed}
              onToggle={() =>
                setExpandedShelves((current) => ({
                  ...current,
                  snoozed: !current.snoozed,
                }))
              }
              shelf="snoozed"
              visibleThreads={visibleSnoozed}
              activeThreadId={activeThreadId}
              lifecycle={lifecycle}
              snoozePresets={snoozePresets}
              onNavigate={onNavigate}
              selectedThreadIds={selection.selectedIds}
              onSelectionClick={handleSelectionClick}
              projectIconRevision={projectIconRevision}
            />
            <ParkedShelf
              label="Settled"
              threads={settled}
              projectNameById={projectNameById}
              expanded={expandedShelves.settled}
              onToggle={() =>
                setExpandedShelves((current) => ({
                  ...current,
                  settled: !current.settled,
                }))
              }
              shelf="settled"
              visibleThreads={visibleSettled}
              activeThreadId={activeThreadId}
              lifecycle={lifecycle}
              snoozePresets={snoozePresets}
              onNavigate={onNavigate}
              selectedThreadIds={selection.selectedIds}
              onSelectionClick={handleSelectionClick}
              projectIconRevision={projectIconRevision}
              settledLimit={settledLimit}
              onLoadMore={() =>
                setSettledLimit((limit) => limit + SETTLED_PAGE_SIZE)
              }
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ActiveEmptyState() {
  return (
    <div
      role="status"
      className="flex flex-col items-center px-5 pb-7 pt-8 text-center text-muted-foreground"
    >
      <svg
        viewBox="0 0 180 104"
        className="mb-3 h-auto w-36"
        aria-hidden="true"
      >
        <circle cx="132" cy="24" r="11" fill="currentColor" opacity="0.12" />
        <path
          d="M16 77c18-18 36-24 55-17 14 5 23 5 36-3 18-11 36-7 57 20"
          fill="currentColor"
          opacity="0.08"
        />
        <path
          d="M12 78c22-13 43-14 64-3 16 8 31 8 45 0 16-9 31-8 47 3"
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth="1.5"
          opacity="0.38"
        />
        <g
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="1.5"
          opacity="0.55"
        >
          <path d="M51 76c0-13-2-22-8-30M51 66c-6-3-10-7-13-12M51 61c5-5 8-10 9-16" />
          <path d="M104 77c1-12 5-21 12-28M107 66c6-2 11-6 15-11M108 62c-2-6-2-11-1-16" />
          <path d="M76 75c0-8-2-14-6-20M77 69c4-3 7-6 9-11" />
        </g>
      </svg>
      <p className="text-xs font-medium text-foreground/75">
        All clear. Time to touch some grass.
      </p>
    </div>
  );
}

/**
 * A collapsed shelf of parked threads. The header stays while anything is
 * parked — the count is the whole footprint when collapsed — and the shelf
 * vanishes entirely at zero.
 */
function ParkedShelf({
  label,
  threads,
  projectNameById,
  expanded,
  onToggle,
  shelf,
  visibleThreads,
  activeThreadId,
  lifecycle,
  snoozePresets,
  onNavigate,
  selectedThreadIds,
  onSelectionClick,
  projectIconRevision,
  settledLimit,
  onLoadMore,
}: {
  label: string;
  threads: readonly PluginSidebarThread[];
  projectNameById?: ReadonlyMap<string, string>;
  expanded: boolean;
  onToggle: () => void;
  shelf: "snoozed" | "settled";
  visibleThreads: readonly PluginSidebarThread[];
  activeThreadId: string | null;
  lifecycle: ReturnType<typeof useLifecycle>;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onNavigate: () => void;
  selectedThreadIds: ReadonlySet<string>;
  projectIconRevision: number;
  onSelectionClick: (
    threadId: string,
    event: ReactMouseEvent<HTMLAnchorElement>,
  ) => boolean;
  settledLimit?: number;
  onLoadMore?: () => void;
}) {
  const attachListAutoAnimateRef = useListAutoAnimate<HTMLUListElement>();
  if (threads.length === 0) return null;
  const now = Date.now();
  const limit =
    shelf === "settled" ? (settledLimit ?? threads.length) : threads.length;
  const hasMore = shelf === "settled" && threads.length > limit;
  return (
    <CollapsibleShelf
      label={label}
      count={threads.length}
      expanded={expanded}
      onToggle={onToggle}
    >
      <ul ref={attachListAutoAnimateRef} className="flex flex-col gap-px">
        {visibleThreads.map((thread) => (
          <SlimRow
            key={thread.id}
            thread={thread}
            projectName={projectNameById?.get(thread.projectId) ?? null}
            projectIconUrl={projectIconUrl(
              thread.projectId,
              projectIconRevision,
            )}
            isActive={thread.id === activeThreadId}
            isSelected={selectedThreadIds.has(thread.id)}
            shelf={shelf}
            wakeAt={lifecycle.wakeAtFor(thread)}
            now={now}
            snoozePresets={snoozePresets}
            onSnooze={(until) => void lifecycle.snooze(thread.id, until)}
            onNavigate={onNavigate}
            onSelectionClick={(event) => onSelectionClick(thread.id, event)}
            onRestore={() =>
              shelf === "snoozed"
                ? void lifecycle.unsnooze(thread.id)
                : void lifecycle.unsettle(thread.id)
            }
          />
        ))}
      </ul>
      {expanded && hasMore && onLoadMore ? (
        <button
          type="button"
          onClick={onLoadMore}
          className="ml-2.5 mt-1 rounded px-1.5 py-1 text-2xs font-medium text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
        >
          Load {Math.min(SETTLED_PAGE_SIZE, threads.length - limit)} more
        </button>
      ) : null}
    </CollapsibleShelf>
  );
}

function CollapsibleShelf({
  label,
  count,
  expanded,
  onToggle,
  action,
  children,
}: {
  label: string;
  count: number;
  expanded: boolean;
  onToggle: () => void;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section aria-label={label}>
      <div className="relative">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          // Padded like a card, so the chevron ends on the same right edge as
          // every row's status and provider glyph.
          className="mt-3 flex w-full items-center gap-2 px-2.5 pb-1 text-left"
        >
          <span className="text-2xs font-medium text-muted-foreground/70">
            {expanded ? label : `${label} (${count})`}
          </span>
          <span className="h-px flex-1 bg-sidebar-border" />
          {action ? (
            <span aria-hidden="true" className="size-4 shrink-0" />
          ) : null}
          <span className={TRAILING_GLYPH_BOX_CLASS}>
            <Icon
              name="ChevronDown"
              className={cn(
                "size-3 text-muted-foreground/70 transition-transform duration-150 ease-out motion-reduce:transition-none",
                expanded && "rotate-180",
              )}
            />
          </span>
        </button>
        {action}
      </div>
      {children}
    </section>
  );
}

function ActiveProjectGroup({
  projectName,
  threadCount,
  children,
}: {
  projectName: string;
  threadCount: number;
  children: React.ReactNode;
}) {
  const attachListAutoAnimateRef = useListAutoAnimate<HTMLUListElement>();
  return (
    <ul
      ref={attachListAutoAnimateRef}
      aria-label={`${projectName} active threads`}
      className={cn(
        "flex flex-col gap-px",
        threadCount > 1 &&
          "rounded-lg border border-sidebar-border/30 p-px",
      )}
    >
      {children}
    </ul>
  );
}

function ProjectGroups({
  groups,
  projectNameById,
  renderThread,
}: {
  groups: readonly ActiveThreadGroup[];
  projectNameById: ReadonlyMap<string, string>;
  renderThread: (
    thread: PluginSidebarThread,
    shelf: ActiveShelfKind,
  ) => React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      {groups.map((group) => (
        <ActiveProjectGroup
          key={group.projectId}
          projectName={projectNameById.get(group.projectId) ?? "Project"}
          threadCount={group.entries.length}
        >
          {group.entries.map(({ thread, shelf }) =>
            renderThread(thread, shelf),
          )}
        </ActiveProjectGroup>
      ))}
    </div>
  );
}

function Shelf({
  label,
  children,
}: {
  label: string | null;
  children: React.ReactNode;
}) {
  const attachListAutoAnimateRef = useListAutoAnimate<HTMLUListElement>();
  return (
    // A named section is exposed as a landmark region; shelf rows stay in an
    // unnamed list beneath their collapsible heading.
    <section {...(label ? { "aria-label": label } : {})}>
      {label ? (
        <h2 className={cn("flex items-center gap-2 px-2.5 pb-1 pt-3")}>
          <span className="text-2xs font-medium text-muted-foreground/70">
            {label}
          </span>
          <span className="h-px flex-1 bg-sidebar-border" />
        </h2>
      ) : null}
      <ul ref={attachListAutoAnimateRef} className="flex flex-col gap-px">
        {children}
      </ul>
    </section>
  );
}
