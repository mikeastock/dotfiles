import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
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
import {
  autoAnimate,
  type AnimationController,
} from "@formkit/auto-animate";
import { toast } from "sonner";
import { Icon, type IconName } from "./components/Icon";
import { cn } from "./lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "./components/Select";
import { ProjectScopeSelect } from "./ProjectScopeSelect";
import { ThreadCard, type ThreadReorderControls } from "./ThreadCard";
import { SlimRow } from "./SlimRow";
import { SearchResults } from "./SearchResults";
import { childThreadsByParent } from "./ChildThreadList";
import { useLifecycle, type LifecycleApi } from "./useLifecycle";
import { usePinnedReorder } from "./usePinnedReorder";
import { useInboxReorder } from "./useInboxReorder";
import { TRAILING_GLYPH_BOX_CLASS } from "./StatusSlot";
import { WorkingSinceContext, useWorkingSince } from "./useWorkingSince";
import { OpenPortsProvider } from "./OpenPorts";
import {
  ALL_PROJECTS,
  filterByProject,
  hideChildrenOfVisibleParents,
  partitionPinned,
  reconcileProjectScope,
  searchThreadsByTitle,
  sortByCreatedAtDescending,
  sortSettledThreads,
  threadDisplayTitle,
  visibleInboxThreads,
} from "./inbox";
import {
  movePinnedId,
  movePinnedIdByOffset,
  orderPinnedThreads,
  rebaseMovedId,
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
  PROJECT_ICONS_CHANNEL,
  projectIconUrl,
} from "./project-icons";
import type { bbSidebarRpcContract } from "./server";
import {
  cachedSidebarSettings,
  cacheSidebarSettings,
  DEFAULT_SIDEBAR_SETTINGS,
  SIDEBAR_SETTINGS_CHANNEL,
  type SidebarSettingsValues,
} from "./sidebar-settings";
import {
  MAX_CHILD_EXPANSION,
  pruneChildExpansion,
  safeSetItem,
} from "./lib/safe-storage";

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
    const filtered = parsed.filter(
      (value): value is string => typeof value === "string",
    );
    const trimmed =
      filtered.length > MAX_CHILD_EXPANSION
        ? filtered.slice(-MAX_CHILD_EXPANSION)
        : filtered;
    return new Set(trimmed);
  } catch {
    return new Set();
  }
}

// A drag reads insertion from row geometry, so no row may be mid-flight while
// it reads: an animating rect reports where a row was, not the slot the order
// has already given it. Every list registers here so a drag can hold them all
// still for its duration.
const listAnimations = new Set<AnimationController>();
// Counted rather than a flag: two sidebars can be mounted at once, and the
// first drag to finish must not re-enable animation under a drag still running
// in the other one.
let listAnimationHolds = 0;

function suspendListAnimations(): void {
  listAnimationHolds += 1;
  if (listAnimationHolds > 1) return;
  for (const animation of listAnimations) animation.disable();
}

function resumeListAnimations(): void {
  if (listAnimationHolds === 0) return;
  listAnimationHolds -= 1;
  if (listAnimationHolds > 0) return;
  for (const animation of listAnimations) animation.enable();
}

function useListAutoAnimate<T extends HTMLElement>() {
  return useCallback((node: T | null) => {
    if (!node || typeof window.matchMedia !== "function") return;
    const animation = autoAnimate(node, {
      duration: 150,
      easing: "ease-out",
    });
    if (listAnimationHolds > 0) animation.disable();
    listAnimations.add(animation);
    return () => {
      listAnimations.delete(animation);
      // Dropping our reference is not enough: auto-animate holds the parent in
      // its own registry and keeps observers and a polling interval alive until
      // it is told to let go.
      animation.destroy?.();
    };
  }, []);
}

/**
 * Swallow the click a finished drag would otherwise fire on the row it started
 * from. Armed the moment a drag engages rather than when it drops, so drop,
 * Escape and a blurred window are all covered by the same listener.
 *
 * It disarms after one swallowed click, and on the next pointer press either
 * way. Staying armed would eat the click that Enter raises on the same row —
 * that click has no pointer press in front of it to clear the trap.
 *
 * Returns its own disarm so the caller can drop it on unmount.
 */
function armClickSuppression(threadId: string): () => void {
  const disarm = () => {
    window.removeEventListener("click", suppress, true);
    window.removeEventListener("pointerdown", disarm, true);
  };
  function suppress(event: MouseEvent) {
    const clickedThreadId =
      event.target instanceof Element
        ? event.target
            .closest("[data-sidebar-thread-id]")
            ?.getAttribute("data-sidebar-thread-id")
        : null;
    if (clickedThreadId !== threadId) return;
    event.preventDefault();
    event.stopPropagation();
    disarm();
  }
  window.addEventListener("click", suppress, true);
  window.addEventListener("pointerdown", disarm, true);
  return disarm;
}

/** Nearest ancestor that actually scrolls, so a drag can reach past the fold. */
function findScrollContainer(from: Element | null): HTMLElement | null {
  for (
    let node = from?.parentElement ?? null;
    node;
    node = node.parentElement
  ) {
    const overflowY = window.getComputedStyle(node).overflowY;
    if (
      (overflowY === "auto" ||
        overflowY === "scroll" ||
        overflowY === "overlay") &&
      node.scrollHeight > node.clientHeight
    ) {
      return node;
    }
  }
  return null;
}

function sameOrder(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length && left.every((id, index) => id === right[index])
  );
}

/** How close to an edge a drag must come before the shelf starts scrolling. */
const DRAG_SCROLL_EDGE = 48;
/** Pixels per frame at the very edge, ramping down to nothing at the hot zone. */
const DRAG_SCROLL_SPEED = 14;

interface ShelfExpansionState {
  active: boolean;
  pinned: boolean;
  inactive: boolean;
  parked: boolean;
  snoozed: boolean;
  settled: boolean;
}

const DEFAULT_SHELF_EXPANSION: ShelfExpansionState = {
  active: true,
  pinned: true,
  inactive: false,
  parked: false,
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
      parked: parsed.parked === true,
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
 * The sidebar's scrolling list. Manual order is durable, while optional views
 * can sort the same rows without changing their saved positions.
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
  const workingSince = useWorkingSince(threads);
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
      void 0; // Older test harnesses and a backend still reloading have no method yet.
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
    sidebarSettings?.inactiveThreadsEnabled ??
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
  useEffect(() => {
    const pruned = pruneChildExpansion([...expandedChildParentIds]);
    safeSetItem(
      CHILD_EXPANSION_STORAGE_KEY,
      JSON.stringify(pruned),
    );
  }, [expandedChildParentIds]);
  useEffect(() => {
    safeSetItem(SHELF_EXPANSION_STORAGE_KEY, JSON.stringify(expandedShelves));
  }, [expandedShelves]);
  useEffect(() => {
    safeSetItem(ACTIVE_SORT_STORAGE_KEY, activeSortMode);
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
    parked,
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
    const onParkedShelf: typeof visible = [];
    const onSnoozeShelf: typeof visible = [];
    const onSettledShelf: typeof visible = [];
    for (const thread of visible) {
      const shelf = lifecycle.shelfFor(thread);
      if (shelf === "parked") onParkedShelf.push(thread);
      else if (shelf === "snoozed") onSnoozeShelf.push(thread);
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
      parked: sortSettledThreads(onParkedShelf, lifecycle.parkedAtFor),
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
  const clickSuppressionRef = useRef<(() => void) | null>(null);
  useEffect(
    () => () => {
      activeReorderCancelRef.current?.();
      // Suppression outlives the gesture on purpose, but not the component.
      clickSuppressionRef.current?.();
    },
    [],
  );
  // A thread can be deleted from anywhere while it is being dragged. Unmounting
  // the whole sidebar already cancels; losing just this row has to as well, or
  // the drag keeps steering an order around an id that is gone. This catches
  // the thread leaving the host's list, not every way a row can stop being a
  // valid drag source — archiving or parking it still leaves the gesture
  // running until the drop rebases it.
  useEffect(() => {
    if (!dragOrder) return;
    if (!threads.some((candidate) => candidate.id === dragOrder.movingId)) {
      activeReorderCancelRef.current?.();
    }
  }, [dragOrder, threads]);
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
  // Leaving a thread follows Pinned, then Active, including collapsed rows.
  const nextThreadCandidates = useMemo(
    () => [
      ...pinned,
      ...(activeSortMode === "project"
        ? groupActiveThreadsByProject([], inbox, projectNameById).flatMap(
            (group) => group.entries.map((entry) => entry.thread),
          )
        : sortActiveThreads(inbox, activeSortMode)),
    ],
    [activeSortMode, inbox, pinned, projectNameById],
  );
  const nextThreadCandidatesRef = useRef(nextThreadCandidates);
  nextThreadCandidatesRef.current = nextThreadCandidates;

  // A drag installs its listeners once, at pointer-down, but the shelf keeps
  // moving underneath it: the host pushes order changes mid-gesture. The order
  // and the membership a drop depends on are therefore read through these refs
  // rather than captured, or the write reverts whatever landed while the
  // pointer was down. The row and shelf a gesture belongs to stay captured —
  // those are what the gesture is about.
  const reorderTargetsRef = useRef({
    pinned: pinnedReorder,
    inbox: inboxReorder,
  });
  reorderTargetsRef.current = { pinned: pinnedReorder, inbox: inboxReorder };
  const visibleReorderIds = useCallback(
    (thread: PluginSidebarThread, shelf: "pinned" | "inbox") =>
      (shelf === "pinned" ? visiblePinned : visibleInbox)
        .filter(
          (candidate) =>
            activeSortMode !== "project" ||
            candidate.projectId === thread.projectId,
        )
        .map((candidate) => candidate.id),
    [activeSortMode, visibleInbox, visiblePinned],
  );
  const visibleReorderIdsRef = useRef(visibleReorderIds);
  visibleReorderIdsRef.current = visibleReorderIds;
  // Keyboard reordering moves a row with no pointer to follow and no sound, so
  // the only feedback a screen reader gets is what this region says.
  const [reorderAnnouncement, setReorderAnnouncement] = useState("");

  const threadReorderControls = (
    thread: PluginSidebarThread,
    shelf: "pinned" | "inbox",
  ): ThreadReorderControls => {
    const target = shelf === "pinned" ? pinnedReorder : inboxReorder;
    return {
      disabled: target.isReordering,
      isDragging:
        dragOrder?.shelf === shelf && dragOrder.movingId === thread.id,
      onPointerDown: (event) => {
        // Touch has no hover and no spare axis here: the row fills the width, so
        // a finger dragging it is far more likely to mean "scroll the shelf".
        // Reordering by touch needs a long-press to claim the gesture, which
        // this does not implement, so it declines the gesture instead of
        // competing with the scroller for it.
        if (
          target.isReordering ||
          event.button !== 0 ||
          event.pointerType === "touch"
        ) {
          return;
        }

        activeReorderCancelRef.current?.();
        const pointerId = event.pointerId;
        const startX = event.clientX;
        const startY = event.clientY;
        const movingId = thread.id;
        // Captured while the event is still being dispatched, which is the only
        // time `currentTarget` is meaningful.
        const rowAnchor = event.currentTarget;
        let engaged = false;
        let finished = false;
        let previousUserSelect = "";
        let previousCursor = "";
        let listElement: HTMLElement | null = null;
        let scrollContainer: HTMLElement | null = null;
        let scrollFrame = 0;
        let pointerX = startX;
        let pointerY = startY;

        function cleanup() {
          window.removeEventListener("pointermove", onPointerMove);
          window.removeEventListener("pointerup", onPointerUp);
          window.removeEventListener("pointercancel", onPointerCancel);
          window.removeEventListener("keydown", onKeyDown);
          window.removeEventListener("blur", cancel);
          window.removeEventListener("resize", cancel);
          window.removeEventListener("pagehide", cancel);
          document.removeEventListener("visibilitychange", onVisibilityChange);
          if (scrollFrame !== 0) {
            window.cancelAnimationFrame(scrollFrame);
            scrollFrame = 0;
          }
          if (engaged) {
            document.body.style.userSelect = previousUserSelect;
            document.body.style.cursor = previousCursor;
            resumeListAnimations();
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
          suspendListAnimations();
          clickSuppressionRef.current?.();
          clickSuppressionRef.current = armClickSuppression(movingId);
          listElement = rowAnchor.closest("ul");
          scrollContainer = findScrollContainer(listElement);
          const next = {
            shelf,
            movingId,
            ids: visibleReorderIdsRef.current(thread, shelf),
          };
          dragOrderRef.current = next;
          setDragOrder(next);
          scrollFrame = window.requestAnimationFrame(onScrollFrame);
        }

        function reorderAt(clientX: number, clientY: number) {
          const current = dragOrderRef.current;
          if (!current || current.shelf !== shelf) return;
          const visibleIds = visibleReorderIdsRef.current(thread, shelf);
          const hit = document.elementFromPoint(clientX, clientY);
          const row = hit instanceof Element ? hit.closest("li") : null;
          const targetId = row
            ?.querySelector<HTMLAnchorElement>("[data-sidebar-thread-id]")
            ?.getAttribute("data-sidebar-thread-id");

          let nextIds: string[] | null = null;
          if (
            row &&
            targetId &&
            visibleIds.includes(targetId) &&
            current.movingId !== targetId
          ) {
            const rect = row.getBoundingClientRect();
            nextIds = movePinnedId(
              current.ids,
              current.movingId,
              targetId,
              clientY < rect.top + rect.height / 2 ? "before" : "after",
            );
          } else if (!targetId && listElement) {
            // Headers, padding and the run-off below the last row are not rows,
            // so hit-testing alone strands a drag aimed at either end of a
            // shelf. Resolve those against the list box instead — but only
            // directly above or below it, or a pointer parked off to the side
            // of the sidebar would keep snapping the row to an end.
            const listRect = listElement.getBoundingClientRect();
            const within =
              clientX >= listRect.left && clientX <= listRect.right;
            const before = within && clientY < listRect.top;
            const after = within && clientY > listRect.bottom;
            const edgeId = before
              ? current.ids.find((id) => id !== current.movingId)
              : after
                ? [...current.ids]
                    .reverse()
                    .find((id) => id !== current.movingId)
                : undefined;
            if (edgeId) {
              nextIds = movePinnedId(
                current.ids,
                current.movingId,
                edgeId,
                before ? "before" : "after",
              );
            }
          }

          if (!nextIds || sameOrder(nextIds, current.ids)) return;
          const next = { ...current, ids: nextIds };
          dragOrderRef.current = next;
          setDragOrder(next);
        }

        function onScrollFrame() {
          scrollFrame = 0;
          if (finished || !engaged) return;
          if (scrollContainer) {
            const rect = scrollContainer.getBoundingClientRect();
            const fromTop = pointerY - rect.top;
            const fromBottom = rect.bottom - pointerY;
            // A pointer dragged off to the side has left the shelf; it should
            // not keep driving it.
            const within =
              pointerX >= rect.left && pointerX <= rect.right;
            const delta = !within
              ? 0
              : fromTop < DRAG_SCROLL_EDGE
                ? -DRAG_SCROLL_SPEED *
                  (1 - Math.max(fromTop, 0) / DRAG_SCROLL_EDGE)
                : fromBottom < DRAG_SCROLL_EDGE
                  ? DRAG_SCROLL_SPEED *
                    (1 - Math.max(fromBottom, 0) / DRAG_SCROLL_EDGE)
                  : 0;
            if (delta !== 0) {
              const scrollTop = scrollContainer.scrollTop;
              scrollContainer.scrollTop = scrollTop + delta;
              // Only re-resolve when the view actually moved, so a drag parked
              // against an end does not churn state every frame. A host update
              // can still shift rows without the scroll position changing;
              // the next pointermove or the drop picks that up.
              if (scrollContainer.scrollTop !== scrollTop) {
                reorderAt(pointerX, pointerY);
              }
            }
          }
          scrollFrame = window.requestAnimationFrame(onScrollFrame);
        }

        function onPointerMove(moveEvent: PointerEvent) {
          if (finished || moveEvent.pointerId !== pointerId) return;
          // A button let go outside the window never delivers its pointerup.
          if ((moveEvent.buttons & 1) === 0) {
            cancel();
            return;
          }
          pointerX = moveEvent.clientX;
          pointerY = moveEvent.clientY;
          if (!engaged) {
            const deltaX = moveEvent.clientX - startX;
            const deltaY = moveEvent.clientY - startY;
            // Radial distance, but still vertical-dominant: a sideways gesture
            // belongs to the host's drag-to-split, not to reordering.
            if (
              Math.hypot(deltaX, deltaY) < 6 ||
              Math.abs(deltaY) <= Math.abs(deltaX)
            ) {
              return;
            }
            engage();
          }
          moveEvent.preventDefault();
          reorderAt(moveEvent.clientX, moveEvent.clientY);
        }

        function onPointerUp(upEvent: PointerEvent) {
          if (finished || upEvent.pointerId !== pointerId) return;
          // Auto-scroll and host updates both move the list under a pointer
          // that never moved again, so the last pointermove is not necessarily
          // the last word on where this row belongs.
          if (engaged) reorderAt(upEvent.clientX, upEvent.clientY);
          const current = dragOrderRef.current;
          finished = true;
          cleanup();
          if (!engaged || !current || current.shelf !== shelf) return;

          dragOrderRef.current = null;
          setDragOrder(null);
          if (shelf === "pinned") {
            const live = reorderTargetsRef.current.pinned;
            void live.reorder(
              rebaseMovedId(live.ids, current.ids, current.movingId),
              current.movingId,
            );
          } else {
            const live = reorderTargetsRef.current.inbox;
            void live.reorder(
              rebaseMovedId(live.ids, current.ids, current.movingId),
            );
          }
        }

        function onPointerCancel(cancelEvent: PointerEvent) {
          if (cancelEvent.pointerId === pointerId) cancel();
        }

        function onKeyDown(keyEvent: KeyboardEvent) {
          if (keyEvent.key === "Escape") cancel();
        }

        function onVisibilityChange() {
          if (document.visibilityState === "hidden") cancel();
        }

        window.addEventListener("pointermove", onPointerMove, {
          passive: false,
        });
        window.addEventListener("pointerup", onPointerUp);
        window.addEventListener("pointercancel", onPointerCancel);
        window.addEventListener("keydown", onKeyDown);
        // A gesture interrupted by lost focus, a hidden tab or a resize has no
        // drop target left worth guessing at.
        window.addEventListener("blur", cancel);
        window.addEventListener("resize", cancel);
        window.addEventListener("pagehide", cancel);
        document.addEventListener("visibilitychange", onVisibilityChange);
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
        const currentIds = visibleReorderIdsRef.current(thread, shelf);
        const ids = movePinnedIdByOffset(
          currentIds,
          thread.id,
          event.key === "ArrowUp" ? -1 : 1,
        );
        const shelfName = shelf === "pinned" ? "Pinned" : "Active";
        const title = threadDisplayTitle(thread);
        setReorderAnnouncement(
          sameOrder(ids, currentIds)
            ? `${title} is already ${
                event.key === "ArrowUp" ? "first" : "last"
              } in ${shelfName}`
            : `${title} moved to ${ids.indexOf(thread.id) + 1} of ${
                ids.length
              } in ${shelfName}`,
        );
        if (shelf === "pinned") {
          const live = reorderTargetsRef.current.pinned;
          void live.reorder(rebaseMovedId(live.ids, ids, thread.id), thread.id);
        } else {
          const live = reorderTargetsRef.current.inbox;
          void live.reorder(rebaseMovedId(live.ids, ids, thread.id));
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
  const visibleParked = useMemo(
    () =>
      visibleShelfThreads(
        parked,
        expandedShelves.parked,
        activeListThreadId,
      ),
    [activeListThreadId, expandedShelves.parked, parked],
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
  const wokeThreadIds = useMemo(
    () =>
      new Set(
        [...pinned, ...inbox, ...inactive]
          .filter((thread) => lifecycle.wokeFor(thread))
          .map((thread) => thread.id),
      ),
    [inactive, inbox, lifecycle, pinned],
  );

  const parkActiveThread = async (
    thread: PluginSidebarThread,
    mutation: () => Promise<boolean>,
  ) => {
    const parked = await mutation();
    if (!parked || activeThreadIdRef.current !== thread.id) return;

    // Read the latest list after the request, since another client may
    // have moved or reordered the first candidate while it was pending.
    const nextThread = nextThreadCandidatesRef.current.find(
      (candidate) => candidate.id !== thread.id,
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

  const parkThread = (thread: PluginSidebarThread) =>
    void parkActiveThread(thread, () => lifecycle.park(thread.id));
  const settleThread = (thread: PluginSidebarThread) =>
    void parkActiveThread(thread, () => lifecycle.settle(thread.id));
  const snoozeThread = (thread: PluginSidebarThread, until: number) =>
    void parkActiveThread(thread, () => lifecycle.snooze(thread.id, until));

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
      isWoke={wokeThreadIds.has(thread.id)}
      canPark={lifecycle.canPark(thread)}
      snoozePresets={snoozePresets}
      onNavigate={onNavigate}
      onPark={() => parkThread(thread)}
      onSettle={() => settleThread(thread)}
      onSnooze={(until) => snoozeThread(thread, until)}
      onAcknowledgeWake={() => void lifecycle.acknowledgeWake(thread.id)}
      childThreads={childrenByParentId.get(thread.id) ?? []}
      childrenByParent={childrenByParentId}
      activeThreadId={activeThreadId}
      childrenExpanded={expandedChildParentIds.has(thread.id)}
      showRunningChildrenWhenCollapsed={
        sidebarSettings?.showRunningChildrenWhenCollapsed ??
        DEFAULT_SIDEBAR_SETTINGS.showRunningChildrenWhenCollapsed
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
    <WorkingSinceContext.Provider value={workingSince}>
    <OpenPortsProvider>
      <div className="flex min-h-0 flex-1 flex-col">
        {/* The one control the host has no equivalent for. Everything else in
            the chrome above — New thread, search — is bb's and stays bb's. */}
        <div className="flex shrink-0 items-center gap-1 px-2 pb-1">
          <ProjectScopeSelect
            scope={scope}
            projects={projects}
            projectIconRevision={projectIconRevision}
            onScopeChange={setScope}
          />
        </div>

        <p role="status" aria-live="polite" className="sr-only">
          {reorderAnnouncement}
        </p>

        <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-2">
          {status === "loading" ? (
            <ThreadListLoading />
          ) : status === "error" ? (
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
              onNavigate={onNavigate}
            />
          ) : (
            <div ref={attachShelvesAutoAnimateRef} className="flex flex-col">
              {pinned.length > 0 ? (
                <CollapsibleShelf
                  label="Pinned"
                  icon="Pin"
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
                  icon="Pulse"
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
                  icon="PauseCircle"
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
              <CompactShelf
                label="Snoozed"
                onPark={parkThread}
                onSettle={settleThread}
                onSnooze={snoozeThread}
                icon="Clock"
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
                projectIconRevision={projectIconRevision}
              />
              <CompactShelf
                label="Parked"
                onPark={parkThread}
                onSettle={settleThread}
                onSnooze={snoozeThread}
                icon="Car"
                threads={parked}
                projectNameById={projectNameById}
                expanded={expandedShelves.parked}
                onToggle={() =>
                  setExpandedShelves((current) => ({
                    ...current,
                    parked: !current.parked,
                  }))
                }
                shelf="parked"
                visibleThreads={visibleParked}
                activeThreadId={activeThreadId}
                lifecycle={lifecycle}
                snoozePresets={snoozePresets}
                onNavigate={onNavigate}
                projectIconRevision={projectIconRevision}
              />
              <CompactShelf
                label="Settled"
                onPark={parkThread}
                onSettle={settleThread}
                onSnooze={snoozeThread}
                icon="Meditation"
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
    </OpenPortsProvider>
    </WorkingSinceContext.Provider>
  );
}

/**
 * How long the initial load may run before the indicator shows. Most loads
 * finish well inside this, and a spinner that appears only to vanish at once
 * reads as a flicker, not as progress.
 */
const LOADING_INDICATOR_DELAY_MS = 200;

/**
 * The list's placeholder while bb is still loading threads. The paragraph
 * mounts empty at the size it will have with text, so the layout does not
 * jump when the text arrives. Because the live region already exists before
 * its text is added, a screen reader announces "Loading threads…" once, and
 * says nothing when a load finishes before the delay. Unmounting on any new
 * status cancels the timer.
 */
function ThreadListLoading() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const timer = window.setTimeout(
      () => setVisible(true),
      LOADING_INDICATOR_DELAY_MS,
    );
    return () => window.clearTimeout(timer);
  }, []);
  return (
    <p
      role="status"
      className="px-2 py-6 text-center text-xs text-muted-foreground"
    >
      <span className="flex h-4 items-center justify-center gap-1.5">
        {visible ? (
          <>
            <Icon
              name="Loading"
              aria-hidden="true"
              className="size-3.5 shrink-0 animate-spin opacity-75 motion-reduce:animate-none"
            />
            Loading threads…
          </>
        ) : null}
      </span>
    </p>
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
function CompactShelf({
  label,
  icon,
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
  projectIconRevision,
  settledLimit,
  onLoadMore,
  onPark,
  onSettle,
  onSnooze,
}: {
  label: string;
  icon: IconName;
  threads: readonly PluginSidebarThread[];
  projectNameById?: ReadonlyMap<string, string>;
  expanded: boolean;
  onToggle: () => void;
  shelf: "parked" | "snoozed" | "settled";
  visibleThreads: readonly PluginSidebarThread[];
  activeThreadId: string | null;
  lifecycle: LifecycleApi;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onNavigate: () => void;
  projectIconRevision: number;
  settledLimit?: number;
  onLoadMore?: () => void;
  onPark: (thread: PluginSidebarThread) => void;
  onSettle: (thread: PluginSidebarThread) => void;
  onSnooze: (thread: PluginSidebarThread, until: number) => void;
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
      icon={icon}
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
            shelf={shelf}
            parkedAt={lifecycle.parkedAtFor(thread)}
            onPark={() => onPark(thread)}
            onSettle={() => onSettle(thread)}
            wakeAt={lifecycle.wakeAtFor(thread)}
            now={now}
            snoozePresets={snoozePresets}
            onSnooze={(until) => onSnooze(thread, until)}
            onNavigate={onNavigate}
            onRestore={() =>
              shelf === "parked"
                ? void lifecycle.resume(thread.id)
                : shelf === "snoozed"
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
  icon,
  count,
  expanded,
  onToggle,
  action,
  children,
}: {
  label: string;
  icon: IconName;
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
          <span className="flex shrink-0 items-center gap-1.5 text-2xs font-medium text-muted-foreground/70">
            <Icon name={icon} className="size-3.5 shrink-0" aria-hidden />
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
