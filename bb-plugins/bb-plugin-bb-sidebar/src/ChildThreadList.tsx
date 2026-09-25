import { useId, useState } from "react";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { Disc } from "./Disc";
import { cn } from "./lib/utils";
import { StatusGlyph } from "./StatusGlyph";
import {
  STATUS_SLOT_CLASS,
  StatusOrTime,
  threadStatusLabel,
} from "./StatusSlot";
import { useWorkingSinceContext } from "./useWorkingSince";
import { threadDisplayTitle } from "./inbox";
import { canParkThread } from "./lifecycle";
import { RowContextMenu } from "./RowContextMenu";
import { InlineThreadTitle } from "./InlineThreadTitle";
import { ThreadDetailsTooltip } from "./ThreadDetailsTooltip";
import { OpenPortsIndicator } from "./OpenPorts";
import {
  childStatusIndicator,
  childStatusKind,
  childStatusPhrase,
  childStatusSummary,
  childSubtree,
  type ChildStatusKind,
} from "./child-status";

const MAX_CHILD_DOTS = 3;

export function childrenOf(
  threads: readonly PluginSidebarThread[],
  parentThreadId: string,
): PluginSidebarThread[] {
  return threads
    .filter(
      (thread) =>
        !thread.isArchived && thread.parentThreadId === parentThreadId,
    )
    .sort((left, right) => left.createdAt - right.createdAt);
}

export function childThreadsByParent(
  threads: readonly PluginSidebarThread[],
): ReadonlyMap<string, readonly PluginSidebarThread[]> {
  const result = new Map<string, PluginSidebarThread[]>();
  for (const thread of threads) {
    if (thread.isArchived || !thread.parentThreadId) continue;
    const siblings = result.get(thread.parentThreadId) ?? [];
    siblings.push(thread);
    result.set(thread.parentThreadId, siblings);
  }
  for (const siblings of result.values()) {
    siblings.sort((left, right) => left.createdAt - right.createdAt);
  }
  return result;
}

export function childNeedsYouCount(
  threads: readonly PluginSidebarThread[],
): number {
  return threads.filter(
    (thread) => !thread.isArchived && thread.hasPendingInteraction,
  ).length;
}

/**
 * The children a collapsed list still shows: the active child, or the child
 * whose grandchild is active. Mirrors how a collapsed shelf keeps its active
 * thread visible, so collapsing a parent never hides the open chat.
 */
export function activeChildThreads(
  threads: readonly PluginSidebarThread[],
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>,
  activeThreadId: string | null | undefined,
): PluginSidebarThread[] {
  if (!activeThreadId) return [];
  return threads.filter(
    (child) =>
      !child.isArchived &&
      (child.id === activeThreadId ||
        childrenByParent
          .get(child.id)
          ?.some((grandchild) => grandchild.id === activeThreadId) === true),
  );
}

/**
 * Whether a child earns a row while its section is collapsed: anything with
 * a status to report (failed, waiting on the user, finished but unread, or
 * still working). Read and idle children fold away; so does any indicator bb
 * ships later, until it is given a kind. This is the same set the collapsed
 * badge counts, so the rows and the badge never disagree.
 */
export function childNeedsAttention(thread: PluginSidebarThread): boolean {
  return childStatusKind(thread) !== null;
}

/** Children retained while collapsed, including paths to visible grandchildren. */
export function collapsedChildThreads(
  threads: readonly PluginSidebarThread[],
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>,
  activeThreadId: string | null | undefined,
  showAttentionChildren: boolean,
): PluginSidebarThread[] {
  return threads.filter((child) => {
    if (child.isArchived) return false;
    const grandchildren = childrenByParent.get(child.id) ?? [];
    return (
      child.id === activeThreadId ||
      grandchildren.some((grandchild) => grandchild.id === activeThreadId) ||
      (showAttentionChildren &&
        (childNeedsAttention(child) ||
          grandchildren.some(
            (grandchild) =>
              !grandchild.isArchived && childNeedsAttention(grandchild),
          )))
    );
  });
}

export function ChildThreadDots({
  threads,
  compact = false,
}: {
  threads: readonly PluginSidebarThread[];
  compact?: boolean;
}) {
  const visibleThreads = threads.filter((thread) => !thread.isArchived);
  return (
    <span className="flex shrink-0 items-center" aria-hidden>
      {visibleThreads.slice(0, MAX_CHILD_DOTS).map((thread, index) => (
        <span
          key={thread.id}
          data-child-thread-dot=""
          className={cn(index > 0 && (compact ? "-ml-1" : "-ml-1.5"))}
        >
          <Disc
            thread={thread}
            className={
              compact
                ? "size-[9px] border-[1.5px] border-sidebar"
                : undefined
            }
          />
        </span>
      ))}
    </span>
  );
}

/**
 * The badge tint for the subtree's most urgent state. Needs-you keeps the
 * amber the rest of the sidebar uses for a raised hand in a child row; the
 * others borrow the status glyph tones so the card and the child rows agree.
 */
function childStatusBadgeClass(kind: ChildStatusKind | null): string {
  switch (kind) {
    case "failed":
      return "bg-[color:var(--bb-sidebar-badge-failed-bg)] text-[color:var(--bb-sidebar-badge-failed-fg)]";
    case "needs-you":
      return "bg-[color:var(--bb-sidebar-badge-needs-you-bg)] text-[color:var(--bb-sidebar-badge-needs-you-fg)]";
    case "done":
      return "bg-[color:var(--bb-sidebar-badge-done-bg)] text-[color:var(--bb-sidebar-badge-done-fg)]";
    case "working":
      return "bg-[color:var(--bb-sidebar-badge-working-bg)] text-[color:var(--bb-sidebar-badge-working-fg)]";
    default:
      return "bg-muted text-foreground";
  }
}

export function ChildThreadBadge({
  threads,
  childrenByParent,
  expanded,
  controls,
  onToggle,
}: {
  threads: readonly PluginSidebarThread[];
  /** When given, grandchildren count toward the status rollup (not the count). */
  childrenByParent?: ReadonlyMap<string, readonly PluginSidebarThread[]>;
  expanded: boolean;
  controls: string;
  onToggle: () => void;
}) {
  const visibleThreads = threads.filter((thread) => !thread.isArchived);
  const count = visibleThreads.length;
  const summary = childStatusSummary(
    childrenByParent
      ? childSubtree(visibleThreads, childrenByParent)
      : visibleThreads,
  );
  const tooltip = `${count} child thread${count === 1 ? "" : "s"}${childStatusPhrase(summary)}`;

  return (
    <Tooltip label={tooltip} side="bottom">
      <button
        type="button"
        aria-label={tooltip}
        aria-expanded={expanded}
        aria-controls={controls}
        data-child-status={summary.dominant ?? undefined}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onToggle();
        }}
        className={cn(
          "pointer-events-auto flex h-5 shrink-0 items-center gap-1 rounded-full px-1.5 text-xs font-medium",
          "outline-none focus-visible:ring-1 focus-visible:ring-ring",
          childStatusBadgeClass(summary.dominant),
        )}
      >
        <ChildThreadDots threads={threads} compact />
        <span className="tabular-nums">{count}</span>
        {summary.dominant ? (
          <StatusGlyph
            indicator={childStatusIndicator(summary.dominant)}
            label={null}
            className="size-3 text-current"
          />
        ) : null}
        <Icon
          name={expanded ? "ChevronUp" : "ChevronDown"}
          className="size-3"
          aria-hidden
        />
      </button>
    </Tooltip>
  );
}

export function ChildThreadList({
  threads,
  childrenByParent,
  variant,
  now,
  id,
  activeThreadId,
  expanded = true,
  showRunningChildrenWhenCollapsed = false,
  onOpenThread,
}: {
  threads: readonly PluginSidebarThread[];
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>;
  variant: "header" | "sidebar";
  now?: number;
  id?: string;
  activeThreadId?: string | null;
  /** When false, only the active child (or the child of the active grandchild) shows. */
  expanded?: boolean;
  /**
   * While collapsed, also keep children with something to report: failed,
   * waiting on the user, unread, or working. The setting keeps its original
   * key; only its wording changed when it grew beyond running children.
   */
  showRunningChildrenWhenCollapsed?: boolean;
  onOpenThread: (threadId: string) => void;
}) {
  const disclosureId = useId();
  const visibleThreads = expanded
    ? threads.filter((thread) => !thread.isArchived)
    : collapsedChildThreads(
        threads,
        childrenByParent,
        activeThreadId,
        showRunningChildrenWhenCollapsed,
      );
  const [expandedGrandchildParentIds, setExpandedGrandchildParentIds] =
    useState<ReadonlySet<string>>(() => new Set());

  const toggleGrandchildren = (threadId: string) => {
    setExpandedGrandchildParentIds((current) => {
      const next = new Set(current);
      if (next.has(threadId)) {
        next.delete(threadId);
      } else {
        next.add(threadId);
      }
      return next;
    });
  };

  return (
    <ul
      id={id}
      aria-label="Child threads"
      data-child-thread-list={variant}
      onContextMenu={(event) => event.stopPropagation()}
      className={cn(
        "flex flex-col",
        variant === "header"
          ? "gap-px p-1.5 pt-0.5"
          : "ml-[21px] mt-1 border-l-[1.5px] border-border pl-3",
      )}
    >
      {visibleThreads.map((child) => {
        const title = threadDisplayTitle(child);
        const grandchildren = (childrenByParent.get(child.id) ?? []).filter(
          (thread) => !thread.isArchived,
        );
        const grandchildrenExpanded = expandedGrandchildParentIds.has(child.id);
        // A collapsed disclosure still shows the active grandchild, so the
        // open chat stays reachable without forcing the list open.
        const visibleGrandchildren = grandchildrenExpanded
          ? grandchildren
          : grandchildren.filter(
              (grandchild) =>
                grandchild.id === activeThreadId ||
                (showRunningChildrenWhenCollapsed &&
                  childNeedsAttention(grandchild)),
            );
        const grandchildrenId = `${disclosureId}-${child.id}`;
        return (
          <li key={child.id} className="list-none">
            <ChildThreadRow
              thread={child}
              relation="child"
              variant={variant}
              now={now}
              isActive={child.id === activeThreadId}
              onOpenThread={onOpenThread}
              disclosure={
                grandchildren.length > 0
                  ? {
                      count: grandchildren.length,
                      expanded: grandchildrenExpanded,
                      controls: grandchildrenId,
                      onToggle: () => toggleGrandchildren(child.id),
                    }
                  : undefined
              }
            />
            {visibleGrandchildren.length > 0 ? (
              <ul
                id={grandchildrenId}
                aria-label={`Grandchildren of ${title}`}
                data-grandchild-thread-list={variant}
                className={cn(
                  "flex flex-col",
                  variant === "header"
                    ? "ml-5 border-l border-border pl-1"
                    : "ml-3 border-l-[1.5px] border-border pl-2",
                )}
              >
                {visibleGrandchildren.map((grandchild) => (
                  <li key={grandchild.id} className="list-none">
                    <ChildThreadRow
                      thread={grandchild}
                      relation="grandchild"
                      variant={variant}
                      now={now}
                      isActive={grandchild.id === activeThreadId}
                      onOpenThread={onOpenThread}
                    />
                  </li>
                ))}
              </ul>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

interface GrandchildDisclosure {
  count: number;
  expanded: boolean;
  controls: string;
  onToggle: () => void;
}

function ChildThreadRow({
  thread,
  relation,
  variant,
  now,
  isActive = false,
  onOpenThread,
  disclosure,
}: {
  thread: PluginSidebarThread;
  relation: "child" | "grandchild";
  variant: "header" | "sidebar";
  now?: number;
  isActive?: boolean;
  onOpenThread: (threadId: string) => void;
  disclosure?: GrandchildDisclosure;
}) {
  const title = threadDisplayTitle(thread);
  const needsYou = thread.hasPendingInteraction;
  const effectiveNow = now ?? Date.now();
  const workingSince = useWorkingSinceContext();
  const visibleStatus = threadStatusLabel(
    thread,
    workingSince.get(thread.id),
    effectiveNow,
  );
  const [isRenaming, setIsRenaming] = useState(false);
  const RowAction = isRenaming ? "div" : "button";

  return (
    <RowContextMenu
      thread={thread}
      canArchive={canParkThread(thread)}
      onRename={() => setIsRenaming(true)}
    >
      <div
        data-child-thread-row=""
        data-active={isActive ? "true" : undefined}
        className={cn(
          "flex w-full items-center rounded-md text-left",
          variant === "header"
            ? "hover:bg-accent"
            : "h-7 hover:bg-sidebar-accent/60",
          variant === "sidebar" &&
            needsYou &&
            !isActive &&
            cn(
              "bg-[color:var(--bb-sidebar-needs-you-tint)]",
              "hover:bg-[color:var(--bb-sidebar-needs-you-tint-hover)]",
              // In dark the amber fill is only a 1.07:1 step off the sidebar,
              // so a leading rule carries where the fill cannot. It is
              // transparent in light, where the cream band already reads.
              "shadow-[inset_2px_0_0_0_var(--bb-sidebar-needs-you-accent)]",
            ),
          // The open chat gets the same tint as an active parent card, so the
          // eye finds it in a long tree the way it finds a card in the list.
          isActive &&
            (variant === "header"
              ? "bg-accent"
              : "bg-sidebar-accent hover:bg-sidebar-accent"),
        )}
      >
        <ThreadDetailsTooltip thread={thread} disabled={isRenaming}>
          <RowAction
            type={isRenaming ? undefined : "button"}
            aria-label={
              isRenaming
                ? undefined
                : childThreadOpenLabel(relation, title, visibleStatus)
            }
            aria-current={isActive && !isRenaming ? "page" : undefined}
            onClick={isRenaming ? undefined : () => onOpenThread(thread.id)}
            onKeyDown={isRenaming ? (event) => event.stopPropagation() : undefined}
            className={cn(
              "flex min-w-0 flex-1 items-center text-left outline-none focus-visible:ring-1 focus-visible:ring-ring",
              variant === "header"
                ? "gap-2 rounded-md px-2 py-1.5"
                : "h-full gap-2 rounded-md pl-2",
            )}
          >
            <Disc
              thread={thread}
              className={variant === "header" ? undefined : "size-2 border-0"}
            />
            <span
              className={cn(
                "min-w-0 flex-1 text-xs",
                variant === "header" ? "flex flex-col" : "truncate",
                isActive && "font-medium text-foreground",
              )}
            >
              <InlineThreadTitle
                thread={thread}
                editing={isRenaming}
                onEditingChange={setIsRenaming}
                className="truncate"
              />
              {variant === "header" ? (
                <span className="truncate text-2xs text-muted-foreground">
                  {thread.originKind ?? "thread"}
                </span>
              ) : null}
            </span>
            <OpenPortsIndicator thread={thread} />
            {variant === "header" ? (
              <span className="shrink-0">
                <StatusGlyph
                  indicator={thread.indicator}
                  label={thread.indicatorLabel}
                />
              </span>
            ) : null}
            {variant === "sidebar" ? (
              // Match parent cards: a recognized status owns the trailing
              // slot; an idle or future unknown status leaves it to the age.
              //
              // Sized to the label rather than fixed at the 112px "Monitoring
              // · 27m" needs: a child row also pays an indent rail and a
              // grandchild disclosure, so at a 280px sidebar a fixed slot left
              // the title about six characters. No floor either: the label is
              // right-aligned, so a floor under "8h" is only empty space the
              // title could use. The ceiling keeps the longest status intact;
              // the cost is that the title's truncation point shifts with the
              // length of that row's status.
              <span
                className={cn(STATUS_SLOT_CLASS, "w-auto max-w-28 pr-2")}
              >
                <StatusOrTime thread={thread} now={effectiveNow} />
              </span>
            ) : null}
          </RowAction>
        </ThreadDetailsTooltip>
        {disclosure ? (
          <GrandchildDisclosureButton title={title} {...disclosure} />
        ) : null}
      </div>
    </RowContextMenu>
  );
}

function childThreadOpenLabel(
  relation: "child" | "grandchild",
  title: string,
  status: string | null,
): string {
  return `Open ${relation} thread: ${title}${status ? `, ${status}` : ""}`;
}

function GrandchildDisclosureButton({
  title,
  count,
  expanded,
  controls,
  onToggle,
}: GrandchildDisclosure & { title: string }) {
  const noun = `grandchild thread${count === 1 ? "" : "s"}`;
  const label = `${expanded ? "Hide" : "Show"} ${count} ${noun} for ${title}`;

  return (
    <Tooltip label={`${count} ${noun}`} side="bottom">
      <button
        type="button"
        aria-label={label}
        aria-expanded={expanded}
        aria-controls={controls}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onToggle();
        }}
        className="mr-1 flex h-5 shrink-0 items-center gap-0.5 rounded px-1 font-mono text-2xs tabular-nums text-muted-foreground outline-none hover:bg-accent hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
      >
        <span>{count}</span>
        <Icon
          name={expanded ? "ChevronUp" : "ChevronDown"}
          className="size-3"
          aria-hidden
        />
      </button>
    </Tooltip>
  );
}
