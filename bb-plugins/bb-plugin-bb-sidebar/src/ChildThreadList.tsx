import { useId, useState } from "react";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { Disc } from "./Disc";
import { cn } from "./lib/utils";
import { relativeTimeLabel } from "./relative-time";
import { StatusGlyph } from "./StatusGlyph";
import { threadDisplayTitle } from "./inbox";
import { canParkThread } from "./lifecycle";
import { RowContextMenu } from "./RowContextMenu";

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

export function isChildRunning(thread: PluginSidebarThread): boolean {
  switch (thread.indicator) {
    case "runtime":
    case "workflow":
    case "background-agent":
    case "background-command":
    case "plan-mode":
    case "goal":
    case "working-draft":
      return true;
    default:
      return false;
  }
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

export function ChildThreadBadge({
  threads,
  expanded,
  controls,
  onToggle,
}: {
  threads: readonly PluginSidebarThread[];
  expanded: boolean;
  controls: string;
  onToggle: () => void;
}) {
  const visibleThreads = threads.filter((thread) => !thread.isArchived);
  const needsYou = childNeedsYouCount(visibleThreads);
  const count = visibleThreads.length;
  const tooltip = `${count} child thread${count === 1 ? "" : "s"}${
    needsYou > 0 ? `, ${needsYou} need you` : ""
  }`;

  return (
    <Tooltip label={tooltip} side="bottom">
      <button
        type="button"
        aria-label={tooltip}
        aria-expanded={expanded}
        aria-controls={controls}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onToggle();
        }}
        className={cn(
          "pointer-events-auto flex h-5 shrink-0 items-center gap-1 rounded-full px-1.5 text-xs font-medium",
          "outline-none focus-visible:ring-1 focus-visible:ring-ring",
          needsYou > 0
            ? "bg-[#fbf0dd] text-[#c9791b] dark:bg-amber-950/60 dark:text-amber-300"
            : "bg-[#ececee] text-[#3a3a3c] dark:bg-muted dark:text-foreground",
        )}
      >
        <ChildThreadDots threads={threads} compact />
        <span className="tabular-nums">{count}</span>
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
  onOpenThread,
}: {
  threads: readonly PluginSidebarThread[];
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>;
  variant: "header" | "sidebar";
  now?: number;
  id?: string;
  activeThreadId?: string | null;
  onOpenThread: (threadId: string) => void;
}) {
  const disclosureId = useId();
  const visibleThreads = threads.filter((thread) => !thread.isArchived);
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
          : "ml-[21px] mt-1 border-l-[1.5px] border-[#d6d6d8] pl-3 dark:border-border",
      )}
    >
      {visibleThreads.map((child) => {
        const title = threadDisplayTitle(child);
        const grandchildren = (childrenByParent.get(child.id) ?? []).filter(
          (thread) => !thread.isArchived,
        );
        const grandchildrenExpanded =
          expandedGrandchildParentIds.has(child.id) ||
          grandchildren.some((grandchild) => grandchild.id === activeThreadId);
        const grandchildrenId = `${disclosureId}-${child.id}`;
        return (
          <li key={child.id} className="list-none">
            <ChildThreadRow
              thread={child}
              relation="child"
              variant={variant}
              now={now}
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
            {grandchildren.length > 0 && grandchildrenExpanded ? (
              <ul
                id={grandchildrenId}
                aria-label={`Grandchildren of ${title}`}
                data-grandchild-thread-list={variant}
                className={cn(
                  "flex flex-col",
                  variant === "header"
                    ? "ml-5 border-l border-border pl-1"
                    : "ml-3 border-l-[1.5px] border-[#d6d6d8] pl-2 dark:border-border",
                )}
              >
                {grandchildren.map((grandchild) => (
                  <li key={grandchild.id} className="list-none">
                    <ChildThreadRow
                      thread={grandchild}
                      relation="grandchild"
                      variant={variant}
                      now={now}
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
  onOpenThread,
  disclosure,
}: {
  thread: PluginSidebarThread;
  relation: "child" | "grandchild";
  variant: "header" | "sidebar";
  now?: number;
  onOpenThread: (threadId: string) => void;
  disclosure?: GrandchildDisclosure;
}) {
  const title = threadDisplayTitle(thread);
  const needsYou = thread.hasPendingInteraction;
  const running = !needsYou && isChildRunning(thread);

  return (
    <RowContextMenu thread={thread} canArchive={canParkThread(thread)}>
      <div
        className={cn(
          "flex w-full items-center rounded-md text-left",
          variant === "header"
            ? "hover:bg-accent"
            : "h-7 hover:bg-sidebar-accent/60",
          variant === "sidebar" &&
            needsYou &&
            "bg-[#fdf6ea] hover:bg-[#fdf6ea] dark:bg-amber-950/30 dark:hover:bg-amber-950/40",
        )}
      >
        <button
          type="button"
          aria-label={childThreadOpenLabel(thread, relation, title)}
          onClick={() => onOpenThread(thread.id)}
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
            )}
          >
            <span className="truncate">{title}</span>
            {variant === "header" ? (
              <span className="truncate text-2xs text-muted-foreground">
                {thread.originKind ?? "thread"}
              </span>
            ) : null}
          </span>
          {variant === "header" ? (
            <span className="shrink-0">
              <StatusGlyph
                indicator={thread.indicator}
                label={thread.indicatorLabel}
              />
            </span>
          ) : null}
          {variant === "sidebar" ? (
            <span className="flex shrink-0 items-center gap-1 pr-2">
              {needsYou ? <ChildStatusFlag kind="needs-you" /> : null}
              {running ? <ChildStatusFlag kind="running" /> : null}
              <span className="shrink-0 font-mono text-2xs tabular-nums text-[#a0a0a4]">
                {relativeTimeLabel(thread.updatedAt, now ?? Date.now())}
              </span>
            </span>
          ) : null}
        </button>
        {disclosure ? (
          <GrandchildDisclosureButton title={title} {...disclosure} />
        ) : null}
      </div>
    </RowContextMenu>
  );
}

function childThreadOpenLabel(
  thread: PluginSidebarThread,
  relation: "child" | "grandchild",
  title: string,
): string {
  const status = thread.hasPendingInteraction
    ? "Needs you"
    : isChildRunning(thread)
      ? "Running"
      : thread.indicatorLabel;
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

function ChildStatusFlag({ kind }: { kind: "needs-you" | "running" }) {
  return (
    <span
      className={cn(
        "shrink-0 rounded px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-[0.08em]",
        kind === "needs-you"
          ? "bg-[#fbf0dd] text-[#c9791b] dark:bg-amber-950/60 dark:text-amber-300"
          : "bg-[#e7eefa] text-[#3f6fc4] dark:bg-sky-950/60 dark:text-sky-300",
      )}
    >
      {kind === "needs-you" ? "Needs you" : "Running"}
    </span>
  );
}
