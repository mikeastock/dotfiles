import {
  useId,
  useState,
  type KeyboardEventHandler,
  type PointerEventHandler,
} from "react";
import {
  experimental_useSidebarThreadPullRequest as useSidebarThreadPullRequest,
  experimental_useSidebarThreadSplit as useSidebarThreadSplit,
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarPullRequest,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import {
  ChildThreadBadge,
  ChildThreadList,
  collapsedChildThreads,
} from "./ChildThreadList";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { ThreadDetailsTooltip } from "./ThreadDetailsTooltip";
import { SnoozeSelect } from "./SnoozeSelect";
import { cn } from "./lib/utils";
import { RowContextMenu } from "./RowContextMenu";
import { ProviderGlyph, type SidebarProvider } from "./ProviderGlyph";
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
import { threadDisplayTitle } from "./inbox";
import { InlineThreadTitle } from "./InlineThreadTitle";
import type { ConfiguredSnoozePreset } from "./lifecycle";
import { ProjectFavicon } from "./ProjectFavicon";
import { OpenPortsIndicator } from "./OpenPorts";
import "./settle-button.css";

export interface ThreadReorderControls {
  disabled: boolean;
  isDragging: boolean;
  onPointerDown: PointerEventHandler<HTMLAnchorElement>;
  onKeyDown: KeyboardEventHandler<HTMLAnchorElement>;
}

/**
 * One thread as a three-line card: project and status, title, then branch and
 * activity. Status lives in the row instead of its position, so manual order
 * can stay fixed while work changes state.
 *
 * The row is a positioned container with a full-bleed anchor UNDER the
 * controls, the way bb's own thread row does it: a `<button>` inside an `<a>`
 * is invalid interactive nesting and breaks keyboard behaviour.
 */
export function ThreadCard({
  thread,
  provider,
  projectName,
  projectIconUrl,
  isActive,
  isWoke,
  canPark,
  snoozePresets,
  onNavigate,
  onPark,
  onSettle,
  onSnooze,
  onAcknowledgeWake,
  childThreads,
  childrenByParent,
  activeThreadId,
  childrenExpanded,
  showRunningChildrenWhenCollapsed,
  onToggleChildren,
  reorder,
  now,
}: {
  thread: PluginSidebarThread;
  provider: SidebarProvider | null;
  projectName: string | null;
  projectIconUrl: string | null;
  isActive: boolean;
  /** A snooze ended and has not yet been acknowledged. */
  isWoke: boolean;
  /** False while the thread is working or blocked on the user. */
  canPark: boolean;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onNavigate: () => void;
  onPark?: () => void;
  onSettle: () => void;
  onSnooze: (snoozedUntil: number) => void;
  onAcknowledgeWake: () => void;
  childThreads: readonly PluginSidebarThread[];
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>;
  activeThreadId: string | null;
  childrenExpanded: boolean;
  showRunningChildrenWhenCollapsed: boolean;
  onToggleChildren: () => void;
  reorder?: ThreadReorderControls;
  /** Quantized clock, so every card in one render agrees on "now". */
  now: number;
}) {
  const actions = useSidebarThreadActions();
  const { splitProps, layout } = useSidebarThreadSplit(thread.id);
  // Opt-in per row: this costs a git-host lookup, and threads sharing a
  // worktree share one.
  const { pullRequest } = useSidebarThreadPullRequest(thread.id);
  const [isRenaming, setIsRenaming] = useState(false);
  const [isSnoozeOpen, setIsSnoozeOpen] = useState(false);
  const childListId = useId();
  const emphasis = isWoke
    ? "woke"
    : thread.isUnread
      ? "unread"
      : thread.indicator === "none"
        ? "read-idle"
        : "active";

  const showParkActions = !isWoke && canPark && (snoozePresets.length > 0 || !!onPark);
  const unpinButton = thread.isPinned ? (
    <Tooltip label="Unpin thread">
      <button
        type="button"
        aria-label={`Unpin ${threadDisplayTitle(thread)}`}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          void actions.setPinned(thread.id, false).catch((error) => {
            toast.error("Could not unpin thread", {
              description:
                error instanceof Error ? error.message : undefined,
            });
          });
        }}
        className={cn(
          "shrink-0 rounded p-0.5 text-muted-foreground hover:text-foreground",
          !showParkActions &&
            "pointer-events-auto opacity-0 transition-opacity duration-150 ease-out focus-visible:opacity-100 group-hover/card:opacity-100 motion-reduce:transition-none",
        )}
      >
        <Icon name="PinOff" className="size-3.5" />
      </button>
    </Tooltip>
  ) : null;

  return (
    <RowContextMenu
      thread={thread}
      onPark={canPark ? onPark : undefined}
      canSnooze={canPark}
      canArchive={canPark}
      snoozePresets={snoozePresets}
      onSnooze={onSnooze}
      onSettle={canPark ? onSettle : undefined}
      onRename={() => setIsRenaming(true)}
    >
      <li
        className={cn(
          "list-none",
          // The row stays in the flow — the list reorders around it — but it
          // is drawn over its neighbours rather than under them, so its shadow
          // and ring are not clipped by the rows it sits between.
          reorder?.isDragging && "relative z-20",
        )}
      >
        <div
          data-parent-card=""
          className={cn(
            "group/card relative rounded-md px-2.5 py-2 transition-colors duration-150 ease-out motion-reduce:transition-none",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
            // A thread open in another pane gets a weaker tint than the active
            // row, so the two states stay distinguishable.
            !isActive && layout !== null && "bg-sidebar-accent/30",
            // Lifted, not faded: the row under the cursor is the one the user
            // is acting on, so it should read as the most present thing on the
            // shelf. The two stacked gradients put an opaque sidebar base under
            // the accent tint, because a translucent row would let the rows it
            // passes over show straight through it.
            reorder?.isDragging &&
              "bg-[linear-gradient(var(--sidebar-accent),var(--sidebar-accent)),linear-gradient(var(--sidebar),var(--sidebar))] shadow-lg ring-1 ring-sidebar-border",
          )}
        >
          <ThreadDetailsTooltip thread={thread} disabled={isRenaming || !!reorder?.isDragging}>
            <a
              // Both attributes, or bb's nine thread shortcuts stop finding rows.
              data-sidebar-thread-shortcut-target=""
              data-sidebar-thread-id={thread.id}
              href="#"
              aria-label={threadDisplayTitle(thread)}
              aria-current={isActive ? "page" : undefined}
              draggable={false}
              aria-keyshortcuts={
                reorder ? "Alt+ArrowUp Alt+ArrowDown" : undefined
              }
              onPointerDown={(event) => {
                splitProps.onPointerDown?.(event);
                reorder?.onPointerDown(event);
              }}
              onKeyDown={reorder?.onKeyDown}
              onClick={(event) => {
                event.preventDefault();
                if (isRenaming || event.detail > 1) return;
                if (isWoke) onAcknowledgeWake();
                actions.open(thread.id, { split: false });
                onNavigate();
              }}
              onDoubleClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                setIsRenaming(true);
              }}
              className={cn(
                // Vertical panning stays with the scroller; this row never
                // claims a touch gesture for reordering.
                "absolute inset-0 touch-pan-y rounded-md",
                reorder && !reorder.disabled
                  ? "cursor-grab active:cursor-grabbing"
                  : "cursor-pointer",
              )}
            />
          </ThreadDetailsTooltip>
          <div className="pointer-events-none relative flex h-5 items-center gap-1.5">
            <span className="flex min-w-0 flex-1 items-center gap-1.5 text-2xs font-medium text-muted-foreground">
              {projectName ? (
                <ProjectFavicon src={projectIconUrl} className="size-3" />
              ) : null}
              <span className="min-w-0 truncate">{projectName ?? " "}</span>
            </span>
            {isWoke ? (
              <span className={cn(STATUS_SLOT_CLASS, "w-auto gap-1.5")}>
                {unpinButton}
                <Tooltip label="Dismiss Woke marker">
                  <button
                    type="button"
                    aria-label="Dismiss Woke marker"
                    onClick={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      onAcknowledgeWake();
                    }}
                    className="pointer-events-auto text-2xs font-medium text-[color:var(--bb-sidebar-woke)] hover:underline"
                  >
                    Woke
                  </button>
                </Tooltip>
                <StatusOrTime thread={thread} now={now} />
              </span>
            ) : (
              <span
                className={cn(
                  STATUS_SLOT_CLASS,
                  "group/status-slot pointer-events-auto relative h-5",
                  showParkActions &&
                    "[@media(hover:none)]:w-auto [@media(hover:none)]:gap-1.5",
                  !showParkActions && "w-auto min-w-20",
                )}
              >
                <span
                  className={cn(
                    "flex items-center justify-end gap-0.5 transition-opacity duration-150 ease-out motion-reduce:transition-none",
                    showParkActions &&
                      "absolute inset-y-0 right-0 [@media(hover:hover)]:group-hover/card:opacity-0 [@media(hover:hover)]:group-has-[:focus-visible]/status-slot:opacity-0 [@media(hover:none)]:static [@media(hover:none)]:opacity-100",
                    isSnoozeOpen &&
                      "opacity-0 [@media(hover:none)]:opacity-100",
                  )}
                >
                  {!showParkActions ? unpinButton : null}
                  <StatusOrTime thread={thread} now={now} />
                </span>
                {showParkActions ? (
                  <span
                    className={cn(
                      "pointer-events-none absolute inset-y-0 right-0 flex items-center gap-0.5 opacity-0 transition-opacity duration-150 ease-out has-[:focus-visible]:pointer-events-auto has-[:focus-visible]:opacity-100 group-hover/card:pointer-events-auto group-hover/card:opacity-100 [@media(hover:none)]:static [@media(hover:none)]:pointer-events-auto [@media(hover:none)]:opacity-100 motion-reduce:transition-none",
                      isSnoozeOpen && "pointer-events-auto opacity-100",
                    )}
                  >
                    {unpinButton}
                    <SnoozeSelect
                      label="Snooze thread"
                      snoozePresets={snoozePresets}
                      triggerClassName="h-5 w-5 border-0 px-0.5 py-0 shadow-none hover:bg-transparent focus:ring-0 [&>svg:last-child]:size-3"
                      onOpenChange={setIsSnoozeOpen}
                      onSnooze={onSnooze}
                      onPark={onPark}
                    />
                    <ParkButton
                      label="Settle thread"
                      onActivate={onSettle}
                    />
                  </span>
                ) : null}
              </span>
            )}
          </div>
          <div
            data-row-emphasis={emphasis}
            className={cn(
              "pointer-events-none relative mt-0.5 truncate text-sm",
              isRenaming && "pointer-events-auto",
              emphasis === "read-idle"
                ? "text-muted-foreground"
                : "text-foreground",
              (emphasis === "unread" || emphasis === "woke") && "font-medium",
            )}
          >
            <InlineThreadTitle
              thread={thread}
              editing={isRenaming}
              onEditingChange={setIsRenaming}
            />
          </div>
          <div className="pointer-events-none relative mt-0.5 flex h-4 items-center gap-1.5 text-2xs text-muted-foreground">
            {/* A thread without a worktree still runs somewhere, so the
                machine takes the branch's place rather than leaving the line
                blank. */}
            <ThreadLocation thread={thread} />
            <OpenPortsIndicator thread={thread} />
            {childThreads.length > 0 ? (
              <ChildThreadBadge
                threads={childThreads}
                childrenByParent={childrenByParent}
                expanded={childrenExpanded}
                controls={childListId}
                onToggle={onToggleChildren}
              />
            ) : null}
            {thread.environment?.branchName && thread.host ? (
              <Icon
                name="Computer"
                aria-label={`Machine: ${thread.host.name}`}
                className="size-3 shrink-0 text-muted-foreground/60"
              />
            ) : null}
            {thread.activity.workflows > 0 ? (
              <ActivityCount
                label="workflows"
                count={thread.activity.workflows}
              />
            ) : null}
            {thread.activity.backgroundAgents > 0 ? (
              <ActivityCount
                label="background agents"
                count={thread.activity.backgroundAgents}
              />
            ) : null}
            {pullRequest ? (
              <Tooltip
                label={`${pullRequest.title}\n${pullRequestStatusLabel(pullRequest)}`}
                className="whitespace-pre-line"
              >
                <a
                  href={pullRequest.url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(event) => event.stopPropagation()}
                  className={cn(
                    "pointer-events-auto relative shrink-0 font-mono hover:underline",
                    pullRequestToneClass(pullRequest),
                  )}
                >
                  #{pullRequest.number}
                </a>
              </Tooltip>
            ) : null}
            <ProviderGlyph
              providerId={thread.providerId}
              provider={provider}
            />
          </div>
        </div>
        {childThreads.length > 0 &&
        (childrenExpanded ||
          collapsedChildThreads(
            childThreads,
            childrenByParent,
            activeThreadId,
            showRunningChildrenWhenCollapsed,
          ).length > 0) ? (
          <ChildThreadList
            id={childListId}
            threads={childThreads}
            childrenByParent={childrenByParent}
            activeThreadId={activeThreadId}
            expanded={childrenExpanded}
            showRunningChildrenWhenCollapsed={
              showRunningChildrenWhenCollapsed
            }
            variant="sidebar"
            now={now}
            onOpenThread={(childId) => {
              actions.open(childId, { split: false });
              onNavigate();
            }}
          />
        ) : null}
      </li>
    </RowContextMenu>
  );
}

function ThreadLocation({ thread }: { thread: PluginSidebarThread }) {
  const branchName = thread.environment?.branchName;
  if (branchName) {
    const isWorktree =
      thread.environment?.workspaceDisplayKind === "managed-worktree" ||
      thread.environment?.workspaceDisplayKind === "unmanaged-worktree";
    return (
      <span className="flex min-w-0 flex-1 items-center gap-1 truncate">
        <Icon
          name={isWorktree ? "FolderGit" : "GitBranch"}
          aria-label={isWorktree ? "Worktree branch" : "Branch"}
          className="size-3 shrink-0 text-muted-foreground/60"
        />
        <span className="truncate font-mono">{branchName}</span>
      </span>
    );
  }
  if (thread.host) {
    return (
      <span className="flex min-w-0 flex-1 items-center gap-1 truncate">
        <Icon
          name="Computer"
          aria-hidden
          className="size-3 shrink-0 text-muted-foreground/60"
        />
        <span className="truncate">{thread.host.name}</span>
      </span>
    );
  }
  return <span className="flex-1" />;
}

function pullRequestStatusLabel(pullRequest: PluginSidebarPullRequest): string {
  switch (pullRequest.attention) {
    case "blocked":
      return "Blocked";
    case "changes_requested":
      return "Changes requested";
    case "checks_failed":
      return "Checks failed";
    case "checks_pending":
      return "Checks pending";
    case "conflicts":
      return "Conflicts";
    case "ready_to_merge":
      return "Ready to merge";
    case "review_requested":
      return "Review requested";
    case "draft":
      return "Draft";
    case "merged":
      return "Merged";
    case "closed":
      return "Closed";
    case "none":
      return pullRequest.state === "open"
        ? "Open"
        : pullRequest.state[0]!.toUpperCase() + pullRequest.state.slice(1);
  }
}

function pullRequestToneClass(pullRequest: PluginSidebarPullRequest): string {
  if (pullRequest.state === "merged" || pullRequest.attention === "merged") {
    return "text-[color:var(--bb-sidebar-pr-merged)]";
  }
  if (
    pullRequest.attention === "blocked" ||
    pullRequest.attention === "changes_requested" ||
    pullRequest.attention === "checks_failed" ||
    pullRequest.attention === "conflicts"
  ) {
    return "text-[color:var(--bb-sidebar-pr-alert)]";
  }
  if (
    pullRequest.state === "draft" ||
    pullRequest.attention === "draft"
  ) {
    return "text-muted-foreground/60";
  }
  if (pullRequest.state === "closed" || pullRequest.attention === "closed") {
    return "text-[color:var(--bb-sidebar-pr-alert)]";
  }
  if (pullRequest.state === "open") {
    return "text-[color:var(--bb-sidebar-pr-open)]";
  }
  return "text-muted-foreground";
}

function ParkButton({
  label,
  onActivate,
}: {
  label: string;
  onActivate: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onActivate();
      }}
      className={cn(
        "bb-sidebar-settle group/settle relative flex size-5 shrink-0 cursor-pointer items-center justify-center rounded-md text-muted-foreground",
        "transition-colors duration-200 ease-out hover:text-[color:var(--bb-sidebar-settle-active)]",
        "focus-visible:text-[color:var(--bb-sidebar-settle-active)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/50",
        "motion-reduce:transition-none",
      )}
    >
      {/* Move only the artwork so hovering an edge cannot move the hit area. */}
      <span
        aria-hidden="true"
        className={cn(
          "pointer-events-none relative flex size-full items-center justify-center rounded-[inherit]",
          "transition-[background-color,box-shadow,transform] duration-200 ease-out motion-reduce:transition-none",
          "group-hover/settle:bg-emerald-500/15 group-hover/settle:shadow-[0_0_0_3px_rgb(16_185_129_/_0.08)] group-focus-visible/settle:bg-emerald-500/15",
          "motion-safe:group-hover/settle:-translate-y-0.5 motion-safe:group-focus-visible/settle:-translate-y-0.5 motion-safe:group-active/settle:translate-y-0 motion-safe:group-active/settle:scale-90 group-active/settle:bg-emerald-500/25",
        )}
      >
        <Icon
          name="Check"
          aria-hidden
          className="size-3.5 transition-transform duration-200 ease-out motion-safe:group-hover/settle:rotate-[-8deg] motion-safe:group-hover/settle:scale-110 motion-safe:group-focus-visible/settle:rotate-[-8deg] motion-safe:group-focus-visible/settle:scale-110 motion-reduce:transition-none"
        />
        {[0, 1, 2, 3, 4].map((sparkle) => (
          <span
            key={sparkle}
            aria-hidden="true"
            className="bb-sidebar-settle-sparkle"
          />
        ))}
      </span>
    </button>
  );
}

function ActivityCount({ label, count }: { label: string; count: number }) {
  return (
    <span
      aria-label={`${count} ${label}`}
      className="shrink-0 rounded bg-muted px-1 font-mono text-2xs text-muted-foreground"
    >
      {count}
    </span>
  );
}
