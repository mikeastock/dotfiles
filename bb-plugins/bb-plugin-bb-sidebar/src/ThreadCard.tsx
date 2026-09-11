import {
  useId,
  useState,
  type KeyboardEventHandler,
  type MouseEvent as ReactMouseEvent,
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
} from "./ChildThreadList";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { SnoozeSelect } from "./SnoozeSelect";
import { cn } from "./lib/utils";
import { RowContextMenu } from "./RowContextMenu";
import { ProviderGlyph, type SidebarProvider } from "./ProviderGlyph";
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
import { threadDisplayTitle } from "./inbox";
import { InlineThreadTitle } from "./InlineThreadTitle";
import type { ConfiguredSnoozePreset } from "./lifecycle";
import { ProjectFavicon } from "./ProjectFavicon";

export interface ThreadReorderControls {
  disabled: boolean;
  isDragging: boolean;
  onPointerDown: PointerEventHandler<HTMLAnchorElement>;
  onKeyDown: KeyboardEventHandler<HTMLAnchorElement>;
}

/**
 * One thread as a three-line card: project and status, title, then branch and
 * activity. The card is the whole point of this sidebar — status lives in the
 * row instead of in its position, which is what lets the list stay still.
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
  isSelected,
  isWoke,
  canPark,
  snoozePresets,
  onNavigate,
  onSettle,
  onSnooze,
  onAcknowledgeWake,
  onSelectionClick,
  childThreads,
  childrenByParent,
  activeThreadId,
  childrenExpanded,
  onToggleChildren,
  reorder,
  now,
}: {
  thread: PluginSidebarThread;
  provider: SidebarProvider | null;
  projectName: string | null;
  projectIconUrl: string | null;
  isActive: boolean;
  isSelected: boolean;
  /** A snooze ended and has not yet been acknowledged. */
  isWoke: boolean;
  /** False while the thread is working or blocked on the user. */
  canPark: boolean;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onNavigate: () => void;
  onSettle: () => void;
  onSnooze: (snoozedUntil: number) => void;
  onAcknowledgeWake: () => void;
  onSelectionClick: (event: ReactMouseEvent<HTMLAnchorElement>) => boolean;
  childThreads: readonly PluginSidebarThread[];
  childrenByParent: ReadonlyMap<string, readonly PluginSidebarThread[]>;
  activeThreadId: string | null;
  childrenExpanded: boolean;
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

  return (
    <RowContextMenu
      thread={thread}
      canSnooze={canPark}
      canArchive={canPark}
      snoozePresets={snoozePresets}
      onSnooze={onSnooze}
      onSettle={canPark ? onSettle : undefined}
      onRename={() => setIsRenaming(true)}
    >
      <li
        className={cn(
          "list-none transition-opacity duration-150 ease-out motion-reduce:transition-none",
          reorder?.isDragging && "opacity-50",
        )}
      >
        <div
          data-parent-card=""
          className={cn(
            "group/card relative rounded-md px-2.5 py-2 transition-colors duration-150 ease-out motion-reduce:transition-none",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
            isSelected &&
              "bg-sidebar-accent ring-1 ring-inset ring-primary/60",
            // A thread open in another pane gets a weaker tint than the active
            // row, so the two states stay distinguishable.
            !isActive && layout !== null && "bg-sidebar-accent/30",
          )}
        >
          <a
            // Both attributes, or bb's nine thread shortcuts stop finding rows.
            data-sidebar-thread-shortcut-target=""
            data-sidebar-thread-id={thread.id}
            href="#"
            aria-label={`${isSelected ? "Selected, " : ""}${threadDisplayTitle(thread)}`}
            aria-current={isActive ? "page" : undefined}
            data-selected={isSelected ? "true" : undefined}
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
              if (onSelectionClick(event)) return;
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
              "absolute inset-0 rounded-md",
              reorder && !reorder.disabled
                ? "cursor-grab active:cursor-grabbing"
                : "cursor-pointer",
            )}
          />
          <div className="pointer-events-none relative flex h-5 items-center gap-1.5">
            <span className="flex min-w-0 flex-1 items-center gap-1.5 text-2xs font-medium text-muted-foreground">
              {projectName ? (
                <ProjectFavicon src={projectIconUrl} className="size-3" />
              ) : null}
              <span className="min-w-0 truncate">{projectName ?? " "}</span>
            </span>
            {thread.isPinned ? (
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
                  className="pointer-events-auto rounded p-0.5 text-muted-foreground opacity-0 transition-opacity duration-150 ease-out hover:text-foreground focus-visible:opacity-100 group-hover/card:opacity-100 motion-reduce:transition-none"
                >
                  <Icon name="PinOff" className="size-3.5" />
                </button>
              </Tooltip>
            ) : null}
            {isWoke ? (
              <Tooltip label="Dismiss Woke marker">
                <button
                  type="button"
                  aria-label="Dismiss Woke marker"
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    onAcknowledgeWake();
                  }}
                  className={cn(
                    STATUS_SLOT_CLASS,
                    "pointer-events-auto justify-end text-2xs font-medium text-amber-700 hover:underline dark:text-amber-300",
                  )}
                >
                  Woke
                </button>
              </Tooltip>
            ) : (
              <span
                className={cn(
                  STATUS_SLOT_CLASS,
                  "group/status-slot pointer-events-auto relative h-5",
                )}
              >
                <span
                  className={cn(
                    "absolute inset-y-0 right-0 flex items-center justify-end transition-opacity duration-150 ease-out group-has-[:focus-visible]/status-slot:opacity-0 motion-reduce:transition-none",
                    canPark &&
                      snoozePresets.length > 0 &&
                      "group-hover/card:opacity-0",
                    isSnoozeOpen && "opacity-0",
                  )}
                >
                  <StatusOrTime thread={thread} now={now} />
                </span>
                {canPark && snoozePresets.length > 0 ? (
                  <span
                    className={cn(
                      "pointer-events-none absolute inset-y-0 right-0 flex items-center gap-0.5 opacity-0 transition-opacity duration-150 ease-out has-[:focus-visible]:pointer-events-auto has-[:focus-visible]:opacity-100 group-hover/card:pointer-events-auto group-hover/card:opacity-100 motion-reduce:transition-none",
                      isSnoozeOpen && "pointer-events-auto opacity-100",
                    )}
                  >
                    <SnoozeSelect
                      label="Snooze thread"
                      snoozePresets={snoozePresets}
                      triggerClassName="h-5 w-5 border-0 px-0.5 py-0 shadow-none hover:bg-transparent focus:ring-0 [&>svg:last-child]:size-3"
                      onOpenChange={setIsSnoozeOpen}
                      onSnooze={onSnooze}
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
            {childThreads.length > 0 ? (
              <ChildThreadBadge
                threads={childThreads}
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
            <Tooltip
              label={threadMetadataLabel(thread, projectName, provider)}
              side="left"
              className="whitespace-pre-line"
            >
              <span
                tabIndex={0}
                aria-label="Thread details"
                className="pointer-events-auto rounded-sm outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                <ProviderGlyph
                  providerId={thread.providerId}
                  provider={provider}
                />
              </span>
            </Tooltip>
          </div>
        </div>
        {childThreads.length > 0 && childrenExpanded ? (
          <ChildThreadList
            id={childListId}
            threads={childThreads}
            childrenByParent={childrenByParent}
            activeThreadId={activeThreadId}
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

function workspaceLabel(thread: PluginSidebarThread): string | null {
  switch (thread.environment?.workspaceDisplayKind) {
    case "managed-worktree":
      return "Managed worktree";
    case "unmanaged-worktree":
      return "Unmanaged worktree";
    case "other":
      return "Checkout";
    default:
      return null;
  }
}

function activityLabel(thread: PluginSidebarThread): string {
  const parts: string[] = [];
  if (thread.hasPendingInteraction) parts.push("needs user input");
  const counts = [
    [thread.activity.workflows, "workflow"],
    [thread.activity.backgroundAgents, "background agent"],
    [thread.activity.backgroundCommands, "background command"],
    [thread.activity.planMode, "plan"],
    [thread.activity.goals, "goal"],
  ] as const;
  for (const [count, label] of counts) {
    if (count > 0) parts.push(`${count} ${label}${count === 1 ? "" : "s"}`);
  }
  return parts.length > 0 ? parts.join(", ") : "Idle";
}

function threadMetadataLabel(
  thread: PluginSidebarThread,
  projectName: string | null,
  provider: SidebarProvider | null,
): string {
  const workspace = workspaceLabel(thread);
  const lines = [
    projectName ? `Project: ${projectName}` : null,
    thread.environment?.name
      ? `Environment: ${thread.environment.name}`
      : null,
    workspace ? `Workspace: ${workspace}` : null,
    thread.environment?.branchName
      ? `Branch: ${thread.environment.branchName}`
      : null,
    thread.host ? `Machine: ${thread.host.name}` : null,
    `Provider: ${provider?.displayName ?? thread.providerId}`,
    `Activity: ${activityLabel(thread)}`,
  ];
  return lines.filter((line): line is string => line !== null).join("\n");
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
    return "text-violet-600 dark:text-violet-300/90";
  }
  if (
    pullRequest.attention === "blocked" ||
    pullRequest.attention === "changes_requested" ||
    pullRequest.attention === "checks_failed" ||
    pullRequest.attention === "conflicts"
  ) {
    return "text-red-600 dark:text-red-300/90";
  }
  if (
    pullRequest.state === "draft" ||
    pullRequest.attention === "draft"
  ) {
    return "text-muted-foreground/60";
  }
  if (pullRequest.state === "closed" || pullRequest.attention === "closed") {
    return "text-red-600 dark:text-red-300/90";
  }
  if (pullRequest.state === "open") {
    return "text-emerald-600 dark:text-emerald-300/90";
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
    <Tooltip label={label}>
      <button
        type="button"
        aria-label={label}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onActivate();
        }}
        className="rounded p-0.5 text-muted-foreground hover:text-foreground"
      >
        <Icon name="Check" className="size-3.5" />
      </button>
    </Tooltip>
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
