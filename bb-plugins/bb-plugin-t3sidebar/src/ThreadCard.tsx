import { useRef, useState } from "react";
import {
  experimental_useSidebarThreadPullRequest as useSidebarThreadPullRequest,
  experimental_useSidebarThreadSplit as useSidebarThreadSplit,
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { Icon, type IconName } from "./components/Icon";
import { cn } from "./lib/utils";
import { RowContextMenu, RowMenuButton, type RowLifecycle } from "./RowMenu";
import { ProviderGlyph } from "./ProviderGlyph";
import { STATUS_SLOT_CLASS, StatusOrTime, WaitingPill } from "./StatusSlot";
import type { SubtreeSummary } from "./tree";
import { threadDisplayTitle } from "./inbox";
import { TitleEditor } from "./TitleEditor";
import { resolveSnoozePresets } from "./lifecycle";
import {
  NO_TOUCH_CALLOUT,
  TOUCH_TARGET_CLASS,
  useIsCompactViewport,
} from "./useCompactViewport";

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
  projectName,
  parentTitle,
  depth,
  subtree,
  isCollapsed,
  onToggleCollapsed,
  isActive,
  canPark,
  onNavigate,
  onSettle,
  onSnooze,
  now,
}: {
  thread: PluginSidebarThread;
  projectName: string | null;
  /**
   * The thread this one was spawned under, named only when it is NOT the row
   * directly above. A nested child sits under its parent, so saying the name
   * again would be noise; a child whose parent is off screen has been promoted
   * to the left edge, and the name is the only thing that explains why.
   */
  parentTitle: string | null;
  /** Nesting level; 0 sits at the list's left edge. */
  depth: number;
  /** What this row is hiding when collapsed; null when it has no children. */
  subtree: SubtreeSummary | null;
  isCollapsed: boolean;
  onToggleCollapsed: () => void;
  isActive: boolean;
  /** False while the thread is working or blocked on the user. */
  canPark: boolean;
  onNavigate: () => void;
  onSettle: () => void;
  onSnooze: (snoozedUntil: number) => void;
  /** Quantized clock, so every card in one render agrees on "now". */
  now: number;
}) {
  const actions = useSidebarThreadActions();
  const { splitProps, layout } = useSidebarThreadSplit(thread.id);
  // Opt-in per row: this costs a git-host lookup, and threads sharing a
  // worktree share one.
  const { pullRequest } = useSidebarThreadPullRequest(thread.id);
  const isCompact = useIsCompactViewport();
  const [isRenaming, setIsRenaming] = useState(false);
  const titleRef = useRef<HTMLDivElement>(null);

  const lifecycle: RowLifecycle = canPark
    ? { kind: "park", onSnooze, onSettle }
    : null;
  const title = threadDisplayTitle(thread);
  // The one state this list shouts about. Keyed off the same field as
  // `canPark`, so the rail and the park actions can never disagree about
  // whether a thread is blocked.
  const isWaiting = thread.hasPendingInteraction;

  return (
    <RowContextMenu
      thread={thread}
      lifecycle={lifecycle}
      onStartRename={() => setIsRenaming(true)}
    >
      <li
        className="list-none"
        // Indent on the wrapper, not the card, so a nested card keeps its own
        // padding, its rail, and its full-bleed anchor intact. bb indents its
        // own rows 24px per level; a card is far taller than bb's 28px row and
        // its title needs the width more, so this steps in 14px.
        style={{
          ...(isCompact ? NO_TOUCH_CALLOUT : undefined),
          paddingLeft: depth * 14,
        }}
      >
        <div
          className={cn(
            "group/card relative rounded-md px-2 py-1.5 transition-colors",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
            // A thread open in another pane gets a weaker tint than the active
            // row, so the two states stay distinguishable.
            !isActive && layout !== null && "bg-sidebar-accent/30",
            // A rail, and deliberately no background tint. Tint is how this
            // list says "selected"; letting it also say "blocked" would make
            // the two states cousins. The rail is a channel nothing else uses,
            // so it survives selection instead of competing with it.
            isWaiting && "shadow-[inset_2px_0_0_var(--warning)]",
          )}
        >
          <a
            // Both attributes, or bb's nine thread shortcuts stop finding rows.
            data-sidebar-thread-shortcut-target=""
            data-sidebar-thread-id={thread.id}
            href="#"
            // The arrow glyph naming the parent is decorative, so the row's
            // own name is where that relationship has to be readable.
            aria-label={
              parentTitle === null ? title : `${title}, under ${parentTitle}`
            }
            {...splitProps}
            onClick={(event) => {
              event.preventDefault();
              actions.open(thread.id, {
                split: event.metaKey || event.ctrlKey,
              });
              onNavigate();
            }}
            // Renaming hangs off the anchor rather than off the title, so the
            // title keeps taking no pointer events: giving it any would cost
            // the row single-click opening and drag-to-split over its widest
            // line. The anchor covers the whole card, so the pointer's own
            // position is what says the user aimed at the title.
            //
            // The first click of the pair has already opened the thread. That
            // is the row's normal answer to a click and renaming the thread
            // you just opened is no surprise, so it is left alone.
            onDoubleClick={(event) => {
              const line = titleRef.current?.getBoundingClientRect();
              if (line === undefined) return;
              if (event.clientY < line.top || event.clientY > line.bottom) {
                return;
              }
              event.preventDefault();
              setIsRenaming(true);
            }}
            className="absolute inset-0 cursor-pointer rounded-md"
          />
          <div className="pointer-events-none relative flex h-5 items-center gap-1.5">
            {subtree === null ? null : (
              <CollapseToggle
                isCollapsed={isCollapsed}
                count={subtree.total}
                onToggle={onToggleCollapsed}
              />
            )}
            {isRenaming ? (
              <TitleEditor
                initialTitle={title}
                className="text-sm text-foreground"
                onCommit={(next) => {
                  setIsRenaming(false);
                  void actions.rename(thread.id, next);
                }}
                onCancel={() => setIsRenaming(false)}
              />
            ) : (
              <span
                ref={titleRef}
                className={cn(
                  // Weight alone carries unread. Fading the title — or the
                  // whole card — makes a thread at rest read as disabled, and
                  // at rest is what most of the list is most of the time.
                  "min-w-0 flex-1 truncate text-sm text-foreground",
                  thread.isUnread && "font-medium",
                )}
              >
                {title}
              </span>
            )}
            {/* Status at rest, park actions on hover. Only the status yields,
                so the title never shifts.

                A coarse pointer has no hover to reveal them with, so there the
                menu button below carries these actions instead and the status
                simply stays put. */}
            {canPark && !isCompact ? (
              <span className="pointer-events-auto hidden items-center gap-0.5 group-hover/card:flex">
                <ParkButton
                  label="Snooze until tomorrow"
                  icon="Clock"
                  onActivate={() =>
                    onSnooze(resolveSnoozePresets(new Date())[2]!.snoozedUntil)
                  }
                />
                <ParkButton
                  label="Settle thread"
                  icon="Check"
                  onActivate={onSettle}
                />
              </span>
            ) : null}
            <span
              className={cn(
                STATUS_SLOT_CLASS,
                // The pill sets its own width, so the fixed column yields for
                // it. Nothing else in the list is allowed to.
                isWaiting && "w-auto",
                canPark && !isCompact && "group-hover/card:hidden",
              )}
            >
              {isWaiting ? (
                <WaitingPill thread={thread} now={now} />
              ) : (
                <StatusOrTime thread={thread} now={now} />
              )}
            </span>
            {isCompact ? (
              <RowMenuButton
                thread={thread}
                lifecycle={lifecycle}
                onStartRename={() => setIsRenaming(true)}
              />
            ) : null}
          </div>
          <div
            className={cn(
              "pointer-events-none relative mt-px flex h-3.5 items-center gap-1.5 text-muted-foreground",
              isCompact ? "text-xs" : "text-2xs",
            )}
          >
            {/* Two lines, not three. The title leads and takes the status
                beside it; the project comes down here, where it costs nothing
                — it repeats down the whole column, so it was never worth a
                line of its own, and reading it before the title had the
                hierarchy backwards.

                One leading slot, filled by whichever of these the row has,
                most specific first. A collapsed summary and a promoted
                child's parent both say more than a project name that the
                scope picker above already implies. */}
            {subtree !== null && isCollapsed ? (
              // A collapsed row answers for what it is hiding. Without this,
              // collapsing would be a way to lose a thread waiting on you.
              <span className="flex min-w-0 flex-1 items-center gap-1.5">
                <span className="truncate">
                  {subtree.total} {subtree.total === 1 ? "thread" : "threads"}
                </span>
                {subtree.waiting > 0 ? (
                  <span className="shrink-0 font-medium text-[color:var(--warning)]">
                    {subtree.waiting} waiting
                  </span>
                ) : subtree.unread > 0 ? (
                  <span className="shrink-0 text-[color:var(--timeline-accent)]">
                    {subtree.unread} unread
                  </span>
                ) : null}
              </span>
            ) : parentTitle !== null ? (
              <span className="flex min-w-0 flex-1 items-center gap-0.5">
                <Icon
                  name="ArrowTurnBackward"
                  className="size-3 shrink-0 -scale-x-100 text-muted-foreground/60"
                  aria-hidden
                />
                <span className="truncate">{parentTitle}</span>
              </span>
            ) : (
              <span className="min-w-0 flex-1 truncate">
                {projectName ?? " "}
              </span>
            )}
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
              <a
                href={pullRequest.url}
                target="_blank"
                rel="noreferrer"
                onClick={(event) => event.stopPropagation()}
                title={pullRequest.title}
                // `title` is a hover tooltip and a touch screen has no hover,
                // so the number carries the PR's title for anyone who cannot
                // read it off the tooltip.
                aria-label={`Pull request #${pullRequest.number}: ${pullRequest.title}`}
                className={cn(
                  "pointer-events-auto relative shrink-0 font-mono hover:underline",
                  // Tiny mono text sitting on top of the card's full-bleed
                  // anchor: without a bigger target, a near miss opens the
                  // thread instead of the pull request.
                  isCompact && TOUCH_TARGET_CLASS,
                  pullRequest.state === "merged"
                    ? "text-[color:var(--pr-merged)]"
                    : pullRequest.attention === "checks_failed" ||
                        pullRequest.attention === "conflicts"
                      ? "text-destructive-text"
                      : pullRequest.attention === "ready_to_merge"
                        ? "text-success-foreground"
                        : "text-muted-foreground",
                )}
              >
                #{pullRequest.number}
              </a>
            ) : null}
            {/* Always drawn, so the line has a fixed right edge. */}
            <ProviderGlyph providerId={thread.providerId} />
          </div>
        </div>
      </li>
    </RowContextMenu>
  );
}

/**
 * The one control that opens and closes a subtree.
 *
 * It sits above the card's full-bleed anchor, so it has to take pointer events
 * back and stop the click reaching the row underneath — otherwise collapsing a
 * parent would also navigate to it.
 */
function CollapseToggle({
  isCollapsed,
  count,
  onToggle,
}: {
  isCollapsed: boolean;
  count: number;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      aria-expanded={!isCollapsed}
      aria-label={`${isCollapsed ? "Expand" : "Collapse"} ${count} child ${
        count === 1 ? "thread" : "threads"
      }`}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onToggle();
      }}
      className="pointer-events-auto relative -ml-1 flex size-4 shrink-0 cursor-pointer items-center justify-center rounded text-muted-foreground/70 hover:bg-sidebar-accent hover:text-foreground"
    >
      <Icon
        name="ChevronDown"
        className={cn(
          "size-3 transition-transform",
          isCollapsed && "-rotate-90",
        )}
        aria-hidden
      />
    </button>
  );
}

function ParkButton({
  label,
  icon,
  onActivate,
}: {
  label: string;
  icon: Extract<IconName, "Clock" | "Check">;
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
      className="cursor-pointer rounded p-0.5 text-muted-foreground hover:text-foreground"
    >
      <Icon name={icon} className="size-3.5" />
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
