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
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
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
  isActive,
  canPark,
  onNavigate,
  onSettle,
  onSnooze,
  now,
}: {
  thread: PluginSidebarThread;
  projectName: string | null;
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

  return (
    <RowContextMenu
      thread={thread}
      lifecycle={lifecycle}
      onStartRename={() => setIsRenaming(true)}
    >
      <li
        className="list-none"
        style={isCompact ? NO_TOUCH_CALLOUT : undefined}
      >
        <div
          className={cn(
            "group/card relative rounded-md px-2.5 py-2 transition-colors",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
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
            aria-label={title}
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
            <span
              className={cn(
                "min-w-0 flex-1 truncate font-medium text-muted-foreground",
                isCompact ? "text-xs" : "text-2xs",
              )}
            >
              {projectName ?? " "}
            </span>
            {/* Status at rest, park actions on hover. Only the status yields,
                so the project name never shifts.

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
                canPark && !isCompact && "group-hover/card:hidden",
              )}
            >
              <StatusOrTime thread={thread} now={now} />
            </span>
            {isCompact ? (
              <RowMenuButton
                thread={thread}
                lifecycle={lifecycle}
                onStartRename={() => setIsRenaming(true)}
              />
            ) : null}
          </div>
          {isRenaming ? (
            <TitleEditor
              initialTitle={title}
              className="mt-0.5 text-sm text-foreground"
              onCommit={(next) => {
                setIsRenaming(false);
                void actions.rename(thread.id, next);
              }}
              onCancel={() => setIsRenaming(false)}
            />
          ) : (
            <div
              ref={titleRef}
              className={cn(
                // Weight alone carries unread. Fading the title — or the whole
                // card — makes a thread at rest read as disabled, and at rest
                // is what most of the list is most of the time.
                "pointer-events-none relative mt-0.5 truncate text-sm text-foreground",
                thread.isUnread && "font-medium",
              )}
            >
              {title}
            </div>
          )}
          <div
            className={cn(
              "pointer-events-none relative mt-0.5 flex h-4 items-center gap-1.5 text-muted-foreground",
              isCompact ? "text-xs" : "text-2xs",
            )}
          >
            {/* A thread without a worktree still runs somewhere, so the
                machine takes the branch's place rather than leaving the line
                blank. */}
            {thread.environment?.branchName ? (
              <span className="min-w-0 flex-1 truncate font-mono">
                {thread.environment.branchName}
              </span>
            ) : thread.host ? (
              <span className="min-w-0 flex-1 truncate">
                {thread.host.name}
              </span>
            ) : (
              <span className="flex-1" />
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
      className="rounded p-0.5 text-muted-foreground hover:text-foreground"
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
