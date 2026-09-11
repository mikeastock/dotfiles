import { useState, type MouseEvent as ReactMouseEvent } from "react";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { cn } from "./lib/utils";
import { RowContextMenu } from "./RowContextMenu";
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
import { threadDisplayTitle } from "./inbox";
import { snoozeWakeLabel } from "./lifecycle";
import type { ConfiguredSnoozePreset } from "./lifecycle";
import { InlineThreadTitle } from "./InlineThreadTitle";
import { ProjectFavicon } from "./ProjectFavicon";

/**
 * A parked thread: one line instead of a card. Density comes from the user
 * actually parking work, never from the sidebar guessing what still matters.
 *
 * Same structure as the card — a full-bleed anchor under the restore button,
 * because a `<button>` inside an `<a>` is invalid interactive nesting.
 */
export function SlimRow({
  thread,
  projectName,
  projectIconUrl,
  isActive,
  isSelected,
  shelf,
  wakeAt,
  now,
  snoozePresets,
  onNavigate,
  onRestore,
  onSnooze,
  onSelectionClick,
}: {
  thread: PluginSidebarThread;
  projectName: string | null;
  projectIconUrl: string | null;
  isActive: boolean;
  isSelected: boolean;
  shelf: "snoozed" | "settled";
  wakeAt: number | null;
  now: number;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onNavigate: () => void;
  onRestore: () => void;
  onSnooze: (snoozedUntil: number) => void;
  onSelectionClick: (event: ReactMouseEvent<HTMLAnchorElement>) => boolean;
}) {
  const actions = useSidebarThreadActions();
  const title = threadDisplayTitle(thread);
  const rowLabel = projectName ? `${projectName} · ${title}` : title;
  const [isRenaming, setIsRenaming] = useState(false);

  return (
    <RowContextMenu
      thread={thread}
      canSnooze={shelf === "settled"}
      snoozePresets={snoozePresets}
      onSnooze={onSnooze}
      onWake={shelf === "snoozed" ? onRestore : undefined}
      onUnsettle={shelf === "settled" ? onRestore : undefined}
      onRename={() => setIsRenaming(true)}
    >
      <li className="list-none">
        <div
          className={cn(
            "group/slim relative flex h-8 items-center gap-2 rounded-md px-2.5 text-xs transition-colors duration-150 ease-out motion-reduce:transition-none",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
            isSelected &&
              "bg-sidebar-accent ring-1 ring-inset ring-primary/60",
          )}
        >
          <a
            data-sidebar-thread-shortcut-target=""
            data-sidebar-thread-id={thread.id}
            href="#"
            aria-label={`${isSelected ? "Selected, " : ""}${rowLabel}`}
            aria-current={isActive ? "page" : undefined}
            data-selected={isSelected ? "true" : undefined}
            onClick={(event) => {
              event.preventDefault();
              if (isRenaming || event.detail > 1) return;
              if (onSelectionClick(event)) return;
              actions.open(thread.id, { split: false });
              onNavigate();
            }}
            onDoubleClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              setIsRenaming(true);
            }}
            className="absolute inset-0 cursor-pointer rounded-md"
          />
          <span
            className={cn(
              "pointer-events-none relative flex min-w-0 flex-1 items-center gap-1",
              isRenaming && "pointer-events-auto",
              isActive ? "text-foreground" : "text-muted-foreground/70",
              "group-hover/slim:text-foreground",
            )}
          >
            {projectName && !isRenaming ? (
              <>
                <ProjectFavicon src={projectIconUrl} className="size-3" />
                <span
                  className={cn(
                    "max-w-[40%] shrink truncate",
                    isActive
                      ? "text-muted-foreground/70"
                      : "text-muted-foreground/50 group-hover/slim:text-muted-foreground/70",
                  )}
                >
                  {projectName}
                </span>
                <span
                  aria-hidden="true"
                  className={cn(
                    "shrink-0 text-sm leading-none",
                    isActive
                      ? "text-muted-foreground/60"
                      : "text-muted-foreground/45 group-hover/slim:text-muted-foreground/60",
                  )}
                >
                  ·
                </span>
              </>
            ) : null}
            <InlineThreadTitle
              thread={thread}
              editing={isRenaming}
              onEditingChange={setIsRenaming}
              className={cn(
                "min-w-0 flex-1 truncate",
                isActive
                  ? "text-foreground"
                  : "text-foreground/80 group-hover/slim:text-foreground",
              )}
            />
          </span>
          {/* The same slot as a card, so a shelf keeps the card's column. A
              snoozed row spends it on the wake time: when the thread comes
              BACK is that shelf's whole question, and it outranks an age the
              user has already decided to ignore.

              The restore button shares this one cell instead of following it.
              A button of its own would sit between the age and the row's edge
              and push the whole column off the card's, which is the one thing
              the fixed slot exists to prevent. */}
          <span
            className={cn(
              STATUS_SLOT_CLASS,
              "pointer-events-none relative tabular-nums text-2xs text-muted-foreground/60",
            )}
          >
            <span className="flex items-center transition-opacity duration-150 ease-out group-hover/slim:opacity-0 motion-reduce:transition-none">
              {shelf === "snoozed" && wakeAt !== null ? (
                snoozeWakeLabel(wakeAt, now)
              ) : (
                <StatusOrTime thread={thread} now={now} />
              )}
            </span>
            <Tooltip
              label={
                shelf === "snoozed" ? "Wake thread now" : "Un-settle thread"
              }
            >
              <button
                type="button"
                aria-label={
                  shelf === "snoozed"
                    ? "Wake thread now"
                    : "Un-settle thread"
                }
                onClick={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  onRestore();
                }}
                // Pulled right by its own padding, so the icon — not the hit
                // area — lands on the column.
                className="pointer-events-auto absolute -right-0.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground opacity-0 transition-opacity duration-150 ease-out hover:text-foreground focus-visible:opacity-100 group-hover/slim:opacity-100 motion-reduce:transition-none"
              >
                <Icon
                  name={shelf === "snoozed" ? "Clock" : "ArrowTurnBackward"}
                  className="size-3.5"
                />
              </button>
            </Tooltip>
          </span>
        </div>
      </li>
    </RowContextMenu>
  );
}
