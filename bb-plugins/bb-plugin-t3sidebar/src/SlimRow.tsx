import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import { RowContextMenu, RowMenuButton, type RowLifecycle } from "./RowMenu";
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
import { threadDisplayTitle } from "./inbox";
import { snoozeWakeLabel } from "./lifecycle";
import { NO_TOUCH_CALLOUT, useIsCompactViewport } from "./useCompactViewport";

/**
 * A parked thread: one line instead of a card. Density comes from the user
 * actually parking work, never from the sidebar guessing what still matters.
 *
 * Same structure as the card — a full-bleed anchor under the restore button,
 * because a `<button>` inside an `<a>` is invalid interactive nesting.
 */
export function SlimRow({
  thread,
  isActive,
  shelf,
  wakeAt,
  now,
  onNavigate,
  onRestore,
}: {
  thread: PluginSidebarThread;
  isActive: boolean;
  shelf: "snoozed" | "settled";
  wakeAt: number | null;
  now: number;
  onNavigate: () => void;
  onRestore: () => void;
}) {
  const actions = useSidebarThreadActions();
  const title = threadDisplayTitle(thread);
  const isCompact = useIsCompactViewport();

  const lifecycle: RowLifecycle = { kind: "restore", shelf, onRestore };

  return (
    <RowContextMenu thread={thread} lifecycle={lifecycle}>
      <li
        className="list-none"
        style={isCompact ? NO_TOUCH_CALLOUT : undefined}
      >
        <div
          className={cn(
            "group/slim relative flex h-8 items-center gap-2 rounded-md px-2.5 text-xs",
            isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
          )}
        >
          <a
            data-sidebar-thread-shortcut-target=""
            data-sidebar-thread-id={thread.id}
            href="#"
            aria-label={title}
            onClick={(event) => {
              event.preventDefault();
              actions.open(thread.id, {
                split: event.metaKey || event.ctrlKey,
              });
              onNavigate();
            }}
            className="absolute inset-0 cursor-pointer rounded-md"
          />
          <span
            className={cn(
              "pointer-events-none relative min-w-0 flex-1 truncate",
              isActive ? "text-foreground" : "text-muted-foreground/70",
              "group-hover/slim:text-foreground",
            )}
          >
            {title}
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
              "pointer-events-none relative tabular-nums text-muted-foreground/60",
              isCompact ? "text-xs" : "text-2xs",
            )}
          >
            <span
              className={cn(
                "flex items-center",
                !isCompact && "group-hover/slim:opacity-0",
              )}
            >
              {shelf === "snoozed" && wakeAt !== null ? (
                snoozeWakeLabel(wakeAt, now)
              ) : (
                <StatusOrTime thread={thread} now={now} />
              )}
            </span>
            {/* Hover swaps the wake time for the restore button on a pointer.
                A phone gets neither: the wake time stays — when a snoozed
                thread comes back is the shelf's whole question — and restoring
                moves into the row's menu. */}
            {isCompact ? null : (
              <button
                type="button"
                aria-label={
                  shelf === "snoozed" ? "Wake thread now" : "Un-settle thread"
                }
                onClick={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  onRestore();
                }}
                // Pulled right by its own padding, so the icon — not the hit
                // area — lands on the column.
                className="pointer-events-auto absolute -right-0.5 top-1/2 -translate-y-1/2 cursor-pointer rounded p-0.5 text-muted-foreground opacity-0 hover:text-foreground focus-visible:opacity-100 group-hover/slim:opacity-100"
              >
                <Icon
                  name={shelf === "snoozed" ? "Clock" : "ArrowTurnBackward"}
                  className="size-3.5"
                />
              </button>
            )}
          </span>
          {isCompact ? (
            <RowMenuButton thread={thread} lifecycle={lifecycle} />
          ) : null}
        </div>
      </li>
    </RowContextMenu>
  );
}
