import type { ReactNode } from "react";
import { experimental_useSidebarThreadActions as useSidebarThreadActions } from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import { BotAvatar } from "./BotAvatar";
import type { SidebarBot } from "./bots";
import type { BotActivitySummary } from "./bot-shelf";
import { STATUS_SLOT_CLASS, statusToneClass } from "./StatusSlot";

/**
 * One bot, as the heading of its own group of cards.
 *
 * A single line rather than a card: the bot is not work, it is who the work
 * below belongs to. It borrows the card's grammar anyway — the fixed status
 * slot on the right, the same status palette — so the column lines up and
 * the row speaks the same language as the cards under it.
 *
 * Same structure as a card: a full-bleed anchor UNDER the controls, because a
 * `<button>` inside an `<a>` is invalid interactive nesting and breaks
 * keyboard behaviour. The bot's cards render as `children`, a nested list
 * inside this row's own list item.
 */
export function BotRow({
  bot,
  activity,
  openTarget,
  hasRows,
  isCollapsed,
  onToggleCollapsed,
  containsActive,
  onNavigate,
  children,
}: {
  bot: SidebarBot;
  activity: BotActivitySummary;
  /** The thread a click opens; null when the bot has no conversation yet. */
  openTarget: string | null;
  /** Whether the row has cards under it to fold away. */
  hasRows: boolean;
  isCollapsed: boolean;
  onToggleCollapsed: () => void;
  /** The active thread is one of this bot's; drawn only while folded shut. */
  containsActive: boolean;
  onNavigate: () => void;
  children?: ReactNode;
}) {
  const actions = useSidebarThreadActions();
  const label =
    bot.role.trim().length > 0 ? `${bot.name}, ${bot.role}` : bot.name;

  return (
    <li className="list-none" data-bot-id={bot.id}>
      <div
        className={cn(
          "group/bot relative flex h-7 items-center gap-1.5 rounded-md px-2.5 transition-colors duration-150 ease-out motion-reduce:transition-none",
          // Tinted only while the selected conversation is folded out of
          // sight: while it is visible, its own card carries the tint.
          containsActive && isCollapsed
            ? "bg-sidebar-accent"
            : "hover:bg-sidebar-accent/60",
        )}
      >
        {openTarget === null ? null : (
          <a
            href="#"
            aria-label={`${label}: open main conversation`}
            onClick={(event) => {
              event.preventDefault();
              actions.open(openTarget, {
                split: event.metaKey || event.ctrlKey,
              });
              onNavigate();
            }}
            className="absolute inset-0 cursor-pointer rounded-md"
          />
        )}
        <span className="pointer-events-none relative flex size-4 shrink-0 items-center justify-center">
          <BotAvatar avatar={bot.avatar} size={16} />
        </span>
        <span className="pointer-events-none relative min-w-0 flex-1 truncate text-sm font-medium text-foreground">
          {bot.name}
        </span>
        {bot.role.trim().length > 0 ? (
          <span className="pointer-events-none relative hidden min-w-0 max-w-[40%] truncate text-2xs text-muted-foreground sm:inline">
            {bot.role}
          </span>
        ) : null}
        <span className={cn("pointer-events-none relative", STATUS_SLOT_CLASS)}>
          <BotStatus activity={activity} />
        </span>
        {hasRows ? (
          <button
            type="button"
            aria-expanded={!isCollapsed}
            aria-label={`${isCollapsed ? "Expand" : "Collapse"} ${bot.name}'s conversations`}
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              onToggleCollapsed();
            }}
            className="pointer-events-auto relative flex size-4 shrink-0 cursor-pointer items-center justify-center rounded text-muted-foreground/70 hover:bg-sidebar-accent hover:text-foreground"
          >
            <Icon
              name="ChevronDown"
              className={cn(
                "size-3 transition-transform duration-150 ease-out motion-reduce:transition-none",
                isCollapsed && "-rotate-90",
              )}
              aria-hidden
            />
          </button>
        ) : (
          <span className="flex size-4 shrink-0" aria-hidden />
        )}
      </div>
      {children}
    </li>
  );
}

/**
 * The bot's own status slot: what its conversations add up to, in the same
 * words and colours the cards use. A raised hand carries its count. Idle, the
 * slot says how many conversations the row groups — the one number a
 * collapsed bot still has to answer for.
 */
function BotStatus({ activity }: { activity: BotActivitySummary }) {
  const shared = "max-w-full truncate text-2xs font-medium";
  switch (activity.kind) {
    case "waiting":
      return (
        <span
          aria-label={`${activity.waiting} ${
            activity.waiting === 1 ? "conversation needs" : "conversations need"
          } you`}
          className={cn(shared, statusToneClass("waiting-for-input"))}
        >
          {activity.waiting === 1 ? "Needs you" : `${activity.waiting} need you`}
        </span>
      );
    case "working":
      return (
        <span
          aria-label={`${activity.working} ${
            activity.working === 1 ? "conversation" : "conversations"
          } working`}
          className={cn(shared, statusToneClass("runtime"))}
        >
          Working
        </span>
      );
    case "error":
      return (
        <span
          aria-label="A conversation failed"
          className={cn(shared, statusToneClass("unread-error"))}
        >
          Failed
        </span>
      );
    case "unread":
      return (
        <span
          aria-label="Unread conversations"
          className={cn(shared, statusToneClass("unread-success"))}
        >
          Unread
        </span>
      );
    case "idle":
    default:
      return (
        <span
          aria-label={`${activity.total} ${
            activity.total === 1 ? "conversation" : "conversations"
          }`}
          className="max-w-full truncate tabular-nums text-2xs text-muted-foreground"
        >
          {activity.total} {activity.total === 1 ? "thread" : "threads"}
        </span>
      );
  }
}
